import importlib.util
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from lib.helpers import removeNonAsciiDrop


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("asterscan_updater", ROOT / "asterscan-updater.py")
updater_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater_module)


class QuietLogger:
    def log(self, *_args):
        pass


def archive(member, content):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        if isinstance(member, dict):
            for name, data in member.items():
                bundle.writestr(name, data)
        else:
            bundle.writestr(member, content)
    return output.getvalue()


VALID_RULE = "rule ValidRule { condition: true }"


class AsterScanTests(unittest.TestCase):
    def test_printable_first_bytes_are_text(self):
        self.assertEqual(removeNonAsciiDrop(b"AB\x00CD\n"), "ABCD")

    def test_clean_signature_update_keeps_both_sources(self):
        with tempfile.TemporaryDirectory() as app_path:
            sig_dir = Path(app_path) / "signature-base"
            sig_dir.mkdir()
            (sig_dir / "stale.txt").write_text("old", encoding="utf-8")
            sources = {
                "https://example.invalid/one.zip": archive("one/iocs/test-hash.txt", "hash rule"),
                "https://example.invalid/two.zip": archive("two/yara/test.yar", VALID_RULE),
            }
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = list(sources)
            with patch.object(updater_module, "urlopen", side_effect=lambda url: io.BytesIO(sources[url])):
                self.assertTrue(updater.update_signatures(clean=True))
            self.assertFalse((sig_dir / "stale.txt").exists())
            self.assertEqual((sig_dir / "iocs" / "test-hash.txt").read_text(), "hash rule")
            self.assertEqual((sig_dir / "yara" / "test.yar").read_text(), VALID_RULE)

    def test_bad_second_download_keeps_existing_signatures(self):
        with tempfile.TemporaryDirectory() as app_path:
            sig_dir = Path(app_path) / "signature-base"
            sig_dir.mkdir()
            (sig_dir / "known-good.yar").write_text("keep me", encoding="utf-8")
            sources = {
                "https://example.invalid/one.zip": archive("one/yara/new.yar", VALID_RULE),
                "https://example.invalid/two.zip": b"not a ZIP archive",
            }
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = list(sources)
            with patch.object(updater_module, "urlopen", side_effect=lambda url: io.BytesIO(sources[url])):
                self.assertFalse(updater.update_signatures(clean=True))
            self.assertEqual((sig_dir / "known-good.yar").read_text(), "keep me")
            self.assertFalse((sig_dir / "yara" / "new.yar").exists())

    def test_failed_download_does_not_mark_source_current(self):
        with tempfile.TemporaryDirectory() as app_path:
            previous_cwd = os.getcwd()
            os.chdir(app_path)
            try:
                sig_url = "https://github.com/acme/rules/archive/main.zip"
                commit_url = "https://api.github.com/repos/acme/rules/commits/main"
                updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
                updater.UPDATE_URL_SIGS = [sig_url]
                cache = Path(app_path) / "_acme_rules.cache"

                def failed_download(url):
                    return io.BytesIO(json.dumps({"sha": "abc"}).encode() if url == commit_url else b"bad ZIP")

                with patch.object(updater_module, "urlopen", side_effect=failed_download):
                    self.assertFalse(updater.update_signatures())
                self.assertFalse(cache.exists())

                def good_download(url):
                    return io.BytesIO(json.dumps({"sha": "abc"}).encode() if url == commit_url else archive("rules/yara/new.yar", VALID_RULE))

                with patch.object(updater_module, "urlopen", side_effect=good_download):
                    self.assertTrue(updater.update_signatures())
                self.assertEqual(cache.read_text(), "abc")
            finally:
                os.chdir(previous_cwd)

    def test_clean_update_rejects_archive_without_signatures(self):
        with tempfile.TemporaryDirectory() as app_path:
            sig_dir = Path(app_path) / "signature-base"
            sig_dir.mkdir()
            old_rule = sig_dir / "known-good.yar"
            old_rule.write_text(VALID_RULE, encoding="utf-8")
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = ["https://example.invalid/empty.zip"]
            with patch.object(updater_module, "urlopen", return_value=io.BytesIO(archive("repo/README.md", "notes"))):
                self.assertFalse(updater.update_signatures(clean=True))
            self.assertEqual(old_rule.read_text(), VALID_RULE)

    def test_collision_within_archive_keeps_existing_signatures(self):
        with tempfile.TemporaryDirectory() as app_path:
            sig_dir = Path(app_path) / "signature-base"
            sig_dir.mkdir()
            old_rule = sig_dir / "known-good.yar"
            old_rule.write_text(VALID_RULE, encoding="utf-8")
            bundle = archive({"repo/yara/a/shared.yar": VALID_RULE,
                              "repo/yara/b/shared.yar": "rule Other { condition: true }"}, None)
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = ["https://example.invalid/collision.zip"]
            with patch.object(updater_module, "urlopen", return_value=io.BytesIO(bundle)):
                self.assertFalse(updater.update_signatures(clean=True))
            self.assertEqual(old_rule.read_text(), VALID_RULE)
            self.assertFalse((sig_dir / "yara" / "shared.yar").exists())

    def test_collision_across_archives_keeps_existing_signatures(self):
        with tempfile.TemporaryDirectory() as app_path:
            sig_dir = Path(app_path) / "signature-base"
            sig_dir.mkdir()
            old_rule = sig_dir / "known-good.yar"
            old_rule.write_text(VALID_RULE, encoding="utf-8")
            sources = {
                "https://example.invalid/one.zip": archive("one/yara/shared.yar", VALID_RULE),
                "https://example.invalid/two.zip": archive("two/yara/shared.yar", "rule Other { condition: true }"),
            }
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = list(sources)
            with patch.object(updater_module, "urlopen", side_effect=lambda url: io.BytesIO(sources[url])):
                self.assertFalse(updater.update_signatures(clean=True))
            self.assertEqual(old_rule.read_text(), VALID_RULE)

    def test_invalid_yara_rule_does_not_replace_signatures(self):
        with tempfile.TemporaryDirectory() as app_path:
            sig_dir = Path(app_path) / "signature-base"
            sig_dir.mkdir()
            old_rule = sig_dir / "known-good.yar"
            old_rule.write_text(VALID_RULE, encoding="utf-8")
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = ["https://example.invalid/bad-rule.zip"]
            with patch.object(updater_module, "urlopen", return_value=io.BytesIO(archive("repo/yara/bad.yar", "invalid yara"))):
                self.assertFalse(updater.update_signatures(clean=True))
            self.assertEqual(old_rule.read_text(), VALID_RULE)

    def test_missing_local_signatures_ignore_matching_cache(self):
        with tempfile.TemporaryDirectory() as app_path:
            sig_url = "https://github.com/acme/rules/archive/main.zip"
            commit_url = "https://api.github.com/repos/acme/rules/commits/main"
            (Path(app_path) / "_acme_rules.cache").write_text("abc", encoding="utf-8")
            sources = {
                commit_url: json.dumps({"sha": "abc"}).encode(),
                sig_url: archive("rules/yara/new.yar", VALID_RULE),
            }
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = [sig_url]
            with patch.object(updater_module, "urlopen", side_effect=lambda url: io.BytesIO(sources[url])) as fetch:
                self.assertTrue(updater.update_signatures())
            self.assertIn(sig_url, [call.args[0] for call in fetch.call_args_list])
            self.assertTrue((Path(app_path) / "signature-base/yara/new.yar").exists())

    def test_one_provider_missing_or_corrupt_refreshes_only_that_provider(self):
        first_url = "https://github.com/acme/first/archive/main.zip"
        second_url = "https://github.com/acme/second/archive/main.zip"
        first_api = "https://api.github.com/repos/acme/first/commits/main"
        second_api = "https://api.github.com/repos/acme/second/commits/main"
        sources = {
            first_api: json.dumps({"sha": "first-revision"}).encode(),
            second_api: json.dumps({"sha": "second-revision"}).encode(),
            first_url: archive("first/yara/first.yar", "rule First { condition: true }"),
            second_url: archive("second/yara/second.yar", "rule Second { condition: true }"),
        }
        for damage in ("missing", "corrupt"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as app_path:
                updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
                updater.UPDATE_URL_SIGS = [first_url, second_url]
                fetch_source = lambda url: io.BytesIO(sources[url])
                with patch.object(updater_module, "urlopen", side_effect=fetch_source):
                    self.assertTrue(updater.update_signatures())

                first_rule = Path(app_path) / "signature-base/yara/first.yar"
                second_rule = Path(app_path) / "signature-base/yara/second.yar"
                if damage == "missing":
                    first_rule.unlink()
                else:
                    first_rule.write_text("rule Tampered { condition: true }", encoding="utf-8")

                with patch.object(updater_module, "urlopen", side_effect=fetch_source) as fetch:
                    self.assertTrue(updater.update_signatures())
                fetched_urls = [call.args[0] for call in fetch.call_args_list]
                self.assertIn(first_url, fetched_urls)
                self.assertNotIn(second_url, fetched_urls)
                self.assertEqual(first_rule.read_text(), "rule First { condition: true }")
                self.assertEqual(second_rule.read_text(), "rule Second { condition: true }")

    def test_source_refresh_removes_obsolete_owned_rule(self):
        sig_url = "https://github.com/acme/rules/archive/main.zip"
        commit_url = "https://api.github.com/repos/acme/rules/commits/main"
        with tempfile.TemporaryDirectory() as app_path:
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = [sig_url]
            sources = {commit_url: json.dumps({"sha": "one"}).encode(),
                       sig_url: archive("rules/yara/old.yar", VALID_RULE)}
            with patch.object(updater_module, "urlopen", side_effect=lambda url: io.BytesIO(sources[url])):
                self.assertTrue(updater.update_signatures())
            sources[commit_url] = json.dumps({"sha": "two"}).encode()
            sources[sig_url] = archive("rules/yara/new.yar", "rule New { condition: true }")
            with patch.object(updater_module, "urlopen", side_effect=lambda url: io.BytesIO(sources[url])):
                self.assertTrue(updater.update_signatures())
            self.assertFalse((Path(app_path) / "signature-base/yara/old.yar").exists())
            self.assertTrue((Path(app_path) / "signature-base/yara/new.yar").exists())

    def test_refresh_cannot_overwrite_cached_provider_rule(self):
        first_url = "https://github.com/acme/first/archive/main.zip"
        second_url = "https://github.com/acme/second/archive/main.zip"
        first_api = "https://api.github.com/repos/acme/first/commits/main"
        second_api = "https://api.github.com/repos/acme/second/commits/main"
        with tempfile.TemporaryDirectory() as app_path:
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = [first_url, second_url]
            sources = {
                first_api: json.dumps({"sha": "one"}).encode(),
                second_api: json.dumps({"sha": "stable"}).encode(),
                first_url: archive("first/yara/first.yar", "rule First { condition: true }"),
                second_url: archive("second/yara/shared.yar", "rule Shared { condition: true }"),
            }
            fetch_source = lambda url: io.BytesIO(sources[url])
            with patch.object(updater_module, "urlopen", side_effect=fetch_source):
                self.assertTrue(updater.update_signatures())
            sources[first_api] = json.dumps({"sha": "two"}).encode()
            sources[first_url] = archive("first/yara/shared.yar", "rule Replacement { condition: true }")
            with patch.object(updater_module, "urlopen", side_effect=fetch_source):
                self.assertFalse(updater.update_signatures())
            sig_dir = Path(app_path) / "signature-base/yara"
            self.assertEqual((sig_dir / "shared.yar").read_text(), "rule Shared { condition: true }")
            self.assertTrue((sig_dir / "first.yar").exists())


if __name__ == "__main__":
    unittest.main()
