import importlib.util
import io
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
        bundle.writestr(member, content)
    return output.getvalue()


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
                "https://example.invalid/two.zip": archive("two/yara/test.yar", "yara rule"),
            }
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = list(sources)
            with patch.object(updater_module, "urlopen", side_effect=lambda url: io.BytesIO(sources[url])):
                self.assertTrue(updater.update_signatures(clean=True))
            self.assertFalse((sig_dir / "stale.txt").exists())
            self.assertEqual((sig_dir / "iocs" / "test-hash.txt").read_text(), "hash rule")
            self.assertEqual((sig_dir / "yara" / "test.yar").read_text(), "yara rule")

    def test_bad_second_download_keeps_existing_signatures(self):
        with tempfile.TemporaryDirectory() as app_path:
            sig_dir = Path(app_path) / "signature-base"
            sig_dir.mkdir()
            (sig_dir / "known-good.yar").write_text("keep me", encoding="utf-8")
            sources = {
                "https://example.invalid/one.zip": archive("one/yara/new.yar", "new rule"),
                "https://example.invalid/two.zip": b"not a ZIP archive",
            }
            updater = updater_module.LOKIUpdater(False, QuietLogger(), app_path)
            updater.UPDATE_URL_SIGS = list(sources)
            with patch.object(updater_module, "urlopen", side_effect=lambda url: io.BytesIO(sources[url])):
                self.assertFalse(updater.update_signatures(clean=True))
            self.assertEqual((sig_dir / "known-good.yar").read_text(), "keep me")
            self.assertFalse((sig_dir / "yara" / "new.yar").exists())


if __name__ == "__main__":
    unittest.main()
