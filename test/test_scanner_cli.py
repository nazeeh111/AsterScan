import os
import json
import contextlib
import io
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lib.lokilogger import LokiLogger


SOURCE = Path(__file__).resolve().parents[1]


class ScannerCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / 'app'
        self.app.mkdir()
        shutil.copy2(SOURCE / 'asterscan.py', self.app)
        shutil.copytree(SOURCE / 'lib', self.app / 'lib', ignore=shutil.ignore_patterns('__pycache__'))
        (self.app / 'config').mkdir()
        (self.app / 'config' / 'excludes.cfg').write_text('', encoding='utf-8')
        (self.app / 'signature-base' / 'yara').mkdir(parents=True)
        (self.app / 'signature-base' / 'iocs').mkdir()
        (self.app / 'signature-base' / 'misc').mkdir()
        (self.app / 'signature-base' / 'misc' / 'file-type-signatures.txt').write_text('', encoding='utf-8')
        (self.app / 'signature-base' / 'yara' / 'test.yar').write_text(
            'rule AsterCliTest { strings: $marker = "ASTERSCAN_CLI_TEST" condition: $marker }\n',
            encoding='utf-8',
        )
        self.target = self.root / 'target.txt'
        self.target.write_text('ASTERSCAN_CLI_TEST\n', encoding='utf-8')

    def run_scan(self, *extra):
        return subprocess.run(
            [sys.executable, str(self.app / 'asterscan.py'), '--nolog', '--noindicator',
             '--noprocscan', '--intense', *extra],
            cwd=self.root,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def test_explicit_file_detects_yara_marker(self):
        result = self.run_scan('-p', str(self.target))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('AsterCliTest', result.stdout)
        self.assertIn('Suspicious objects detected!', result.stdout)

    def test_missing_path_never_reports_clean(self):
        result = self.run_scan('-p', str(self.root / 'missing'))
        self.assertEqual(result.returncode, 2)
        self.assertIn('SCAN INCOMPLETE', result.stdout)
        self.assertNotIn('SYSTEM SEEMS TO BE CLEAN', result.stdout)

    def test_only_relevant_still_reports_incomplete_scan(self):
        result = self.run_scan('--onlyrelevant', '-p', str(self.root / 'missing'))
        self.assertEqual(result.returncode, 2)
        self.assertIn('SCAN INCOMPLETE', result.stdout)

    def test_no_scan_selected_never_reports_clean(self):
        result = self.run_scan('--nofilescan')
        self.assertEqual(result.returncode, 2)
        self.assertIn('SCAN INCOMPLETE', result.stdout)

    def test_invalid_score_rejected(self):
        result = self.run_scan('-a', 'oops')
        self.assertEqual(result.returncode, 2)
        self.assertIn('invalid int value', result.stderr)

    def test_jsonl_emits_structured_finding_without_banner(self):
        result = subprocess.run(
            [sys.executable, str(self.app / 'asterscan.py'), '--jsonl', '--nolog',
             '--noprocscan', '--intense', '-p', str(self.target)],
            cwd=self.root, text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        finding = next(event for event in events if event.get('data', {}).get('kind') == 'file')
        self.assertEqual(finding['level'], 'WARNING')
        self.assertEqual(finding['data']['path'], str(self.target))
        self.assertEqual(finding['data']['score'], 70)
        self.assertIn('AsterCliTest', finding['data']['reasons'][0])
        coverage = next(event['data'] for event in events if event.get('data', {}).get('kind') == 'coverage')
        self.assertEqual(coverage['files_seen'], 1)
        self.assertEqual(coverage['contents_inspected'], 1)

    def test_jsonl_and_csv_are_exclusive(self):
        result = self.run_scan('--jsonl', '--csv')
        self.assertEqual(result.returncode, 2)
        self.assertIn('cannot be used together', result.stderr)

    def test_html_report_contains_structured_finding_and_escapes_rule_text(self):
        (self.app / 'signature-base' / 'yara' / 'test.yar').write_text(
            'rule AsterCliTest { meta: description = "<img src=x onerror=alert(1)> __ASTER_LOGO__" '
            'strings: $marker = "ASTERSCAN_CLI_TEST" condition: $marker }\n',
            encoding='utf-8',
        )
        report = self.root / 'report.html'
        result = self.run_scan('--report', str(report), '-p', str(self.target))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        html = report.read_text(encoding='utf-8')
        self.assertIn('Scan report', html)
        self.assertNotIn('<img src=x onerror=alert(1)>', html)
        embedded = html.split('const report=', 1)[1].split(';\nconst $=', 1)[0]
        payload = json.loads(embedded)
        self.assertEqual(payload['status'], 'warning')
        self.assertEqual(payload['coverage']['contents_inspected'], 1)
        finding = next(event for event in payload['events'] if event.get('data', {}).get('kind') == 'file')
        self.assertIn('<img src=x onerror=alert(1)>', finding['data']['reasons'][0])
        self.assertIn('__ASTER_LOGO__', finding['data']['reasons'][0])

    def test_html_report_marks_incomplete_scan(self):
        report = self.root / 'incomplete.html'
        result = self.run_scan('--report', str(report), '-p', str(self.root / 'missing'))
        self.assertEqual(result.returncode, 2)
        html = report.read_text(encoding='utf-8')
        embedded = html.split('const report=', 1)[1].split(';\nconst $=', 1)[0]
        self.assertEqual(json.loads(embedded)['status'], 'incomplete')

    def test_html_report_never_overwrites_existing_file(self):
        report = self.root / 'existing.html'
        report.write_text('keep me', encoding='utf-8')
        result = self.run_scan('--report', str(report), '-p', str(self.target))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report.read_text(encoding='utf-8'), 'keep me')

    def test_failed_explicit_update_returns_nonzero(self):
        result = self.run_scan('--update')
        self.assertEqual(result.returncode, 2)
        self.assertIn('Cannot find the AsterScan updater', result.stdout)

    def test_missing_signatures_stop_scan(self):
        shutil.rmtree(self.app / 'signature-base')
        result = self.run_scan('-p', str(self.target))
        self.assertEqual(result.returncode, 2)
        self.assertIn('Signatures are unavailable', result.stdout)
        self.assertNotIn('SYSTEM SEEMS TO BE CLEAN', result.stdout)

    def test_jsonl_remains_parseable_when_bootstrap_updater_fails(self):
        shutil.rmtree(self.app / 'signature-base')
        (self.app / 'asterscan-updater.py').write_text(
            'print("UPDATER OUTPUT")\nraise SystemExit(1)\n', encoding='utf-8')
        result = subprocess.run(
            [sys.executable, str(self.app / 'asterscan.py'), '--jsonl', '--nolog',
             '--noprocscan', '-p', str(self.target)],
            cwd=self.root, text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(any(event['level'] == 'ERROR' for event in events))
        self.assertTrue(any(event['module'] == 'Update' and 'UPDATER OUTPUT' in event['message']
                            for event in events))

    def test_interrupt_emits_jsonl_error_and_nonzero_exit(self):
        output = io.StringIO()
        scanner = runpy.run_path(str(SOURCE / 'asterscan.py'))
        with contextlib.redirect_stdout(output):
            logger = LokiLogger(True, '', 'test-host', '', '', False, False, False,
                                False, 'linux', 'test', jsonl=True)
            scanner['signal_handler'].__globals__['logger'] = logger
            with self.assertRaises(SystemExit) as result:
                scanner['signal_handler'](None, None)
        self.assertEqual(result.exception.code, 130)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(events[-1]['level'], 'ERROR')

    @unittest.skipIf(os.name == 'nt', 'POSIX permission test')
    def test_unreadable_fast_mode_file_never_reports_clean(self):
        target = self.root / 'unreadable.bin'
        target.write_text('not a detection fixture', encoding='utf-8')
        target.chmod(0)
        self.addCleanup(target.chmod, 0o600)
        if os.access(target, os.R_OK):
            self.skipTest('test process can still read mode-000 files')
        result = subprocess.run(
            [sys.executable, str(self.app / 'asterscan.py'), '--nolog', '--noindicator',
             '--noprocscan', '-p', str(target)],
            cwd=self.root, text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('SCAN INCOMPLETE', result.stdout)
        self.assertNotIn('SYSTEM SEEMS TO BE CLEAN', result.stdout)


if __name__ == '__main__':
    unittest.main()
