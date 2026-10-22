import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
