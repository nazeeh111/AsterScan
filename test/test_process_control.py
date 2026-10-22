import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from lib.process_control import process_group_options, stop_process_tree


class ProcessControlTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'POSIX process-group integration check')
    def test_stop_terminates_scanner_and_updater_child(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'ready'
            marker = Path(directory) / 'child-finished'
            child_code = ('import pathlib,time; time.sleep(2); '
                          'pathlib.Path(%r).write_text("finished")' % str(marker))
            parent_code = ('import pathlib,subprocess,sys,time; '
                           'subprocess.Popen([sys.executable,"-c",%r]); '
                           'pathlib.Path(%r).write_text("ready"); time.sleep(10)'
                           % (child_code, str(ready)))
            process = subprocess.Popen([sys.executable, '-c', parent_code],
                                       **process_group_options())
            self.addCleanup(lambda: stop_process_tree(process, force=True))
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists())
            stop_process_tree(process)
            process.wait(timeout=3)
            time.sleep(2.2)
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
