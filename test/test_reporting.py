import contextlib
import io
import unittest

from lib.lokilogger import LokiLogger


class ReportingTests(unittest.TestCase):
    def test_late_finding_and_error_survive_routine_event_limit(self):
        with contextlib.redirect_stdout(io.StringIO()):
            logger = LokiLogger(True, '', 'test-host', '', '', False, True, True,
                                False, 'linux', 'test', capture_report=True)
            for index in range(2001):
                logger.log('NOTICE', 'Test', 'routine %s' % index)
            logger.log('ALERT', 'FileScan', 'late alert', data={'kind': 'file', 'path': '/tmp/a'})
            logger.log('ERROR', 'FileScan', 'late error')
            logger.log('NOTICE', 'FileScan', 'late notice finding', data={'kind': 'file', 'path': '/tmp/b'})
        self.assertEqual(logger.report_dropped, 1)
        self.assertEqual([event['message'] for event in logger.report_events[-3:]],
                         ['late alert', 'late error', 'late notice finding'])
        self.assertEqual(logger.alerts, 1)
        self.assertEqual(logger.errors, 1)


if __name__ == '__main__':
    unittest.main()
