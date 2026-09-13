from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import BadZipFile

from asap.config import Config
from asap.server import Dashboard, analysis_failure_message
from asap.storage import Store


class AnalysisFailureMessageTests(unittest.TestCase):
    def test_limits_identify_the_actual_configured_setting(self):
        cfg = Config(max_files=123, max_entry_bytes=456, max_compression_ratio=78,
                     max_archive_bytes=901, max_source_bytes=234)
        cases = {
            'archive file count limit exceeded': 'max_files=123',
            'source file count limit exceeded': 'max_files=123',
            'archive entry size limit exceeded': 'max_entry_bytes=456 bytes',
            'archive compression ratio limit exceeded': 'max_compression_ratio=78',
            'archive expanded size limit exceeded': 'max_archive_bytes=901 bytes',
            'nested APK budget exceeded': 'max_archive_bytes=901 bytes',
            'aggregate source byte limit exceeded': 'max_source_bytes=234 bytes',
            'archive text aggregate source byte limit exceeded': 'max_source_bytes=234 bytes',
        }
        for error, setting in cases.items():
            with self.subTest(error=error):
                message = analysis_failure_message(ValueError(error), cfg)
                self.assertIn(setting, message)
                self.assertIn('재분석', message)
                self.assertNotIn('Analysis failed', message)

    def test_directory_and_split_limits_are_explicit(self):
        message = analysis_failure_message(ValueError('directory traversal file budget exceeded'), Config(max_files=123))
        self.assertIn('max_files=123', message)
        self.assertIn('492', message)
        message = analysis_failure_message(ValueError('split APK limit exceeded'), Config())
        self.assertIn('128', message)

    def test_known_input_failures_offer_specific_actions(self):
        cases = {
            'input does not exist': '다시 업로드',
            'split archive contains no APKs': 'APK가 없습니다',
            'encrypted archives are not supported': '암호화되지 않은',
            'Retained APK changed before analysis': '달라졌습니다',
            'unsafe archive path': '파일 경로',
            'duplicate or case-colliding archive entry': '중복',
            'archive links and special files are forbidden': '특수 파일',
        }
        for error, expected in cases.items():
            with self.subTest(error=error):
                self.assertIn(expected, analysis_failure_message(ValueError(error), Config()))

    def test_exception_details_and_paths_are_never_disclosed(self):
        secret = '/private/customer/APK/<script>secret-token</script>'
        cases = [
            (ValueError(secret), 'ValueError'),
            (ValueError('archive compression ratio limit exceeded: ' + secret), 'ValueError'),
            (RuntimeError(secret), 'RuntimeError'),
            (BadZipFile(secret), '압축 파일'),
            (FileNotFoundError(secret), '찾을 수 없습니다'),
            (PermissionError(secret), '권한'),
        ]
        for exc, expected in cases:
            with self.subTest(exception=type(exc).__name__, message=str(exc)):
                message = analysis_failure_message(exc, Config())
                self.assertIn(expected, message)
                self.assertNotIn(secret, message)
                self.assertNotIn('secret-token', message)

    def test_dashboard_persists_failed_state_and_safe_message(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = Config(max_compression_ratio=99)
            dashboard = Dashboard(Path(directory) / 'workspace', cfg)
            try:
                for number, exc in enumerate([
                    ValueError('archive compression ratio limit exceeded'),
                    ValueError('/private/customer/secret-token'),
                ]):
                    job_id = f'{number + 1:032x}'
                    dashboard.store.create(job_id, 'sample.apk', 'queued')
                    with patch('asap.server.scan', side_effect=exc), patch('asap.server.write_reports') as write:
                        dashboard.process(job_id, Path(directory) / 'sample.apk')
                    job = dashboard.store.get(job_id)
                    self.assertEqual(job['state'], 'failed')
                    self.assertEqual(job['message'], analysis_failure_message(exc, cfg))
                    self.assertNotIn('secret-token', job['message'])
                    self.assertIsNone(job['active'])
                    write.assert_not_called()
                persisted = Store(dashboard.store.root).get(f'{1:032x}')
                self.assertEqual(persisted['state'], 'failed')
                self.assertIn('max_compression_ratio=99', persisted['message'])
            finally:
                dashboard.pool.shutdown(wait=True, cancel_futures=True)


if __name__ == '__main__':
    unittest.main()
