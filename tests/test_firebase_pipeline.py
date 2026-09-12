"""Firebase attachments, report isolation, category filtering, and CLI behavior."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from asap.cli import main
from asap.config import Config
from asap.engine import scan, should_fail
from asap.reporting import write_reports

FIXTURE = Path(__file__).parent / 'fixtures/firebase'


class FirebasePipelineTests(unittest.TestCase):
    def base_source(self, directory):
        root = Path(directory) / 'app'
        root.mkdir()
        shutil.copyfile(FIXTURE / 'AndroidManifest.xml', root / 'AndroidManifest.xml')
        return root

    def test_full_scan_reaches_all_four_firebase_rules_without_network(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = scan(FIXTURE, Config(decompile=False))
        self.assertTrue({'DS009', 'DS010', 'DS011', 'DS012'} <= {f.rule_id for f in result.findings})
        self.assertEqual(result.coverage['enabled_rule_count'], 43)
        self.assertFalse(result.coverage['network_requests_by_engine'])
        self.assertNotIn('RULE_ENGINE_ERROR', {d['code'] for d in result.diagnostics})

    def test_export_values_absent_from_every_report_format(self):
        result = scan(FIXTURE, Config(decompile=False))
        with TemporaryDirectory() as directory:
            paths = write_reports(result, Path(directory), legacy=True)
            for path in paths.values():
                text = Path(path).read_text()
                for value in ('SYNTHETIC_EXPORT_VALUE_8726', 'SYNTHETIC_PRIVATE_NAME_9261', 'SYNTHETIC_TAG_6291'):
                    self.assertNotIn(value, text)
            self.assertIn('firebase-path-panel', Path(paths['html']).read_text())

    def test_attachment_any_filename_has_stable_logical_source_and_hash(self):
        with TemporaryDirectory() as directory:
            root = self.base_source(directory)
            attachment = Path(directory) / 'owner-copy.json'
            attachment.write_text('{"profiles":{"child":{"name":"first"}}}')
            cfg = Config(firebase_data=str(attachment), decompile=False)
            first = scan(root, cfg)
            attachment.write_text('{"profiles":{"child":{"name":"second"}}}')
            second = scan(root, cfg)
            finding = next(f for f in second.findings if f.rule_id == 'DS012')
            self.assertEqual(finding.evidence[0].path, '__firebase__/firebase-export.json')
            self.assertNotEqual(first.scan['source_set_sha256'], second.scan['source_set_sha256'])
            self.assertNotIn(str(attachment), json.dumps(second.to_dict()))

    def test_attachment_failure_is_partial(self):
        with TemporaryDirectory() as directory:
            result = scan(self.base_source(directory), Config(firebase_rules=str(Path(directory)/'missing.json')))
            self.assertEqual(result.coverage['status'], 'partial')
            self.assertIn('FIREBASE_ATTACHMENT_UNREADABLE', {d['code'] for d in result.diagnostics})

    def test_in_directory_attachment_is_not_also_analyzed_as_source(self):
        with TemporaryDirectory() as directory:
            root = self.base_source(directory)
            attachment = root / 'owner-copy.json'
            attachment.write_text('{"note":"https://asap-offline-fixture.firebaseio.com/PRIVATE_SCALAR_VALUE.json",'
                                  '"api_key":"AIza00000000000000000000000000000000000"}')
            result = scan(root, Config(firebase_data=str(attachment), decompile=False))
            self.assertEqual([s['path'] for s in result.inventory['files'] if s['path'].endswith('.json')],
                             ['__firebase__/firebase-export.json'])
            self.assertFalse({'DS009','HC001','HC003','HC004'} & {f.rule_id for f in result.findings})
            text = json.dumps(result.to_dict())
            self.assertNotIn('PRIVATE_SCALAR_VALUE', text)
            self.assertNotIn('AIza00000000000000000000000000000000000', text)
            disabled = scan(root, Config(categories=['HardCoded'], firebase_data=str(attachment), decompile=False))
            self.assertFalse(disabled.findings)
            self.assertFalse(any(s['path'].endswith('.json') for s in disabled.inventory['files']))

    def test_attachment_cannot_shadow_source_path(self):
        with TemporaryDirectory() as directory:
            root = self.base_source(directory)
            (root/'__firebase__').mkdir()
            (root/'__firebase__/firebase-export.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'collides'):
                scan(root, Config(firebase_data=str(FIXTURE/'firebase-export.json')))

    def test_attachment_size_and_symlink_limits(self):
        with TemporaryDirectory() as directory:
            root = self.base_source(directory)
            big = Path(directory)/'big.json'
            big.write_text(' ' * 1025)
            result = scan(root, Config(firebase_data=str(big), max_file_bytes=1024))
            self.assertIn('FILE_TOO_LARGE', {d['code'] for d in result.diagnostics})
            link = Path(directory)/'link.json'
            link.symlink_to(big)
            result = scan(root, Config(firebase_data=str(link)))
            self.assertIn('FIREBASE_ATTACHMENT_UNREADABLE', {d['code'] for d in result.diagnostics})

    def test_category_exclusion_skips_firebase_analysis_and_attachments(self):
        cfg = Config(categories=['WebView'], firebase_data='/missing/local-file.json', decompile=False)
        result = scan(FIXTURE, cfg)
        self.assertFalse(result.findings)
        self.assertFalse(any(d['code'].startswith('FIREBASE') for d in result.diagnostics))

    def test_cli_attachments_and_strict_diagnostics(self):
        with TemporaryDirectory() as directory:
            root = self.base_source(directory)
            out = Path(directory)/'out'
            args = ['scan', str(root), '-o', str(out), '--firebase-rules', str(FIXTURE/'database.rules.json'),
                    '--firebase-data', str(FIXTURE/'firebase-export.json'), '--no-decompile', '--strict']
            with redirect_stdout(StringIO()):
                status = main(args)
            self.assertEqual(status, 2)
            report = json.loads((out/'report.json').read_text())
            self.assertTrue({'DS010','DS011','DS012'} <= {f['rule_id'] for f in report['findings']})

    def test_rules_public_write_applies_ci_threshold_but_inventory_does_not(self):
        result = scan(FIXTURE, Config(decompile=False))
        self.assertTrue(should_fail(result, 'high'))
        result.findings = [f for f in result.findings if f.rule_id in ('DS009','DS012')]
        self.assertFalse(should_fail(result, 'info'))

    def test_config_accepts_local_paths_and_rejects_urls_and_invalid_types(self):
        Config(firebase_rules='rules.json', firebase_data='export.json').validate()
        for value in (True, 123, '', 'https://fixture.invalid/export.json', 'bad\x00path'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Config(firebase_data=value).validate()


if __name__ == '__main__':
    unittest.main()
