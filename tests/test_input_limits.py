"""Bounded source collection must preserve useful partial analysis results."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

from asap.cli import main
from asap.config import Config
from asap.engine import scan
from asap.inputs import PreparedInput


MANIFEST = b'<manifest package="example.limit"><uses-sdk android:targetSdkVersion="37" xmlns:android="http://schemas.android.com/apk/res/android"/><application/></manifest>'
JAVA_A = b'package example; class A { void f() { Cipher.getInstance("DES"); } }'
JAVA_B = b'package example; class B { String padding = "' + b'x' * 200 + b'"; }'


def codes(result):
    return {item['code'] for item in result.diagnostics}


def write_apk(path, assets=()):
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('AndroidManifest.xml', MANIFEST)
        archive.writestr('classes.dex', b'SYNTHETIC_DEX')
        for name, value in assets:
            archive.writestr(name, value)


class SourceLimitTests(unittest.TestCase):
    def test_byte_limit_keeps_counters_atomic_and_stops_once(self):
        prepared = PreparedInput(Path('.'), Config(max_source_bytes=len(JAVA_A)))
        prepared._add('A.java', JAVA_A)
        prepared._add('B.java', JAVA_B)
        prepared._add('C.java', b'class C {}')
        self.assertEqual(prepared.counts['source_bytes'], len(JAVA_A))
        self.assertEqual(prepared.counts['selected_files'], 1)
        self.assertEqual([item['code'] for item in prepared.diagnostics], ['SOURCE_BYTES_LIMIT'])

    def test_file_limit_applies_after_exclusions_vendor_and_decode(self):
        prepared = PreparedInput(Path('.'), Config(max_files=1, exclude=['skip.java']))
        prepared._add('A.java', JAVA_A)
        prepared._add('skip.java', JAVA_A)
        prepared._add('Vendor.java', b'package com.google.firebase.fixture; class Vendor {}')
        prepared._add('Binary.java', b'\xff')
        self.assertFalse(prepared._collection_stopped)
        self.assertEqual(prepared.counts['excluded_files'], 1)
        self.assertEqual(prepared.counts['vendor_files'], 1)
        prepared._add('B.java', JAVA_B)
        self.assertEqual(prepared.counts['selected_files'], 1)
        self.assertEqual(prepared.counts['source_bytes'], len(JAVA_A))
        self.assertIn('SOURCE_FILES_LIMIT', {item['code'] for item in prepared.diagnostics})

    def test_smali_vendor_filter_matches_java_and_supports_opt_in(self):
        data = b'.class public Lcom/google/firebase/fixture/Vendor;\n.super Ljava/lang/Object;'
        for include_vendor in (False, True):
            with self.subTest(include_vendor=include_vendor):
                prepared = PreparedInput(Path('.'), Config(include_vendor=include_vendor))
                prepared._add('Vendor.smali', data)
                self.assertEqual(prepared.counts['selected_files'], int(include_vendor))
                self.assertEqual(prepared.counts['vendor_files'], int(not include_vendor))

    def test_smali_app_class_is_not_filtered(self):
        prepared = PreparedInput(Path('.'), Config())
        prepared._add('A.smali', b'.class public Lexample/google/firebase/A;\n.super Ljava/lang/Object;')
        self.assertEqual(prepared.counts['selected_files'], 1)

    def test_directory_keeps_manifest_and_deterministic_partial_sources(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            for name, data in [('AndroidManifest.xml', MANIFEST), ('A.java', JAVA_A), ('B.java', JAVA_B), ('C.java', JAVA_A)]:
                (root / name).write_bytes(data)
            cfg = Config(max_source_bytes=len(MANIFEST) + len(JAVA_A) + 1)
            first, second = scan(root, cfg), scan(root, cfg)
            self.assertEqual(first.coverage['status'], 'partial')
            self.assertEqual(first.coverage['source_bytes'], len(MANIFEST) + len(JAVA_A))
            self.assertEqual(first.inventory['files'], second.inventory['files'])
            self.assertEqual({item['path'] for item in first.inventory['files']}, {'AndroidManifest.xml', 'A.java'})
            self.assertTrue(first.inventory['manifests'])
            self.assertIn('SOURCE_BYTES_LIMIT', codes(first))

    def test_unsupported_files_still_have_a_bounded_traversal_budget(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            for index in range(5):
                (root / f'a{index}.bin').write_bytes(b'x')
            (root / 'z.java').write_bytes(JAVA_A)
            result = scan(root, Config(max_files=1))
            self.assertIn('SOURCE_TRAVERSAL_LIMIT', codes(result))
            self.assertEqual(result.coverage['selected_files'], 0)

    def test_jadx_limit_keeps_partial_output_and_skips_apktool(self):
        with TemporaryDirectory() as td:
            apk = Path(td) / 'sample.apk'
            write_apk(apk, [('assets/unread.json', b'\xff')])

            def fake_tool(command, cwd, timeout):
                out = Path(command[command.index('-d') + 1])
                (out / 'resources').mkdir(parents=True)
                (out / 'sources').mkdir()
                (out / 'resources/AndroidManifest.xml').write_bytes(MANIFEST)
                (out / 'sources/A.java').write_bytes(JAVA_A)
                (out / 'sources/B.java').write_bytes(JAVA_B)
                return 3, 'nonzero_exit'

            cfg = Config(jadx='fake-jadx', apktool='fake-apktool', max_source_bytes=len(MANIFEST) + len(JAVA_A) + 1)
            with patch('asap.inputs.run_tool', side_effect=fake_tool) as run:
                result = scan(apk, cfg)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(result.coverage['selected_files'], 2)
            self.assertEqual(result.coverage['source_bytes'], len(MANIFEST) + len(JAVA_A))
            self.assertTrue({'SOURCE_BYTES_LIMIT', 'JADX_PARTIAL', 'TOOL_SKIPPED_SOURCE_LIMIT'} <= codes(result))
            self.assertTrue({'JADX_UNAVAILABLE', 'APKTOOL_UNAVAILABLE', 'DEX_NOT_ANALYZED', 'DECODE_FAILED'}.isdisjoint(codes(result)))
            self.assertEqual(result.scan['tools'][-1], {'name':'apktool', 'status':'skipped_source_limit'})
            self.assertTrue(result.inventory['manifests'])

    def test_raw_manifest_is_retained_when_jadx_provides_only_code(self):
        with TemporaryDirectory() as td:
            apk = Path(td) / 'sample.apk'
            write_apk(apk)

            def fake_tool(command, cwd, timeout):
                out = Path(command[command.index('-d') + 1])
                out.mkdir()
                (out / 'A.java').write_bytes(JAVA_A)
                (out / 'B.java').write_bytes(JAVA_B)
                return 0, 'ok'

            cfg = Config(jadx='fake-jadx', max_source_bytes=len(MANIFEST) + len(JAVA_A))
            with patch('asap.inputs.shutil.which', return_value=None), patch('asap.inputs.run_tool', side_effect=fake_tool):
                result = scan(apk, cfg)
            self.assertTrue(result.inventory['manifests'])
            self.assertIn('apk/AndroidManifest.xml', {item['path'] for item in result.inventory['files']})
            self.assertIn('SOURCE_BYTES_LIMIT', codes(result))

    def test_exact_full_budget_skips_next_tool_without_an_extra_source(self):
        with TemporaryDirectory() as td:
            apk = Path(td) / 'sample.apk'
            write_apk(apk)

            def fake_tool(command, cwd, timeout):
                out = Path(command[command.index('-d') + 1])
                out.mkdir()
                (out / 'AndroidManifest.xml').write_bytes(MANIFEST)
                (out / 'A.java').write_bytes(JAVA_A)
                return 0, 'ok'

            cfg = Config(jadx='fake-jadx', apktool='fake-apktool', max_source_bytes=len(MANIFEST) + len(JAVA_A))
            with patch('asap.inputs.run_tool', side_effect=fake_tool) as run:
                result = scan(apk, cfg)
            self.assertEqual(run.call_count, 1)
            self.assertTrue({'SOURCE_BYTES_LIMIT', 'TOOL_SKIPPED_SOURCE_LIMIT'} <= codes(result))
            self.assertEqual(result.coverage['source_bytes'], cfg.max_source_bytes)

    def test_jadx_file_limit_keeps_partial_output(self):
        with TemporaryDirectory() as td:
            apk = Path(td) / 'sample.apk'
            write_apk(apk)

            def fake_tool(command, cwd, timeout):
                out = Path(command[command.index('-d') + 1])
                out.mkdir()
                (out / 'AndroidManifest.xml').write_bytes(MANIFEST)
                (out / 'A.java').write_bytes(JAVA_A)
                (out / 'B.java').write_bytes(JAVA_B)
                return 0, 'ok'

            with patch('asap.inputs.shutil.which', return_value=None), patch('asap.inputs.run_tool', side_effect=fake_tool):
                result = scan(apk, Config(jadx='fake-jadx', max_files=2))
            self.assertEqual(result.coverage['selected_files'], 2)
            self.assertIn('SOURCE_FILES_LIMIT', codes(result))
            self.assertNotIn('JADX_UNAVAILABLE', codes(result))

    def test_apktool_collection_limit_is_not_reported_as_unavailable(self):
        with TemporaryDirectory() as td:
            apk = Path(td) / 'sample.apk'
            write_apk(apk)

            def fake_tool(command, cwd, timeout):
                out = Path(command[command.index('-o') + 1])
                out.mkdir()
                (out / 'AndroidManifest.xml').write_bytes(MANIFEST)
                (out / 'A.smali').write_bytes(b'.class public Lexample/A;')
                (out / 'B.smali').write_bytes(b'.class public Lexample/B;' + b' ' * 200)
                return 0, 'ok'

            cfg = Config(apktool='fake-apktool', max_source_bytes=len(MANIFEST) + 30)
            with patch('asap.inputs.shutil.which', return_value=None), patch('asap.inputs.run_tool', side_effect=fake_tool):
                result = scan(apk, cfg)
            self.assertIn('SOURCE_BYTES_LIMIT', codes(result))
            self.assertNotIn('APKTOOL_UNAVAILABLE', codes(result))
            self.assertLessEqual(result.coverage['source_bytes'], cfg.max_source_bytes)

    def test_raw_fallback_byte_limit_after_tool_output_is_partial(self):
        with TemporaryDirectory() as td:
            apk = Path(td) / 'sample.apk'
            write_apk(apk, [('assets/data.json', b'"' + b'x' * 200 + b'"')])

            def fake_tool(command, cwd, timeout):
                out = Path(command[command.index('-d') + 1])
                out.mkdir()
                (out / 'AndroidManifest.xml').write_bytes(MANIFEST)
                (out / 'A.java').write_bytes(JAVA_A)
                return 0, 'ok'

            cfg = Config(jadx='fake-jadx', max_source_bytes=len(MANIFEST) + len(JAVA_A) + 1)
            with patch('asap.inputs.shutil.which', return_value=None), patch('asap.inputs.run_tool', side_effect=fake_tool):
                result = scan(apk, cfg)
            self.assertIn('SOURCE_BYTES_LIMIT', codes(result))
            self.assertEqual(result.coverage['selected_files'], 2)
            self.assertEqual(result.coverage['source_bytes'], len(MANIFEST) + len(JAVA_A))

    def test_raw_fallback_deduplicates_tool_suffixes(self):
        with TemporaryDirectory() as td:
            apk = Path(td) / 'sample.apk'
            write_apk(apk, [('res/xml/config.xml', b'<resources/>'), ('assets/only.json', b'{}')])

            def fake_tool(command, cwd, timeout):
                out = Path(command[command.index('-d') + 1])
                (out / 'resources/res/xml').mkdir(parents=True)
                (out / 'resources/AndroidManifest.xml').write_bytes(MANIFEST)
                (out / 'resources/res/xml/config.xml').write_bytes(b'<resources/>')
                return 0, 'ok'

            with patch('asap.inputs.shutil.which', return_value=None), patch('asap.inputs.run_tool', side_effect=fake_tool):
                result = scan(apk, Config(jadx='fake-jadx'))
            paths = {item['path'] for item in result.inventory['files']}
            self.assertEqual(paths, {'jadx/resources/AndroidManifest.xml', 'jadx/resources/res/xml/config.xml', 'apk/assets/only.json'})

    def test_unexpected_collection_error_is_not_mislabeled_as_tool_start_failure(self):
        with TemporaryDirectory() as td:
            apk = Path(td) / 'sample.apk'
            write_apk(apk)

            def fake_tool(command, cwd, timeout):
                Path(command[command.index('-d') + 1]).mkdir()
                return 0, 'ok'

            with patch('asap.inputs.shutil.which', return_value=None), patch('asap.inputs.run_tool', side_effect=fake_tool), patch.object(PreparedInput, '_directory', side_effect=ValueError('collection failure')):
                with self.assertRaisesRegex(ValueError, 'collection failure'):
                    scan(apk, Config(jadx='fake-jadx'))

    def test_source_limit_strict_mode_writes_report_and_returns_two(self):
        with TemporaryDirectory() as td, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            root = Path(td)
            source = root / 'input'
            source.mkdir()
            (source / 'AndroidManifest.xml').write_bytes(MANIFEST)
            (source / 'A.java').write_bytes(JAVA_A)
            config = root / 'config.json'
            config.write_text(json.dumps({'max_source_bytes':len(MANIFEST)}))
            output = root / 'report'
            status = main(['scan', str(source), '--config', str(config), '-o', str(output), '--strict'])
            self.assertEqual(status, 2)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['coverage']['status'], 'partial')
            self.assertIn('SOURCE_BYTES_LIMIT', {item['code'] for item in report['diagnostics']})


if __name__ == '__main__':
    unittest.main()
