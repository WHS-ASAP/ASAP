"""Verify rule context and module guidance in scans and offline reports."""
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest

from asap import CATEGORIES
from asap.engine import scan
from asap.guidance import module_catalog
from asap.reporting import render_html

ROOT = Path(__file__).resolve().parents[1]


class RefinementPipelineTests(unittest.TestCase):
    def test_scan_retains_refined_context_before_fingerprints_and_reporting(self):
        result = scan(ROOT / 'tests/fixtures/demo')
        sql = next(f for f in result.findings if f.rule_id == 'SQL001')
        logging = next(f for f in result.findings if f.rule_id == 'LG002')
        self.assertEqual(sql.properties['sql_argument_index'], 0)
        self.assertEqual(logging.properties['logging_level'], 'BODY')
        self.assertEqual(len(sql.fingerprint), 64)
        self.assertFalse(any(d['code'] == 'RULE_ENGINE_ERROR' for d in result.diagnostics))

    def test_manifest_refinement_applies_in_full_scan(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'AndroidManifest.xml').write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example">
<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/>
<uses-permission android:name="example.permission.CAMERA"/>
<uses-permission android:name="android.permission.CAMERA" android:maxSdkVersion="0x1e"/>
<application android:allowBackup="false"/></manifest>''')
            result = scan(root)
            permissions = [f for f in result.findings if f.rule_id == 'PM004']
            self.assertEqual(len(permissions), 1)
            self.assertEqual(permissions[0].properties['permission_max_sdk'], 30)
            self.assertEqual(len([f for f in result.findings if f.rule_id == 'DS006']), 1)

    def test_catalog_and_offline_html_bundle_all_seven_guides(self):
        modules = module_catalog()
        self.assertEqual([m['category'] for m in modules], list(CATEGORIES))
        self.assertEqual(sum(m['rule_count'] for m in modules), 43)
        for module in modules:
            self.assertTrue(module['guidance_available'])
            self.assertTrue(module['review_questions'])
            self.assertTrue(module['implemented_changes'])
            self.assertTrue(module['references'])
            self.assertTrue(all(ref['url'].startswith('https://') for ref in module['references']))
        report = scan(ROOT / 'tests/fixtures/demo').to_dict()
        html = render_html(report)
        embedded = re.search(r'<script id="asap-guides" type="application/json">(.*?)</script>', html, re.S)
        self.assertEqual(json.loads(embedded[1]), json.loads(json.dumps(modules)))
        self.assertNotIn('<!--GUIDES-->', html)


if __name__ == '__main__':
    unittest.main()
