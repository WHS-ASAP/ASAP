"""Synthetic local fixtures for defensive data-protection refinements."""
import json
from pathlib import Path
import unittest

from asap.rules.analyze import code_findings, secret_findings, manifest_findings
from asap.rules.data_refinements import refine
from asap.manifest import parse_manifest
from tests.helpers import source


def scan_code(body, language='java'):
    s = source('class Example { public void check() {\n' + body + '\n} }' if language == 'java' else body, language)
    return refine(s, code_findings(s, []) + secret_findings(s), [])


def scan_manifest(declarations='', attributes='', minimum=26, target=35):
    s = source(f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example"><uses-sdk android:minSdkVersion="{minimum}" android:targetSdkVersion="{target}"/>{declarations}<application {attributes}/></manifest>', 'xml')
    m = parse_manifest(s)
    return refine(s, manifest_findings(s, m, [s]), [m])


class DataRefinementsTests(unittest.TestCase):
    def test_google_key_is_inventory_with_unverified_service_association(self):
        token = 'AIza' + 'A' * 35  # Nonfunctional synthetic literal.
        s = source(json.dumps({'mobilesdk_app_id': 'synthetic', 'current_key': token}), 'text', 'resources/google-services.json')
        f = next(f for f in refine(s, secret_findings(s), []) if f.rule_id == 'HC004')
        self.assertEqual((f.kind, f.severity), ('inventory', 'info'))
        self.assertIn('firebase_markers_in_same_file', f.properties['service_context'])
        self.assertEqual(f.properties['api_restrictions'], 'not_verified')
        self.assertNotIn(token, json.dumps(f.to_dict()))

    def test_google_unknown_context_and_gemini_hint_never_assert_validity(self):
        for marker, expected in [('', 'service_not_identified'), ('GenerativeModel', 'gemini_markers_in_same_file')]:
            s = source('api_key="' + 'AIza' + 'B' * 35 + '"\n' + marker, 'text')
            f = next(f for f in refine(s, secret_findings(s), []) if f.rule_id == 'HC004')
            self.assertEqual(f.properties['service_context'], [expected])
            self.assertEqual(f.severity, 'info')
            self.assertEqual(f.properties['credential_validity'], 'not_tested')

    def test_custom_permission_suffix_does_not_become_android_permission(self):
        result = scan_manifest('<uses-permission android:name="example.permission.CAMERA"/><uses-permission android:name="example.ACCESS_LOCAL_NETWORK"/>')
        self.assertFalse(any(f.rule_id in {'PM004', 'PM007'} for f in result))

    def test_permission_maximum_uses_runtime_not_target(self):
        result = scan_manifest('<uses-permission android:name="android.permission.CAMERA" android:maxSdkVersion="30"/>', minimum=26, target=35)
        f = next(f for f in result if f.rule_id == 'PM004')
        self.assertEqual(f.properties['permission_runtime_applicability'], 'runtime_api_at_most_max_sdk')
        self.assertFalse(f.properties['target_sdk_is_runtime_sdk'])
        self.assertEqual(f.properties['runtime_grant'], 'not_verified')

    def test_permission_outside_supported_api_is_inventory(self):
        result = scan_manifest('<uses-permission android:name="android.permission.CAMERA" android:maxSdkVersion="22"/>', minimum=26)
        f = next(f for f in result if f.rule_id == 'PM004')
        self.assertEqual(f.properties['permission_runtime_applicability'], 'no_supported_runtime')
        self.assertEqual(f.kind, 'inventory')

    def test_permission_hex_maximum_is_numeric(self):
        result = scan_manifest('<uses-permission android:name="android.permission.CAMERA" android:maxSdkVersion="0x1e"/>')
        f = next(f for f in result if f.rule_id == 'PM004')
        self.assertEqual(f.properties['permission_max_sdk'], 30)
        self.assertEqual(f.properties['permission_max_sdk_state'], 'literal')
        self.assertEqual(f.properties['permission_runtime_applicability'], 'runtime_api_at_most_max_sdk')

    def test_permission_absent_maximum_is_explicitly_absent(self):
        result = scan_manifest('<uses-permission android:name="android.permission.CAMERA"/>')
        f = next(f for f in result if f.rule_id == 'PM004')
        self.assertEqual(f.properties['permission_max_sdk_state'], 'absent')
        self.assertEqual(f.properties['permission_runtime_applicability'], 'not_bounded_by_max_sdk')

    def test_permission_unresolved_maximum_is_never_unbounded(self):
        for raw in ('@integer/permission_limit', '@0x7f010000', 'not_a_number', '', '-1', '9' * 5000):
            with self.subTest(raw=raw[:30]):
                result = scan_manifest(f'<uses-permission android:name="android.permission.CAMERA" android:maxSdkVersion="{raw}"/>')
                f = next(f for f in result if f.rule_id == 'PM004')
                self.assertIsNone(f.properties['permission_max_sdk'])
                self.assertEqual(f.properties['permission_max_sdk_state'], 'unresolved')
                self.assertEqual(f.properties['permission_runtime_applicability'], 'max_sdk_unresolved_requires_review')

    def test_unknown_encrypt_wrapper_does_not_lower_storage_review(self):
        f = next(f for f in scan_code('prefs.putString("access_token", encrypt(accessToken));') if f.rule_id == 'DS005')
        self.assertEqual(f.severity, 'medium')
        self.assertTrue(f.properties['encryption_call_observed'])
        self.assertEqual(f.properties['encryption_effectiveness'], 'not_verified')

    def test_non_sensitive_preferences_do_not_gain_a_storage_finding(self):
        self.assertFalse(any(f.rule_id == 'DS005' for f in scan_code('prefs.putString("theme", selectedTheme);')))

    def test_modern_backup_false_retains_d2d_inventory(self):
        result = scan_manifest(attributes='android:allowBackup="false" android:dataExtractionRules="@xml/rules"', target=35)
        f = next(f for f in result if f.rule_id == 'DS006')
        self.assertEqual((f.kind, f.severity), ('inventory', 'info'))
        self.assertFalse(f.properties['allow_backup'])
        self.assertEqual(f.properties['backup_rule_contents'], 'not_evaluated_by_this_rule')
        self.assertEqual(f.properties['device_transfer_outcome'], 'oem_and_runtime_dependent')

    def test_legacy_backup_false_does_not_gain_modern_d2d_observation(self):
        self.assertFalse(any(f.rule_id == 'DS006' for f in scan_manifest(attributes='android:allowBackup="false"', target=30)))

    def test_headers_setter_is_an_explicit_logging_review(self):
        f = next(f for f in scan_code('HttpLoggingInterceptor logging = new HttpLoggingInterceptor();\nlogging.setLevel(HttpLoggingInterceptor.Level.HEADERS);') if f.rule_id == 'LG002')
        self.assertEqual(f.properties['logging_level'], 'HEADERS')
        self.assertIn('헤더', f.title)
        self.assertTrue(f.properties['http_logging_receiver_observed'])

    def test_kotlin_body_property_and_same_receiver_redaction(self):
        result = scan_code('fun configure() {\nval logging = HttpLoggingInterceptor()\nval other = HttpLoggingInterceptor()\nlogging.redactHeader("Authorization")\nother.redactHeader("Cookie")\nlogging.level = HttpLoggingInterceptor.Level.BODY\n}', 'kotlin')
        f = next(f for f in result if f.rule_id == 'LG002')
        self.assertEqual(f.properties['logging_syntax'], 'kotlin_property')
        self.assertEqual(f.properties['sensitive_headers_redaction_observed'], ['authorization'])
        self.assertFalse(f.properties['body_redaction_verified'])
        self.assertEqual(f.severity, 'medium')

    def test_unrelated_level_enum_is_not_http_logging(self):
        self.assertFalse(any(f.rule_id == 'LG002' for f in scan_code('layout.setLevel(Level.BODY);')))

    def test_import_alone_does_not_prove_receiver(self):
        self.assertFalse(any(f.rule_id == 'LG002' for f in scan_code('HttpLoggingInterceptor unused;\nlayout.setLevel(Level.BODY);')))

    def test_nested_constructor_does_not_type_outer_receiver(self):
        for body in (
            'new CustomWidget(new HttpLoggingInterceptor()).setLevel(Level.HEADERS);',
            'CustomWidget logging = new CustomWidget(new HttpLoggingInterceptor());\nlogging.setLevel(Level.BODY);',
        ):
            with self.subTest(body=body):
                self.assertFalse(any(f.rule_id == 'LG002' for f in scan_code(body)))

    def test_prior_method_declaration_does_not_type_same_name(self):
        s = source('class Example { void first(){ HttpLoggingInterceptor logging; } void second(){ CustomWidget logging; logging.setLevel(Level.HEADERS); } }')
        result = refine(s, code_findings(s, []), [])
        self.assertFalse(any(f.rule_id == 'LG002' for f in result))

    def test_ambiguous_local_declarations_do_not_type_receiver(self):
        result = scan_code('fun configure() {\nval logging: HttpLoggingInterceptor = getLogging()\nrun {\nval logging: CustomWidget = getWidget()\nlogging.level = Level.HEADERS\n}\n}', 'kotlin')
        self.assertFalse(any(f.rule_id == 'LG002' for f in result))

    def test_explicit_enum_with_unknown_receiver_remains_medium_observation(self):
        result = scan_code('new CustomWidget(new HttpLoggingInterceptor()).setLevel(HttpLoggingInterceptor.Level.HEADERS);')
        f = next(f for f in result if f.rule_id == 'LG002')
        self.assertFalse(f.properties['http_logging_receiver_observed'])
        self.assertEqual(f.confidence, 'medium')

    def test_current_method_typed_receiver_remains_observed(self):
        result = scan_code('HttpLoggingInterceptor logging;\nlogging.setLevel(Level.HEADERS);')
        f = next(f for f in result if f.rule_id == 'LG002')
        self.assertTrue(f.properties['http_logging_receiver_observed'])

    def test_interceptor_factory_chain_is_not_assumed_to_preserve_type(self):
        result = scan_code('new HttpLoggingInterceptor().customWidget().setLevel(Level.HEADERS);')
        self.assertFalse(any(f.rule_id == 'LG002' for f in result))

    def test_none_and_basic_do_not_create_headers_or_body_review(self):
        for level in ('NONE', 'BASIC'):
            self.assertFalse(any(f.rule_id == 'LG002' for f in scan_code(f'HttpLoggingInterceptor logging = new HttpLoggingInterceptor();\nlogging.setLevel(HttpLoggingInterceptor.Level.{level});')))

    def test_comments_and_strings_do_not_create_logging_configuration(self):
        result = scan_code('fun configure() {\n// logger.level = HttpLoggingInterceptor.Level.BODY\nval label = "logger.level = HttpLoggingInterceptor.Level.HEADERS"\n}', 'kotlin')
        self.assertFalse(any(f.rule_id == 'LG002' for f in result))

    def test_receiver_constructor_arguments_are_redacted(self):
        literal = 'synthetic_sensitive_argument'
        result = scan_code('new HttpLoggingInterceptor("' + literal + '").setLevel(Level.BODY);')
        f = next(f for f in result if f.rule_id == 'LG002')
        self.assertNotIn(literal, json.dumps(f.to_dict()))

    def test_permission_legacy_api_does_not_assume_maximum_is_honored(self):
        result = scan_manifest('<uses-permission android:name="android.permission.CAMERA" android:maxSdkVersion="12"/>', minimum=16)
        f = next(f for f in result if f.rule_id == 'PM004')
        self.assertEqual(f.properties['permission_runtime_applicability'], 'legacy_runtime_support_requires_review')

    def test_non_owned_findings_are_preserved(self):
        f = next(f for f in scan_code('Cipher.getInstance("AES/ECB/PKCS5Padding");') if f.rule_id == 'DS001')
        self.assertEqual(f.severity, 'medium')

    def test_module_guides_have_sources_and_review_content(self):
        root = Path(__file__).resolve().parents[1] / 'asap' / 'guides'
        for category in ('HardCoded', 'Permission', 'Insecure_DataStorage', 'Insecure_Logging'):
            data = json.loads((root / f'{category}.json').read_text())
            self.assertEqual(data['category'], category)
            for key in ('summary', 'review_questions', 'safe_patterns', 'limitations', 'references', 'implemented_changes'):
                self.assertTrue(data[key])
            for ref in data['references']:
                self.assertTrue(ref['url'].startswith('https://'))
                self.assertEqual(ref['accessed_at'], '2026-09-12')


if __name__ == '__main__':
    unittest.main()
