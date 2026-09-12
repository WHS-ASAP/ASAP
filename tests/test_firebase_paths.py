"""Synthetic source-only Firebase location inventory tests."""
import json
import unittest

from asap.rules.firebase_paths import analyze, MAX_PATHS
from tests.helpers import source


JAVA_IMPORT = 'import com.google.firebase.database.FirebaseDatabase;\n'
KOTLIN_IMPORT = 'import com.google.firebase.database.FirebaseDatabase\n'


def inventory(body, language='java', header=None):
    if header is None:
        header = JAVA_IMPORT if language == 'java' else KOTLIN_IMPORT
    text = header + ('class Example { void inspect() {\n' + body + '\n} }' if language == 'java' else 'fun inspect() {\n' + body + '\n}')
    return analyze(source(text, language))


class FirebasePathTests(unittest.TestCase):
    def test_direct_sdk_child_chain_keeps_all_observed_prefixes(self):
        finding = inventory('FirebaseDatabase.getInstance().getReference("users").child("staff").child("profile");')[0]
        self.assertEqual(finding.properties['firebase_paths'], ['/users', '/users/staff', '/users/staff/profile'])
        self.assertEqual(finding.properties['database_hosts'], [])
        self.assertFalse(finding.properties['unresolved_segments'])
        self.assertEqual((finding.rule_id, finding.category, finding.kind, finding.severity),
                         ('DS009', 'Insecure_DataStorage', 'inventory', 'info'))
        self.assertFalse(finding.properties['network_checked'])

    def test_java_method_local_database_and_reference_aliases(self):
        finding = inventory('FirebaseDatabase database = FirebaseDatabase.getInstance();\n'
                            'String collection = "users";\n'
                            'DatabaseReference root = database.getReference(collection);\n'
                            'DatabaseReference group = root.child("staff");\n'
                            'group.child("profile");')[0]
        self.assertIn('/users/staff/profile', finding.properties['firebase_paths'])
        self.assertIn('inspect', finding.properties['lexical_scopes'])

    def test_kotlin_property_and_local_aliases(self):
        finding = inventory('val database = FirebaseDatabase.getInstance()\n'
                            'val root = database.reference\n'
                            'val members = root.child("members")\n'
                            'members.child("public").child("displayName")', 'kotlin')[0]
        self.assertIn('/members/public/displayName', finding.properties['firebase_paths'])

    def test_dynamic_child_remains_symbolic_with_known_suffix(self):
        finding = inventory('FirebaseDatabase.getInstance().getReference("users").child(userId).child("profile");')[0]
        self.assertIn('/users/{dynamic}/profile', finding.properties['firebase_paths'])
        self.assertTrue(finding.properties['unresolved_segments'])
        self.assertNotIn('userId', json.dumps(finding.to_dict()))

    def test_concatenated_local_constants_resolve(self):
        finding = inventory('String group = "users/" + "staff";\n'
                            'FirebaseDatabase.getInstance().getReference(group + "/" + userId).child("profile");')[0]
        self.assertIn('/users/staff/{dynamic}/profile', finding.properties['firebase_paths'])

    def test_kotlin_template_is_symbolic(self):
        finding = inventory('FirebaseDatabase.getInstance().getReference("users/$userId/profile")', 'kotlin')[0]
        self.assertIn('/users/{dynamic}/profile', finding.properties['firebase_paths'])

    def test_explicit_database_url_and_from_url(self):
        finding = inventory('FirebaseDatabase.getInstance("https://demo.europe-west1.firebasedatabase.app")'
                            '.getReferenceFromUrl("https://demo.europe-west1.firebasedatabase.app/users.json?auth=fake-secret")'
                            '.child("profile");')[0]
        self.assertEqual(finding.properties['database_hosts'], ['demo.europe-west1.firebasedatabase.app'])
        self.assertIn('/users/profile', finding.properties['firebase_paths'])
        self.assertNotIn('fake-secret', json.dumps(finding.to_dict()))

    def test_google_services_configuration(self):
        text = json.dumps({'project_info': {'firebase_url': 'https://demo-default-rtdb.firebaseio.com/'}})
        finding = analyze(source(text, 'text', 'app/google-services.json'))[0]
        self.assertEqual(finding.properties['database_hosts'], ['demo-default-rtdb.firebaseio.com'])
        self.assertEqual(finding.properties['firebase_paths'], ['/'])

    def test_database_url_configuration_and_android_resource(self):
        for text, language in (
            ('{"databaseURL":"https://demo.firebaseio.com/public/items.json?auth=do-not-copy#private"}', 'text'),
            ('<resources><string name="firebase_database_url">https://demo.firebaseio.com/public/items.json?auth=do-not-copy&amp;shallow=true</string></resources>', 'xml'),
        ):
            with self.subTest(language=language):
                finding = analyze(source(text, language))[0]
                self.assertEqual(finding.properties['firebase_paths'], ['/public/items'])
                serialized = json.dumps(finding.to_dict())
                self.assertNotIn('do-not-copy', serialized)
                self.assertNotIn('shallow=true', serialized)

    def test_userinfo_is_never_reported(self):
        finding = analyze(source('endpoint=https://sensitive-user:sensitive-password@demo.firebaseio.com/users.json?auth=secret-query#secret-fragment', 'text'))[0]
        serialized = json.dumps(finding.to_dict())
        self.assertEqual(finding.properties['database_hosts'], ['demo.firebaseio.com'])
        for value in ('sensitive-user', 'sensitive-password', 'secret-query', 'secret-fragment'):
            self.assertNotIn(value, serialized)

    def test_lookalike_hosts_and_userinfo_confusion_are_rejected(self):
        for url in (
            'https://demo.firebaseio.com.attacker.example/users.json',
            'https://firebaseio.com/users.json',
            'https://demo.firebaseio.com@attacker.example/users.json',
            'https://demo.firebasedatabase.app/users.json',
            'https://demo.region.firebasedatabase.app.attacker.example/users.json',
            'https://other.demo.firebaseio.com/users.json',
        ):
            with self.subTest(url=url):
                self.assertEqual(analyze(source(url, 'text')), [])

    def test_unrelated_child_and_reference_calls_are_ignored(self):
        self.assertEqual(inventory('Widget widget = new Widget();\n'
                                   'widget.child("users").child("passwords");\n'
                                   'widget.getReference("users");'), [])

    def test_unknown_chained_factory_does_not_inherit_firebase_type(self):
        self.assertEqual(inventory('FirebaseDatabase.getInstance().customWidget().getReference("users").child("profile");'), [])

    def test_short_sdk_type_without_import_is_not_assumed(self):
        self.assertEqual(inventory('FirebaseDatabase.getInstance().getReference("users").child("profile");', header=''), [])

    def test_fully_qualified_sdk_type_needs_no_import(self):
        finding = inventory('com.google.firebase.database.FirebaseDatabase.getInstance().getReference("users").child("profile");', header='')[0]
        self.assertIn('/users/profile', finding.properties['firebase_paths'])

    def test_wildcard_sdk_import(self):
        finding = inventory('FirebaseDatabase.getInstance().getReference("users");', header='import com.google.firebase.database.*;\n')[0]
        self.assertEqual(finding.properties['firebase_paths'], ['/users'])

    def test_comments_and_string_examples_do_not_create_sdk_paths(self):
        self.assertEqual(inventory('// FirebaseDatabase.getInstance().getReference("commented").child("value");\n'
                                   '/* FirebaseDatabase.getInstance().getReference("other"); */\n'
                                   'String example = "database.getReference(\\"users\\").child(\\"profile\\")";'), [])

    def test_comment_urls_are_ignored(self):
        self.assertEqual(inventory('// https://demo.firebaseio.com/private.json\n'
                                   '/* https://demo.firebaseio.com/other.json */'), [])
        self.assertEqual(analyze(source('<!-- https://demo.firebaseio.com/private.json -->', 'xml')), [])

    def test_method_aliases_do_not_leak_between_methods(self):
        text = JAVA_IMPORT + 'class Example { void first() {\n'
        text += 'DatabaseReference root = FirebaseDatabase.getInstance().getReference("users");\n}\n'
        text += 'void second() { root.child("should-not-appear"); } }'
        finding = analyze(source(text))[0]
        self.assertEqual(finding.properties['firebase_paths'], ['/users'])

    def test_latest_alias_assignment_wins(self):
        finding = inventory('DatabaseReference root = FirebaseDatabase.getInstance().getReference("users");\n'
                            'root = otherWidget;\nroot.child("should-not-appear");')[0]
        self.assertEqual(finding.properties['firebase_paths'], ['/users'])

    def test_credentials_and_opaque_literal_identifiers_are_redacted(self):
        secret = 'ghp_' + 'A' * 36
        finding = inventory('String authToken = "token-value-do-not-print";\n'
                            'FirebaseDatabase.getInstance().getReference("users").child(authToken).child("profile");\n'
                            'FirebaseDatabase.getInstance().getReference("sessions").child("' + secret + '");')[0]
        self.assertIn('/users/{dynamic}/profile', finding.properties['firebase_paths'])
        self.assertIn('/sessions/{dynamic}', finding.properties['firebase_paths'])
        serialized = json.dumps(finding.to_dict())
        for sensitive in ('token-value-do-not-print', secret, 'authToken'):
            self.assertNotIn(sensitive, serialized)

    def test_inventory_paths_are_bounded_and_truncation_is_explicit(self):
        text = '\n'.join('https://demo.firebaseio.com/collection_' + str(index) + '.json' for index in range(MAX_PATHS + 2))
        finding = analyze(source(text, 'text'))[0]
        self.assertEqual(len(finding.properties['firebase_paths']), MAX_PATHS)
        self.assertTrue(finding.properties['truncated'])
        self.assertEqual(finding.confidence, 'low')

    def test_long_or_deep_paths_stay_bounded(self):
        finding = analyze(source('https://demo.firebaseio.com/' + '/'.join(['child'] * 100), 'text'))[0]
        self.assertLessEqual(len(finding.properties['firebase_paths'][0].split('/')), 65)
        self.assertTrue(finding.properties['unresolved_segments'])

    def test_escaped_json_configuration_urls(self):
        finding = analyze(source('{"firebase_url":"https:\\/\\/demo.firebaseio.com\\/public\\/items.json?auth=secret-query"}', 'text'))[0]
        self.assertEqual(finding.properties['firebase_paths'], ['/public/items'])
        self.assertNotIn('secret-query', json.dumps(finding.to_dict()))

    def test_xml_comments_do_not_shift_evidence_lines(self):
        text = '<!--\ncomment\n-->\n<string name="firebase_database_url">https://demo.firebaseio.com/users.json</string>'
        finding = analyze(source(text, 'xml'))[0]
        self.assertEqual(finding.evidence[0].line, 4)

    def test_long_sdk_chain_preserves_nested_children(self):
        chain = 'FirebaseDatabase.getInstance().getReference("root")' + ''.join('.child("level' + str(i) + '")' for i in range(20))
        finding = inventory(chain + ';')[0]
        self.assertIn('/root/' + '/'.join('level' + str(i) for i in range(20)), finding.properties['firebase_paths'])

    def test_typed_database_receiver_provides_sdk_context(self):
        finding = inventory('FirebaseDatabase database;\ndatabase.getReference("users").child("profile");')[0]
        self.assertIn('/users/profile', finding.properties['firebase_paths'])

    def test_typed_reference_has_an_unknown_prefix(self):
        finding = inventory('DatabaseReference root;\nroot.child("users").child("profile");',
                            header=JAVA_IMPORT + 'import com.google.firebase.database.DatabaseReference;\n')[0]
        self.assertIn('/{dynamic}/users/profile', finding.properties['firebase_paths'])
        self.assertTrue(finding.properties['unresolved_segments'])

    def test_kotlin_firebase_extension_database_property(self):
        finding = inventory('Firebase.database.reference.child("users").child("profile")', 'kotlin',
                            'import com.google.firebase.ktx.Firebase\nimport com.google.firebase.database.ktx.database\n')[0]
        self.assertIn('/users/profile', finding.properties['firebase_paths'])

    def test_duplicate_paths_are_aggregated_once_per_source(self):
        findings = inventory('FirebaseDatabase.getInstance().getReference("users");\n'
                             'FirebaseDatabase.getInstance().getReference("users");')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].properties['firebase_paths'], ['/users'])
        self.assertEqual(findings[0].properties['configuration_scope'], 'sources/Example.java::<file>')


if __name__ == '__main__':
    unittest.main()
