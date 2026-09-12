import hashlib
import json
import unittest

from asap.model import Source
from asap.rules.firebase_local import analyze, input_kind


def source(value, name='database.rules.json'):
    text = value if isinstance(value, str) else json.dumps(value)
    return Source(name, text, 'json', hashlib.sha256(text.encode()).hexdigest())


def inspect_rules(rules, **limits):
    return analyze(source({'rules': rules}), **limits)


def inspect_data(data, **limits):
    return analyze(source(data, 'firebase-export.json'), **limits)


class FirebaseLocalTests(unittest.TestCase):
    def test_only_known_input_filenames_are_recognized(self):
        for name in ('database.rules.json', 'nested/firebase.rules.json', '__firebase__/database.rules.json'):
            self.assertEqual(input_kind(source('{}', name)), 'rules')
        for name in ('firebase-export.json', 'nested/database-export.json', 'rtdb-export.json', '__firebase__/firebase-export.json'):
            self.assertEqual(input_kind(source('{}', name)), 'data')
        for name in ('arbitrary.json', 'google-services.json', 'my-database.rules.json'):
            self.assertIsNone(input_kind(source('{}', name)))
            self.assertEqual(analyze(source('{}', name)), ([], []))

    def test_child_grant_is_found_when_root_denies(self):
        findings, diagnostics = inspect_rules({'.read': False, 'profiles': {'private': {'.read': True}}})
        self.assertEqual(diagnostics, [])
        self.assertEqual([(f.rule_id, f.properties['firebase_path']) for f in findings], [('DS010', '/profiles/private')])
        self.assertEqual(findings[0].properties['inherited_from'], [])

    def test_root_grant_remains_effective_below_child_false(self):
        findings, diagnostics = inspect_rules({'.read': True, 'private': {'.read': False, 'deep': {'.read': 'false'}}})
        self.assertEqual(diagnostics, [])
        self.assertEqual(len(findings), 1)
        props = findings[0].properties
        self.assertEqual(props['affected_child_paths'], ['/private', '/private/deep'])
        self.assertEqual(props['child_denies_overridden'], ['/private', '/private/deep'])
        self.assertEqual(props['permission_state'], 'unconditional_grant')

    def test_each_explicit_grant_has_its_own_stable_scope(self):
        findings, _ = inspect_rules({'.read': True, '.write': True, 'nested': {'.read': True}})
        scopes = [f.properties['configuration_scope'] for f in findings]
        self.assertEqual(scopes, ['firebase-rtdb:read:/', 'firebase-rtdb:write:/', 'firebase-rtdb:read:/nested'])
        self.assertEqual(findings[-1].properties['inherited_from'], ['/'])
        self.assertEqual(findings[-1].properties['affected_child_paths'], [])

    def test_write_grant_does_not_claim_validate_constraints_pass(self):
        findings, _ = inspect_rules({'.write': True, '.validate': False, 'child': {'.write': False}})
        props = findings[0].properties
        self.assertEqual(findings[0].rule_id, 'DS011')
        self.assertEqual(props['validation_constraints'], 'not_evaluated')
        self.assertEqual(props['effective_write_access'], 'unknown')
        self.assertEqual(props['child_denies_overridden'], ['/child'])
        self.assertIn('.validate', findings[0].message)

    def test_wildcard_paths_are_preserved(self):
        findings, _ = inspect_rules({'users': {'$uid': {'.read': ' true ', 'entries': {'$entry': {'.write': True}}}}})
        self.assertEqual([f.properties['firebase_path'] for f in findings], ['/users/$uid', '/users/$uid/entries/$entry'])
        self.assertEqual(findings[0].properties['affected_child_paths'], ['/users/$uid/entries', '/users/$uid/entries/$entry'])

    def test_dynamic_expressions_are_unknown_without_expression_leakage(self):
        secret = 'private-expression-secret-473829'
        findings, diagnostics = inspect_rules({'x': {'.read': f"auth.uid == '{secret}'", '.write': 'auth != null'}})
        self.assertEqual(findings, [])
        self.assertEqual([d['code'] for d in diagnostics], ['FIREBASE_RULE_EXPRESSION_UNKNOWN'])
        self.assertNotIn(secret, json.dumps(diagnostics))
        self.assertIn('2 dynamic', diagnostics[0]['message'])

    def test_dynamic_descendant_does_not_cancel_known_ancestor_grant(self):
        findings, diagnostics = inspect_rules({'.read': True, 'x': {'.read': 'auth != null'}})
        self.assertEqual(findings[0].properties['affected_child_paths'], ['/x'])
        self.assertEqual(findings[0].properties['unknown_child_expression_paths'], ['/x'])
        self.assertEqual(findings[0].properties['child_denies_overridden'], [])
        self.assertEqual(diagnostics[0]['code'], 'FIREBASE_RULE_EXPRESSION_UNKNOWN')

    def test_boolean_like_numbers_and_expressions_are_not_literal_grants(self):
        findings, diagnostics = inspect_rules({'number': {'.read': 1}, 'expression': {'.read': 'true || auth != null'}, 'caps': {'.write': 'TRUE'}})
        self.assertEqual(findings, [])
        self.assertEqual({d['code'] for d in diagnostics}, {'FIREBASE_INVALID_RULE_TYPE', 'FIREBASE_RULE_EXPRESSION_UNKNOWN'})

    def test_rules_comments_preserve_real_permission_line_numbers(self):
        text = '''{
  // a comment with ".read": true
  "rules": {
    /* comment spanning
       multiple lines */
    "users": {
      ".read": true,
      ".write": "auth.uid == 'https://example.invalid/a/*b*/'"
    }
  }
}'''
        findings, diagnostics = analyze(source(text))
        self.assertEqual(findings[0].evidence[0].line, 7)
        self.assertEqual(findings[0].evidence[0].end_line, 7)
        self.assertEqual(findings[0].evidence[0].role, 'observation')
        self.assertEqual(diagnostics[0]['code'], 'FIREBASE_RULE_EXPRESSION_UNKNOWN')

    def test_escaped_permission_key_has_correct_line(self):
        findings, _ = analyze(source('{"rules": {".indexOn": ["x", "y"],\n "child": {"\\u002eread": true}}}'))
        self.assertEqual(findings[0].evidence[0].line, 2)

    def test_duplicate_json_keys_are_rejected_at_any_depth(self):
        for text in ('{"rules":{".read":false,".read":true}}', '{"rules":{"x":{".read":true},"x":{}}}', '{"rules":{},"rules":{".read":true}}'):
            findings, diagnostics = analyze(source(text))
            self.assertEqual(findings, [])
            self.assertEqual(diagnostics[0]['code'], 'FIREBASE_DUPLICATE_KEY')

    def test_invalid_json_diagnostic_does_not_echo_source(self):
        secret = 'invalid-private-token-9472398'
        for text in ('{"rules":' + secret, '{"rules":{/*' + secret, '{"rules":{".read":NaN}}'):
            findings, diagnostics = analyze(source(text))
            self.assertEqual(findings, [])
            self.assertEqual(diagnostics[0]['code'], 'FIREBASE_INVALID_JSON')
            self.assertNotIn(secret, json.dumps(diagnostics))

    def test_invalid_root_shapes_have_explicit_diagnostics(self):
        for value in ([], None, {'rules': []}, {'rules': True}, {'other': {'.read': True}}):
            findings, diagnostics = analyze(source(json.dumps(value)))
            self.assertEqual(findings, [])
            self.assertEqual(diagnostics[0]['code'], 'FIREBASE_INVALID_RULES')

    def test_invalid_child_and_directive_types_are_reported(self):
        findings, diagnostics = inspect_rules({'x': [], 'y': {'.read': None}, 'z': {'.validate': {}, '.indexOn': [1]}, 'bad/key': {'.read': True}, '': {'.read': True}})
        self.assertEqual(findings, [])
        self.assertIn('FIREBASE_INVALID_RULE_TYPE', [d['code'] for d in diagnostics])

    def test_node_limit_keeps_partial_rules_coverage_explicit(self):
        findings, diagnostics = inspect_rules({'.read': True, 'a': {'.read': True}, 'b': {'.read': True}}, max_nodes=2)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.properties['truncated'] for f in findings))
        self.assertEqual(findings[0].properties['affected_child_paths'], ['/a'])
        self.assertEqual(diagnostics[0]['code'], 'FIREBASE_NODE_LIMIT')

    def test_depth_limit_does_not_silently_skip_nested_rules(self):
        findings, diagnostics = inspect_rules({'.read': True, 'a': {'b': {'.write': True}}}, max_depth=1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].properties['affected_child_paths'], ['/a'])
        self.assertTrue(findings[0].properties['truncated'])
        self.assertEqual(diagnostics[0]['code'], 'FIREBASE_DEPTH_LIMIT')

    def test_export_lists_root_and_all_nested_object_array_paths(self):
        findings, diagnostics = inspect_data({'users': [{'name': 'alice'}, None, True], 'count': 3, 'empty': {}})
        self.assertEqual(diagnostics, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'DS012')
        self.assertEqual(findings[0].kind, 'inventory')
        self.assertEqual(findings[0].evidence[0].role, 'observation')
        props = findings[0].properties
        self.assertEqual([(p['path'], p['type']) for p in props['paths']], [('/', 'object'), ('/users', 'array'), ('/users/0', 'object'), ('/users/0/name', 'string'), ('/users/1', 'null'), ('/users/2', 'boolean'), ('/count', 'number'), ('/empty', 'object')])
        self.assertEqual(props['node_count'], 8)
        self.assertEqual(props['type_counts']['object'], 3)
        self.assertEqual(props['paths'][0]['child_count'], 3)
        self.assertFalse(props['scalar_values_included'])
        self.assertEqual(props['access_status'], 'not_inferred_from_local_export')

    def test_export_scalar_values_and_priorities_never_enter_output(self):
        secrets = ['private-scalar-837281', 'priority-secret-13217', 'second-sensitive-14331']
        findings, diagnostics = inspect_data({'one': {'.value': secrets[0], '.priority': secrets[1]}, 'two': secrets[2], 'n': 928172837192})
        serialized = json.dumps({'findings': [f.to_dict() for f in findings], 'diagnostics': diagnostics})
        for secret in [*secrets, '928172837192']:
            self.assertNotIn(secret, serialized)
        self.assertEqual(findings[0].properties['paths'][1], {'path': '/one', 'type': 'string', 'depth': 1, 'child_count': 0, 'has_priority': True})

    def test_priority_on_container_is_metadata_not_child_path(self):
        findings, diagnostics = inspect_data({'.priority': 2, 'child': {'.value': False, '.priority': None}})
        self.assertEqual(diagnostics, [])
        self.assertEqual([p['path'] for p in findings[0].properties['paths']], ['/', '/child'])
        self.assertTrue(all(p['has_priority'] for p in findings[0].properties['paths']))
        self.assertEqual(findings[0].properties['paths'][1]['type'], 'boolean')

    def test_malformed_export_metadata_is_explicit_and_keeps_real_children(self):
        findings, diagnostics = inspect_data({'.value': 'hidden-secret', '.priority': [], 'real': {'child': 7}})
        self.assertEqual([p['path'] for p in findings[0].properties['paths']], ['/', '/real', '/real/child'])
        self.assertEqual(diagnostics[0]['code'], 'FIREBASE_EXPORT_METADATA_INVALID')
        self.assertNotIn('hidden-secret', json.dumps(findings[0].to_dict()))

    def test_scalar_and_empty_export_roots_are_inventoried(self):
        for value, expected in ((None, 'null'), (True, 'boolean'), (5, 'number'), ('"secret"', 'string'), ({}, 'object'), ([], 'array')):
            findings, diagnostics = inspect_data(value)
            self.assertEqual(diagnostics, [])
            self.assertEqual(findings[0].properties['paths'][0]['type'], expected)
            self.assertEqual(findings[0].properties['node_count'], 1)

    def test_export_node_and_depth_limits_are_reported(self):
        findings, diagnostics = inspect_data({'a': [1, 2, 3], 'b': {}}, max_nodes=3)
        self.assertEqual(findings[0].properties['node_count'], 3)
        self.assertTrue(findings[0].properties['truncated'])
        self.assertEqual(diagnostics[0]['code'], 'FIREBASE_NODE_LIMIT')
        findings, diagnostics = inspect_data({'a': [1, 2]}, max_depth=1)
        self.assertEqual([p['path'] for p in findings[0].properties['paths']], ['/', '/a'])
        self.assertEqual(diagnostics[0]['code'], 'FIREBASE_DEPTH_LIMIT')

    def test_export_does_not_accept_rules_comments(self):
        findings, diagnostics = analyze(source('{/* comment */ "a":1}', 'firebase-export.json'))
        self.assertEqual(findings, [])
        self.assertEqual(diagnostics[0]['code'], 'FIREBASE_INVALID_JSON')

    def test_deeply_nested_json_cannot_raise_recursion_error(self):
        text = '{"rules":' + '{"child":' * 1500 + '{}' + '}' * 1501
        findings, diagnostics = analyze(source(text))
        self.assertEqual(findings, [])
        self.assertIn(diagnostics[0]['code'], {'FIREBASE_INVALID_JSON', 'FIREBASE_DEPTH_LIMIT'})

    def test_oversized_paths_are_skipped_without_colliding_truncation(self):
        long_key = 'x' * 2500
        findings, diagnostics = inspect_rules({'.read': True, long_key: {'.read': True}, 'short': {}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].properties['affected_child_paths'], ['/short'])
        self.assertTrue(findings[0].properties['truncated'])
        self.assertIn('FIREBASE_PATH_LIMIT', [d['code'] for d in diagnostics])
        findings, diagnostics = inspect_data({long_key: {'a': 1}, 'short': {}})
        self.assertEqual([p['path'] for p in findings[0].properties['paths']], ['/', '/short'])
        self.assertTrue(findings[0].properties['truncated'])
        self.assertIn('FIREBASE_PATH_LIMIT', [d['code'] for d in diagnostics])

    def test_wide_export_aggregate_path_budget_is_bounded(self):
        payload = {('x' * 1800) + str(i): {'child': i} for i in range(900)}
        findings, diagnostics = inspect_data(payload)
        paths = findings[0].properties['paths']
        self.assertLessEqual(sum(len(p['path'].encode()) for p in paths), 1024 * 1024)
        self.assertTrue(findings[0].properties['truncated'])
        self.assertIn('FIREBASE_PATH_LIMIT', [d['code'] for d in diagnostics])
        self.assertLess(len(json.dumps(findings[0].to_dict())), 1200 * 1024)

    def test_many_nested_grants_have_bounded_affected_path_output(self):
        node = {'.read': True, '.write': True}
        root = node
        for i in range(50):
            child = {'.read': True, '.write': True}
            node['part' + str(i) + ('x' * 24)] = child
            node = child
        findings, diagnostics = inspect_rules(root)
        self.assertTrue(findings)
        self.assertTrue(all(f.properties['truncated'] for f in findings))
        self.assertIn('FIREBASE_PATH_LIMIT', [d['code'] for d in diagnostics])
        self.assertLess(len(json.dumps([f.to_dict() for f in findings])), 1300 * 1024)

    def test_invalid_surrogate_path_does_not_break_encoding(self):
        findings, diagnostics = analyze(source('{"\\ud800":1,"ok":2}', 'firebase-export.json'))
        self.assertEqual([p['path'] for p in findings[0].properties['paths']], ['/', '/ok'])
        self.assertIn('FIREBASE_PATH_LIMIT', [d['code'] for d in diagnostics])

    def test_all_finding_evidence_is_synthetic_and_not_json_source(self):
        secret = 'never-copy-sensitive-json-1717377'
        text = json.dumps({'rules': {'.read': True, '.write': True, '.validate': f"newData.val() == '{secret}'"}})
        findings, diagnostics = analyze(source(text))
        self.assertEqual(diagnostics, [])
        serialized = json.dumps([f.to_dict() for f in findings])
        self.assertNotIn(secret, serialized)
        self.assertTrue(all(f.evidence[0].role == 'observation' for f in findings))
        self.assertTrue(all('Firebase Rules' in f.evidence[0].snippet for f in findings))

    def test_export_path_escaping_cannot_collide_with_root_or_separator(self):
        findings, diagnostics = inspect_data({'': 'omitted', 'a/b': 1, 'a~1b': 2})
        self.assertEqual([p['path'] for p in findings[0].properties['paths']], ['/', '/a~1b', '/a~01b'])
        self.assertIn('FIREBASE_PATH_LIMIT', [d['code'] for d in diagnostics])

    def test_input_size_limit_is_explicit(self):
        findings, diagnostics = analyze(source(' ' * (8 * 1024 * 1024 + 1)))
        self.assertEqual(findings, [])
        self.assertEqual(diagnostics[0]['code'], 'FIREBASE_INPUT_LIMIT')

    def test_invalid_limits_are_rejected(self):
        for limits in ({'max_nodes': 0}, {'max_nodes': True}, {'max_depth': -1}, {'max_depth': False}):
            with self.assertRaises(ValueError):
                inspect_rules({}, **limits)


if __name__ == '__main__':
    unittest.main()
