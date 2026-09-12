import json
import unittest

from helpers import ids, manifest, source
from asap.rules.analyze import code_findings
from asap.rules.entry_refinements import refine


def refined(body, header='', language='java'):
    text = ('package example;\n' + header + '\nclass Example {\nvoid inspect(){\n' + body + '\n}\n}') if language == 'java' else body
    s = source(text, language)
    return refine(s, code_findings(s, []), [])


class EntryRefinementTests(unittest.TestCase):
    def test_distinct_query_columns_are_not_selection(self):
        fs = refined('SQLiteDatabase db; db.query(true,"items",columns,"id=?",new String[]{input},null,null,null,null);')
        self.assertFalse(ids(fs) & {'SQL001', 'SQL002'})

    def test_distinct_query_external_selection_is_preserved(self):
        fs = refined('SQLiteDatabase db; String x=getIntent().getStringExtra("filter"); db.query(true,"items",null,"value="+x,null,null,null,null,null);')
        f = next(f for f in fs if f.rule_id == 'SQL001')
        self.assertEqual(f.properties['sql_argument_index'], 3)
        self.assertEqual(f.properties['sql_api_signature'], 'query_with_distinct')

    def test_distinct_variable_uses_declared_database_type(self):
        fs = refined('SQLiteDatabase db; db.query(distinct,"items",columns,"id=?",args,null,null,null,null);')
        self.assertFalse(ids(fs) & {'SQL001', 'SQL002'})

    def test_kotlin_distinct_database_type(self):
        fs = refined('class Example { fun inspect() {\nval db: SQLiteDatabase = database\ndb.query(distinct,"items",columns,"id=?",args,null,null,null,null)\n} }', language='kotlin')
        self.assertFalse(ids(fs) & {'SQL001', 'SQL002'})

    def test_query_builder_cancellation_overload_keeps_selection_index(self):
        fs = refined('SQLiteQueryBuilder builder; builder.query(db,columns,"id="+unknown,args,null,null,null,null,cancel);')
        f = next(f for f in fs if f.rule_id == 'SQL002')
        self.assertEqual(f.properties['sql_argument_index'], 2)

    def test_database_declaration_in_another_method_does_not_change_signature(self):
        s = source('class Example { void first(){ SQLiteDatabase db; } void second(){ SQLiteQueryBuilder db; db.query(database,columns,"id="+unknown,args,null,null,null,null,cancel); } }')
        fs = refine(s, code_findings(s, []), [])
        self.assertEqual(next(f for f in fs if f.rule_id == 'SQL002').properties['sql_argument_index'], 2)

    def test_bind_argument_does_not_hide_dynamic_sql(self):
        fs = refined('String x=getIntent().getStringExtra("filter"); db.rawQuery("SELECT * FROM items WHERE a="+x+" AND b=?",new String[]{other});')
        f = next(f for f in fs if f.rule_id == 'SQL001')
        self.assertTrue(f.properties['binding_argument_present'])
        self.assertIn('not_proven', f.properties['binding_safety'])

    def test_simple_sqlite_query_bound_values_are_not_sql(self):
        self.assertFalse(ids(refined('new SimpleSQLiteQuery("SELECT * FROM items WHERE a=?",new Object[]{getIntent().getStringExtra("value")});')) & {'SQL001', 'SQL002'})

    def test_factory_raw_query_tracks_correct_bind_index(self):
        fs = refined('db.rawQueryWithFactory(factory,"SELECT * FROM items ORDER BY "+unknown,args,null);')
        f = next(f for f in fs if f.rule_id == 'SQL002')
        self.assertEqual(f.properties['sql_argument_index'], 1)
        self.assertTrue(f.properties['binding_argument_present'])

    def test_compile_statement_does_not_call_itself_bound(self):
        f = next(f for f in refined('db.compileStatement("SELECT "+unknown);') if f.rule_id == 'SQL002')
        self.assertFalse(f.properties['binding_argument_present'])

    def test_compat_message_content_wildcard_is_not_origin(self):
        fs = refined('WebViewCompat.postWebMessage(web,new WebMessageCompat("*"),Uri.parse("https://example.invalid"));')
        self.assertNotIn('WV008', ids(fs))

    def test_compat_message_target_uses_third_argument(self):
        fs = refined('WebViewCompat.postWebMessage(web,message,Uri.parse("*"));')
        f = next(f for f in fs if f.rule_id == 'WV008')
        self.assertEqual(f.properties['origin_argument_index'], 2)

    def test_platform_message_target_uses_second_argument(self):
        fs = refined('web.postWebMessage(message,Uri.parse("*"));')
        self.assertEqual(next(f for f in fs if f.rule_id == 'WV008').properties['origin_argument_index'], 1)

    def test_origin_alias_and_reassignment(self):
        fs = refined('Uri origin=Uri.parse("*"); WebViewCompat.postWebMessage(web,message,origin); origin=Uri.parse("https://example.invalid"); WebViewCompat.postWebMessage(web,message,origin);')
        self.assertEqual(len([f for f in fs if f.rule_id == 'WV008']), 1)

    def test_subdomain_pattern_is_not_all_origins(self):
        fs = refined('WebViewCompat.addWebMessageListener(web,"bridge",Collections.singleton("https://*.example.invalid"),handler);')
        self.assertNotIn('WV008', ids(fs))

    def test_concatenated_subdomain_is_not_all_origins(self):
        for expression in ('"https://" + "*" + ".example.invalid"', '"https://" + star + ".example.invalid"'):
            fs = refined('String star="*"; WebViewCompat.addWebMessageListener(web,"bridge",Collections.singleton(' + expression + '),handler);')
            self.assertNotIn('WV008', ids(fs))

    def test_concatenated_target_uri_is_not_all_origins(self):
        fs = refined('WebViewCompat.postWebMessage(web,message,Uri.parse("https://" + "*" + ".example.invalid"));')
        self.assertNotIn('WV008', ids(fs))

    def test_unknown_origin_transform_does_not_prove_wildcard(self):
        fs = refined('WebViewCompat.postWebMessage(web,message,restrictedOrigin("*"));')
        self.assertNotIn('WV008', ids(fs))

    def test_complete_star_collection_element_is_preserved(self):
        fs = refined('WebViewCompat.addWebMessageListener(web,"bridge",new HashSet<>(Arrays.asList("*","https://"+"*"+".example.invalid")),handler);')
        self.assertIn('WV008', ids(fs))

    def test_current_webkit_listener_overload(self):
        fs = refined('WebViewCompat.addWebMessageListener(web,"bridge",Collections.singleton("*"),world,handler);')
        self.assertEqual(next(f for f in fs if f.rule_id == 'WV008').properties['origin_argument_index'], 2)

    def test_static_import_compat_message(self):
        fs = refined('postWebMessage(web,message,Uri.parse("*"));', header='import static androidx.webkit.WebViewCompat.postWebMessage;')
        self.assertIn('WV008', ids(fs))

    def test_fixed_class_intent_with_external_extra_is_review(self):
        fs = refined('startActivity(new Intent(this,Detail.class).putExtra("value",getIntent().getStringExtra("value")));')
        f = next(f for f in fs if f.rule_id == 'DL003')
        self.assertEqual(f.severity, 'low')
        self.assertEqual(f.properties['intent_construction'], 'fresh_fixed_class_with_external_data')
        self.assertEqual(f.properties['authorization'], 'not_verified')

    def test_kotlin_fixed_class_intent(self):
        fs = refined('class Example { fun inspect() { startActivity(Intent(this, Detail::class.java).putExtra("value",intent.getStringExtra("value"))) } }', language='kotlin')
        f = next(f for f in fs if f.rule_id == 'DL003')
        self.assertEqual(f.properties['intent_construction'], 'fresh_fixed_class_with_external_data')

    def test_copied_external_intent_not_fixed_class(self):
        f = next(f for f in refined('startActivity(new Intent(getIntent()));') if f.rule_id == 'DL003')
        self.assertEqual(f.severity, 'medium')
        self.assertEqual(f.properties['intent_construction'], 'external_intent_or_unresolved_construction')

    def test_later_component_setter_prevents_fixed_class_label(self):
        f = next(f for f in refined('startActivity(new Intent(this,Detail.class).setComponent(getIntent().getComponent()));') if f.rule_id == 'DL003')
        self.assertEqual(f.severity, 'medium')

    def test_local_intent_variable_is_not_a_fixed_target_proof(self):
        fs = refined('Intent next=new Intent(this,Detail.class).putExtra("x",getIntent().getDataString()); startActivity(next);')
        f = next(f for f in fs if f.rule_id == 'DL003')
        self.assertEqual(f.severity, 'medium')
        self.assertEqual(f.properties['intent_construction'], 'external_intent_or_unresolved_construction')

    def test_local_intent_component_mutation_prevents_downgrade(self):
        fs = refined('Intent next=new Intent(this,Detail.class).putExtra("x",getIntent().getDataString()); next.setComponent(getIntent().getComponent()); startActivity(next);')
        f = next(f for f in fs if f.rule_id == 'DL003')
        self.assertEqual(f.severity, 'medium')
        self.assertEqual(f.properties['intent_construction'], 'external_intent_or_unresolved_construction')

    def test_unknown_local_intent_mutation_prevents_downgrade(self):
        fs = refined('Intent next=new Intent(this,Detail.class).putExtra("x",getIntent().getDataString()); configure(next); startActivity(next);')
        f = next(f for f in fs if f.rule_id == 'DL003')
        self.assertEqual(f.severity, 'medium')

    def test_parenthesized_direct_constructor_keeps_narrow_review(self):
        fs = refined('startActivity((new Intent(this,Detail.class).putExtra("x",getIntent().getDataString())));')
        f = next(f for f in fs if f.rule_id == 'DL003')
        self.assertEqual(f.severity, 'low')

    def test_sanitizer_return_only_observation(self):
        fs = refined('startActivity(policy.sanitizeByThrowing(getIntent()));')
        f = next(f for f in fs if f.rule_id == 'DL003')
        self.assertTrue(f.properties['sanitizer_return_in_expression'])
        self.assertEqual(f.properties['sanitizer_policy'], 'not_verified')
        self.assertIn('AndroidX 타입', f.message)

    def test_unused_sanitizer_return_does_not_label_input_safe(self):
        fs = refined('Intent incoming=getIntent(); policy.sanitizeByFiltering(incoming); startActivity(incoming);')
        f = next(f for f in fs if f.rule_id == 'DL003')
        self.assertFalse(f.properties['sanitizer_return_in_expression'])
        self.assertEqual(f.severity, 'medium')

    def test_same_line_intent_calls_have_separate_context(self):
        fs = refined('startActivity(new Intent(this,Detail.class).putExtra("x",getIntent().getDataString())); startActivity(getIntent());')
        self.assertEqual([f.severity for f in fs if f.rule_id == 'DL003'], ['low', 'medium'])

    def test_file_access_default_keeps_explicit_true(self):
        f = next(f for f in refined('settings.setAllowFileAccess(true);') if f.rule_id == 'WV007')
        self.assertIn('explicit_true_observed', f.properties['file_access_default'])

    def test_filter_context_combines_data_elements_but_not_remote_state(self):
        body = '<activity android:name=".A" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https"/><data android:host="example.invalid"/></intent-filter></activity>'
        s, m, fs = manifest(body)
        f = next(f for f in refine(s, fs, [m]) if f.rule_id == 'DL002')
        self.assertEqual(f.properties['domain_verification'], 'not_tested')
        self.assertEqual(f.properties['link_filter_context'][0]['data_element_count'], 2)
        self.assertFalse(f.properties['link_filter_context'][0]['default_category'])

    def test_provider_uri_grants_remain_declaration_context(self):
        s, m, fs = manifest('<provider android:name=".P" android:exported="true" android:grantUriPermissions="true"><grant-uri-permission android:pathPrefix="/files"/></provider>')
        f = next(f for f in refine(s, fs, [m]) if f.rule_id == 'SQL003')
        self.assertEqual(f.properties['uri_grant_path_count'], 1)
        self.assertEqual(f.properties['uri_grant_policy_declared'], 'true')
        self.assertEqual(f.severity, 'low')

    def test_comments_and_string_examples_do_not_create_calls(self):
        fs = refined('// WebViewCompat.postWebMessage(web,message,Uri.parse("*"));\nString example="db.query(true,table,columns,selection,args,null,null,null,null)";')
        self.assertFalse(ids(fs) & {'SQL001', 'SQL002', 'WV008'})

    def test_properties_do_not_include_literal_values(self):
        marker = 'TEST_ONLY_DO_NOT_EXPORT_3829'
        fs = refined('db.rawQuery("SELECT * FROM '+marker+' WHERE a="+unknown,args);')
        self.assertNotIn(marker, json.dumps([f.to_dict() for f in fs]))

    def test_other_source_findings_are_preserved(self):
        other = source('class Other { void inspect() { db.rawQuery("SELECT "+value,null); } }', path='sources/Other.java')
        fs = code_findings(other, [])
        s = source('class Example {}')
        result = refine(s, fs, [])
        self.assertEqual([f.to_dict() for f in result], [f.to_dict() for f in fs])


if __name__ == '__main__':
    unittest.main()
