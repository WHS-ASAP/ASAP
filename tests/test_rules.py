import unittest
from helpers import code,source,manifest,ids
from asap.rules.analyze import secret_findings,smali_findings
from asap.rules.registry import RULES
from asap import CATEGORIES

POSITIVES = {
 'SQL001':'String x=getIntent().getStringExtra("q"); db.rawQuery("SELECT * FROM t WHERE v="+x,null);',
 'SQL002':'db.rawQuery("SELECT * FROM t WHERE v="+unknown,null);',
 'WV001':'String u=getIntent().getDataString(); web.loadUrl(u);',
 'WV002':'web.addJavascriptInterface(bridge,"app");',
 'WV003':'settings.setAllowUniversalAccessFromFileURLs(true);',
 'WV004':'SslErrorHandler handler; handler.proceed();',
 'WV005':'WebView.setWebContentsDebuggingEnabled(true);',
 'WV006':'settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);',
 'WV007':'settings.setAllowFileAccess(true);',
 'WV008':'WebViewCompat.addWebMessageListener(web,"listener",Collections.singleton("*"),handler);',
 'WV009':'if (url.startsWith("https://example.invalid")) { accept(); }',
 'DL003':'Intent i=getIntent().getParcelableExtra("target");startActivity(i);',
 'DL004':'i.removeLaunchSecurityProtection();',
 'HC001':'String client_secret="ONLY_A_TEST_CONSTANT_2468";',
 'HC002':'String pem="-----BEGIN PRIVATE KEY-----";',
 'HC003':'String credential="ghp_000000000000000000000000000000000000";',
 'HC004':'String key="AIza00000000000000000000000000000000000";',
 'HC005':'String endpoint="https://demo:static_password@example.invalid/";',
 'PM006':'PendingIntent.getActivity(context,0,intent,PendingIntent.FLAG_MUTABLE);',
 'DS001':'Cipher.getInstance("AES/ECB/PKCS5Padding");',
 'DS002':'MessageDigest.getInstance("MD5");',
 'DS003':'new IvParameterSpec(new byte[16]);',
 'DS004':'int mode=MODE_WORLD_READABLE;',
 'DS005':'prefs.edit().putString("access_token",accessToken);',
 'DS007':'EncryptedSharedPreferences.create(context);',
 'DS008':'new SecretKeySpec("DEMO_ONLY_STATIC_KEY".getBytes(),"AES");',
 'LG001':'Log.d("demo","token="+accessToken);',
 'LG002':'interceptor.setLevel(HttpLoggingInterceptor.Level.BODY);',
}
class RuleTests(unittest.TestCase):
    def test_categories_preserved(self):
        self.assertEqual(set(CATEGORIES),{r.category for r in RULES.values()})
        self.assertEqual(len(CATEGORIES),7)
        self.assertEqual(len(RULES),43)
    def test_parameterized_sql_negative(self):
        self.assertFalse(ids(code('db.rawQuery("SELECT * FROM t WHERE v=?",new String[]{input});'))&{'SQL001','SQL002'})
    def test_sql_does_not_blanket_suppress_file(self):
        findings=code('String q=getIntent().getStringExtra("q");db.rawQuery("SELECT * FROM t WHERE v="+q,null);db.rawQuery("SELECT 1",null);',header='import android.database.sqlite.SQLiteOpenHelper; import androidx.room.Query;')
        self.assertIn('SQL001',ids(findings))
    def test_reassignment_kills_source(self):
        self.assertNotIn('WV001',ids(code('String u=getIntent().getDataString();u="https://example.invalid";web.loadUrl(u);')))
    def test_comments_are_not_code(self):
        self.assertNotIn('DS001',ids(code('// Cipher.getInstance("DES");\n/* Cipher.getInstance("DES"); */')))
    def test_strings_are_not_calls(self):
        self.assertNotIn('DS001',ids(code('String text="Cipher.getInstance(\\"DES\\")";')))
    def test_secure_crypto_negative(self):
        self.assertNotIn('DS001',ids(code('Cipher.getInstance("AES/GCM/NoPadding");')))
    def test_non_sensitive_log_label_negative(self):
        self.assertNotIn('LG001',ids(code('Log.i("app","Password reset requested");')))
    def test_non_sensitive_value_log_negative(self):
        self.assertNotIn('LG001',ids(code('Log.i("password label",count);')))
    def test_unknown_receiver_log_negative(self):
        self.assertNotIn('LG001',ids(code('someClass.print(accessToken);')))
    def test_false_settings_negative(self):
        self.assertFalse(ids(code('WebView.setWebContentsDebuggingEnabled(false); settings.setAllowFileAccess(false);'))&{'WV005','WV007'})
    def test_no_cross_method_taint(self):
        body='package example; class Example {void a(){String x=getIntent().getDataString();}void b(){web.loadUrl(x);}}'
        self.assertNotIn('WV001',ids(code(body,language='kotlin')))
    def test_kotlin_local_flow(self):
        body='package example\nclass Example { fun test() {\nval value = intent.getStringExtra("q")\nval sql = "SELECT * FROM t WHERE x=" + value\ndb.rawQuery(sql,null)\n} }'
        self.assertIn('SQL001',ids(code(body,language='kotlin')))
    def test_kotlin_interpolation_logging(self):
        self.assertIn('LG001',ids(code('class Example { fun test() { Timber.d("token=$accessToken") } }',language='kotlin')))
    def test_multi_line_query(self):
        fs=code('String x=getIntent().getStringExtra("x");\ndb.rawQuery(\n"SELECT * FROM t WHERE x="+x,\nnull\n);')
        f=next(f for f in fs if f.rule_id=='SQL001')
        self.assertGreater(f.evidence[-1].end_line,f.evidence[-1].line)
        self.assertGreater(len(f.evidence),1)
    def test_no_secret_plaintext_in_evidence(self):
        value='SYNTHETIC_SECRET_MUST_NOT_APPEAR_72815'
        fs=code(f'String client_secret="{value}"; Log.d("secret="+client_secret);')
        self.assertTrue(fs)
        self.assertNotIn(value,str([f.to_dict() for f in fs]))
    def test_firebase_is_inventory(self):
        f=next(f for f in code(POSITIVES['HC004']) if f.rule_id=='HC004')
        self.assertEqual((f.severity,f.kind),('info','inventory'))
    def test_public_key_not_private(self):
        self.assertNotIn('HC002',ids(secret_findings(source('-----BEGIN PUBLIC KEY-----','text'))))
    def test_resource_secret_and_label(self):
        fs=secret_findings(source('<resources><string name="service_secret">TEST_ONLY_VALUE_4269</string><string name="password_hint">Enter password</string></resources>','xml'))
        self.assertEqual([f.rule_id for f in fs],['HC001'])
    def test_smali_is_inventory(self):
        fs=smali_findings(source('invoke-virtual {v0}, Landroid/content/Intent;->removeLaunchSecurityProtection()V','smali'))
        self.assertEqual(fs[0].severity,'info');self.assertEqual(fs[0].kind,'inventory')
    def test_bundle_is_not_preferences(self):
        self.assertNotIn('DS005',ids(code('Bundle bundle=new Bundle();bundle.putString("access_token",accessToken);')))

for rule_id,body in POSITIVES.items():
    def check(self,rule_id=rule_id,body=body):
        self.assertIn(rule_id,ids(code(body)))
    setattr(RuleTests,'test_positive_'+rule_id,check)

class ManifestRuleTests(unittest.TestCase):
    def test_SQL003(self):
        _,_,f=manifest('<provider android:name=".P" android:exported="true" android:authorities="example.data"/>')
        self.assertIn('SQL003',ids(f));self.assertEqual(next(x for x in f if x.rule_id=='SQL003').severity,'low')
    def test_WV010(self):
        _,_,f=manifest(app_attrs='android:usesCleartextTraffic="true"')
        self.assertIn('WV010',ids(f))
    def test_DL001(self):
        _,_,f=manifest('<activity android:name=".A" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="custom"/></intent-filter></activity>')
        self.assertIn('DL001',ids(f))
    def test_DL002(self):
        _,_,f=manifest('<activity android:name=".A" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https" android:host="example.invalid"/></intent-filter></activity>')
        self.assertIn('DL002',ids(f))
    def test_PM001(self):
        self.assertIn('PM001',ids(manifest(app_attrs='android:debuggable="true"')[2]))
    def test_PM002(self):
        self.assertIn('PM002',ids(manifest('<service android:name=".S" android:exported="true"/>')[2]))
    def test_PM003(self):
        self.assertIn('PM003',ids(manifest(root_extra='<permission android:name="example.weak" android:protectionLevel="normal"/>')[2]))
    def test_PM004(self):
        self.assertIn('PM004',ids(manifest(root_extra='<uses-permission android:name="android.permission.READ_SMS"/>')[2]))
    def test_PM005(self):
        self.assertIn('PM005',ids(manifest('<receiver android:name=".R"><intent-filter><action android:name="example.action"/></intent-filter></receiver>')[2]))
    def test_PM007(self):
        fs=manifest(root_extra='<uses-permission android:name="android.permission.ACCESS_LOCAL_NETWORK"/>')[2]
        self.assertIn('PM007',ids(fs));self.assertTrue(next(f for f in fs if f.rule_id=='PM007').properties['api37_target_requirement'])
    def test_DS006(self):
        from asap.manifest import parse_manifest
        from asap.rules.analyze import manifest_findings
        s=source('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example"><application/></manifest>','xml')
        self.assertIn('DS006',ids(manifest_findings(s,parse_manifest(s),[s])))
    def test_provider_permission_inheritance(self):
        _,m,f=manifest('<provider android:name=".P" android:exported="true"/>',app_attrs='android:permission="example.private"')
        self.assertNotIn('SQL003',ids(f));self.assertEqual(m.components[0]['permission'],'example.private')
    def test_read_only_guard_does_not_cover_write(self):
        self.assertIn('SQL003',ids(manifest('<provider android:name=".P" android:exported="true" android:readPermission="example.read"/>')[2]))
    def test_provider_default_sdk17(self):
        _,m,f=manifest('<provider android:name=".P"/>',target=17)
        self.assertFalse(m.components[0]['effective_exported']);self.assertNotIn('SQL003',ids(f))
    def test_provider_default_sdk16(self):
        _,m,f=manifest('<provider android:name=".P"/>',target=16)
        self.assertTrue(m.components[0]['effective_exported']);self.assertIn('SQL003',ids(f))
    def test_disabled_application(self):
        self.assertNotIn('PM002',ids(manifest('<service android:name=".S" android:exported="true"/>',app_attrs='android:enabled="false"')[2]))
    def test_launcher_exposure_is_not_finding(self):
        app='<activity android:name=".A" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>'
        self.assertNotIn('PM002',ids(manifest(app)[2]))
    def test_signature_permission_negative(self):
        self.assertNotIn('PM003',ids(manifest(root_extra='<permission android:name="example.guard" android:protectionLevel="signature|privileged"/>')[2]))
    def test_autoverify_negative(self):
        app='<activity android:name=".A" android:exported="true"><intent-filter android:autoVerify="true"><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https" android:host="example.invalid"/></intent-filter></activity>'
        self.assertNotIn('DL002',ids(manifest(app)[2]))
    def test_nsc_overrides_cleartext_attribute(self):
        self.assertNotIn('WV010',ids(manifest(app_attrs='android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/network_security_config"')[2]))
