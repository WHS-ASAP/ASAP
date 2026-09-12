"""Offline regression and integration tests. Fixtures are original synthetic data."""
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout,redirect_stderr
from io import StringIO,BytesIO
import hashlib
import http.client
import json
import os
import re
import stat
import struct
import sys
import threading
import time
import unittest
from unittest.mock import patch
import zipfile
from helpers import source,code,ids,axml_fixture
from asap.axml import decode_axml
from asap.cli import main
from asap.config import Config
from asap.engine import scan,baseline_fingerprints,should_fail
from asap.inputs import archive_entries,PreparedInput,tool_command,run_tool
from asap.manifest import parse_manifest,resources_for
from asap.model import Source
from asap.reporting import write_reports
from asap.server import make_server
from asap.storage import Store
from asap.text import Lexical
from asap.xmlutil import safe_xml

DEMO=Path(__file__).parent/'fixtures/demo'


def apk_bytes(binary=True):
    b=BytesIO()
    with zipfile.ZipFile(b,'w',zipfile.ZIP_STORED) as z:
        z.writestr('AndroidManifest.xml',axml_fixture() if binary else (DEMO/'resources/AndroidManifest.xml').read_bytes())
        z.writestr('classes.dex',b'SYNTHETIC_NOT_A_VALID_DEX')
        z.writestr('lib/arm64-v8a/libfixture.so',b'SYNTHETIC_NOT_A_LIBRARY')
    return b.getvalue()


class LexicalRegressionTests(unittest.TestCase):
    def test_chain_receiver(self):
        calls=Lexical('prefs.edit().putString("token",accessToken);').calls({'putString'})
        self.assertEqual(calls[0].receiver,'prefs.edit()')
    def test_chained_receiver_literals_redacted(self):
        fs=code('getSharedPreferences("DO_NOT_LEAK_87923",0).edit().putString("token",accessToken);')
        self.assertIn('DS005',ids(fs))
        self.assertNotIn('DO_NOT_LEAK_87923',str([f.to_dict() for f in fs]))
    def test_kotlin_sql_template(self):
        text='class Example { fun run() {\nval value = intent.getStringExtra("q")\nval query = "SELECT * FROM t WHERE x=$value"\ndb.rawQuery(query,null)\n} }'
        self.assertIn('SQL001',ids(code(text,language='kotlin')))
    def test_kotlin_second_template_logging(self):
        self.assertIn('LG001',ids(code('class Example { fun run() { Timber.d("n=$count t=$accessToken") } }',language='kotlin')))
    def test_java_dollar_label_not_sensitive_value(self):
        self.assertNotIn('LG001',ids(code('Log.d("demo","$accessToken label only");')))
    def test_literal_source_name_not_taint(self):
        self.assertNotIn('WV001',ids(code('web.loadUrl("https://example.invalid/getIntent()");')))
    def test_kotlin_template_web_flow(self):
        text='class A { fun run() {\nval value=intent.getDataString()\nweb.loadUrl("https://example.invalid/$value")\n} }'
        self.assertIn('WV001',ids(code(text,language='kotlin')))
    def test_resource_module_isolation(self):
        m=source('<manifest/>','xml','app/src/main/AndroidManifest.xml')
        right=source('<resources><string name="scheme">good</string></resources>','xml','app/src/main/res/values/strings.xml')
        wrong=source('<resources><string name="scheme">wrong</string><string name="only_other">bad</string></resources>','xml','other/src/main/res/values/strings.xml')
        self.assertEqual(resources_for(m,[wrong,right]),{'scheme':'good'})
    def test_ambiguous_resource_not_guessed(self):
        m=source('<manifest/>','xml','AndroidManifest.xml')
        ss=[source(f'<resources><string name="k">{v}</string></resources>','xml',f'res/values/{v}.xml') for v in ['a','b']]
        self.assertEqual(resources_for(m,ss),{})
    def test_unresolved_enabled_is_unknown(self):
        m=parse_manifest(source('<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:enabled="@bool/feature"><service android:name="A" android:exported="true"/></application></manifest>','xml'))
        self.assertIsNone(m.components[0]['effective_enabled'])


class AxmlTests(unittest.TestCase):
    def test_utf8(self):
        m=parse_manifest(source(decode_axml(axml_fixture()),'xml'))
        self.assertEqual((m.package,m.min_sdk,m.target_sdk),('example.binary',26,37))
        self.assertEqual(m.application['debuggable'],'true')
    def test_utf16(self):
        m=parse_manifest(source(decode_axml(axml_fixture(False)),'xml'))
        self.assertEqual(m.target_sdk,37)
    def test_all_truncations_rejected(self):
        data=axml_fixture()
        for n in range(len(data)):
            with self.assertRaises(ValueError):decode_axml(data[:n])
    def test_invalid_pool_rejected(self):
        data=bytearray(axml_fixture());struct.pack_into('<I',data,16,0x7fffffff)
        with self.assertRaises(ValueError):decode_axml(bytes(data))
    def test_invalid_chunk_rejected(self):
        data=bytearray(axml_fixture());struct.pack_into('<H',data,8,0x8888)
        with self.assertRaises(ValueError):decode_axml(bytes(data))
    def test_xml_entity_rejected(self):
        with self.assertRaises(ValueError):safe_xml('<!DOCTYPE manifest [<!ENTITY x "fixture">]><manifest>&x;</manifest>')


class ArchiveTests(unittest.TestCase):
    def check_entries(self,entries,cfg=None):
        b=BytesIO()
        with zipfile.ZipFile(b,'w') as z:
            for n,v in entries:z.writestr(n,v)
        b.seek(0)
        with zipfile.ZipFile(b) as z:return archive_entries(z,cfg or Config())
    def test_good_archive(self):
        self.assertEqual(len(self.check_entries([('AndroidManifest.xml',b'<manifest/>')])),1)
    def test_symlink(self):
        i=zipfile.ZipInfo('link');i.create_system=3;i.external_attr=(stat.S_IFLNK|0o777)<<16
        with self.assertRaises(ValueError):self.check_entries([(i,b'fixture')])
    def test_case_collision(self):
        with self.assertRaises(ValueError):self.check_entries([('A.xml',b'a'),('a.xml',b'b')])
    def test_entry_budget(self):
        with self.assertRaises(ValueError):self.check_entries([('a',b'12345')],Config(max_entry_bytes=4))
    def test_expanded_budget(self):
        with self.assertRaises(ValueError):self.check_entries([('a',b'123'),('b',b'456')],Config(max_archive_bytes=5))
    def test_source_byte_budget(self):
        with TemporaryDirectory() as td:
            p=Path(td)/'sample.apk';p.write_bytes(apk_bytes())
            with self.assertRaises(ValueError):scan(p,Config(decompile=False,max_source_bytes=100))
    def test_source_symlink_skipped(self):
        with TemporaryDirectory() as td:
            p=Path(td);(p/'target.java').write_text('class A {}');(p/'link.java').symlink_to(p/'target.java')
            r=scan(p);self.assertIn('SYMLINK_SKIPPED',{d['code'] for d in r.diagnostics})
    def test_compression_ratio(self):
        b=BytesIO()
        with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('a.xml',b'x'*10000)
        b.seek(0)
        with zipfile.ZipFile(b) as z:
            with self.assertRaises(ValueError):archive_entries(z,Config(max_compression_ratio=2))

for i,name in enumerate(['../escape.xml','/absolute.xml','a\\b.xml','C:/a.xml','a:stream','NUL.xml','folder/file.']):
    def test(self,name=name):
        with self.assertRaises(ValueError):self.check_entries([(name,b'fixture')])
    setattr(ArchiveTests,f'test_reject_path_{i}',test)


class PipelineTests(unittest.TestCase):
    def test_demo_all_categories(self):
        r=scan(DEMO)
        self.assertEqual(len({f.category for f in r.findings}),7)
        self.assertFalse(r.diagnostics)
        self.assertEqual(r.summary['confirmed_vulnerabilities'],0)
        self.assertEqual(r.coverage['enabled_rule_count'],43)
    def test_deterministic_workers(self):
        a=scan(DEMO,Config(workers=1));b=scan(DEMO,Config(workers=4))
        self.assertEqual([f.to_dict() for f in a.findings],[f.to_dict() for f in b.findings])
    def test_safe_fixture_negative(self):
        from asap.rules.analyze import code_findings,secret_findings
        s=source((DEMO/'sources/com/example/asap/SafeExamples.java').read_text())
        self.assertEqual(code_findings(s,[])+secret_findings(s),[])
    def test_baseline_roundtrip(self):
        with TemporaryDirectory() as td:
            p=Path(td);r=scan(DEMO);write_reports(r,p)
            later=scan(DEMO,baseline=p/'report.json')
            self.assertEqual(later.summary['new'],0)
            self.assertFalse(should_fail(later,'low',True))
    def test_fingerprint_survives_blank_line(self):
        with TemporaryDirectory() as td:
            p=Path(td);f=p/'A.java';content='class A {void a(){Cipher.getInstance("DES");}}'
            f.write_text(content);a=scan(p)
            f.write_text('\n\n'+content);b=scan(p)
            self.assertEqual(a.findings[0].fingerprint,b.findings[0].fingerprint)
    def test_suppression(self):
        r=scan(DEMO);f=r.findings[0]
        c=Config(suppressions=[{'fingerprint':f.fingerprint,'reason':'Synthetic test review'}])
        after=scan(DEMO,c)
        self.assertEqual(after.summary['suppressed'],1)
    def test_expired_suppression(self):
        c=Config(suppressions=[{'rule_id':'DS001','path':'**','reason':'Expired test','expires':'2000-01-01'}])
        r=scan(DEMO,c)
        self.assertEqual(r.summary['suppressed'],0)
        self.assertIn('SUPPRESSION_EXPIRED',{d['code'] for d in r.diagnostics})
    def test_category_alias(self):
        r=scan(DEMO,Config(categories=['Crypto']))
        self.assertEqual({f.category for f in r.findings},{'Insecure_DataStorage'})
    def test_invalid_baseline(self):
        with TemporaryDirectory() as td:
            p=Path(td)/'bad.json';p.write_text('{"fingerprints":["not-a-hash"]}')
            with self.assertRaises(ValueError):baseline_fingerprints(p)
    def test_apk_binary_manifest_partial(self):
        with TemporaryDirectory() as td:
            p=Path(td)/'fixture.apk';p.write_bytes(apk_bytes())
            before=hashlib.sha256(p.read_bytes()).hexdigest()
            r=scan(p,Config(decompile=False))
            self.assertIn('PM001',ids(r.findings));self.assertEqual(r.coverage['binary_xml_decoded'],1)
            self.assertTrue({'DEX_NOT_ANALYZED','NATIVE_NOT_ANALYZED'} <= {d['code'] for d in r.diagnostics})
            self.assertEqual(before,hashlib.sha256(p.read_bytes()).hexdigest())
    def test_split_apk_inventory(self):
        with TemporaryDirectory() as td:
            p=Path(td)/'fixture.apks'
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('base.apk',apk_bytes());z.writestr('config.apk',apk_bytes())
            r=scan(p,Config(decompile=False))
            self.assertEqual(len(r.scan['artifacts']),2)
    def test_malformed_xml_partial(self):
        with TemporaryDirectory() as td:
            p=Path(td);(p/'AndroidManifest.xml').write_text('<manifest>')
            r=scan(p)
            self.assertIn('XML_PARSE_FAILED',{d['code'] for d in r.diagnostics})
    def test_vendor_opt_in(self):
        with TemporaryDirectory() as td:
            p=Path(td);(p/'A.java').write_text('package com.google.firebase.fixture; class A {void a(){Cipher.getInstance("DES");}}')
            self.assertFalse(scan(p).findings)
            self.assertTrue(scan(p,Config(include_vendor=True)).findings)
    def test_rule_error_is_diagnostic(self):
        with patch('asap.engine.code_findings',side_effect=RuntimeError('test fixture')):
            r=scan(DEMO)
        self.assertIn('RULE_ENGINE_ERROR',{d['code'] for d in r.diagnostics})
    def test_report_formats_and_html_escaping(self):
        with TemporaryDirectory() as td:
            p=Path(td);r=scan(DEMO);r.scan['input_name']='</script><script>alert("not executed")</script>'
            paths=write_reports(r,p,True)
            report=json.loads((p/'report.json').read_text())
            sarif=json.loads((p/'report.sarif').read_text())
            html=(p/'report.html').read_text()
            self.assertEqual(sarif['version'],'2.1.0')
            self.assertEqual(len(sarif['runs'][0]['results']),len(report['findings']))
            self.assertNotIn(r.scan['input_name'],html)
            self.assertIn('sha256-',html)
            self.assertTrue((p/'legacy_findings.json').exists())
    def test_cli_exit_codes_and_baseline(self):
        with TemporaryDirectory() as td, redirect_stdout(StringIO()),redirect_stderr(StringIO()):
            out=Path(td)/'out'
            self.assertEqual(main(['scan',str(DEMO),'-o',str(out),'--fail-on','high']),1)
            base=Path(td)/'baseline.json'
            self.assertEqual(main(['baseline',str(out/'report.json'),'-o',str(base)]),0)
            self.assertEqual(main(['scan',str(DEMO),'-o',str(out),'--fail-on','high','--only-new','--baseline',str(base)]),0)
            self.assertEqual(main(['scan',str(Path(td)/'missing')]),2)
    def test_cli_strict_partial(self):
        with TemporaryDirectory() as td,redirect_stdout(StringIO()),redirect_stderr(StringIO()):
            p=Path(td);(p/'empty').mkdir()
            self.assertEqual(main(['scan',str(p/'empty'),'-o',str(p/'out'),'--strict']),2)
    def test_invalid_config(self):
        for c in [Config(workers=0),Config(categories=['New_Category']),Config(suppressions=[{'rule_id':'DS001','path':'**'}])]:
            with self.assertRaises(ValueError):c.validate()
    def test_jadx_windows_command_no_shell(self):
        with TemporaryDirectory() as td:
            p=Path(td);(p/'bin').mkdir();(p/'lib').mkdir();(p/'lib'/'jadx-cli.jar').touch()
            cmd=tool_command(str(p/'bin'/'jadx.bat'),'jadx',['input file.apk'])
            self.assertEqual(cmd[0],'java');self.assertIn('jadx.cli.JadxCLI',cmd);self.assertEqual(cmd[-1],'input file.apk')
    def test_tool_wrapper_subprocess_success(self):
        with TemporaryDirectory() as td:
            self.assertEqual(run_tool([sys.executable,'-c','print("synthetic wrapper test")'],Path(td),5),(0,'ok'))
    def test_tool_wrapper_timeout(self):
        with TemporaryDirectory() as td:
            self.assertEqual(run_tool([sys.executable,'-c','import time; time.sleep(5)'],Path(td),1),(-1,'timeout'))
    def test_sqlite_restart_recovery(self):
        with TemporaryDirectory() as td:
            s=Store(Path(td));s.create('1','fixture.apk');s.update('1','analyzing')
            self.assertEqual(Store(Path(td)).get('1')['state'],'interrupted')


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=TemporaryDirectory();cls.server=make_server(Path(cls.tmp.name),0,Config(decompile=False))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.port=cls.server.server_address[1]
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.server.app.pool.shutdown(wait=True);cls.thread.join();cls.tmp.cleanup()
    def request(self,method,path,body=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=10)
        c.request(method,path,body=body,headers=headers or {})
        r=c.getresponse();result=(r.status,dict(r.getheaders()),r.read());c.close();return result
    def test_home_csp(self):
        status,headers,body=self.request('GET','/')
        self.assertEqual(status,200);self.assertIn('Content-Security-Policy',headers)
        self.assertIn(self.server.app.token.encode(),body)
    def test_bad_host(self):
        self.assertEqual(self.request('GET','/',headers={'Host':'untrusted.invalid'})[0],403)
    def test_missing_csrf(self):
        self.assertEqual(self.request('POST','/api/upload?name=test.apk',b'x')[0],403)
    def test_cross_origin(self):
        self.assertEqual(self.request('POST','/api/upload?name=test.apk',b'x',{'X-ASAP-Token':self.server.app.token,'Origin':'https://untrusted.invalid'})[0],403)
    def test_bad_upload_name(self):
        self.assertEqual(self.request('POST','/api/upload?name=..%2Ffixture.apk',b'x',{'X-ASAP-Token':self.server.app.token})[0],400)
    def test_bad_extension(self):
        self.assertEqual(self.request('POST','/api/upload?name=fixture.txt',b'x',{'X-ASAP-Token':self.server.app.token})[0],400)
    def test_missing_report(self):
        self.assertEqual(self.request('GET','/reports/'+'0'*32+'/report.html')[0],404)
    def test_upload_to_report(self):
        status,_,body=self.request('POST','/api/upload?name=synthetic.apk',apk_bytes(),{'X-ASAP-Token':self.server.app.token})
        self.assertEqual(status,202);id=json.loads(body)['id']
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            job=self.server.app.store.get(id)
            if job['state'] in ('completed','failed'):break
            time.sleep(.03)
        self.assertEqual(job['state'],'completed')
        status,_,body=self.request('GET',f'/reports/{id}/report.json')
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['scan']['input_name'],'synthetic.apk')
        self.assertEqual(self.request('GET',f'/reports/{id}/report.html')[0],200)
