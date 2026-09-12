from pathlib import Path
import hashlib
import struct
from asap.model import Source
from asap.manifest import parse_manifest
from asap.rules.analyze import code_findings,secret_findings,manifest_findings,smali_findings


def source(text,language='java',path=None):
    return Source(path or {'java':'sources/Example.java','kotlin':'sources/Example.kt','xml':'resources/AndroidManifest.xml','smali':'smali/Example.smali','text':'assets/config.json'}[language],text,language,hashlib.sha256(text.encode()).hexdigest())


def code(body,header='',language='java'):
    text='package example;\n'+header+'\nclass Example {\n public void test() {\n'+body+'\n}\n}' if language=='java' else body
    s=source(text,language)
    return code_findings(s,[])+secret_findings(s)


def manifest(app='',root_extra='',target=37,app_attrs=''):
    text=f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example"><uses-sdk android:minSdkVersion="26" android:targetSdkVersion="{target}"/>{root_extra}<application android:allowBackup="false" {app_attrs}>{app}</application></manifest>'
    s=source(text,'xml');m=parse_manifest(s)
    return s,m,manifest_findings(s,m,[s])


def ids(findings):return {f.rule_id for f in findings}


def axml_fixture(utf8=True):
    """Original synthetic AXML fixture; NOT an installable APK or external app."""
    strings=['manifest','package','example.binary','uses-sdk','http://schemas.android.com/apk/res/android','minSdkVersion','targetSdkVersion','application','debuggable','allowBackup']
    chunks=[];offsets=[];body=b''
    for s in strings:
        offsets.append(len(body))
        raw=s.encode('utf-8' if utf8 else 'utf-16-le')
        body+=(bytes([len(s),len(raw)])+raw+b'\x00') if utf8 else (struct.pack('<H',len(s))+raw+b'\x00\x00')
    start=28+len(strings)*4
    size=start+len(body);padding=(-size)%4
    chunks.append(struct.pack('<HHIIIIII',1,28,size+padding,len(strings),0,0x100 if utf8 else 0,start,0)+struct.pack('<'+'I'*len(offsets),*offsets)+body+b'\x00'*padding)
    def attr(name,value,typ=3,ns=4):return struct.pack('<IIIHBBI',ns,name,0xffffffff,8,0,typ,value)
    def starttag(name,attributes=[]):
        ext=struct.pack('<IIHHHHHH',0xffffffff,name,20,20,len(attributes),0,0,0)+b''.join(attributes)
        return struct.pack('<HHIII',0x102,16,16+len(ext),1,0xffffffff)+ext
    def endtag(name):return struct.pack('<HHIIIII',0x103,16,24,1,0xffffffff,0xffffffff,name)
    chunks += [starttag(0,[attr(1,2,3,0xffffffff)]),starttag(3,[attr(5,26,0x10),attr(6,37,0x10)]),endtag(3),starttag(7,[attr(8,1,0x12),attr(9,0,0x12)]),endtag(7),endtag(0)]
    result=b''.join(chunks)
    return struct.pack('<HHI',3,8,len(result)+8)+result
