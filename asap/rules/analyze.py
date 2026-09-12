from __future__ import annotations
import re
from ..model import Evidence, Finding, Manifest, Source
from ..text import Lexical, SENSITIVE, mask, literals, redact, external_source, dynamic_string, expression_code, blank
from ..manifest import component_context
from ..xmlutil import safe_xml, boolean, attrs
from .registry import RULES


def make(rule_id: str, source: Source, start: int, end: int, message: str,
         *, confidence: str = 'medium', kind: str = 'review', severity: str | None = None,
         properties: dict | None = None, trace: list[int] | None = None) -> Finding:
    rule = RULES[rule_id]
    line = source.text.count('\n',0,start)+1
    end_line = source.text.count('\n',0,max(start,end-1))+1
    a = source.text.rfind('\n',0,start)+1
    b = source.text.find('\n',end)
    if b < 0: b = len(source.text)
    snippet = redact(source.text[a:b],source.language)[:1600]
    evidence = []
    for point in (trace or [])[-6:]:
        ln = source.text.count('\n',0,point)+1
        left = source.text.rfind('\n',0,point)+1
        right = source.text.find('\n',point)
        if right < 0: right = len(source.text)
        evidence.append(Evidence(source.path,ln,ln,redact(source.text[left:right],source.language)[:800],'local_assignment'))
    evidence.append(Evidence(source.path,line,end_line,snippet,'observation'))
    return Finding(rule.id,rule.category,rule.title,severity or rule.severity,confidence,kind,
                   message,evidence,rule.remediation,rule.cwe,rule.masvs,list(rule.references),
                   properties=properties or {})


def code_findings(source: Source, manifests: list[Manifest]) -> list[Finding]:
    lex = Lexical(source.text, source.language)
    context = component_context(source,manifests)
    findings: list[Finding] = []
    def emit(id: str, call, message: str, **kw) -> None:
        props = {**context, 'method':call.scope[2], 'receiver':redact(call.receiver), **kw.pop('properties',{})}
        findings.append(make(id,source,call.start,call.end,message,properties=props,**kw))
    # SQL: a safe call elsewhere must never suppress a different dynamic query.
    for c in lex.calls({'rawQuery','execSQL','compileStatement','rawQueryWithFactory','SimpleSQLiteQuery','query'}):
        index = 1 if c.name == 'rawQueryWithFactory' else 0
        if c.name == 'query':
            # SQLiteDatabase.query: selection is index 2. Generic query APIs are not guessed.
            if len(c.args) < 7 or not re.search(r'SQLiteDatabase|SQLiteQueryBuilder',lex.code): continue
            index = 2
        if len(c.args) <= index: continue
        expr, trace = lex.resolve(c.args[index],c.start,c.scope)
        if c.args[index].strip() in {'null','None'} or not dynamic_string(expr, source.language): continue
        if not (re.search(r'\+|\$\{|\$[A-Za-z_]|\.format\s*\(|StringBuilder|\.append\s*\(',expr) or external_source(expr, source.language)):
            # Unknown raw SQL variables are kept as lower-confidence review, not proven taint.
            if c.name == 'compileStatement': continue
        external = external_source(expr, source.language)
        emit('SQL001' if external else 'SQL002',c,
             '동일 메서드의 표현식 연결에서 외부 입력이 동적 SQL 인자에 포함됩니다. 실제 도달성과 권한 경계는 미검증입니다.' if external else
             'SQL 구문 인자가 상수로 확인되지 않았습니다. 출처·매개변수화 여부를 검토하세요.',
             trace=trace,confidence='medium' if external else 'low')
    for c in lex.calls({'loadUrl','loadData','loadDataWithBaseURL','postUrl','evaluateJavascript'}):
        if not c.args: continue
        # loadDataWithBaseURL: both base URL and content can be untrusted.
        indexes = range(min(2,len(c.args))) if c.name == 'loadDataWithBaseURL' else [0]
        for i in indexes:
            expr, trace = lex.resolve(c.args[i],c.start,c.scope)
            if external_source(expr, source.language):
                emit('WV001',c,'외부 입력에서 WebView 계열 API 인자로 이어지는 로컬 표현식 경로입니다. 사용자 정의 래퍼·정확한 receiver 타입·검증 분기는 별도 검토가 필요합니다.',
                     trace=trace,properties={'argument_index':i})
                break
    flags = {
        'setAllowUniversalAccessFromFileURLs':'WV003', 'setAllowFileAccessFromFileURLs':'WV003',
        'setWebContentsDebuggingEnabled':'WV005', 'setAllowFileAccess':'WV007',
    }
    for c in lex.calls(set(flags)):
        if c.args and c.args[0].strip() == 'true':
            emit(flags[c.name],c,'보안 관련 설정이 명시적으로 true입니다. 호출 실행 조건과 빌드 변형을 확인하세요.',confidence='high',kind='configuration')
    for c in lex.calls({'addJavascriptInterface'}):
        emit('WV002',c,'Native bridge 등록을 관찰했습니다. JavaScript 활성화·콘텐츠 출처·프레임별 노출을 함께 검토하세요.',confidence='high',severity='low')
    for c in lex.calls({'proceed'}):
        if c.scope[2] == 'onReceivedSslError' or re.search(r'\bSslErrorHandler\b',lex.code[max(0,c.scope[0]-200):c.scope[1]]):
            emit('WV004',c,'SSL 오류 처리 문맥에서 proceed 호출을 관찰했습니다.',confidence='high')
    for c in lex.calls({'setMixedContentMode'}):
        if c.args and (c.args[0].strip() == '0' or 'MIXED_CONTENT_ALWAYS_ALLOW' in c.args[0]):
            emit('WV006',c,'혼합 콘텐츠를 항상 허용하는 설정입니다.',confidence='high',kind='configuration')
    for c in lex.calls({'postWebMessage','addWebMessageListener'}):
        # Origin is arg1 of postWebMessage, arg2 of addWebMessageListener.
        i = 1 if c.name == 'postWebMessage' else 2
        if len(c.args) > i and '*' in literals(c.args[i]):
            emit('WV008',c,'웹 메시지 출처/대상 인자에 wildcard를 관찰했습니다.',confidence='high')
    for c in lex.calls({'contains','startsWith','endsWith'}):
        before = lex.clean[max(c.scope[0],c.start-140):c.start]
        if re.search(r'(?i)(?:getHost\s*\(\)|\bhost\b|\burl\b|\buri\b)',before) and c.args and any('.' in s or '://' in s for s in literals(c.args[0])):
            emit('WV009',c,'URI/host 문맥의 부분 문자열 비교입니다. 이것이 실제 보안 검증에 사용되는지 확인하세요.',confidence='low')
    for c in lex.calls({'startActivity','startService','bindService','sendBroadcast','startForegroundService'}):
        if not c.args: continue
        expr, trace = lex.resolve(c.args[0],c.start,c.scope)
        if external_source(expr, source.language):
            sanitized = bool(re.search(r'\bsanitizeBy(?:Throwing|Filtering)\s*\(',expr))
            emit('DL003',c,'외부 입력 기반 Intent 시작 경로입니다. Android 16+ 기본 보호와 명시적 컴포넌트·flags·sanitizer 정책을 검토하세요.',trace=trace,
                 confidence='low' if sanitized else 'medium',severity='low' if sanitized else None,
                 properties={'sanitizer_call_observed':sanitized,'android_16_plus_default_protection':'may_apply; runtime_not_tested'})
    for c in lex.calls({'removeLaunchSecurityProtection'}):
        emit('DL004',c,'Intent launch 보호를 명시적으로 해제하는 API입니다. API 호출 존재만으로 악용 가능성을 확정하지 않습니다.',confidence='high',kind='configuration')
    for c in lex.calls({'getActivity','getActivities','getService','getBroadcast','getForegroundService'}):
        if 'PendingIntent' in c.receiver and any(re.search(r'\bFLAG_MUTABLE\b',a) for a in c.args):
            emit('PM006',c,'Mutable PendingIntent 생성 경로입니다. mutability 필요성과 전달 대상을 검토하세요.',confidence='high')
    # Cryptography: inspect all source filenames, not only shared/pref paths.
    for c in lex.calls({'getInstance'}):
        if not c.args: continue
        expr, trace = lex.resolve(c.args[0],c.start,c.scope)
        values = literals(expr)
        if not values: continue
        value = values[0].upper()
        if c.receiver.endswith('Cipher') and (value == 'AES' or '/ECB' in value or value.split('/')[0] in {'DES','DESEDE','TRIPLEDES','3DES','RC4','ARCFOUR'}):
            emit('DS001',c,'레거시 알고리즘 또는 ECB/기본 모드 사용을 관찰했습니다. 암호 사용 목적을 검토하세요.',trace=trace,confidence='high')
        if c.receiver.endswith('MessageDigest') and value.replace('-','') in {'MD5','SHA1'}:
            emit('DS002',c,'MD5/SHA-1 digest 사용입니다. 비보안 체크섬인지 보안 경계인지 구분하세요.',trace=trace,confidence='high')
    for c in lex.calls({'IvParameterSpec','GCMParameterSpec','SecretKeySpec'}):
        index = 1 if c.name == 'GCMParameterSpec' else 0
        if len(c.args) <= index: continue
        expr, trace = lex.resolve(c.args[index],c.start,c.scope)
        if literals(expr) or re.search(r'new\s+byte\s*\[|byteArrayOf\s*\(|ByteArray\s*\(\s*\d+\s*\)',expr):
            emit('DS008' if c.name == 'SecretKeySpec' else 'DS003',c,
                 '암호 파라미터가 상수 문자열·상수 배열·초기화된 byte 배열에 기반합니다. 실제 키/nonce 수명주기를 확인하세요.',trace=trace)
    for m in re.finditer(r'\bMODE_WORLD_(?:READABLE|WRITEABLE)\b',lex.code):
        findings.append(make('DS004',source,m.start(),m.end(),'레거시 공개 저장 모드입니다. OS별 제한·예외 때문에 실제 공개 저장이 된다고 단정하지 않습니다.',confidence='high',properties=context))
    for c in lex.calls({'putString'}):
        if len(c.args) < 2: continue
        # Require receiver provenance or a lexical SharedPreferences context; not Bundle.putString.
        receiver, _ = lex.resolve(c.receiver,c.start,c.scope)
        pref = bool(re.search(r'(?i)sharedpreferences|getSharedPreferences|PreferenceManager|\bprefs?\b|\bpreferences\b',receiver))
        if not pref and not ('SharedPreferences' in lex.code and re.search(r'(?i)editor',c.receiver)):
            continue
        value, trace = lex.resolve(c.args[1],c.start,c.scope)
        sensitive = SENSITIVE.search(mask(c.args[1],True)) or any(SENSITIVE.search(x) for x in literals(c.args[0]))
        if sensitive:
            encrypted = bool(re.search(r'\b(?:encrypt|encryptToString|doFinal)\s*\(',value))
            emit('DS005',c,'민감한 이름의 값이 preferences 계열 저장 호출에 전달됩니다. 실제 평문 여부·암호화 래퍼는 미검증입니다.',
                 trace=trace,confidence='low' if encrypted else 'medium',severity='low' if encrypted else None,
                 properties={'encryption_call_observed':encrypted})
    for m in re.finditer(r'\b(?:EncryptedSharedPreferences|EncryptedFile|MasterKeys)\b',lex.code):
        if lex.code[max(0,m.start()-80):m.start()].strip().endswith('import androidx.security.crypto.'):
            continue
        findings.append(make('DS007',source,m.start(),m.end(),'Deprecated Security-Crypto API 사용을 관찰했습니다. 취약점이 아닌 마이그레이션 검토 항목입니다.',confidence='high',kind='inventory',properties=context))
        break
    log_names = {'v','d','i','w','e','wtf','println','print','debug','info','warn','error','trace','fatal','log'}
    for c in lex.calls(log_names):
        if not re.search(r'(?i)(?:^|\.)(?:log|logger|timber|out|err)$',c.receiver): continue
        args = c.args[1:] if c.receiver in ('Log','android.util.Log') and len(c.args)>1 else c.args
        sensitive = False
        points = []
        for arg in args:
            expr, trace = lex.resolve(arg,c.start,c.scope)
            code_args = expression_code(arg, source.language) + ' ' + expression_code(expr, source.language)
            if SENSITIVE.search(code_args):
                sensitive = True; points.extend(trace)
        if sensitive:
            emit('LG001',c,'로그 메시지의 실제 인자 또는 보간 표현식에 민감한 이름을 관찰했습니다. 고정 라벨만 있는 메시지는 제외합니다.',trace=sorted(set(points)))
    for c in lex.calls({'setLevel'}):
        if c.args and re.search(r'\b(?:HttpLoggingInterceptor\.)?Level\.BODY\b',c.args[0]):
            emit('LG002',c,'HTTP 본문 로깅 설정입니다. 배포 변형과 데이터 마스킹 정책을 확인하세요.',confidence='high',kind='configuration')
    return findings


def secret_findings(source: Source) -> list[Finding]:
    text = mask(source.text) if source.language in ('java','kotlin') else source.text
    out = []
    covered: list[tuple[int,int]] = []
    patterns = [
        ('HC002',r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'),
        ('HC003',r'\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk_live_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{20,})\b'),
        ('HC004',r'\bAIza[A-Za-z0-9_-]{35}\b'),
        ('HC005',r'\bhttps?://[^\s/:@"\'<>]+:[^\s/@"\'<>]+@[^\s/"\'<>]+'),
    ]
    for id,pattern in patterns:
        for m in re.finditer(pattern,text):
            covered.append(m.span())
            # For plain-text PEM/key files redact the whole evidence, not just quotes.
            f = make(id,source,m.start(),m.end(),'상수 형식의 검토 지점입니다. 값은 마스킹했으며 유효성·서비스 접근·악용 여부는 검사하지 않았습니다.',
                     confidence='high' if id != 'HC005' else 'medium',kind='inventory' if id=='HC004' else 'review')
            for e in f.evidence:
                e.snippet = '[REDACTED: credential-shaped literal; inspect local source]'
            out.append(f)
    named = re.compile(r'(?P<name>[A-Za-z_][\w]*)\s*(?::\s*(?:String\??)\s*)?=\s*(?:"""(?P<triple>[\s\S]*?)"""|"(?P<value>(?:\\.|[^"\\])*)")')
    matches = [(m["name"],m['triple'] if m['triple'] is not None else m['value'],m.start(),m.end()) for m in named.finditer(text)]
    # JSON/properties/assets and Android string resources.
    matches += [(m[1],m[2],m.start(),m.end()) for m in re.finditer(r'"([A-Za-z_][\w]*)"\s*:\s*"([^"\n]+)"',text)]
    if source.language == 'xml':
        matches += [(m[1],m[2],m.start(),m.end()) for m in re.finditer(r'<string\b[^>]*\bname=["\']([^"\']+)["\'][^>]*>([^<]+)</string>',text)]
    if source.language == 'text':
        matches += [(m[1],m[2].strip(),m.start(),m.end()) for m in re.finditer(r'(?m)^([A-Za-z_][\w.]*)\s*=\s*([^\r\n]+)',text)]
    for name,value,start,end in matches:
        if not SENSITIVE.search(name) or len(value)<3: continue
        if re.search(r'(?i)(?:hint|label|title|error|regex|pattern|preference_key|_key_name)$',name): continue
        if re.sub(r'\W','',name).lower() == re.sub(r'\W','',value).lower(): continue
        if value.startswith(('@string/','${','YOUR_','<')): continue
        if any(a <= end and b >= start for a,b in covered): continue
        f = make('HC001',source,start,end,'민감한 식별자에 고정 문자열이 할당되어 있습니다. 필드 이름만으로 실제 자격 증명을 확정하지 않습니다.',confidence='medium',properties={'identifier':name})
        for e in f.evidence: e.snippet = '[REDACTED: named sensitive constant; inspect local source]'
        out.append(f)
    return out


def manifest_findings(source: Source, manifest: Manifest, sources: list[Source]) -> list[Finding]:
    m = manifest
    out = []
    def add(id: str, needle: str, message: str, **kw) -> None:
        start = source.text.find(needle)
        if start<0: start = 0
        props = {'package':m.package,'target_sdk':m.target_sdk,'min_sdk':m.min_sdk,**kw.pop('properties',{})}
        out.append(make(id,source,start,start+len(needle),message,properties=props,**kw))
    if boolean(m.application.get('debuggable')) is True:
        add('PM001','debuggable','debuggable=true입니다. 배포용 병합 Manifest인지 확인하세요.',confidence='high',kind='configuration')
    for permission,level in m.declared_permissions.items():
        protected = 'signature' in level.lower()
        try: protected = protected or (int(level,0)&15) in (2,3,4)
        except ValueError: pass
        if not protected:
            add('PM003',permission,'사용자 정의 권한의 보호 수준이 signature 경계로 확인되지 않습니다.',properties={'permission':permission,'protection_level':level})
    sensitive_permissions = {'READ_SMS','RECEIVE_SMS','SEND_SMS','READ_CONTACTS','WRITE_CONTACTS',
                            'READ_CALL_LOG','RECORD_AUDIO','CAMERA','ACCESS_FINE_LOCATION','ACCESS_BACKGROUND_LOCATION',
                            'MANAGE_EXTERNAL_STORAGE','QUERY_ALL_PACKAGES','REQUEST_INSTALL_PACKAGES','READ_PHONE_STATE'}
    for p in m.permissions:
        name = p.get('name','')
        if name.endswith('.ACCESS_LOCAL_NETWORK'):
            add('PM007',name,'Android 17/API 37 target부터 로컬 네트워크 권한 정책이 적용됩니다. 선언 상태만 기록합니다.',kind='inventory',confidence='high',properties={'permission':name,'api37_target_requirement':bool(m.target_sdk and m.target_sdk>=37)})
        elif name.rsplit('.',1)[-1] in sensitive_permissions:
            add('PM004',name,'민감 권한 선언 정보입니다. 기능상 필요성·runtime grant는 별도 검토입니다.',kind='inventory',confidence='high',properties={'permission':name,'max_sdk':p.get('maxSdkVersion')})
    for c in m.components:
        prop = {'component':c['name'],'component_type':c['type'],'exported':c['effective_exported'],
                'exported_basis':c['exported_basis'],'permission':c.get('permission')}
        if not c['effective_enabled']: continue
        needle = c['name'] if c['name'] in source.text else c['name'].split('.')[-1]
        if c['exported_basis'] == 'missing_required_exported':
            add('PM005',needle,'targetSdk >= 31의 intent-filter 보유 컴포넌트에 exported 명시가 없습니다.',kind='compatibility',confidence='high',properties=prop)
        if c['effective_exported'] is not True: continue
        if c['type'] == 'provider':
            read = c.get('readPermission',c.get('permission'))
            write = c.get('writePermission',c.get('permission'))
            if not read or not write:
                add('SQL003',needle,'exported Provider의 선언상 읽기/쓰기 권한 중 비어 있는 경계가 있습니다. path-permission 및 코드 내부 검증은 별도 검토하세요.',
                    properties={**prop,'authorities':c.get('authorities',''),'read_permission':read,'write_permission':write,
                                'path_permission_count':len(c['path_permissions']),'runtime_access':'not_tested'})
        else:
            launcher = any('android.intent.action.MAIN' in f['actions'] and 'android.intent.category.LAUNCHER' in f['categories'] for f in c['filters'])
            if not c.get('permission') and not launcher:
                add('PM002',needle,'권한이 선언되지 않은 외부 진입점입니다. 정상 사용 목적과 코드 내부 인증·인가를 확인하세요.',properties=prop)
        for f in c['filters']:
            if 'android.intent.action.VIEW' not in f['actions'] or 'android.intent.category.BROWSABLE' not in f['categories']: continue
            schemes = sorted({d['scheme'] for d in f['data'] if d.get('scheme')})
            if any(s not in ('http','https') and not s.startswith('@') for s in schemes):
                add('DL001',needle,'커스텀 스킴의 외부 진입점입니다. URL 호출이나 기기 검증은 수행하지 않았습니다.',kind='inventory',confidence='high',properties={**prop,'schemes':schemes})
            if any(s in ('http','https') for s in schemes) and f['autoVerify'] is not True:
                add('DL002',needle,'웹 링크 필터에 autoVerify=true가 없습니다. 도메인 소유권 검증 상태는 정적 선언만으로 알 수 없습니다.',properties=prop)
    if boolean(m.application.get('allowBackup')) is not False:
        add('DS006','application','백업 가능 설정입니다. 실제 백업에 민감 파일이 포함된다고 단정하지 않습니다.',kind='inventory',confidence='high',
            properties={'fullBackupContent':m.application.get('fullBackupContent'),'dataExtractionRules':m.application.get('dataExtractionRules')})
    nsc = m.application.get('networkSecurityConfig','')
    if boolean(m.application.get('usesCleartextTraffic')) is True and not (nsc and m.min_sdk is not None and m.min_sdk>=24):
        add('WV010','usesCleartextTraffic','Manifest의 평문 트래픽 허용입니다. NSC가 있으면 Android 7/API 24 이상에서는 NSC 정책이 우선합니다.',kind='configuration',confidence='high',properties={'nsc_declared':bool(nsc)})
    if nsc.startswith('@xml/'):
        basename = nsc[5:]+'.xml'
        candidates = [s for s in sources if s.path.endswith('/res/xml/'+basename)]
        for s in candidates:
            try: root = safe_xml(s.text)
            except Exception: continue
            for node in root.iter():
                if node.tag in ('base-config','domain-config') and boolean(node.get('cleartextTrafficPermitted')) is True:
                    offset = s.text.find('cleartextTrafficPermitted')
                    out.append(make('WV010',s,max(0,offset),max(0,offset)+25,'참조된 Network Security Config에 명시적인 평문 허용이 있습니다. 도메인 범위와 실제 통신 경로를 검토하세요.',kind='configuration',confidence='high',properties={'package':m.package,'configuration_scope':node.tag}))
                    break
    return out


def smali_findings(source: Source) -> list[Finding]:
    """Evidence inventory only; no register/branch flow claims."""
    out = []
    patterns = [
        ('DL004',r'Landroid/content/Intent;->removeLaunchSecurityProtection\('),
        ('WV002',r'Landroid/webkit/WebView;->addJavascriptInterface\('),
    ]
    text = re.sub(r'(?m)^\s*#.*$', '',source.text)
    for rule_id,pattern in patterns:
        for m in re.finditer(pattern,text):
            out.append(make(rule_id,source,m.start(),m.end(),'Smali의 API 참조 정보입니다. 레지스터 값·실행 조건은 분석하지 않았습니다.',confidence='low',severity='info',kind='inventory',properties={'analysis':'smali_api_inventory_only'}))
    return out
