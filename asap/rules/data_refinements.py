"""Defensive, bounded configuration refinements; no network or runtime checks.

These refinements preserve rule identifiers and distinguish observations from
proof. An encryption/redaction function name alone never establishes safety.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from ..model import Finding, Manifest, Source
from ..manifest import component_context
from ..text import Lexical, literals, redact
from ..xmlutil import boolean
from .analyze import make

FIREBASE = 'https://firebase.google.com/docs/projects/api-keys'
GEMINI = 'https://ai.google.dev/gemini-api/docs/api-key'
PERMISSIONS = 'https://developer.android.com/guide/topics/manifest/uses-permission-element'
BACKUP = 'https://developer.android.com/identity/data/autobackup'
KEYSTORE = 'https://developer.android.com/privacy-and-security/keystore'
LOGGING = 'https://raw.githubusercontent.com/square/okhttp/master/okhttp-logging-interceptor/README.md'


def _reference(finding: Finding, *urls: str) -> None:
    finding.references = list(dict.fromkeys([*finding.references, *urls]))


def _manifest_for(source: Source, manifests: list[Manifest]) -> Manifest | None:
    return next((m for m in manifests if m.path == source.path), None)


def _google_context(source: Source) -> list[str]:
    """File-local service hints do not associate a particular key with an API."""
    result = []
    if PurePosixPath(source.path).name == 'google-services.json' or re.search(
            r'\b(?:FirebaseOptions|FirebaseApp|firebase_url|mobilesdk_app_id)\b', source.text):
        result.append('firebase_markers_in_same_file')
    if re.search(r'generativelanguage\.googleapis\.com|\b(?:GenerativeModel|GEMINI_API_KEY)\b', source.text):
        result.append('gemini_markers_in_same_file')
    return result or ['service_not_identified']


def _level(raw: str) -> str | None:
    match = re.fullmatch(r'\s*(?:okhttp3\.logging\.)?(?:HttpLoggingInterceptor\.)?Level\.(BODY|HEADERS)\s*', raw)
    return match[1] if match else None


def _direct_logging_constructor(expr: str, language: str) -> bool:
    """An interceptor used as a nested argument does not type its outer object."""
    expr = expr.strip()
    for _ in range(8):
        parsed = Lexical(expr, language)
        if expr.startswith('(') and parsed.pairs.get(0) == len(expr) - 1:
            expr = expr[1:-1].strip()
        else:
            break
    match = re.match(r'^(?:new\s+)?(?:okhttp3\.logging\.)?HttpLoggingInterceptor\s*\(', expr)
    return bool(match and Lexical(expr, language).pairs.get(match.end() - 1) == len(expr) - 1)


def _logging_type(lex: Lexical, receiver: str, before: int, scope: tuple[int, int, str]) -> bool:
    """Current-method declaration/outer constructor hints, not global type proof.

    Field provenance and repeated local declarations remain unknown. In
    particular, a declaration in an earlier method cannot type this receiver.
    """
    if _direct_logging_constructor(receiver, lex.language):
        return True
    if not re.fullmatch(r'[A-Za-z_$][\w$]*', receiver):
        return False
    name = re.escape(receiver)
    current = lex.code[scope[0]:before]
    java = r'\b([A-Za-z_$][\w.$<>?\[\]]*)\s+' + name + r'\s*(?=[=;,\n)])'
    kotlin = r'\b(?:val|var)\s+' + name + r'\s*:\s*([A-Za-z_$][\w.$<>?\[\]]*)'
    declarations = re.findall(java, current) + re.findall(kotlin, current)
    if len(declarations) > 1:
        return False
    known_types = {'HttpLoggingInterceptor', 'okhttp3.logging.HttpLoggingInterceptor'}
    if declarations and declarations[0].rstrip('?') not in known_types | {'val', 'var'}:
        return False
    resolved, _ = lex.resolve(receiver, before, scope)
    if _direct_logging_constructor(resolved, lex.language):
        return True
    return bool(declarations and declarations[0].rstrip('?') in known_types)


def _logging_observations(source: Source, lex: Lexical, manifests: list[Manifest]) -> list[Finding]:
    out: list[Finding] = []
    configurations = []
    for call in lex.calls({'setLevel'}):
        if call.args and (level := _level(call.args[0])):
            configurations.append((call.start, call.end, call.receiver, call.scope, level, 'setter'))
    if source.language == 'kotlin':
        # A bounded, explicit receiver assignment. apply/also receivers and aliases
        # are deliberately not guessed here.
        pattern = r'\b((?:this\.)?[A-Za-z_$][\w$]*)\s*\.\s*level\s*=\s*((?:(?:okhttp3\.logging\.)?HttpLoggingInterceptor\.)?Level\.(?:BODY|HEADERS))\b'
        for match in re.finditer(pattern, lex.code):
            configurations.append((match.start(), match.end(), match[1], lex.scope(match.start()), _level(match[2]), 'kotlin_property'))
    redactions = lex.calls({'redactHeader'})
    for start, end, receiver, scope, level, syntax in configurations:
        known_receiver = _logging_type(lex, receiver, start, scope)
        # Fully qualified enum is useful evidence even when DI hides receiver type.
        raw = lex.clean[start:end]
        if not known_receiver and 'HttpLoggingInterceptor.Level.' not in raw:
            continue
        # Observe the same lexical receiver/method only, in either configuration
        # order. This is not alias, branch, or runtime object identity proof.
        headers = sorted({value.lower() for call in redactions
                          if call.receiver == receiver and call.scope == scope
                          and len(call.args) == 1
                          for value in literals(call.args[0])
                          if value.lower() in {'authorization', 'cookie', 'set-cookie', 'proxy-authorization'}})
        message = ('HTTP 본문·헤더 로깅 설정입니다.' if level == 'BODY' else 'HTTP 헤더 로깅 설정입니다.')
        message += ' 동일 메서드·receiver의 헤더 마스킹은 설정 관찰이며, 본문 보호나 실행 순서·배포 적용을 보장하지 않습니다.'
        finding = make('LG002', source, start, end, message, kind='configuration', confidence='high' if known_receiver else 'medium', properties={
            **component_context(source, manifests),
            'method': scope[2], 'receiver': redact(receiver, source.language), 'logging_level': level,
            'logging_syntax': syntax, 'http_logging_receiver_observed': known_receiver,
            'sensitive_headers_redaction_observed': headers,
            'redaction_effectiveness': 'not_verified', 'body_redaction_verified': False,
            'release_execution': 'not_verified',
        })
        finding.title = 'HTTP 본문·헤더 로깅 설정' if level == 'BODY' else 'HTTP 헤더 로깅 설정'
        finding.remediation = ('배포 빌드에서는 필요한 최소 로그 수준을 사용하세요. Authorization, Cookie 등 민감 헤더를 제거하고 '
                               'redactHeader는 본문 값을 보호하지 않으므로 요청·응답 본문과 URL의 민감 데이터도 별도로 제외하세요. '
                               '동일 이름의 receiver라도 재할당·분기·커스텀 Logger 설정은 별도 확인이 필요합니다.')
        _reference(finding, LOGGING)
        out.append(finding)
    return out


def _permission_context(finding: Finding, manifest: Manifest | None) -> None:
    _reference(finding, PERMISSIONS)
    finding.properties['runtime_grant'] = 'not_verified'
    finding.properties['target_sdk_is_runtime_sdk'] = False
    maximum = finding.properties.get('max_sdk')
    if maximum is None and manifest:
        matches = [p for p in manifest.permissions if p.get('name') == finding.properties.get('permission')]
        if len(matches) == 1:
            maximum = matches[0].get('maxSdkVersion')
        elif len({p.get('maxSdkVersion') for p in matches}) > 1:
            maximum = '[ambiguous_manifest_declarations]'
    raw_maximum = maximum
    maximum_state = 'absent' if raw_maximum is None else 'unresolved'
    maximum = None
    if raw_maximum is not None:
        literal = str(raw_maximum).strip()
        if len(literal) <= 32 and re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|[0-9]+)', literal):
            candidate = int(literal, 16 if literal.lower().startswith('0x') else 10)
            if candidate <= 0x7fffffff:
                maximum = candidate
                maximum_state = 'literal'
    if manifest:
        finding.properties['supported_min_sdk'] = manifest.min_sdk
        finding.properties['target_sdk'] = manifest.target_sdk
    finding.properties['permission_max_sdk'] = maximum
    finding.properties['permission_max_sdk_state'] = maximum_state
    finding.properties['max_sdk_attribute_supported_from_api'] = 19
    finding.properties['permission_runtime_applicability'] = (
        'no_supported_runtime' if maximum is not None and manifest and manifest.min_sdk is not None and manifest.min_sdk >= 19 and maximum < manifest.min_sdk
        else 'legacy_runtime_support_requires_review' if maximum is not None and (not manifest or manifest.min_sdk is None or manifest.min_sdk < 19)
        else 'runtime_api_at_most_max_sdk' if maximum is not None
        else 'max_sdk_unresolved_requires_review' if maximum_state == 'unresolved'
        else 'not_bounded_by_max_sdk')
    finding.message += ' maxSdkVersion은 실행 기기의 API 상한이며 targetSdkVersion과 비교해 권한을 허용·거부했다고 판단하지 않습니다.'


def _backup_context(source: Source, out: list[Finding], manifest: Manifest | None) -> None:
    if manifest is None:
        return
    existing = [f for f in out if f.rule_id == 'DS006']
    # allowBackup=false is not a universal D2D opt-out for target 31+.
    if not existing and boolean(manifest.application.get('allowBackup')) is False and (
            manifest.target_sdk is None or manifest.target_sdk >= 31):
        start = max(0, source.text.find('allowBackup'))
        existing = [make('DS006', source, start, start + len('allowBackup'),
                         'allowBackup=false 선언입니다. target API 31+에서는 일부 OEM의 기기 간 전송까지 차단된다고 단정할 수 없어 별도 정책 검토가 필요합니다.',
                         kind='inventory', severity='info', confidence='high', properties={
                             'package': manifest.package, 'target_sdk': manifest.target_sdk,
                             'min_sdk': manifest.min_sdk,
                         })]
        out.extend(existing)
    for finding in existing:
        finding.properties.update({
            'allow_backup': boolean(manifest.application.get('allowBackup')),
            'fullBackupContent': manifest.application.get('fullBackupContent'),
            'dataExtractionRules': manifest.application.get('dataExtractionRules'),
            'modern_rules_applicable': manifest.target_sdk >= 31 if manifest.target_sdk is not None else None,
            'backup_rule_contents': 'not_evaluated_by_this_rule',
            'device_transfer_outcome': 'oem_and_runtime_dependent',
        })
        finding.remediation = ('백업 필요성과 민감 데이터별 제외 정책을 분리하세요. API 31+ target의 Android 12+ 기기에서는 '
                               'dataExtractionRules의 cloud-backup과 device-transfer를 각각 검토하고, 이전 OS·target에 필요한 '
                               'fullBackupContent도 관리하세요. allowBackup=false나 XML 참조의 존재만으로 전체 전송 차단을 확인하지 마세요.')
        _reference(finding, BACKUP)


def refine(source: Source, findings: list[Finding], manifests: list[Manifest]) -> list[Finding]:
    """Refine this source's findings without exposing secrets or external effects."""
    out: list[Finding] = []
    manifest = _manifest_for(source, manifests)
    lex = Lexical(source.text, source.language) if source.language in {'java', 'kotlin'} else None
    for finding in findings:
        if finding.rule_id in {'PM004', 'PM007'}:
            # A custom com.example.CAMERA permission is not Android CAMERA.
            if finding.properties.get('permission', '').rsplit('.', 1)[0] != 'android.permission':
                continue
            _permission_context(finding, manifest)
        elif finding.rule_id == 'HC004':
            finding.properties.update({'service_context': _google_context(source),
                                       'key_to_service_association': 'not_verified',
                                       'api_restrictions': 'not_verified', 'credential_validity': 'not_tested'})
            finding.message = ('Google API 키 형식의 상수입니다. 같은 파일의 서비스 표시는 키의 실제 API 권한을 증명하지 않습니다. '
                               'Firebase 전용 제한 키와 Gemini Developer API용 비밀 키를 구분하여 검토하세요.')
            finding.remediation = ('소유자가 API별 제한과 앱 제한을 확인하세요. Firebase 키는 Firebase 전용으로 제한하고 '
                                   'Security Rules·App Check·IAM을 따로 검토하세요. Gemini 키는 앱에 포함하지 말고 서버 측에서 관리하세요. '
                                   '파일명·키 접두사만으로 공개 가능하거나 유효한 키라고 결론내리지 마세요.')
            _reference(finding, FIREBASE, GEMINI)
        elif finding.rule_id == 'DS005':
            finding.properties['encryption_effectiveness'] = 'not_verified'
            finding.properties['storage_content'] = 'requires_review'
            if finding.properties.get('encryption_call_observed'):
                # An arbitrary encrypt() wrapper could return plaintext or use a
                # fixed key. Its name is not a defensible severity reduction.
                finding.severity = 'medium'
                finding.confidence = 'medium'
                finding.message = ('민감한 값의 preferences 저장과 암호화 이름의 호출을 관찰했습니다. '
                                   '함수 이름만으로 평문 배제·키 관리·인증된 암호화를 입증할 수 없어 검토 수준을 유지합니다.')
            _reference(finding, KEYSTORE)
        if finding.rule_id == 'LG002' and lex is not None:
            continue  # Replace with type/context-aware setter and property results.
        out.append(finding)
    _backup_context(source, out, manifest)
    if lex is not None:
        out.extend(_logging_observations(source, lex, manifests))
    return out
