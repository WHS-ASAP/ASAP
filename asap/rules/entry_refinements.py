"""API argument and review-context corrections, never a safety proof.

This module deliberately retains the engine's bounded lexical analysis model.
It performs no URL requests, device operations, or whole-program inference.
"""
from __future__ import annotations

import re

from ..manifest import component_context
from ..model import Finding, Manifest, Source
from ..text import Lexical, dynamic_string, external_source, mask, redact, split_args
from .analyze import make

SQLITE_REFERENCE = 'https://developer.android.com/reference/android/database/sqlite/SQLiteDatabase'
WEBKIT_REFERENCE = 'https://developer.android.com/reference/androidx/webkit/WebViewCompat'
SANITIZER_REFERENCE = 'https://developer.android.com/reference/androidx/core/content/IntentSanitizer'
LINK_REFERENCE = 'https://developer.android.com/training/app-links/add-applinks'


def _reference(finding: Finding, url: str) -> None:
    if url not in finding.references:
        finding.references.append(url)


def _properties(context: dict, call) -> dict:
    return {**context, 'method': call.scope[2], 'receiver': redact(call.receiver),
            'api_name': call.name, 'api_semantics': 'lexical_signature; receiver_type_not_proven'}


def _declares_database(lex: Lexical, receiver: str, before: int) -> bool:
    """Only a declaration hint; never resolve class inheritance or aliases."""
    if not re.fullmatch(r'[A-Za-z_$][\w$]*', receiver):
        return False
    name = re.escape(receiver)
    scope = lex.scope(before)
    return bool(re.search(r'\b(?:android\.database\.sqlite\.)?SQLiteDatabase\s+' + name + r'\b|\b' + name + r'\s*:\s*(?:android\.database\.sqlite\.)?SQLiteDatabase\b', lex.code[scope[0]:before]))


def _sql_findings(source: Source, lex: Lexical, context: dict) -> list[Finding]:
    out = []
    names = {'rawQuery', 'execSQL', 'compileStatement', 'rawQueryWithFactory', 'SimpleSQLiteQuery', 'query'}
    for call in lex.calls(names):
        index = 1 if call.name == 'rawQueryWithFactory' else 0
        signature = call.name
        if call.name == 'query':
            if len(call.args) < 7 or not re.search(r'\bSQLite(?:Database|QueryBuilder)\b', lex.code):
                continue
            # SQLiteDatabase.query has 7/8-argument ordinary and 9/10-argument
            # distinct overloads. SQLiteQueryBuilder has a different 9-arg API.
            distinct = len(call.args) in (9, 10) and (
                call.args[0].strip() in {'true', 'false'} or
                _declares_database(lex, call.receiver, call.start))
            index = 3 if distinct else 2
            signature = 'query_with_distinct' if distinct else 'query_selection'
        if len(call.args) <= index:
            continue
        expr, trace = lex.resolve(call.args[index], call.start, call.scope)
        if call.args[index].strip() in {'null', 'None'} or not dynamic_string(expr, source.language):
            continue
        external = external_source(expr, source.language)
        if call.name == 'compileStatement' and not external and not re.search(
                r'\+|\$\{|\$[A-Za-z_]|\.format\s*\(|StringBuilder|\.append\s*\(', expr):
            continue
        bind_index = index + 1
        binding = call.name != 'compileStatement' and len(call.args) > bind_index and call.args[bind_index].strip() not in {'null', 'None'}
        props = {**_properties(context, call), 'sql_argument_index': index,
                 'sql_api_signature': signature, 'binding_argument_present': binding,
                 'binding_safety': 'not_proven; bindings_do_not_protect_concatenated_sql'}
        message = ('동일 메서드의 표현식 연결에서 외부 입력이 동적 SQL 인자에 포함됩니다. 실제 도달성과 권한 경계는 미검증입니다.' if external else
                   'SQL 구문 인자가 상수로 확인되지 않았습니다. 출처·매개변수화 여부를 검토하세요.')
        if binding:
            message += ' 별도의 bind 인자가 있어도 SQL 구문에 직접 연결한 값까지 보호하지는 않습니다.'
        finding = make('SQL001' if external else 'SQL002', source, call.start, call.end,
                       message, trace=trace, confidence='medium' if external else 'low', properties=props)
        _reference(finding, SQLITE_REFERENCE)
        out.append(finding)
    return out


def _strip_parens(expr: str, language: str) -> str:
    expr = expr.strip()
    for _ in range(8):
        parsed = Lexical(expr, language)
        if expr.startswith('(') and parsed.pairs.get(0) == len(expr) - 1:
            expr = expr[1:-1].strip()
        else:
            break
    return expr


def _whole_star_string(expr: str, language: str) -> bool:
    expr = _strip_parens(expr, language)
    # A token inside a concatenation is not the value of that expression.
    # Leave arbitrary string evaluation unknown instead of widening its origin.
    return expr in {'"*"', '"""*"""'}


def _all_origins_literal(expr: str, role: str, language: str, depth: int = 0) -> bool:
    """Recognize complete '*' values in a few explicit URI/collection forms.

    A nested '*' argument to an unknown transform or a piece of a concatenated
    origin is not evidence that the result accepts all origins.
    """
    if depth > 6:
        return False
    expr = _strip_parens(expr, language)
    if _whole_star_string(expr, language):
        return True
    match = re.match(r'^(?:new\s+)?((?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*)(?:<[^(){};]*>)?\s*\(', expr)
    if not match:
        return False
    opening = match.end() - 1
    closing = Lexical(expr, language).pairs.get(opening)
    if closing != len(expr) - 1:
        return False
    arguments = split_args(expr[opening + 1:closing])
    name = match[1]
    if role == 'target_origin':
        return name in {'Uri.parse', 'android.net.Uri.parse'} and len(arguments) == 1 and _whole_star_string(arguments[0], language)
    factories = {'Collections.singleton', 'java.util.Collections.singleton',
                 'Collections.singletonList', 'java.util.Collections.singletonList',
                 'Set.of', 'java.util.Set.of', 'Arrays.asList', 'java.util.Arrays.asList',
                 'setOf', 'mutableSetOf', 'hashSetOf', 'linkedSetOf', 'listOf'}
    wrappers = {'HashSet', 'java.util.HashSet', 'LinkedHashSet', 'java.util.LinkedHashSet'}
    if name in factories:
        return any(_whole_star_string(argument, language) for argument in arguments)
    if name in wrappers and len(arguments) == 1:
        return _all_origins_literal(arguments[0], role, language, depth + 1)
    return False


def _message_findings(source: Source, lex: Lexical, context: dict) -> list[Finding]:
    out = []
    for call in lex.calls({'postWebMessage', 'addWebMessageListener'}):
        if call.name == 'addWebMessageListener':
            if len(call.args) not in (4, 5):
                continue
            index = 2
            role = 'allowed_origin_rules'
        elif len(call.args) == 3 and (
                call.receiver in {'WebViewCompat', 'androidx.webkit.WebViewCompat'} or
                (not call.receiver and re.search(r'\bimport\s+(?:static\s+)?androidx\.webkit\.WebViewCompat\.(?:postWebMessage|\*)', lex.code))):
            index = 2
            role = 'target_origin'
        elif len(call.args) == 2:
            index = 1
            role = 'target_origin'
        else:
            continue
        # Only origin arguments are considered. A message body containing '*'
        # has no bearing on origin restrictions.
        expr, trace = lex.resolve(call.args[index], call.start, call.scope)
        if not _all_origins_literal(expr, role, source.language):
            continue
        finding = make('WV008', source, call.start, call.end,
                       '웹 메시지의 출처/대상 인자에서 전체 출처 wildcard를 관찰했습니다. 메시지 내용·허용된 프레임·런타임 지원을 검토하세요.',
                       confidence='high', trace=trace,
                       properties={**_properties(context, call), 'origin_argument_index': index,
                                   'origin_argument_role': role, 'origin_scope': 'all_origins_literal',
                                   'runtime_feature_support': 'not_tested'})
        _reference(finding, WEBKIT_REFERENCE)
        out.append(finding)
    return out


def _direct_explicit_intent(expr: str, language: str) -> bool:
    """Observe a fresh fixed-class Intent with only known component-preserving
    fluent setters. Data validation and later object mutation remain unknown.
    """
    expr = _strip_parens(expr, language)
    if not re.match(r'^(?:new\s+)?(?:android\.content\.)?Intent\s*\(', expr):
        return False
    parsed = Lexical(expr, language)
    calls = parsed.calls({'Intent'})
    if not calls or len(calls[0].args) != 2:
        return False
    constructor = calls[0]
    if not re.fullmatch(r'[\w$.]+(?:\.class|::class\.java)', constructor.args[1].strip()):
        return False
    tail = expr[constructor.end:]
    allowed = {'putExtra', 'putExtras', 'setData', 'setType', 'setDataAndType', 'setAction', 'addFlags', 'setFlags', 'setPackage'}
    # Walk only the outer chain. Calls inside extra values cannot alter the
    # constructed component, while arbitrary outer methods are not trusted.
    position = 0
    clean = mask(tail, strings=True)
    pairs = Lexical(tail, language).pairs
    while clean[position:].strip():
        match = re.match(r'\s*\.\s*([A-Za-z_]\w*)\s*\(', clean[position:])
        if not match or match[1] not in allowed:
            return False
        opening = position + match.end() - 1
        if opening not in pairs:
            return False
        position = pairs[opening] + 1
    return True


def _refine_intents(source: Source, findings: list[Finding], lex: Lexical) -> None:
    calls = lex.calls({'startActivity', 'startService', 'bindService', 'sendBroadcast', 'startForegroundService'})
    # Match observations in emission order; source lines may contain >1 call.
    available = list(calls)
    for finding in findings:
        if finding.rule_id != 'DL003' or not finding.evidence or finding.evidence[-1].path != source.path:
            continue
        observation = finding.evidence[-1]
        candidates = [c for c in available if lex.line(c.start) == observation.line and
                      redact(c.receiver) == finding.properties.get('receiver') and c.args and
                      external_source(lex.resolve(c.args[0], c.start, c.scope)[0], source.language)]
        if not candidates:
            continue
        call = candidates[0]
        available.remove(call)
        expr, _ = lex.resolve(call.args[0], call.start, call.scope)
        # Local value resolution does not model later mutations of an Intent
        # object. Only a constructor in the launch argument itself establishes
        # this narrow observation; an alias must not receive the downgrade.
        fixed = _direct_explicit_intent(call.args[0], source.language)
        sanitizer = bool(re.search(r'\bsanitizeBy(?:Throwing|Filtering)\s*\(', mask(expr, strings=True)))
        finding.properties.update({'intent_construction': 'fresh_fixed_class_with_external_data' if fixed else 'external_intent_or_unresolved_construction',
                                   'sanitizer_return_in_expression': sanitizer,
                                   'sanitizer_policy': 'not_verified', 'runtime_os_version': 'not_observed',
                                   'authorization': 'not_verified'})
        if fixed:
            finding.severity = 'low'
            finding.confidence = 'low'
            finding.message = '고정 클래스의 새 Intent에 외부 데이터를 추가하는 표현식입니다. 대상 리디렉션은 확인되지 않았습니다. 수신 컴포넌트의 데이터 검증·인가 및 이후 변이를 검토하세요.'
        elif sanitizer:
            finding.message += ' sanitizer 반환값의 표현식 연결만 관찰했으며 AndroidX 타입·허용 정책·분기별 적용은 검증하지 않았습니다.'
        _reference(finding, SANITIZER_REFERENCE)


def _manifest_context(source: Source, findings: list[Finding], manifests: list[Manifest]) -> None:
    for finding in findings:
        if finding.rule_id not in {'DL001', 'DL002', 'SQL003'} or not finding.evidence or finding.evidence[-1].path != source.path:
            continue
        matches = [(manifest, component) for manifest in manifests if manifest.path == source.path
                   for component in manifest.components if component['name'] == finding.properties.get('component')]
        if len(matches) != 1:
            continue
        manifest, component = matches[0]
        if finding.rule_id == 'SQL003':
            finding.properties.update({'uri_grant_policy_declared': component.get('grantUriPermissions', 'false'),
                                       'uri_grant_path_count': len(component.get('grant_uri_permissions', [])),
                                       'provider_boundary': 'declaration_only; runtime_caller_checks_not_tested'})
            continue
        filters = [f for f in component['filters'] if 'android.intent.action.VIEW' in f['actions'] and
                   'android.intent.category.BROWSABLE' in f['categories']]
        finding.properties.update({'link_filter_count': len(filters),
                                   'link_filter_context': [{'default_category': 'android.intent.category.DEFAULT' in f['categories'],
                                                            'auto_verify_declared': f['autoVerify'],
                                                            'data_element_count': len(f['data']),
                                                            'scheme_count': len({d['scheme'] for d in f['data'] if d.get('scheme')}),
                                                            'host_count': len({d['host'] for d in f['data'] if d.get('host')})} for f in filters],
                                   'domain_verification': 'not_tested',
                                   'dynamic_app_links': 'server_policy_not_available; API35_plus_Google_services_required',
                                   'filter_data_semantics': 'data_elements_combined_within_each_filter'})
        _reference(finding, LINK_REFERENCE)


def refine(source: Source, findings: list[Finding], manifests: list[Manifest]) -> list[Finding]:
    """Return findings with conservative argument/context corrections.

    Pass the findings for one source before fingerprinting/suppression. Findings
    from another file are preserved, including referenced NSC observations.
    """
    out = list(findings)
    if source.language in {'java', 'kotlin'}:
        lex = Lexical(source.text, source.language)
        context = component_context(source, manifests)
        replaced = {'SQL001', 'SQL002', 'WV008'}
        out = [f for f in out if not (f.rule_id in replaced and f.evidence and f.evidence[-1].path == source.path)]
        out.extend(_sql_findings(source, lex, context))
        out.extend(_message_findings(source, lex, context))
        _refine_intents(source, out, lex)
        for finding in out:
            if finding.rule_id == 'WV007' and finding.evidence and finding.evidence[-1].path == source.path:
                finding.properties['file_access_default'] = 'targetSdk<=29:true; targetSdk>=30:false; explicit_true_observed'
                _reference(finding, 'https://developer.android.com/reference/android/webkit/WebSettings')
    _manifest_context(source, out, manifests)
    return out
