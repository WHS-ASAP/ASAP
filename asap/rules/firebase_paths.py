"""Bounded offline inventory of Realtime Database locations present in sources.

This module reads source strings and local SDK expressions only. It neither
contacts a database nor invents child names. Unknown values stay symbolic.
"""
from __future__ import annotations

from dataclasses import dataclass
import html
import json
import re
from urllib.parse import unquote, urlsplit

from ..model import Finding, Source
from ..text import Lexical, SENSITIVE, STRING, blank, mask
from .analyze import make

MAX_PATHS = 512
MAX_CANDIDATES = 2048
MAX_EXPRESSION = 16384
HOST = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.firebaseio\.com|'
                  r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.'
                  r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.firebasedatabase\.app)\Z', re.I)
URL = re.compile(r'https?://[^\s<>"\'\\]+', re.I)
DYNAMIC = '{dynamic}'


@dataclass(frozen=True)
class _Reference:
    kind: str
    host: str = ''
    path: str = '/'
    unresolved: bool = False


def _literal(expression: str) -> str | None:
    expression = expression.strip()
    if not STRING.fullmatch(expression):
        return None
    if expression.startswith('"""'):
        return expression[3:-3]
    if expression.startswith('"'):
        try:
            value = json.loads(expression)
            return value if isinstance(value, str) else None
        except (ValueError, RecursionError):
            pass
    # Java/Kotlin permit escapes not recognised by JSON. Decode only those
    # relevant to path literals; never evaluate a source expression.
    return re.sub(r'\\([\\/"\'])', r'\1', expression[1:-1])


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    for _ in range(8):
        if expression.endswith('!!'):
            expression = expression[:-2].strip()
        parsed = Lexical(expression)
        if expression.startswith('(') and parsed.pairs.get(0) == len(expression) - 1:
            expression = expression[1:-1].strip()
        else:
            break
    return expression


def _safe_segment(segment: str) -> str:
    if segment == DYNAMIC:
        return segment
    if (len(segment) > 96 or any(ord(c) < 32 or ord(c) == 127 for c in segment)
            or re.search(r'[@?#\[\]\\]', segment)
            or re.search(r'(?i)^(?:AIza|ghp_|github_pat_|sk_live_|xox[baprs]-|eyJ)', segment)
            or re.fullmatch(r'(?i)[0-9a-f]{16,}', segment)
            or re.fullmatch(r'(?i)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', segment)
            or re.fullmatch(r'\d{8,}', segment)
            or (len(segment) >= 28 and re.search(r'[A-Za-z]', segment) and re.search(r'\d', segment))):
        return DYNAMIC
    # A Kotlin template may occur inside an otherwise static segment.
    segment = re.sub(r'\$(?:\{[^}]*\}|[A-Za-z_$][\w$]*)', DYNAMIC, segment)
    if '$' in segment or segment in {'.', '..'}:
        return DYNAMIC
    return segment


def _path(value: str) -> tuple[str, bool]:
    if len(value) > 4096:
        return '/' + DYNAMIC, True
    segments = [_safe_segment(segment) for segment in value.split('/') if segment]
    if len(segments) > 64:
        segments = segments[:63] + [DYNAMIC]
    path = '/' + '/'.join(segments)
    return path, DYNAMIC in path


def _endpoint(value: str) -> _Reference | None:
    """Return host/path only; credentials, query parameters and fragments vanish."""
    value = html.unescape(value).strip()
    if len(value) > 8192 or '\\' in value or any(ord(c) < 32 for c in value):
        return None
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or '').lower()
    except ValueError:
        return None
    if parsed.scheme.lower() not in {'https', 'http'} or not HOST.fullmatch(host):
        return None
    raw_path = unquote(parsed.path)
    if raw_path.endswith('.json'):
        raw_path = raw_path[:-5]
    path, unresolved = _path(raw_path)
    return _Reference('reference', host, path, unresolved)


class _SDK:
    def __init__(self, source: Source):
        self.lex = Lexical(source.text, source.language)
        self.language = source.language
        self.imports = set(re.findall(r'(?m)^\s*import\s+(?:static\s+)?([\w.*]+)', self.lex.code))

    def _firebase_type(self, name: str) -> bool:
        if name == 'com.google.firebase.database.FirebaseDatabase':
            return True
        return name == 'FirebaseDatabase' and bool(self.imports & {
            'com.google.firebase.database.FirebaseDatabase', 'com.google.firebase.database.*'})

    def _local(self, name: str, before: int, scope: tuple[int, int, str]):
        return next((item for item in reversed(self.lex.assignments(before, scope)) if item[0] == name), None)

    def value(self, expression: str, before: int, scope: tuple[int, int, str], depth: int = 0) -> str:
        if depth > 8 or len(expression) > MAX_EXPRESSION:
            return DYNAMIC
        expression = _unwrap(expression)
        if (literal := _literal(expression)) is not None:
            return literal
        if re.fullmatch(r'[A-Za-z_$][\w$]*', expression):
            if SENSITIVE.search(expression):
                return DYNAMIC
            if item := self._local(expression, before, scope):
                return self.value(item[1], item[2], scope, depth + 1)
            return DYNAMIC
        # Concatenations retain the known prefix/suffix around unknown values.
        code = mask(expression, strings=True)
        parts, start, level = [], 0, 0
        for i, ch in enumerate(code):
            if ch in '([{':
                level += 1
            elif ch in ')]}':
                level -= 1
            elif ch == '+' and level == 0:
                parts.append(expression[start:i])
                start = i + 1
        if parts:
            parts.append(expression[start:])
            return ''.join(self.value(part, before, scope, depth + 1) for part in parts)[:4097]
        return DYNAMIC

    def _declared(self, name: str, before: int, scope: tuple[int, int, str]) -> _Reference | None:
        if not re.fullmatch(r'[A-Za-z_$][\w$]*', name):
            return None
        current = self.lex.code[scope[0]:before]
        variable = re.escape(name)
        types = re.findall(r'\b([\w.$<>?]+)\s+' + variable + r'\s*(?=[=;,\n)])', current)
        types += re.findall(r'\b(?:val|var)\s+' + variable + r'\s*:\s*([\w.$<>?]+)', current)
        types = [item for item in types if item not in {'val', 'var'}]
        if len(types) != 1:
            return None
        declared = types[0].rstrip('?')
        if self._firebase_type(declared):
            return _Reference('database')
        if (declared == 'com.google.firebase.database.DatabaseReference' or
                declared == 'DatabaseReference' and bool(self.imports & {
                    'com.google.firebase.database.DatabaseReference', 'com.google.firebase.database.*'})):
            return _Reference('reference', path='/' + DYNAMIC, unresolved=True)
        return None

    def reference(self, expression: str, before: int, scope: tuple[int, int, str], depth: int = 0) -> _Reference | None:
        if depth > 80 or len(expression) > MAX_EXPRESSION:
            return None
        expression = _unwrap(expression)
        if self._firebase_type(expression):
            return _Reference('class')
        if re.fullmatch(r'[A-Za-z_$][\w$]*', expression):
            if item := self._local(expression, before, scope):
                resolved = self.reference(item[1], item[2], scope, depth + 1)
                if resolved:
                    return resolved
                # An explicitly typed factory result carries an unknown prefix.
                # Reassignment to another identifier does not inherit that type.
                if Lexical(item[1], self.language).calls({'getReference', 'getDatabase', 'reference', 'database'}):
                    return self._declared(expression, before, scope)
                return None
            return self._declared(expression, before, scope)
        if expression.endswith('.reference'):
            base = self.reference(expression[:-10], before, scope, depth + 1)
            if base and base.kind == 'database':
                return _Reference('reference', base.host)
        if expression == 'Firebase.database' and self.imports & {'com.google.firebase.database.database', 'com.google.firebase.database.ktx.database'}:
            if self.imports & {'com.google.firebase.Firebase', 'com.google.firebase.ktx.Firebase'}:
                return _Reference('database')
        parsed = Lexical(expression, self.language)
        calls = parsed.calls({'getInstance', 'getReference', 'getReferenceFromUrl', 'child'})
        call = next((item for item in reversed(calls) if item.end == len(expression)), None)
        if not call or not call.receiver:
            return None
        base = self.reference(call.receiver, before, scope, depth + 1)
        if not base:
            return None
        if call.name == 'getInstance' and base.kind == 'class':
            # Overloads may contain FirebaseApp before an explicit database URL.
            endpoints = [_endpoint(self.value(arg, before, scope)) for arg in call.args]
            endpoint = next((item for item in endpoints if item), None)
            return _Reference('database', endpoint.host if endpoint else '')
        if call.name == 'getReferenceFromUrl' and base.kind == 'database' and len(call.args) == 1:
            return _endpoint(self.value(call.args[0], before, scope))
        if call.name == 'getReference' and base.kind == 'database' and len(call.args) <= 1:
            path, unresolved = _path(self.value(call.args[0], before, scope)) if call.args else ('/', False)
            return _Reference('reference', base.host, path, unresolved)
        if call.name == 'child' and base.kind == 'reference' and len(call.args) == 1:
            path, unresolved = _path(base.path.rstrip('/') + '/' + self.value(call.args[0], before, scope))
            return _Reference('reference', base.host, path, base.unresolved or unresolved)
        return None


def analyze(source: Source) -> list[Finding]:
    """Inventory explicit RTDB locations without contacting any service."""
    observations: list[tuple[_Reference, int, int, str, str]] = []
    truncated = False
    clean = mask(source.text) if source.language in {'java', 'kotlin'} else re.sub(r'<!--[\s\S]*?-->', lambda match: blank(match.group()), source.text)
    # Only source literals are URL carriers in Java/Kotlin. Other inputs include
    # google-services.json, Android resources and plain-text asset configuration.
    def carriers():
        if source.language not in {'java', 'kotlin'}:
            yield 0, clean
        # Also decode JSON escaped slashes in config strings. For code, literal
        # offsets preserve line attribution even inside multiline strings.
        for token in STRING.finditer(clean):
            yield token.start() + (3 if token.group().startswith('"""') else 1), _literal(token.group()) or ''
    candidates = 0
    for offset, value in carriers():
        for match in URL.finditer(value):
            endpoint = _endpoint(match.group())
            if not endpoint:
                continue
            candidates += 1
            if candidates > MAX_CANDIDATES:
                truncated = True
                break
            start = offset + match.start()
            observations.append((endpoint, start, start + 1, '<file>', 'literal'))
        if truncated:
            break
    if source.language in {'java', 'kotlin'}:
        sdk = _SDK(source)
        calls = sdk.lex.calls({'getReference', 'getReferenceFromUrl', 'child'})
        if len(calls) > MAX_CANDIDATES:
            truncated = True
        for call in calls[:MAX_CANDIDATES]:
            expression = call.receiver + '.' + call.name + '(' + ', '.join(call.args) + ')'
            reference = sdk.reference(expression, call.start, call.scope)
            if reference and reference.kind == 'reference':
                observations.append((reference, call.start, call.end, call.scope[2], 'sdk'))
        for index, match in enumerate(re.finditer(r'\.\s*reference\b(?!\s*\()', sdk.lex.code)):
            if index >= MAX_CANDIDATES:
                truncated = True
                break
            start = match.start() + match.group().find('reference')
            receiver = sdk.lex.receiver(start)
            reference = sdk.reference(receiver + '.reference', start, sdk.lex.scope(start))
            if reference:
                observations.append((reference, start, match.end(), sdk.lex.scope(start)[2], 'sdk'))
    if not observations:
        return []
    paths = sorted({item.path for item, *_ in observations})
    if len(paths) > MAX_PATHS:
        truncated = True
    paths = paths[:MAX_PATHS]
    hosts = sorted({item.host for item, *_ in observations if item.host})
    if len(hosts) > MAX_PATHS:
        truncated = True
    hosts = hosts[:MAX_PATHS]
    unresolved = any(item.unresolved for item, *_ in observations)
    first = min(observations, key=lambda item: item[1])
    scopes = sorted({scope for _, _, _, scope, _ in observations})[:MAX_PATHS]
    finding = make('DS009', source, first[1], first[2],
                   '소스에 선언된 Firebase Realtime Database 호스트와 child 경로입니다. 동적 경로 값은 {dynamic}으로 표시합니다.',
                   confidence='low' if truncated else 'medium', kind='inventory', severity='info', properties={
                       'firebase_paths': paths, 'database_hosts': hosts,
                       'unresolved_segments': unresolved, 'truncated': truncated,
                       'configuration_scope': source.path[:2048] + '::<file>', 'lexical_scopes': scopes,
                       'firebase_observation_sources': sorted({kind for *_, kind in observations}),
                       'network_checked': False,
                   })
    # Values and credentials from source lines never appear in the evidence.
    finding.evidence[0].snippet = 'Firebase Realtime Database paths: ' + ', '.join(paths)[:1500]
    return [finding]
