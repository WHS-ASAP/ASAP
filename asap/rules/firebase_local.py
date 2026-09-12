"""Inspect supplied Firebase Rules and exported data without network access.

Only unconditional Rules grants are classified. Expressions are never evaluated,
export scalar values never enter findings, and traversal has explicit limits.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import PurePosixPath
from typing import Any, Iterator

from ..model import Evidence, Finding, Source
from .registry import RULES

_RULE_FILES = {'database.rules.json', 'firebase.rules.json'}
_DATA_FILES = {'firebase-export.json', 'database-export.json', 'rtdb-export.json'}
_MAX_JSON_CHARS = 8 * 1024 * 1024
_MAX_PATH_CHARS = 2048
_MAX_OUTPUT_PATH_BYTES = 1024 * 1024


def input_kind(source: Source) -> str | None:
    name = PurePosixPath(source.path.replace('\\', '/')).name
    if name in _RULE_FILES:
        return 'rules'
    if name in _DATA_FILES:
        return 'data'
    return None


class _DuplicateKey(ValueError):
    pass


class _LocatedObject(dict):
    def __init__(self, pairs: list[tuple[str, Any]]):
        super().__init__()
        self.permission_lines: dict[str, int] = {}
        for key, value in pairs:
            if key in self:
                raise _DuplicateKey()
            self[key] = value


def _without_comments(text: str) -> str:
    """Replace Rules comments with spaces, preserving character and line offsets."""
    out = list(text)
    pos = 0
    quoted = False
    while pos < len(text):
        char = text[pos]
        if quoted:
            if char == '\\':
                pos += 2
                continue
            if char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif text.startswith('//', pos):
            end = text.find('\n', pos)
            end = len(text) if end < 0 else end
            for index in range(pos, end):
                if text[index] != '\r':
                    out[index] = ' '
            pos = end
            continue
        elif text.startswith('/*', pos):
            end = text.find('*/', pos + 2)
            if end < 0:
                raise ValueError('Unterminated comment')
            for index in range(pos, end + 2):
                if text[index] not in '\r\n':
                    out[index] = ' '
            pos = end + 2
            continue
        pos += 1
    return ''.join(out)


def _key_tokens(text: str) -> Iterator[tuple[str, int]]:
    """Yield actual object keys from already validated JSON in lexical order."""
    pos = 0
    line = 1
    while pos < len(text):
        if text[pos] == '\n':
            line += 1
        if text[pos] != '"':
            pos += 1
            continue
        start, key_line = pos, line
        pos += 1
        while pos < len(text):
            if text[pos] == '\\':
                pos += 2
            elif text[pos] == '"':
                pos += 1
                break
            else:
                pos += 1
        end = pos
        while pos < len(text) and text[pos].isspace():
            if text[pos] == '\n':
                line += 1
            pos += 1
        if pos < len(text) and text[pos] == ':':
            yield json.loads(text[start:end]), key_line


def _assign_lines(root: Any, text: str) -> None:
    """Match parsed keys to tokens iteratively; values are never evidence text."""
    def edges(value: Any):
        if isinstance(value, dict):
            for key, child in value.items():
                yield value, key, child
        elif isinstance(value, list):
            for child in value:
                yield None, None, child

    tokens = iter(_key_tokens(text))
    stack = [iter(edges(root))]
    while stack:
        try:
            owner, key, child = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if owner is not None:
            parsed_key, line = next(tokens)
            if parsed_key != key:
                raise ValueError('JSON position mismatch')
            if key in {'.read', '.write'}:
                owner.permission_lines[key] = line
        if isinstance(child, (dict, list)):
            stack.append(iter(edges(child)))


def _diag(source: Source, code: str, message: str, *, level: str = 'warning') -> dict:
    return {'level': level, 'code': code, 'path': source.path, 'message': message}


def _finding(rule_id: str, source: Source, line: int, message: str,
             snippet: str, properties: dict, *, kind: str = 'configuration') -> Finding:
    rule = RULES[rule_id]
    return Finding(rule.id, rule.category, rule.title, rule.severity, 'high', kind,
                   message, [Evidence(source.path, line, line, snippet, 'observation')],
                   rule.remediation, rule.cwe, rule.masvs, list(rule.references), properties=properties)


def _child_path(parent: str, key: str) -> str | None:
    # Escape structural separators; never truncate keys into colliding paths.
    if not key or len(parent) + len(key) > _MAX_PATH_CHARS or any(0xD800 <= ord(char) <= 0xDFFF for char in key):
        return None
    escaped = key.replace('~', '~0').replace('/', '~1')
    path = ('/' if parent == '/' else parent + '/') + escaped
    return path if len(path) <= _MAX_PATH_CHARS else None


def _literal(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip() in {'true', 'false'}:
        return value.strip() == 'true'
    return None


def _rules(source: Source, root: Any, max_nodes: int, max_depth: int) -> tuple[list[Finding], list[dict]]:
    diagnostics: list[dict] = []
    if not isinstance(root, dict) or not isinstance(root.get('rules'), dict):
        return [], [_diag(source, 'FIREBASE_INVALID_RULES', 'Firebase Rules require a top-level rules object.')]
    if set(root) != {'rules'}:
        diagnostics.append(_diag(source, 'FIREBASE_INVALID_RULES', 'Unexpected properties accompany the top-level rules object; deployment validity is not established.'))
    findings: list[Finding] = []
    visited = 0
    depth_truncated = False
    node_truncated = False
    unknown_count = 0
    invalid_count = 0
    path_truncated = False
    output_path_bytes = 0

    def children(node, path, depth, read_ancestors, write_ancestors):
        nonlocal path_truncated
        for key, child in node.items():
            if not key.startswith('.'):
                child_path = _child_path(path, key)
                if child_path is None:
                    path_truncated = True
                    continue
                yield child, child_path, depth + 1, read_ancestors, write_ancestors, key

    stack = [iter([(root['rules'], '/', 0, (), (), None)])]
    while stack:
        try:
            node, path, depth, read_ancestors, write_ancestors, child_key = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if visited >= max_nodes:
            node_truncated = True
            break
        visited += 1
        if child_key is not None and (not child_key or any(c in child_key for c in '.#[]/\x00\r\n')
                                      or any(ord(c) < 32 or ord(c) == 127 for c in child_key)
                                      or ('$' in child_key and not (child_key.startswith('$') and len(child_key) > 1 and '$' not in child_key[1:]))):
            invalid_count += 1
            continue
        if not isinstance(node, dict):
            invalid_count += 1
            continue
        path_bytes = len(path.encode('utf-8'))
        required_bytes = 0
        for operation, ancestors in (('read', read_ancestors), ('write', write_ancestors)):
            value = _literal(node.get('.' + operation))
            dynamic = isinstance(node.get('.' + operation), str) and value is None
            required_bytes += len(ancestors) * path_bytes * (2 if value is False or dynamic else 1)
            if value is True:
                required_bytes += 3 * path_bytes + sum(len(findings[i].properties['firebase_path'].encode('utf-8')) for i in ancestors)
        if output_path_bytes + required_bytes > _MAX_OUTPUT_PATH_BYTES:
            path_truncated = True
            break
        output_path_bytes += required_bytes
        for operation, ancestors in (('read', read_ancestors), ('write', write_ancestors)):
            key = '.' + operation
            has_rule = key in node
            value = _literal(node.get(key)) if has_rule else None
            dynamic = has_rule and isinstance(node[key], str) and value is None
            if has_rule and not isinstance(node[key], (bool, str)):
                invalid_count += 1
            if dynamic:
                unknown_count += 1
            for ancestor in ancestors:
                props = findings[ancestor].properties
                props['affected_child_paths'].append(path)
                if value is False:
                    props['child_denies_overridden'].append(path)
                if dynamic:
                    props['unknown_child_expression_paths'].append(path)
            if value is True:
                props = {
                    'firebase_input': 'rules', 'firebase_path': path, 'operation': operation,
                    'configuration_scope': f'firebase-rtdb:{operation}:{path}',
                    'permission_state': 'unconditional_grant',
                    'affected_child_paths': [], 'child_denies_overridden': [],
                    'unknown_child_expression_paths': [],
                    'inherited_from': [findings[i].properties['firebase_path'] for i in ancestors],
                    'descendant_access': 'authorization_grant_inherits_to_all_descendants',
                    'deployment_status': 'not_verified', 'truncated': False,
                }
                if operation == 'write':
                    props.update(validation_constraints='not_evaluated', effective_write_access='unknown')
                    message = '로컬 Firebase Rules의 무조건 .write 허용이 하위 경로에 상속됩니다. 하위 false는 상위 허용을 취소하지 않습니다. .validate 제약은 별도로 적용되며 실제 쓰기 성공 여부는 확인하지 않습니다.'
                else:
                    message = '로컬 Firebase Rules의 무조건 .read 허용이 하위 경로에 상속됩니다. 하위 false는 상위 허용을 취소하지 않습니다.'
                finding_index = len(findings)
                findings.append(_finding('DS010' if operation == 'read' else 'DS011', source,
                                         node.permission_lines.get(key, 1), message,
                                         f'Firebase Rules {operation} authorization grant at {path}', props))
                if operation == 'read':
                    read_ancestors = (*read_ancestors, finding_index)
                else:
                    write_ancestors = (*write_ancestors, finding_index)
        for key, value in node.items():
            if key == '.validate' and not isinstance(value, (bool, str)):
                invalid_count += 1
            elif key == '.indexOn' and not (isinstance(value, str) or isinstance(value, list) and all(isinstance(v, str) for v in value)):
                invalid_count += 1
            elif key.startswith('.') and key not in {'.read', '.write', '.validate', '.indexOn'}:
                invalid_count += 1
        if depth >= max_depth:
            if any(not key.startswith('.') for key in node):
                depth_truncated = True
        else:
            stack.append(iter(children(node, path, depth, read_ancestors, write_ancestors)))
    truncated = node_truncated or depth_truncated or path_truncated
    for finding in findings:
        finding.properties.update(node_count=visited, truncated=truncated,
                                  limits={'max_nodes': max_nodes, 'max_depth': max_depth,
                                          'max_path_chars': _MAX_PATH_CHARS, 'max_output_path_bytes': _MAX_OUTPUT_PATH_BYTES})
    if invalid_count:
        diagnostics.append(_diag(source, 'FIREBASE_INVALID_RULE_TYPE', f'{invalid_count} invalid Rules node(s), directive(s), or path key(s); deployment validity is not established.'))
    if unknown_count:
        diagnostics.append(_diag(source, 'FIREBASE_RULE_EXPRESSION_UNKNOWN', f'{unknown_count} dynamic .read/.write expression(s) were not evaluated; no safety or public-access conclusion is inferred from them.', level='info'))
    if node_truncated:
        diagnostics.append(_diag(source, 'FIREBASE_NODE_LIMIT', f'Firebase Rules traversal stopped at the {max_nodes}-node limit.'))
    if depth_truncated:
        diagnostics.append(_diag(source, 'FIREBASE_DEPTH_LIMIT', f'Firebase Rules descendants beyond depth {max_depth} were omitted.'))
    if path_truncated:
        diagnostics.append(_diag(source, 'FIREBASE_PATH_LIMIT', f'Firebase paths are invalid or exceed {_MAX_PATH_CHARS} characters or the {_MAX_OUTPUT_PATH_BYTES}-byte aggregate path budget; affected branches were omitted.'))
    return findings, diagnostics


def _node_type(value: Any) -> str:
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, dict):
        return 'object'
    if isinstance(value, list):
        return 'array'
    if isinstance(value, str):
        return 'string'
    return 'number'


def _data(source: Source, root: Any, max_nodes: int, max_depth: int) -> tuple[list[Finding], list[dict]]:
    paths: list[dict] = []
    types: Counter = Counter()
    invalid_metadata = 0
    node_truncated = False
    depth_truncated = False
    path_truncated = False
    output_path_bytes = 0

    def children(node, path, depth):
        nonlocal path_truncated
        if isinstance(node, dict):
            for key, value in node.items():
                if key not in {'.value', '.priority'}:
                    child_path = _child_path(path, key)
                    if child_path is None:
                        path_truncated = True
                        continue
                    yield value, child_path, depth + 1
        elif isinstance(node, list):
            for index, value in enumerate(node):
                child_path = _child_path(path, str(index))
                if child_path is None:
                    path_truncated = True
                    continue
                yield value, child_path, depth + 1

    stack = [iter([(root, '/', 0)])]
    while stack:
        try:
            node, path, depth = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if len(paths) >= max_nodes:
            node_truncated = True
            break
        path_bytes = len(path.encode('utf-8'))
        if output_path_bytes + path_bytes > _MAX_OUTPUT_PATH_BYTES:
            path_truncated = True
            break
        output_path_bytes += path_bytes
        has_priority = isinstance(node, dict) and '.priority' in node
        if has_priority:
            priority = node['.priority']
            if isinstance(priority, (dict, list, bool)):
                invalid_metadata += 1
        if isinstance(node, dict) and '.value' in node:
            extra_children = bool(set(node) - {'.value', '.priority'})
            if extra_children or isinstance(node['.value'], (dict, list)):
                invalid_metadata += 1
            # Preserve actual children of malformed mixed wrappers. A valid
            # wrapped leaf is this same path, never an extra .value child path.
            if not extra_children:
                node = node['.value']
        node_type = _node_type(node)
        child_count = sum(key not in {'.priority', '.value'} for key in node) if isinstance(node, dict) else len(node) if isinstance(node, list) else 0
        paths.append({'path': path, 'type': node_type, 'depth': depth,
                      'child_count': child_count, 'has_priority': has_priority})
        types[node_type] += 1
        if depth >= max_depth:
            depth_truncated = depth_truncated or bool(child_count)
        else:
            stack.append(iter(children(node, path, depth)))
    diagnostics = []
    if invalid_metadata:
        diagnostics.append(_diag(source, 'FIREBASE_EXPORT_METADATA_INVALID', f'{invalid_metadata} invalid export metadata wrapper(s) or priority type(s); exported values were not included in results.'))
    if node_truncated:
        diagnostics.append(_diag(source, 'FIREBASE_NODE_LIMIT', f'Firebase export traversal stopped at the {max_nodes}-node limit.'))
    if depth_truncated:
        diagnostics.append(_diag(source, 'FIREBASE_DEPTH_LIMIT', f'Firebase export descendants beyond depth {max_depth} were omitted.'))
    if path_truncated:
        diagnostics.append(_diag(source, 'FIREBASE_PATH_LIMIT', f'Firebase paths are invalid or exceed {_MAX_PATH_CHARS} characters or the {_MAX_OUTPUT_PATH_BYTES}-byte aggregate path budget; affected branches were omitted.'))
    props = {'firebase_input': 'data', 'configuration_scope': 'firebase-rtdb:export:/',
             'paths': paths, 'node_count': len(paths), 'type_counts': dict(sorted(types.items())),
             'truncated': node_truncated or depth_truncated or path_truncated,
             'limits': {'max_nodes': max_nodes, 'max_depth': max_depth,
                        'max_path_chars': _MAX_PATH_CHARS, 'max_output_path_bytes': _MAX_OUTPUT_PATH_BYTES},
             'access_status': 'not_inferred_from_local_export', 'scalar_values_included': False}
    return [_finding('DS012', source, 1,
                     '로컬 Firebase 데이터 내보내기의 루트와 하위 경로 구조입니다. 데이터 값은 보고서에 포함하지 않으며 접근 권한은 추론하지 않습니다.',
                     'Firebase local export: path and type inventory only', props, kind='inventory')], diagnostics


def analyze(source: Source, *, max_nodes: int = 4096, max_depth: int = 64) -> tuple[list[Finding], list[dict]]:
    """Analyze a recognized local JSON artifact; unknown filenames are ignored."""
    kind = input_kind(source)
    if kind is None:
        return [], []
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1:
        raise ValueError('max_nodes must be a positive integer')
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 0:
        raise ValueError('max_depth must be a nonnegative integer')
    if len(source.text) > _MAX_JSON_CHARS:
        return [], [_diag(source, 'FIREBASE_INPUT_LIMIT', 'Firebase JSON exceeds the local parser character limit.')]
    try:
        text = _without_comments(source.text) if kind == 'rules' else source.text
        def reject_constant(_value):
            raise ValueError('Non-JSON numeric constant')
        root = json.loads(text, object_pairs_hook=_LocatedObject, parse_constant=reject_constant)
        if kind == 'rules':
            _assign_lines(root, text)
    except _DuplicateKey:
        return [], [_diag(source, 'FIREBASE_DUPLICATE_KEY', 'Duplicate JSON object keys make the supplied Firebase artifact ambiguous; analysis was skipped.')]
    except (ValueError, RecursionError, OverflowError, StopIteration):
        return [], [_diag(source, 'FIREBASE_INVALID_JSON', 'Invalid or excessively nested Firebase JSON; analysis was skipped. Source values are omitted.')]
    return _rules(source, root, max_nodes, max_depth) if kind == 'rules' else _data(source, root, max_nodes, max_depth)
