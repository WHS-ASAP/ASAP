"""Bounded lexical helpers; NOT a Java/Kotlin AST or whole-program taint engine."""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

# Preserve all offsets and newlines when masking comments or literals.
TOKENS = re.compile(r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/')
STRING = re.compile(r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
SENSITIVE = re.compile(r"(?i)(?:password|passwd|pwd|secret|access_?token|auth_?token|refresh_?token|api_?key|private_?key|session_?id|credit_?card|card_?number|ssn|cookie|bearer)")


def blank(value: str) -> str:
    return ''.join('\n' if c == '\n' else ' ' for c in value)


def mask(text: str, strings: bool = False) -> str:
    return TOKENS.sub(lambda m: blank(m.group()) if strings or m.group().startswith(('//', '/*')) else m.group(), text)


def redact(text: str, language: str = "java") -> str:
    """No full literal values in reports, including in a neighbouring expression."""
    if language == "xml":
        # Preserve attribute names but not values (which can themselves be secrets).
        text = re.sub(r'([=]\s*)(["\'])(.*?)\2', lambda m: m[1] + m[2] + '[REDACTED]' + m[2], text, flags=re.S)
        return re.sub(r'>([^<]+)<', lambda m: '>[REDACTED]<' if m[1].strip() else m[0], text)
    text = mask(text)
    return STRING.sub('"[REDACTED]"', text)


def literals(text: str) -> list[str]:
    return [m.group()[3:-3] if m.group().startswith('"""') else m.group()[1:-1] for m in STRING.finditer(text)]


def split_args(text: str) -> list[str]:
    clean = mask(text, strings=True)
    level = 0
    start = 0
    result = []
    for i, c in enumerate(clean):
        if c in '([{':
            level += 1
        elif c in ')]}':
            level -= 1
        elif c == ',' and level == 0:
            result.append(text[start:i].strip())
            start = i + 1
    tail = text[start:].strip()
    if tail or result:
        result.append(tail)
    return result

@dataclass(frozen=True)
class Call:
    name: str
    receiver: str
    start: int
    end: int
    args: tuple[str, ...]
    scope: tuple[int, int, str]

class Lexical:
    def __init__(self, text: str, language: str = "java"):
        self.language = language
        self.text = text
        self.clean = mask(text)
        self.code = mask(text, strings=True)
        self.newlines = [-1] + [m.start() for m in re.finditer('\n', text)]
        self.pairs: dict[int, int] = {}
        stack: list[tuple[str, int]] = []
        for i, c in enumerate(self.code):
            if c in '({[':
                stack.append((c, i))
            elif c in ')}]' and stack and stack[-1][0] == {')':'(', '}':'{', ']':'['}[c]:
                _, j = stack.pop()
                self.pairs[j] = i
        self.reverse_pairs = {end:start for start,end in self.pairs.items()}
        self.scopes = self._scopes()

    def line(self, offset: int) -> int:
        return bisect.bisect_left(self.newlines, offset)

    def _scopes(self) -> list[tuple[int, int, str]]:
        scopes = []
        for start, end in self.pairs.items():
            if self.code[start] != '{':
                continue
            before = self.code[max(0, start-600):start].rstrip()
            m = re.search(r'([\w$]+)\s*\([^{};]*\)\s*(?:throws[\w\s,.]+)?(?::\s*[\w?.<>]+)?\s*$', before)
            if m and m[1] not in {'if','for','while','switch','catch','when','synchronized','with'}:
                # Do not treat trailing invocation lambdas as verified method scopes.
                prefix = before[:m.start()].rsplit(';', 1)[-1]
                if re.search(r'(?:\bfun\b|\bvoid\b|\bpublic\b|\bprivate\b|\bprotected\b|\bstatic\b|[\w<>\[\]?]+\s+)$', prefix):
                    scopes.append((start + 1, end, m[1]))
        return sorted(scopes)

    def scope(self, offset: int) -> tuple[int, int, str]:
        matches = [s for s in self.scopes if s[0] <= offset < s[1]]
        return min(matches, key=lambda s:s[1]-s[0]) if matches else (0, len(self.text), "<file>")

    def receiver(self, start: int) -> str:
        """Recover a bounded receiver chain, including prefs.edit().putString()."""
        i = start - 1
        while i >= 0 and self.code[i].isspace(): i -= 1
        if i < 0 or self.code[i] != '.': return ''
        end = i
        i -= 1
        if i >= 0 and self.code[i] == '?': i -= 1
        floor = max(0, start - 2048)
        while i >= floor:
            if self.code[i].isspace():
                i -= 1
                continue
            if self.code[i] in ')]':
                opening = self.reverse_pairs.get(i)
                if opening is None or opening < floor: break
                i = opening - 1
                continue
            if self.code[i].isalnum() or self.code[i] in '_$':
                while i >= floor and (self.code[i].isalnum() or self.code[i] in '_$'): i -= 1
                look = i
                while look >= floor and self.code[look].isspace(): look -= 1
                if look >= floor and self.code[look] in '.?':
                    i = look - 1
                    continue
                break
            if self.code[i] in '.?':
                i -= 1
                continue
            break
        return self.clean[i+1:end].strip()

    def calls(self, names: set[str]) -> list[Call]:
        out = []
        pattern = r'\b(' + '|'.join(re.escape(n) for n in sorted(names)) + r')\s*\('
        for m in re.finditer(pattern, self.code):
            opening = self.code.find('(', m.start(), m.end())
            closing = self.pairs.get(opening)
            if closing is None:
                continue
            rec = self.receiver(m.start())
            # Declaration names are excluded; calls inside methods remain.
            if any(abs(s[0] - (closing + 2)) <= 3 and s[2] == m[1] for s in self.scopes) and not rec:
                continue
            out.append(Call(m[1], rec, m.start(), closing+1,
                            tuple(split_args(self.clean[opening+1:closing])), self.scope(m.start())))
        return out

    def assignments(self, before: int, scope: tuple[int,int,str]) -> list[tuple[str,str,int]]:
        # Same lexical method only, latest assignment wins; no branch/path proof.
        lo = scope[0]
        piece = self.clean[lo:before]
        masked = self.code[lo:before]
        out = []
        for m in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>?\[\].]+\s*)?(?<![=!<>])=(?!=)', masked):
            start = m.end()
            depth = 0
            end = start
            for i in range(start, min(len(piece), start+16384)):
                ch = masked[i]
                if ch in '([{': depth += 1
                elif ch in ')]}':
                    if depth <= 0: break
                    depth -= 1
                if depth == 0 and ch in ';\n': break
                end = i + 1
            out.append((m[1], piece[start:end].strip(), lo + m.start()))
        return out

    def resolve(self, expr: str, before: int, scope: tuple[int,int,str], depth: int = 0) -> tuple[str, list[int]]:
        """Resolve direct local aliases and substitutions to depth 6, max 16 KiB."""
        if depth > 6 or len(expr) > 16384:
            return expr[:16384], []
        assignments = self.assignments(before, scope)
        # Only bare variables, concatenations and explicit expressions are expanded.
        code = expression_code(expr, self.language)
        used: list[int] = []
        replacements = []
        template_values = []
        plain_code = mask(expr, strings=True)
        for m in re.finditer(r'\b[A-Za-z_$][\w$]*\b', code):
            if (m.start() > 0 and code[m.start()-1] == '.') or code[m.end():].lstrip().startswith('('):
                continue
            candidate = next((a for a in reversed(assignments) if a[0] == m[0]), None)
            if candidate:
                value, points = self.resolve(candidate[1], candidate[2], scope, depth+1)
                if not plain_code[m.start():m.end()].strip():
                    # Keep template substitutions outside string syntax in this symbolic expression.
                    template_values.append(value)
                else:
                    replacements.append((m.start(), m.end(), '(' + value + ')'))
                used.extend(points + [candidate[2]])
        for start, end, value in reversed(replacements):
            expr = expr[:start] + value + expr[end:]
            if len(expr) > 16384:
                return expr[:16384], sorted(set(used))
        if template_values:
            expr += ' + ' + ' + '.join('(' + value + ')' for value in template_values)
        return expr[:16384], sorted(set(used))

    def snippet(self, start: int, end: int) -> str:
        a = self.text.rfind('\n', 0, start) + 1
        b = self.text.find('\n', end)
        if b < 0: b = len(self.text)
        return redact(self.text[a:b])[:1600]


def external_source(expr: str, language: str = "java") -> bool:
    code = expression_code(expr, language)
    return bool(re.search(r'\b(?:getIntent|getData|getDataString|getStringExtra|getCharSequenceExtra|getParcelableExtra|getQueryParameter|getLastPathSegment|getPathSegments|readLine)\s*\(', code) or
                re.search(r'\bintent\.(?:data|dataString|extras)\b', code))


def expression_code(expr: str, language: str = "java") -> str:
    """Expose simple Kotlin template dependencies, preserving expression offsets."""
    clean = mask(expr)
    code = list(mask(expr, strings=True))
    if language == 'kotlin':
        for token in STRING.finditer(clean):
            if not token.group().startswith('"'): continue
            for m in re.finditer(r'(?<!\\)\$(?:\{([^}]+)\}|([A-Za-z_]\w*))',token.group()):
                group = 1 if m[1] is not None else 2
                a, b = token.start()+m.start(group), token.start()+m.end(group)
                code[a:b] = clean[a:b]
    return ''.join(code)


def dynamic_string(expr: str, language: str = "java") -> bool:
    # Constant literals and concatenations thereof are not treated as injection.
    code = expression_code(expr, language)
    return bool(re.search(r'[A-Za-z_$]', code))
