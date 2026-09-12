"""Small, bounds-checked Android binary XML reader (not an ARSC decoder).

Decodes standard XML chunks only. Unsupported/malformed input raises ValueError;
resource references are retained as @0x... rather than invented values.
"""
from __future__ import annotations
import struct
import xml.etree.ElementTree as ET

NO_INDEX = 0xffffffff

def decode_axml(data: bytes) -> str:
    def need(off: int, n: int, limit: int | None = None) -> None:
        if off < 0 or n < 0 or off + n > (len(data) if limit is None else limit):
            raise ValueError('AXML chunk exceeds bounds')
    def u16(off: int) -> int:
        need(off, 2)
        return struct.unpack_from('<H', data, off)[0]
    def u32(off: int) -> int:
        need(off, 4)
        return struct.unpack_from('<I', data, off)[0]
    need(0, 8)
    if u16(0) != 3 or u16(2) != 8 or u32(4) != len(data):
        raise ValueError('not a supported binary XML document')
    strings: list[str] = []
    stack: list[ET.Element] = []
    root: ET.Element | None = None
    p = 8
    nodes = 0
    def string(index: int) -> str:
        if index >= len(strings): raise ValueError('invalid AXML string index')
        return strings[index]
    def name(ns: int, index: int) -> str:
        n = string(index)
        if not n or any(c in n for c in '<>\x00'):
            raise ValueError('invalid XML name')
        return '{'+string(ns)+'}'+n if ns != NO_INDEX else n
    while p < len(data):
        need(p, 8)
        kind, header, size = struct.unpack_from('<HHI', data, p)
        if header < 8 or size < header or size % 4:
            raise ValueError('invalid AXML chunk size')
        end = p + size
        need(p, size)
        if kind == 1:
            if strings or header < 28: raise ValueError('invalid string pool')
            count, styles, flags, start, style_start = struct.unpack_from('<IIIII', data, p+8)
            if count > 100000 or start < header + 4*(count+styles) or start >= size:
                raise ValueError('invalid AXML string pool bounds')
            need(p+header, 4*(count+styles), end)
            limit = p + style_start if style_start else end
            if not p+start <= limit <= end: raise ValueError('invalid AXML styles offset')
            for i in range(count):
                off = p + start + u32(p+header+4*i)
                if off < p+start: raise ValueError('invalid string offset')
                if flags & 0x100:
                    def length8(at: int) -> tuple[int,int]:
                        need(at, 1, limit)
                        v = data[at]
                        if v & 0x80:
                            need(at, 2, limit)
                            return ((v & 0x7f) << 8) | data[at+1], at+2
                        return v, at+1
                    _, off = length8(off)
                    length, off = length8(off)
                    need(off, length+1, limit)
                    if data[off+length] != 0: raise ValueError('unterminated AXML string')
                    strings.append(data[off:off+length].decode('utf-8'))
                else:
                    need(off, 2, limit)
                    length = u16(off); off += 2
                    if length & 0x8000:
                        need(off, 2, limit)
                        length = ((length & 0x7fff) << 16) | u16(off); off += 2
                    need(off, length*2+2, limit)
                    if data[off+length*2:off+length*2+2] != b'\x00\x00':
                        raise ValueError('unterminated AXML UTF16 string')
                    strings.append(data[off:off+length*2].decode('utf-16-le'))
        elif kind == 0x102:
            if header < 16: raise ValueError('invalid start element header')
            need(p+16, 20, end)
            ns, idx = u32(p+16), u32(p+20)
            attr_start, attr_size, count = u16(p+24), u16(p+26), u16(p+28)
            if attr_start < 20 or attr_size < 20 or count > 10000:
                raise ValueError('invalid attribute table')
            need(p+16+attr_start, attr_size*count, end)
            elem = ET.Element(name(ns, idx))
            for i in range(count):
                a = p+16+attr_start+i*attr_size
                a_ns, a_idx, raw = u32(a), u32(a+4), u32(a+8)
                if u16(a+12) != 8: raise ValueError('invalid typed value')
                typ, value = data[a+15], u32(a+16)
                if raw != NO_INDEX: val = string(raw)
                elif typ == 3: val = string(value)
                elif typ == 0x12: val = 'true' if value else 'false'
                elif typ == 0x10: val = str(value if value < 0x80000000 else value - 0x100000000)
                elif typ == 0x11: val = hex(value)
                elif typ in (1,2): val = ('@' if typ == 1 else '?') + f'0x{value:08x}'
                elif typ == 0: val = ''
                else: val = f'0x{value:08x}'
                key = name(a_ns, a_idx)
                if key in elem.attrib: raise ValueError('duplicate XML attribute')
                elem.set(key, val)
            if stack: stack[-1].append(elem)
            elif root is None: root = elem
            else: raise ValueError('multiple XML roots')
            stack.append(elem)
            nodes += 1
            if len(stack) > 128 or nodes > 100000: raise ValueError('XML complexity limit exceeded')
        elif kind == 0x103:
            need(p+16, 8, end)
            if not stack or stack[-1].tag != name(u32(p+16), u32(p+20)):
                raise ValueError('mismatched XML end element')
            stack.pop()
        elif kind == 0x104:
            need(p+16, 12, end)
            if not stack: raise ValueError('text outside root')
            stack[-1].text = (stack[-1].text or '') + string(u32(p+16))
        elif kind not in (0x100, 0x101, 0x180):
            raise ValueError(f'unsupported AXML chunk: {kind:#x}')
        p = end
    if stack or root is None: raise ValueError('incomplete binary XML')
    ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
    ET.indent(root, space='  ')
    return ET.tostring(root, encoding='unicode')
