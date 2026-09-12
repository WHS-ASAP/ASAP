from __future__ import annotations
import re
import xml.etree.ElementTree as ET

ANDROID = 'http://schemas.android.com/apk/res/android'

def safe_xml(text: str) -> ET.Element:
    if re.search(r'<!\s*(?:DOCTYPE|ENTITY)', text, re.I):
        raise ValueError('DTD and entities are not accepted')
    return ET.fromstring(text)

def attrs(node: ET.Element) -> dict[str, str]:
    return {k.split('}', 1)[-1]: v for k, v in node.attrib.items()}

def android_attrs(node: ET.Element) -> dict[str, str]:
    return {k.split('}', 1)[-1]: v for k, v in node.attrib.items() if k.startswith('{'+ANDROID+'}')}

def boolean(value: str | None) -> bool | None:
    if value in ('true', '1', '0xffffffff'): return True
    if value in ('false', '0', '0x0'): return False
    return None

def sdk(value: str | None) -> int | None:
    try:
        return int(value) if value else None
    except ValueError:
        return None
