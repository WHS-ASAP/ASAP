"""Bundled module review guidance; no remote lookups during analysis."""
from dataclasses import asdict
import json
from pathlib import Path

from . import CATEGORIES
from .rules.registry import RULES


def module_catalog() -> list[dict]:
    directory = Path(__file__).with_name('guides')
    modules = []
    for category in CATEGORIES:
        path = directory / (category + '.json')
        guide = json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {
            'category': category, 'summary': '모듈 검토 안내를 사용할 수 없습니다.',
            'review_questions': [], 'safe_patterns': [], 'limitations': [],
            'references': [], 'implemented_changes': [],
        }
        rules = [asdict(rule) for rule in RULES.values() if rule.category == category]
        modules.append({**guide, 'category': category, 'rules': rules,
                        'rule_count': len(rules), 'guidance_available': path.is_file()})
    return modules
