#!/usr/bin/env python3
"""Check package assets, example configs, and reports generated from fixtures."""
from pathlib import Path
import json
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asap import CATEGORIES, __version__
from asap.config import Config
from asap.engine import scan
from asap.guidance import module_catalog
from asap.reporting import write_reports
from asap.rules.registry import RULES


def main():
    failures = []
    if len(RULES) != 43 or {rule.category for rule in RULES.values()} != set(CATEGORIES):
        failures.append('rule/category contract mismatch')
    required = [
        'README.md', 'README_ko.md', 'LICENSE', 'pyproject.toml',
        'docs/testing.md', 'schemas/report.schema.json',
        'asap/web/home.html', 'asap/web/home.js',
        'asap/web/workspace.html', 'asap/web/workspace.js',
        'asap/web/report.html', 'asap/web/report.js', 'asap/web/style.css',
        *(f'asap/guides/{category}.json' for category in CATEGORIES),
    ]
    for name in required:
        if not (ROOT / name).is_file():
            failures.append('missing ' + name)
    for config in (ROOT / 'examples').glob('config*.json'):
        try:
            Config.load(config)
        except (ValueError, OSError) as error:
            failures.append(f'invalid config {config.name}: {error}')
    if not failures:
        result = scan(ROOT / 'tests/fixtures/demo', Config(decompile=False))
        if result.diagnostics:
            failures.append('fixture scan contains diagnostics')
        if {finding.category for finding in result.findings} != set(CATEGORIES):
            failures.append('fixture does not cover all seven categories')
        with TemporaryDirectory(prefix='asap-distribution-') as directory:
            paths = write_reports(result, Path(directory))
            report = json.loads(Path(paths['json']).read_text(encoding='utf-8'))
            if report['schema_version'] != __version__:
                failures.append('report schema version mismatch')
            if report['summary']['total'] != len(report['findings']):
                failures.append('summary count mismatch')
            for finding in report['findings']:
                if finding['rule_id'] not in RULES or not finding['evidence']:
                    failures.append('invalid fixture finding')
            sarif = json.loads(Path(paths['sarif']).read_text(encoding='utf-8'))
            if sarif['version'] != '2.1.0' or len(sarif['runs'][0]['results']) != len(report['findings']):
                failures.append('SARIF structural mismatch')
            html = Path(paths['html']).read_text(encoding='utf-8')
            if any(marker in html for marker in ('<!--STYLE-->', '<!--DATA-->', '<!--GUIDES-->', '<!--SCRIPT-->')):
                failures.append('HTML contains unresolved template assets')
        if not all(module['guidance_available'] for module in module_catalog()):
            failures.append('missing module guidance')
    print(json.dumps({'version': __version__, 'passed': not failures, 'failures': failures}, indent=2))
    return int(bool(failures))

if __name__=='__main__':raise SystemExit(main())
