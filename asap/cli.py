from __future__ import annotations
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import platform
import shutil
import sys
from . import __version__, CATEGORIES
from .config import Config
from .engine import scan, should_fail, baseline_fingerprints
from .reporting import write_reports, atomic_write
from .rules.registry import RULES


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='asap',description='ASAP 3 — offline Android static security review')
    p.add_argument('--version',action='version',version=__version__)
    sub = p.add_subparsers(dest='command',required=True)
    s = sub.add_parser('scan',help='Analyze an APK/APKS/XAPK or source directory')
    s.add_argument('input',type=Path)
    s.add_argument('-o','--output',type=Path,default=Path('asap-results'))
    s.add_argument('--config',type=Path)
    s.add_argument('--categories',help='Comma-separated category names')
    s.add_argument('--include-vendor',action='store_true')
    s.add_argument('--workers',type=int)
    s.add_argument('--jadx',help='Path to trusted JADX launcher or JAR')
    s.add_argument('--apktool',help='Path to trusted Apktool launcher or JAR')
    s.add_argument('--firebase-rules',help='Local Realtime Database Rules JSON to inspect with this scan')
    s.add_argument('--firebase-data',help='Local exported Realtime Database JSON for child path inventory')
    s.add_argument('--no-decompile',action='store_true',help='Only inspect recoverable XML/assets; DEX remains unanalysed')
    s.add_argument('--baseline',type=Path)
    s.add_argument('--fail-on',choices=['none','info','low','medium','high','critical'],default='none')
    s.add_argument('--only-new',action='store_true',help='Apply CI threshold only to new findings')
    s.add_argument('--strict',action='store_true',help='Exit 2 when coverage diagnostics exist')
    s.add_argument('--legacy-json',action='store_true')
    d = sub.add_parser('doctor',help='Check local runtime and tool availability')
    d.add_argument('--config',type=Path)
    r = sub.add_parser('rules',help='List the 43 rules in seven categories')
    r.add_argument('--json',action='store_true')
    b = sub.add_parser('baseline',help='Create an explicit baseline from a report')
    b.add_argument('report',type=Path); b.add_argument('-o','--output',type=Path,required=True)
    diff = sub.add_parser('diff',help='Compare stable finding identities; absence is not proof of remediation')
    diff.add_argument('before',type=Path); diff.add_argument('after',type=Path)
    w = sub.add_parser('web',help='Run a loopback-only APK upload and report dashboard')
    w.add_argument('--workspace',type=Path,default=Path('.asap-workspace'))
    w.add_argument('--port',type=int,default=8765)
    w.add_argument('--config',type=Path)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == 'scan':
            cfg = Config.load(args.config)
            if args.categories: cfg.categories = [c.strip() for c in args.categories.split(',')]
            if args.include_vendor: cfg.include_vendor = True
            if args.workers is not None: cfg.workers = args.workers
            if args.jadx: cfg.jadx = args.jadx
            if args.apktool: cfg.apktool = args.apktool
            if args.firebase_rules: cfg.firebase_rules = args.firebase_rules
            if args.firebase_data: cfg.firebase_data = args.firebase_data
            if args.no_decompile: cfg.decompile = False
            cfg.validate()
            # Avoid rescanning old reports accidentally when output lives inside source input.
            try:
                relative = args.output.resolve().relative_to(args.input.resolve()).as_posix()
                if relative == '.': raise ValueError('output cannot equal the source directory')
                cfg.exclude.extend([relative+'/**',relative])
            except ValueError as exc:
                if str(exc) == 'output cannot equal the source directory': raise
            result = scan(args.input,cfg,args.baseline)
            paths = write_reports(result,args.output,args.legacy_json)
            print(json.dumps({'version':__version__,'coverage':result.coverage['status'],
                              'summary':result.summary,'reports':paths},ensure_ascii=False,indent=2))
            if args.strict and result.diagnostics: return 2
            return 1 if should_fail(result,args.fail_on,args.only_new) else 0
        if args.command == 'doctor':
            cfg = Config.load(args.config)
            def available(path): return bool(path and (Path(path).is_file() or shutil.which(path)))
            tools = {kind:{'path':getattr(cfg,kind) or shutil.which(kind),
                           'available':available(getattr(cfg,kind) or shutil.which(kind))} for kind in ('jadx','apktool')}
            print(json.dumps({'python':platform.python_version(),'platform':platform.platform(),
                              'source_analysis_ready':sys.version_info >= (3,11),'java':shutil.which('java'),
                              'tools':tools,'notes':['Tool availability checks paths without running the tools.',
                              'Configure JADX to analyze DEX code; Apktool is optional for resource decoding.']},indent=2))
            return 0
        if args.command == 'rules':
            if args.json: print(json.dumps([asdict(r) for r in RULES.values()],ensure_ascii=False,indent=2))
            else:
                for c in CATEGORIES:
                    print('\n'+c)
                    for r in RULES.values():
                        if r.category == c: print(f'  {r.id:7} {r.severity:7} {r.title}')
            return 0
        if args.command == 'baseline':
            ids = sorted(baseline_fingerprints(args.report))
            atomic_write(args.output,json.dumps({'schema_version':'3.0.0','fingerprints':ids},indent=2)+'\n')
            print(f'Wrote {len(ids)} baseline identities to {args.output}')
            return 0
        if args.command == 'diff':
            before,after = baseline_fingerprints(args.before),baseline_fingerprints(args.after)
            print(json.dumps({'new':sorted(after-before),'unchanged':sorted(before&after),
                              'absent_from_current_scan':sorted(before-after),
                              'note':'Absence may reflect coverage/configuration changes, not a verified fix.'},indent=2))
            return 0
        if args.command == 'web':
            from .server import serve
            serve(args.workspace,args.port,Config.load(args.config))
            return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f'ASAP error: {type(exc).__name__}: {exc}',file=sys.stderr)
        return 2
    return 0
