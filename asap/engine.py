from __future__ import annotations
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone, date
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import time
import xml.etree.ElementTree as ET
from . import __version__, RESEARCH_DATE, CATEGORIES
from .config import Config
from .inputs import PreparedInput
from .manifest import parse_manifest, resources_for
from .model import Finding, ScanResult, SEVERITIES
from .rules.analyze import code_findings, manifest_findings, secret_findings, smali_findings
from .rules.registry import RULES
from .rules.entry_refinements import refine as refine_entrypoints
from .rules.data_refinements import refine as refine_data_protection
from .rules.firebase_paths import analyze as firebase_paths
from .rules.firebase_local import analyze as firebase_local, input_kind as firebase_input_kind
from .xmlutil import safe_xml
from .text import mask


def fingerprint_findings(findings: list[Finding]) -> list[Finding]:
    unique = []
    seen = set()
    for f in findings:
        e = f.evidence[-1]
        exact = (f.rule_id,e.path,e.line,e.end_line,json.dumps(f.properties,sort_keys=True,ensure_ascii=False))
        if exact not in seen:
            unique.append(f); seen.add(exact)
    unique.sort(key=lambda f:(f.evidence[-1].path,f.evidence[-1].line,f.rule_id,
                               json.dumps(f.properties,sort_keys=True,ensure_ascii=False)))
    counts: Counter = Counter()
    for f in unique:
        e = f.evidence[-1]
        normalized = re.sub(r'\s+','',e.snippet)
        identity = [f.rule_id,e.path,normalized,
                    {k:f.properties.get(k) for k in ('method','component','identifier','permission','configuration_scope')}]
        key = json.dumps(identity,sort_keys=True,ensure_ascii=False)
        counts[key] += 1
        f.fingerprint = hashlib.sha256((key+'#'+str(counts[key])).encode()).hexdigest()
    return unique


def baseline_fingerprints(path: Path | None) -> set[str]:
    if path is None: return set()
    if path.stat().st_size > 100*1024*1024: raise ValueError('baseline is too large')
    raw = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(raw,dict): raise ValueError('invalid baseline object')
    if 'fingerprints' in raw: values = raw['fingerprints']
    elif isinstance(raw.get('findings'),list): values = [f.get('fingerprint') for f in raw['findings'] if isinstance(f,dict)]
    else: raise ValueError('baseline requires fingerprints or a prior report')
    if not isinstance(values,list) or not all(isinstance(v,str) and re.fullmatch('[a-f0-9]{64}',v) for v in values):
        raise ValueError('invalid baseline fingerprints')
    return set(values)


def scan(input_path: Path | str, config: Config | None = None, baseline: Path | None = None) -> ScanResult:
    cfg = config or Config()
    cfg.validate()
    baseline_ids = baseline_fingerprints(baseline)
    started = datetime.now(timezone.utc).isoformat()
    tic = time.perf_counter()
    with PreparedInput(Path(input_path),cfg) as prepared:
        sources = sorted(prepared.sources,key=lambda s:s.path)
        diagnostics = list(prepared.diagnostics)
        manifests = []
        manifest_sources = {}
        xml_valid = set()
        manifest_seen = set()
        for s in sources:
            if s.language != 'xml': continue
            try:
                root = safe_xml(s.text)
                xml_valid.add(s.path)
                if Path(s.path).name == 'AndroidManifest.xml':
                    m = parse_manifest(s,resources_for(s,sources))
                    normalized = asdict(m); normalized.pop('path'); normalized.pop('binary')
                    sig = json.dumps(normalized,sort_keys=True,ensure_ascii=False)
                    if sig not in manifest_seen:
                        manifests.append(m); manifest_sources[m.path] = s; manifest_seen.add(sig)
                    if m.target_sdk is None:
                        diagnostics.append({'level':'warning','code':'SDK_UNKNOWN','path':s.path,
                                            'message':'targetSdk could not be resolved; source manifests may require Gradle/manifest merging.'})
                    if '@0x' in s.text:
                        diagnostics.append({'level':'warning','code':'RESOURCE_REFERENCE_UNRESOLVED','path':s.path,
                                            'message':'Compiled resource references remain unresolved; use JADX/Apktool for decoded resources.'})
            except (ET.ParseError,ValueError) as exc:
                diagnostics.append({'level':'warning','code':'XML_PARSE_FAILED','path':s.path,
                                    'message':f'Malformed or unsupported XML ({type(exc).__name__}); XML-dependent rules skipped.'})
        if not manifests:
            diagnostics.append({'level':'warning','code':'MANIFEST_MISSING','path':'',
                                'message':'No valid AndroidManifest.xml; SDK/component/permission analysis is unavailable.'})
        high_level_classes = set()
        for s in sources:
            if s.language not in ('java','kotlin'): continue
            code = mask(s.text,True)
            package = re.search(r'^\s*package\s+([\w.]+)',code,re.M)
            if package:
                for cls in re.finditer(r'\b(?:class|object|interface)\s+([\w$]+)',code):
                    high_level_classes.add(package[1].replace('.','/')+'/'+cls[1])
        findings = []
        def refine_source(source, found):
            return refine_data_protection(source,refine_entrypoints(source,found,manifests),manifests)
        manifest_observations = {}
        for m in manifests:
            source = manifest_sources[m.path]
            manifest_observations[source.path] = manifest_findings(source,m,sources)
        def analyze_source(s):
            if firebase_input_kind(s):
                return firebase_local(s) if 'Insecure_DataStorage' in cfg.categories else ([], [])
            found = list(manifest_observations.get(s.path,[]))
            if s.language in ('java','kotlin'):
                found.extend(code_findings(s,manifests))
            elif s.language == 'smali':
                # Prefer Java/Kotlin for a matching class to avoid mixed-detail duplicates.
                cls = re.search(r'^\s*\.class\s+[^\n]*?L([^;]+);',s.text,re.M)
                has_high_level = bool(cls and cls[1] in high_level_classes)
                if not has_high_level: found.extend(smali_findings(s))
            if s.language != 'xml' or s.path in xml_valid:
                found.extend(secret_findings(s))
            found = refine_source(s,found)
            source_diagnostics = []
            if 'Insecure_DataStorage' in cfg.categories:
                firebase = firebase_paths(s)
                found.extend(firebase)
                if any(f.properties.get('truncated') for f in firebase):
                    source_diagnostics.append({'level':'warning','code':'FIREBASE_PATHS_TRUNCATED',
                                               'path':s.path,'message':'Firebase path inventory reached its source limit.'})
            return found, source_diagnostics
        with ThreadPoolExecutor(max_workers=cfg.workers,thread_name_prefix='asap-static') as pool:
            futures = [(s,pool.submit(analyze_source,s)) for s in sources]
            for s,future in futures:
                try:
                    source_findings, source_diagnostics = future.result()
                    findings.extend(source_findings)
                    diagnostics.extend(source_diagnostics)
                except Exception as exc:
                    diagnostics.append({'level':'error','code':'RULE_ENGINE_ERROR','path':s.path,
                                        'message':f'Rule evaluation failed ({type(exc).__name__}); results for this file are incomplete.'})
        findings = fingerprint_findings([f for f in findings if f.category in cfg.categories])
        expired = 0
        for f in findings:
            f.baseline_state = 'unchanged' if f.fingerprint in baseline_ids else 'new'
            for suppression in cfg.suppressions:
                if suppression.get('expires') and date.fromisoformat(suppression['expires']) < date.today():
                    continue
                match = suppression.get('fingerprint') == f.fingerprint or (
                    suppression.get('rule_id') == f.rule_id and fnmatch.fnmatchcase(f.evidence[-1].path,suppression.get('path','')))
                if match:
                    f.suppressed = True; f.suppression_reason = suppression['reason']; break
        expired = sum(1 for s in cfg.suppressions if s.get('expires') and date.fromisoformat(s['expires']) < date.today())
        if expired:
            diagnostics.append({'level':'warning','code':'SUPPRESSION_EXPIRED','path':'','message':f'{expired} expired suppressions were ignored.'})
        languages = Counter(s.language for s in sources)
        active = [f for f in findings if not f.suppressed]
        current_ids = {f.fingerprint for f in findings}
        summary = {'total':len(findings),'active':len(active),'suppressed':len(findings)-len(active),
                   'new':sum(f.baseline_state=='new' for f in active),
                   'absent_from_current_scan':len(baseline_ids-current_ids),
                   'by_category':{c:sum(f.category==c for f in active) for c in CATEGORIES},
                   'by_severity':{s:sum(f.severity==s for f in active) for s in reversed(SEVERITIES)},
                   'confirmed_vulnerabilities':0}
        source_hash = hashlib.sha256()
        for s in sources: source_hash.update((s.path+'\0'+s.sha256+'\0').encode())
        coverage = {**prepared.counts,'languages':dict(languages),'enabled_categories':cfg.categories,
                    'enabled_rule_count':sum(r.category in cfg.categories for r in RULES.values()),
                    'status':'partial' if diagnostics else 'analyzed_with_documented_limits',
                    'flow_model':'bounded lexical, intra-method expression tracing; not AST/CFG/path-sensitive',
                    'native_analysis':False,'runtime_validation':False,'network_requests_by_engine':False,
                    'limitations':['No interprocedural/field/alias-complete analysis',
                                   'No complete Kotlin, Smali or Android framework semantic model',
                                   'No reflection, obfuscation recovery, JNI or Flutter native analysis',
                                   'No Gradle variant or split-manifest merge',
                                   'No cryptographic certificate/signature validation or live credential checks',
                                   'No runtime permission, App Links or exploit validation']}
        metadata = {**prepared.metadata,'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),
                    'duration_seconds':round(time.perf_counter()-tic,4),'source_set_sha256':source_hash.hexdigest(),
                    'baseline_used':baseline is not None}
        inventory = {'manifests':[asdict(m) for m in manifests],
                     'files':[{'path':s.path,'language':s.language,'sha256':s.sha256} for s in sources],
                     'native_libraries':prepared.metadata.get('native_libraries',[])}
        return ScanResult('3.0.0',{'name':'ASAP','version':__version__,'research_date':RESEARCH_DATE},
                          metadata,inventory,coverage,findings,diagnostics,summary)


def should_fail(result: ScanResult, threshold: str = 'high', only_new: bool = False) -> bool:
    if threshold == 'none': return False
    if threshold not in SEVERITIES: raise ValueError('invalid severity threshold')
    rank = SEVERITIES.index(threshold)
    return any(not f.suppressed and (not only_new or f.baseline_state=='new') and
               f.kind not in ('inventory','compatibility') and SEVERITIES.index(f.severity)>=rank for f in result.findings)
