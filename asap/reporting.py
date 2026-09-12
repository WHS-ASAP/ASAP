from __future__ import annotations
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import quote
from .model import ScanResult
from .rules.registry import RULES
from .guidance import module_catalog


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.asap-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name,path)
    except BaseException:
        try: os.unlink(name)
        except OSError: pass
        raise


def sarif(result: ScanResult) -> dict:
    used = sorted({f.rule_id for f in result.findings})
    rules = []
    for id in used:
        r = RULES[id]
        rules.append({'id':id,'shortDescription':{'text':r.title},'fullDescription':{'text':r.description},
                      'help':{'text':r.remediation},'helpUri':r.references[0],
                      'properties':{'tags':[r.category,r.cwe,r.masvs]}})
    results = []
    for f in result.findings:
        obs = f.evidence[-1]
        def location(e):
            return {'physicalLocation':{'artifactLocation':{'uri':quote(e.path,safe='/')},
                                        'region':{'startLine':max(1,e.line),'endLine':max(e.line,e.end_line)}}}
        entry = {'ruleId':f.rule_id,'ruleIndex':used.index(f.rule_id),
                 'level':{'critical':'error','high':'error','medium':'warning','low':'note','info':'note'}[f.severity],
                 'message':{'text':f.message},'locations':[location(obs)],
                 'partialFingerprints':{'asap/v3':f.fingerprint},
                 'baselineState':f.baseline_state,
                 'properties':{'severity':f.severity,'confidence':f.confidence,'category':f.category,'kind':f.kind,
                               'runtimeValidated':False,'remediation':f.remediation}}
        if len(f.evidence)>1:
            entry['codeFlows'] = [{'threadFlows':[{'locations':[{'location':location(e),'executionOrder':i+1} for i,e in enumerate(f.evidence)]}]}]
        if f.suppressed: entry['suppressions'] = [{'kind':'external','justification':f.suppression_reason}]
        results.append(entry)
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json',
            'runs':[{'tool':{'driver':{'name':'ASAP','version':result.tool['version'],'rules':rules}},
                     'results':results,'invocations':[{'executionSuccessful':not any(d['level']=='error' for d in result.diagnostics),
                     'toolExecutionNotifications':[{'level':'error' if d['level']=='error' else 'warning','message':{'text':d['code']+': '+d['message']}} for d in result.diagnostics]}],
                     'properties':{'coverage':result.coverage,'researchDate':result.tool['research_date']}}]}


def render_html(data: dict) -> str:
    directory = Path(__file__).with_name('web')
    template = (directory/'report.html').read_text(encoding='utf-8')
    css = (directory/'style.css').read_text(encoding='utf-8')
    js = (directory/'report.js').read_text(encoding='utf-8')
    payload = json.dumps(data,ensure_ascii=False).replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e')
    digest = base64.b64encode(hashlib.sha256(js.encode()).digest()).decode()
    guides = json.dumps(module_catalog(),ensure_ascii=False).replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e')
    return template.replace('<!--STYLE-->',css).replace('<!--DATA-->',payload).replace('<!--GUIDES-->',guides).replace('<!--SCRIPT-->',js).replace('SCRIPT_HASH',digest)


def write_reports(result: ScanResult, out: Path, legacy: bool = False) -> dict[str,str]:
    data = result.to_dict()
    files = {'json':out/'report.json','sarif':out/'report.sarif','html':out/'report.html'}
    atomic_write(files['json'],json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    atomic_write(files['sarif'],json.dumps(sarif(result),ensure_ascii=False,indent=2)+'\n')
    atomic_write(files['html'],render_html(data))
    if legacy:
        aliases = {'SQL_Injection':'SQLInjectionAnalyzer','WebView':'WebViewAnalyzer','DeepLink':'DeepLinkAnalyzer',
                   'HardCoded':'HardCodedAnalyzer','Permission':'PermissionAnalyzer','Insecure_DataStorage':'CryptoAnalyzer','Insecure_Logging':'LogAnalyzer'}
        old = [{'File':f.evidence[-1].path,'Analyzer':aliases[f.category],
                'Result':f'{f.rule_id}: {f.title} | {f.message}'} for f in result.findings]
        files['legacy'] = out/'legacy_findings.json'
        atomic_write(files['legacy'],json.dumps(old,ensure_ascii=False,indent=2)+'\n')
    return {k:str(v) for k,v in files.items()}
