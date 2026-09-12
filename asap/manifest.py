from __future__ import annotations
from pathlib import PurePosixPath
import xml.etree.ElementTree as ET
import re
from .model import Manifest, Source
from .text import mask
from .xmlutil import safe_xml, android_attrs, attrs, boolean, sdk


def qualify(name: str, package: str) -> str:
    if not name: return ''
    if name.startswith('.'): return package+name
    return package+'.'+name if '.' not in name and package else name


def exported_value(component: dict, target: int | None) -> tuple[bool | None, str]:
    explicit = boolean(component.get('exported'))
    if component.get('exported') is not None:
        return explicit, 'explicit' if explicit is not None else 'unresolved_resource'
    if component['type'] == 'provider':
        return ((False if target >= 17 else True), 'target_default') if target else (None, 'unknown_target')
    if target is not None and target >= 31 and component['filters']:
        return None, 'missing_required_exported'
    return bool(component['filters']), 'legacy_filter_default'


def parse_manifest(source: Source, resources: dict[str,str] | None = None) -> Manifest:
    root = safe_xml(source.text)
    if root.tag != 'manifest': raise ValueError('root is not manifest')
    package = root.get('package','')
    uses = root.find('uses-sdk')
    uses_values = android_attrs(uses) if uses is not None else {}
    # Do not guess merged SDK values for source projects with Gradle overrides.
    min_sdk = sdk(uses_values.get('minSdkVersion'))
    target = sdk(uses_values.get('targetSdkVersion'))
    app = root.find('application')
    application = android_attrs(app) if app is not None else {}
    permissions = [android_attrs(n) for n in root if n.tag in ('uses-permission','uses-permission-sdk-23')]
    declared = {android_attrs(n).get('name',''):android_attrs(n).get('protectionLevel','normal') for n in root.findall('permission')}
    components = []
    for node in list(app) if app is not None else []:
        if node.tag not in ('activity','activity-alias','service','receiver','provider'): continue
        c = android_attrs(node)
        c.update({'type':node.tag,'filters':[]})
        c['name'] = qualify(c.get('name',''),package)
        if c.get('targetActivity'): c['targetActivity'] = qualify(c['targetActivity'],package)
        inherited = application.get('permission')
        if 'permission' not in c and inherited: c['permission'] = inherited
        for intent in node.findall('intent-filter'):
            f = {'autoVerify':boolean(android_attrs(intent).get('autoVerify')),
                 'actions':[android_attrs(n).get('name','') for n in intent.findall('action')],
                 'categories':[android_attrs(n).get('name','') for n in intent.findall('category')],
                 'data':[android_attrs(n) for n in intent.findall('data')]}
            for d in f['data']:
                for k,v in list(d.items()):
                    if resources and v.startswith('@string/'):
                        d[k] = resources.get(v[8:],v)
            c['filters'].append(f)
        c['path_permissions'] = [android_attrs(n) for n in node.findall('path-permission')]
        c['grant_uri_permissions'] = [android_attrs(n) for n in node.findall('grant-uri-permission')]
        c['effective_exported'], c['exported_basis'] = exported_value(c,target)
        enabled = [boolean(c.get('enabled','true')), boolean(application.get('enabled','true'))]
        c['effective_enabled'] = False if False in enabled else (None if None in enabled else True)
        components.append(c)
    return Manifest(source.path,package,min_sdk,target,application,permissions,declared,components)


def resources_for(source: Source, all_sources: list[Source]) -> dict[str,str]:
    # Only the manifest's resource root: never mix modules, split APKs or variants.
    parent = PurePosixPath(source.path).parent
    root_prefix = '' if str(parent) == '.' else str(parent) + '/'
    candidates = [s for s in all_sources if re.fullmatch(re.escape(root_prefix)+r'res/values/[^/]+\.xml',s.path)]
    values: dict[str,set[str]] = {}
    for s in sorted(candidates,key=lambda x:x.path):
        try:
            root = safe_xml(s.text)
            for e in root.findall('string'):
                if e.get('name') and e.text:
                    values.setdefault(e.get('name'),set()).add(e.text)
        except (ValueError, ET.ParseError):
            continue
    return {key:next(iter(items)) for key,items in values.items() if len(items)==1}


def component_context(source: Source, manifests: list[Manifest]) -> dict:
    package = re.search(r'^\s*package\s+([\w.]+)',mask(source.text,True),re.M)
    cls = re.search(r'\b(?:class|object)\s+(\w+)',mask(source.text,True))
    fq = (package[1]+'.' if package else '')+(cls[1] if cls else '')
    matches = [(m,c) for m in manifests for c in m.components if fq and fq in (c['name'],c.get('targetActivity'))]
    targets = {m.target_sdk for m in manifests if m.target_sdk is not None}
    context = {'target_sdk':next(iter(targets)) if len(targets)==1 else None,
               'component':None,'external_reachability':'not_established',
               'analysis':'lexical_local_flow; not path-sensitive or interprocedural'}
    if matches:
        m,c = matches[0]
        context.update({'component':c['name'],'target_sdk':m.target_sdk,
                        'exported':c['effective_exported'],'permission':c.get('permission'),
                        'external_reachability':'manifest_exposure_only' if c['effective_exported'] and c['effective_enabled'] else 'not_established'})
    return context
