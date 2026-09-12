"""Loopback-only local dashboard. No remote bind, arbitrary-path API, or target execution."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import hashlib
import html
import json
import os
from pathlib import Path
import re
import secrets
import threading
from urllib.parse import urlsplit, parse_qs
import uuid
from .config import Config
from .engine import scan
from .reporting import write_reports
from .storage import Store

WEB = Path(__file__).with_name('web')
MAX_UPLOAD = 512*1024*1024
MAX_JSON = 16*1024

class Dashboard:
    def __init__(self,workspace: Path,cfg: Config):
        self.cfg = cfg
        self.store = Store(workspace)
        self.token = secrets.token_urlsafe(32)
        self.pool = ThreadPoolExecutor(max_workers=1,thread_name_prefix='asap-jobs')
        self.lock = threading.Lock()

    def process(self,id: str,apk: Path) -> None:
        self.store.update(id,'analyzing')
        try:
            job=self.store.get(id)
            workspace=self.store.workspace(job['workspace_id']) if job else None
            if workspace and workspace['sha256'] and self.store.file_digest(apk)[0]!=workspace['sha256']:
                raise ValueError('Retained APK changed before analysis')
            result=scan(apk,self.cfg)
            result.scan['input_name']=job['name'] if job else apk.name
            if job:
                result.scan['workspace_id']=job['workspace_id']
                result.scan['apk_sha256']=workspace['sha256'] if workspace else None
                self.store.update_packages(job['workspace_id'],result.inventory.get('manifests',[]))
            write_reports(result,self.store.root/'reports'/id)
            self.store.update(id,'completed',active=result.summary['active'],coverage=result.coverage['status'])
        except Exception as exc:
            # Do not publish parser messages containing untrusted content or host paths.
            self.store.update(id,'failed',f'Analysis failed ({type(exc).__name__}). Check input integrity, configured limits and tool paths.')


def make_server(workspace: Path,port: int,cfg: Config) -> ThreadingHTTPServer:
    if not 0 <= port <= 65535: raise ValueError('invalid port')
    cfg.validate()
    app=Dashboard(workspace,cfg)
    class Handler(BaseHTTPRequestHandler):
        server_version='ASAP/3.0'
        sys_version=''
        def log_message(self,*args): pass
        def setup(self):
            super().setup()
            self.connection.settimeout(60)
        def allowed(self) -> bool:
            actual=self.server.server_address[1]
            host=self.headers.get('Host','')
            return host in {f'127.0.0.1:{actual}',f'localhost:{actual}'}
        def send(self,status: int,body: bytes,mime: str = 'application/json; charset=utf-8',**headers):
            self.send_response(status)
            self.send_header('Content-Type',mime)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('X-Frame-Options','DENY')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'") if not headers.pop('report',False) else None
            for k,v in headers.items(): self.send_header(k.replace('_','-'),v)
            self.end_headers()
            self.wfile.write(body)
        def json(self,status: int,payload: dict | list):
            self.send(status,json.dumps(payload,ensure_ascii=False).encode())
        def do_GET(self):
            if not self.allowed(): self.json(403,{'error':'Host rejected'});return
            path=urlsplit(self.path).path
            if path=='/':
                body=(WEB/'home.html').read_text(encoding='utf-8').replace('CSRF_TOKEN',html.escape(app.token))
                self.send(200,body.encode(),'text/html; charset=utf-8');return
            m=re.fullmatch(r'/workspaces/([a-f0-9]{32})',path)
            if m:
                if not app.store.workspace(m[1]): self.json(404,{'error':'Workspace not found'});return
                body=(WEB/'workspace.html').read_text(encoding='utf-8').replace('CSRF_TOKEN',html.escape(app.token)).replace('WORKSPACE_ID',m[1])
                self.send(200,body.encode(),'text/html; charset=utf-8');return
            if path in ('/static/style.css','/static/home.js','/static/workspace.js'):
                self.send(200,(WEB/path.rsplit('/',1)[1]).read_bytes(),
                          'text/css; charset=utf-8' if path.endswith('.css') else 'application/javascript; charset=utf-8');return
            if path=='/api/jobs': self.json(200,app.store.list());return
            if path=='/api/workspaces': self.json(200,app.store.workspaces());return
            m=re.fullmatch(r'/api/workspaces/([a-f0-9]{32})',path)
            if m:
                workspace=app.store.workspace(m[1])
                if not workspace: self.json(404,{'error':'Workspace not found'});return
                self.json(200,{'workspace':workspace,'jobs':app.store.workspace_jobs(m[1])});return
            if path=='/api/modules':
                from .guidance import module_catalog
                self.json(200,module_catalog());return
            if path=='/api/health': self.json(200,{'version':'3.0.0','mode':'loopback_only','queue_limit':8});return
            m=re.fullmatch(r'/reports/([a-f0-9]{32})/(report\.(?:html|json|sarif))',path)
            if m:
                job=app.store.get(m[1])
                if not job or job['state']!='completed': self.json(404,{'error':'Report not ready'});return
                file=app.store.root/'reports'/m[1]/m[2]
                if not file.is_file() or file.is_symlink(): self.json(404,{'error':'Missing report'});return
                self.send(200,file.read_bytes(),'text/html; charset=utf-8' if m[2].endswith('.html') else 'application/json; charset=utf-8',report=m[2].endswith('.html'));return
            self.json(404,{'error':'Not found'})
        def body_length(self,maximum: int,minimum: int = 0) -> int | None:
            if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding'):
                self.json(400,{'error':'Encoded/chunked requests are not accepted'});return None
            if len(self.headers.get_all('Content-Length',[]))!=1:
                self.json(411,{'error':'Single Content-Length required'});return None
            raw=self.headers['Content-Length']
            if not re.fullmatch(r'[0-9]{1,20}',raw):
                self.json(400,{'error':'Invalid content length'});return None
            length=int(raw)
            if not minimum <= length <= maximum:
                self.json(413,{'error':f'Request size must be between {minimum} and {maximum} bytes'});return None
            return length
        def read_json(self,allow_empty: bool = False) -> dict | None:
            length=self.body_length(MAX_JSON)
            if length is None: return None
            if allow_empty and length==0: return {}
            if self.headers.get('Content-Type','').split(';',1)[0].strip().lower()!='application/json':
                self.json(415,{'error':'Content-Type application/json required'});return None
            def unique_fields(pairs):
                result={}
                for key,value in pairs:
                    if key in result: raise ValueError('Duplicate JSON field')
                    result[key]=value
                return result
            def reject_constant(value):
                raise ValueError('Non-finite JSON value')
            try:
                raw=self.rfile.read(length)
                if len(raw)!=length: raise ValueError('Incomplete JSON')
                payload=json.loads(raw.decode('utf-8'),object_pairs_hook=unique_fields,parse_constant=reject_constant)
                if not isinstance(payload,dict): raise ValueError('Expected object')
                return payload
            except (ValueError,UnicodeError,RecursionError,OSError):
                self.json(400,{'error':'A valid, finite JSON object is required'});return None
        def do_POST(self):
            if not self.allowed(): self.json(403,{'error':'Host rejected'});return
            actual=self.server.server_address[1]
            origin=self.headers.get('Origin')
            if origin and origin not in {f'http://127.0.0.1:{actual}',f'http://localhost:{actual}'}:
                self.json(403,{'error':'Origin rejected'});return
            if not hmac.compare_digest(self.headers.get('X-ASAP-Token',''),app.token):
                self.json(403,{'error':'CSRF token required'});return
            url=urlsplit(self.path)
            m=re.fullmatch(r'/api/workspaces/([a-f0-9]{32})(/scan)?',url.path)
            if m:
                workspace=app.store.workspace(m[1])
                if not workspace: self.json(404,{'error':'Workspace not found'});return
                payload=self.read_json(allow_empty=bool(m[2]))
                if payload is None: return
                if not m[2]:
                    try: updated=app.store.edit_workspace(m[1],payload)
                    except ValueError as exc: self.json(400,{'error':str(exc)});return
                    self.json(200,{'workspace':updated});return
                if payload:
                    self.json(400,{'error':'Rescan accepts an empty object only'});return
                with app.lock:
                    if app.store.pending()>=8: self.json(429,{'error':'Queue full'});return
                    file=app.store.workspace_input(m[1],verify=True)
                    if file is None:
                        self.json(409,{'error':'Retained APK is missing or changed. Upload the original APK again.'});return
                    id=uuid.uuid4().hex
                    app.store.create(id,workspace['original_filename'],'queued',m[1])
                    try: app.pool.submit(app.process,id,file)
                    except RuntimeError:
                        app.store.update(id,'failed','Analysis queue is unavailable.')
                        self.json(503,{'error':'Analysis queue is unavailable'});return
                self.json(202,{'id':id,'state':'queued','workspace_id':m[1]});return
            if url.path!='/api/upload': self.json(404,{'error':'Not found'});return
            length=self.body_length(MAX_UPLOAD,1)
            if length is None: return
            name=parse_qs(url.query).get('name',['upload.apk'])[0]
            if len(name)>200 or '/' in name or '\\' in name or any(ord(c)<32 for c in name):
                self.json(400,{'error':'Invalid display name'});return
            suffix=Path(name).suffix.lower()
            if suffix not in ('.apk','.apks','.xapk'):
                self.json(400,{'error':'APK, APKS and XAPK only'});return
            id=uuid.uuid4().hex
            with app.lock:
                if app.store.pending()>=8: self.json(429,{'error':'Queue full'});return
                app.store.create(id,name)
            folder=app.store.root/'uploads'
            file=folder/(id+suffix)
            created=False
            try:
                folder.mkdir(exist_ok=True,mode=0o700)
                if folder.is_symlink(): raise ValueError('Invalid upload directory')
                fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                created=True
                digest=hashlib.sha256()
                with os.fdopen(fd,'wb') as f:
                    remaining=length
                    while remaining:
                        block=self.rfile.read(min(remaining,1024*1024))
                        if not block: raise ValueError('incomplete upload')
                        f.write(block);digest.update(block);remaining-=len(block)
                workspace_id=app.store.attach_upload(id,digest.hexdigest(),length,file.name)
                app.store.update(id,'queued')
                app.pool.submit(app.process,id,file)
            except Exception as exc:
                app.store.update(id,'failed',f'Upload failed ({type(exc).__name__}).')
                if created:
                    try: file.unlink(missing_ok=True)
                    except OSError: pass
                self.json(400,{'error':'Upload did not complete'})
                return
            # A disconnected client must not cancel or delete an already queued input.
            self.json(202,{'id':id,'state':'queued','workspace_id':workspace_id})
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.daemon_threads=True
    server.app=app
    return server


def serve(workspace: Path,port: int,cfg: Config) -> None:
    server=make_server(workspace,port,cfg)
    print(f'ASAP 3 dashboard: http://127.0.0.1:{server.server_address[1]}')
    print('Local use only. Uploads/reports remain in the selected workspace. Ctrl+C to stop.')
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        server.server_close()
        server.app.pool.shutdown(wait=True,cancel_futures=True)
