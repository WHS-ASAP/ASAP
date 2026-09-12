from __future__ import annotations
import fnmatch
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import zipfile
from .axml import decode_axml
from .config import Config
from .model import Source

TEXT_EXT = {'.java':'java', '.kt':'kotlin', '.smali':'smali', '.xml':'xml',
            '.json':'text', '.properties':'text', '.pem':'text', '.key':'text', '.env':'text'}
VENDOR = ('androidx.', 'android.', 'kotlin.', 'kotlinx.', 'com.google.android.',
          'com.google.firebase.', 'org.jetbrains.')


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()


def archive_entries(z: zipfile.ZipFile, cfg: Config) -> list[zipfile.ZipInfo]:
    entries = z.infolist()
    if len(entries) > cfg.max_files: raise ValueError('archive file count limit exceeded')
    total = 0
    seen: set[str] = set()
    for info in entries:
        raw = info.filename
        path = PurePosixPath(raw)
        if ('\\' in raw or '\x00' in raw or path.is_absolute() or '..' in path.parts or
            re.match(r'^[A-Za-z]:', raw) or any(':' in p for p in path.parts)):
            raise ValueError('unsafe archive path')
        if not path.parts or any(p.endswith((' ', '.')) for p in path.parts):
            raise ValueError('ambiguous archive path')
        if any(p.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(10)),*(f'LPT{i}' for i in range(10))} for p in path.parts):
            raise ValueError('reserved archive path')
        key = str(path).casefold()
        if key in seen: raise ValueError('duplicate or case-colliding archive entry')
        seen.add(key)
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
            raise ValueError('archive links and special files are forbidden')
        if info.flag_bits & 1: raise ValueError('encrypted archives are not supported')
        if info.file_size > cfg.max_entry_bytes: raise ValueError('archive entry size limit exceeded')
        if info.file_size > max(1, info.compress_size) * cfg.max_compression_ratio:
            raise ValueError('archive compression ratio limit exceeded')
        total += info.file_size
        if total > cfg.max_archive_bytes: raise ValueError('archive expanded size limit exceeded')
    return entries


def tool_command(tool: str, kind: str, args: list[str]) -> list[str]:
    path = Path(tool).expanduser()
    if path.suffix.lower() == '.jar':
        if kind == 'jadx':
            return ['java', '-Xmx2048m', '-cp', str(path.resolve()), 'jadx.cli.JadxCLI', *args]
        return ['java', '-Xmx2048m', '-jar', str(path.resolve()), *args]
    # Avoid implicit cmd.exe parsing of attacker-controlled arguments on Windows.
    if path.suffix.lower() in ('.bat','.cmd'):
        if kind == 'jadx':
            lib = path.resolve().parent.parent/'lib'
            jars = sorted(lib.glob('*.jar'))
            if not jars: raise ValueError('JADX lib/*.jar not found beside Windows launcher')
            return ['java','-Xmx2048m','-cp',os.pathsep.join(map(str,jars)), 'jadx.cli.JadxCLI', *args]
        jar = path.with_name('apktool.jar')
        if not jar.exists(): raise ValueError('supply the path to apktool.jar on Windows')
        return ['java','-Xmx2048m','-jar',str(jar.resolve()),*args]
    return [str(path.resolve()) if path.exists() else tool, *args]


def run_tool(command: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    # Log to a file, not an unbounded in-memory pipe. Never include raw tool logs in reports.
    with tempfile.TemporaryFile() as log:
        proc = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=(os.name != 'nt'))
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name != 'nt': os.killpg(proc.pid, signal.SIGKILL)
            else: proc.kill()
            proc.wait()
            return -1, 'timeout'
        return code, 'ok' if code == 0 else 'nonzero_exit'

class PreparedInput:
    def __init__(self, path: Path, config: Config):
        self.path = path.expanduser().resolve()
        self.cfg = config
        self.tmp: tempfile.TemporaryDirectory | None = None
        self.diagnostics: list[dict[str,str]] = []
        self.metadata: dict = {'input_name': self.path.name, 'input_kind':'source', 'artifacts':[], 'native_libraries':[]}
        self.counts = {'selected_files':0, 'excluded_files':0, 'vendor_files':0, 'oversized_files':0,
                       'binary_xml_decoded':0, 'unreadable_files':0, 'source_bytes':0}
        self.sources: list[Source] = []
        self.firebase_attachment_paths = {
            Path(value).expanduser().resolve()
            for value in (config.firebase_rules, config.firebase_data) if value
        }

    def warn(self, code: str, message: str, path: str = '') -> None:
        self.diagnostics.append({'level':'warning', 'code':code,'message':message,'path':path})

    def __enter__(self) -> 'PreparedInput':
        try:
            if not self.path.exists(): raise ValueError('input does not exist')
            if self.path.is_dir():
                self._directory(self.path)
            elif self.path.suffix.lower() in ('.apk','.apks','.xapk'):
                self.tmp = tempfile.TemporaryDirectory(prefix='asap-')
                work = Path(self.tmp.name)
                self.metadata['input_kind'] = self.path.suffix.lower()[1:]
                self.metadata['input_sha256'] = sha256_file(self.path)
                if self.path.suffix.lower() == '.apk': self._apk(self.path, work, '')
                else:
                    with zipfile.ZipFile(self.path) as z:
                        entries = archive_entries(z, self.cfg)
                        apks = [i for i in entries if i.filename.lower().endswith('.apk')]
                        if not apks: raise ValueError('split archive contains no APKs')
                        if len(apks) > 128: raise ValueError('split APK limit exceeded')
                        total = 0
                        for n, info in enumerate(apks):
                            total += info.file_size
                            if total > self.cfg.max_archive_bytes: raise ValueError('nested APK budget exceeded')
                            apk = work/f'split-{n}.apk'
                            with z.open(info) as src, apk.open('wb') as dst:
                                shutil.copyfileobj(src, dst, 1024*1024)
                            self._apk(apk, work/f'part-{n}', f'parts/{n:03d}/', info.filename)
            else:
                raise ValueError('input must be a source directory, APK, APKS, or XAPK')
            self._firebase_attachments()
            if not self.sources:
                self.warn('NO_ANALYZABLE_FILES','No supported source or XML files were recovered.')
            return self
        except BaseException:
            if self.tmp: self.tmp.cleanup()
            raise

    def __exit__(self, *_: object) -> None:
        if self.tmp: self.tmp.cleanup()

    def _firebase_attachments(self) -> None:
        if 'Insecure_DataStorage' not in self.cfg.categories:
            return
        for field, name in (('firebase_rules', 'database.rules.json'), ('firebase_data', 'firebase-export.json')):
            configured = getattr(self.cfg, field)
            if not configured:
                continue
            logical_path = '__firebase__/' + name
            if any(source.path == logical_path for source in self.sources):
                raise ValueError('Firebase attachment path collides with an input file: ' + logical_path)
            path = Path(configured).expanduser()
            try:
                if path.is_symlink() or not path.is_file():
                    self.warn('FIREBASE_ATTACHMENT_UNREADABLE', 'Firebase attachment must be a regular local file.', logical_path)
                    continue
                with path.open('rb') as stream:
                    self._add(logical_path, stream.read(self.cfg.max_file_bytes + 1))
            except OSError:
                self.warn('FIREBASE_ATTACHMENT_UNREADABLE', 'Unable to read the configured Firebase attachment.', logical_path)

    def _add(self, path: str, data: bytes) -> None:
        if self.counts['selected_files'] >= self.cfg.max_files:
            raise ValueError('source file count limit exceeded')
        if len(data) > self.cfg.max_file_bytes:
            self.counts['oversized_files'] += 1
            self.warn('FILE_TOO_LARGE','File skipped by configured size limit.',path)
            return
        if any(fnmatch.fnmatchcase(path,p) for p in self.cfg.exclude):
            self.counts['excluded_files'] += 1
            return
        language = TEXT_EXT.get(Path(path).suffix.lower(), 'text')
        try:
            if language == 'xml' and data[:2] == b'\x03\x00':
                text = decode_axml(data)
                self.counts['binary_xml_decoded'] += 1
            else:
                text = data.decode('utf-8-sig')
                if '\x00' in text: raise ValueError('binary text')
        except (UnicodeError, ValueError) as exc:
            self.counts['unreadable_files'] += 1
            self.warn('DECODE_FAILED',f'Unsupported or malformed encoding ({type(exc).__name__}).',path)
            return
        package = re.search(r'^\s*package\s+([\w.]+)', text, re.M) if language in ('java','kotlin') else None
        if not self.cfg.include_vendor and package and package[1].startswith(VENDOR):
            self.counts['vendor_files'] += 1
            return
        self.counts['source_bytes'] += len(data)
        if self.counts['source_bytes'] > self.cfg.max_source_bytes:
            raise ValueError('aggregate source byte limit exceeded')
        self.counts['selected_files'] += 1
        self.sources.append(Source(path,text,language,hashlib.sha256(data).hexdigest()))

    def _directory(self, root: Path, prefix: str = '') -> None:
        visited = 0
        for parent, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in {'.git','node_modules','.gradle','.venv','__pycache__'} and not (Path(parent)/d).is_symlink())
            for filename in sorted(files):
                visited += 1
                if visited > self.cfg.max_files * 4: raise ValueError('directory traversal file budget exceeded')
                file = Path(parent)/filename
                if file.is_symlink():
                    self.warn('SYMLINK_SKIPPED','Symbolic links are not followed.',prefix+file.relative_to(root).as_posix())
                    continue
                # A named attachment has its own artifact role. Do not also feed
                # an in-directory copy through ordinary source/secret analyzers.
                if self.firebase_attachment_paths and file.resolve() in self.firebase_attachment_paths:
                    continue
                if not file.is_file() or file.suffix.lower() not in TEXT_EXT: continue
                name = prefix+file.relative_to(root).as_posix()
                try:
                    if file.stat().st_size > self.cfg.max_file_bytes:
                        self.counts['oversized_files'] += 1
                        self.warn('FILE_TOO_LARGE','File skipped by configured size limit.',name)
                        continue
                    with file.open('rb') as f: self._add(name, f.read(self.cfg.max_file_bytes+1))
                except OSError:
                    self.counts['unreadable_files'] += 1
                    self.warn('READ_FAILED','Unable to read selected source file.',name)

    def _apk(self, apk: Path, work: Path, prefix: str, display_name: str | None = None) -> None:
        work.mkdir(parents=True, exist_ok=True)
        self.metadata['artifacts'].append({'name':display_name or apk.name,'sha256':sha256_file(apk)})
        raw_sources: list[tuple[str,bytes]] = []
        has_dex = False
        raw_bytes = 0
        with zipfile.ZipFile(apk) as z:
            entries = archive_entries(z, self.cfg)
            for info in entries:
                if info.is_dir(): continue
                name = info.filename
                if name.endswith('.dex'): has_dex = True
                if name.startswith('lib/') and name.endswith('.so'):
                    self.metadata['native_libraries'].append({'path':prefix+name,'bytes':info.file_size,'analysis':'not_performed'})
                if Path(name).suffix.lower() in TEXT_EXT and info.file_size <= self.cfg.max_file_bytes:
                    raw_bytes += info.file_size
                    if raw_bytes + self.counts['source_bytes'] > self.cfg.max_source_bytes:
                        raise ValueError('archive text aggregate source byte limit exceeded')
                    raw_sources.append((prefix+'apk/'+name,z.read(info)))
                elif Path(name).suffix.lower() in TEXT_EXT:
                    self.warn('FILE_TOO_LARGE','Archive text file skipped by size limit.',prefix+name)
        jadx = self.cfg.jadx or shutil.which('jadx')
        apktool = self.cfg.apktool or shutil.which('apktool')
        decompiled = False
        if self.cfg.decompile and jadx:
            out = work/'jadx'
            try:
                code, state = run_tool(tool_command(jadx,'jadx',['-d',str(out),str(apk)]),work,self.cfg.tool_timeout)
                self.metadata.setdefault('tools',[]).append({'name':'jadx','status':state,'exit_code':code})
                if out.exists():
                    self._directory(out, prefix+'jadx/')
                    decompiled = any(s.language in ('java','kotlin') and s.path.startswith(prefix+'jadx/') for s in self.sources)
                if code: self.warn('JADX_PARTIAL','JADX failed or produced partial output.',prefix)
            except (OSError,ValueError):
                self.warn('JADX_UNAVAILABLE','JADX could not be started. Check doctor and tool paths.',prefix)
        if has_dex and not decompiled:
            self.warn('DEX_NOT_ANALYZED','DEX code was not decompiled; code-rule coverage is incomplete. Install/configure JADX.',prefix)
        # A configured Apktool is optional for smali and decoded resources.
        if self.cfg.decompile and apktool:
            out = work/'apktool'
            try:
                code, state = run_tool(tool_command(apktool,'apktool',['d','-f','-o',str(out),str(apk)]),work,self.cfg.tool_timeout)
                self.metadata.setdefault('tools',[]).append({'name':'apktool','status':state,'exit_code':code})
                if out.exists(): self._directory(out,prefix+'apktool/')
                if code: self.warn('APKTOOL_PARTIAL','Apktool failed or produced partial output.',prefix)
            except (OSError,ValueError):
                self.warn('APKTOOL_UNAVAILABLE','Apktool could not be started.',prefix)
        # Prefer decoded resources from tools over duplicate raw XML; retain text assets.
        for name,data in raw_sources:
            suffix = name.split('apk/',1)[-1]
            duplicates = [s for s in self.sources if s.path.startswith(prefix) and (s.path.endswith('/'+suffix) or
                          (suffix == 'AndroidManifest.xml' and s.path.endswith('/AndroidManifest.xml')))]
            if not duplicates: self._add(name,data)
        if self.metadata['native_libraries']:
            self.warn('NATIVE_NOT_ANALYZED','Native libraries are inventoried only; JNI/Flutter native behavior is outside this engine.',prefix)
