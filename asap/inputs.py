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
        self._collection_stopped = False
        self.firebase_attachment_paths = {
            Path(value).expanduser().resolve()
            for value in (config.firebase_rules, config.firebase_data) if value
        }

    def warn(self, code: str, message: str, path: str = '') -> None:
        self.diagnostics.append({'level':'warning', 'code':code,'message':message,'path':path})

    def _stop_collection(self, code: str, message: str, path: str = '') -> None:
        if not self._collection_stopped:
            self.warn(code, message + ' Remaining source files were skipped; collected files are still analyzed.', path)
        self._collection_stopped = True

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
        if self._collection_stopped:
            return
        if len(data) > self.cfg.max_file_bytes:
            self.counts['oversized_files'] += 1
            self.warn('FILE_TOO_LARGE','File skipped by configured size limit.',path)
            return
        if any(fnmatch.fnmatchcase(path,p) for p in self.cfg.exclude):
            self.counts['excluded_files'] += 1
            return
        language = TEXT_EXT.get(Path(path).suffix.lower(), 'text')
        binary_xml = language == 'xml' and data[:2] == b'\x03\x00'
        try:
            if binary_xml:
                text = decode_axml(data)
            else:
                text = data.decode('utf-8-sig')
                if '\x00' in text: raise ValueError('binary text')
        except (UnicodeError, ValueError) as exc:
            self.counts['unreadable_files'] += 1
            self.warn('DECODE_FAILED',f'Unsupported or malformed encoding ({type(exc).__name__}).',path)
            return
        package = re.search(r'^\s*package\s+([\w.]+)', text, re.M) if language in ('java','kotlin') else None
        smali_class = re.search(r'^\s*\.class\s+[^\n]*?L([^;]+);', text, re.M) if language == 'smali' else None
        namespace = package[1] if package else smali_class[1].replace('/', '.') if smali_class else ''
        if not self.cfg.include_vendor and namespace.startswith(VENDOR):
            self.counts['vendor_files'] += 1
            return
        if self.counts['selected_files'] >= self.cfg.max_files:
            self._stop_collection('SOURCE_FILES_LIMIT', f'Source file limit reached (max_files={self.cfg.max_files}).', path)
            return
        if self.counts['source_bytes'] + len(data) > self.cfg.max_source_bytes:
            self._stop_collection('SOURCE_BYTES_LIMIT', f'Source byte limit reached (max_source_bytes={self.cfg.max_source_bytes} bytes).', path)
            return
        self.counts['source_bytes'] += len(data)
        self.counts['selected_files'] += 1
        self.counts['binary_xml_decoded'] += int(binary_xml)
        self.sources.append(Source(path,text,language,hashlib.sha256(data).hexdigest()))

    def _directory(self, root: Path, prefix: str = '') -> None:
        if self._collection_stopped:
            return
        visited = 0
        for parent, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted((d for d in dirs if d not in {'.git','node_modules','.gradle','.venv','__pycache__'} and not (Path(parent)/d).is_symlink()),
                             key=lambda d: (d not in {'resources', 'res'}, d))
            for filename in sorted(files, key=lambda name: (name != 'AndroidManifest.xml', name)):
                visited += 1
                if visited > self.cfg.max_files * 4:
                    self._stop_collection('SOURCE_TRAVERSAL_LIMIT', f'Directory traversal limit reached (max_files * 4={self.cfg.max_files * 4}).', prefix)
                    return
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
                    if self._collection_stopped:
                        return
                except OSError:
                    self.counts['unreadable_files'] += 1
                    self.warn('READ_FAILED','Unable to read selected source file.',name)

    def _apk(self, apk: Path, work: Path, prefix: str, display_name: str | None = None) -> None:
        work.mkdir(parents=True, exist_ok=True)
        self.metadata['artifacts'].append({'name':display_name or apk.name,'sha256':sha256_file(apk)})
        # Keep entry references instead of a second in-memory copy of raw assets.
        # The source budget is applied when each fallback file is accepted.
        raw_sources: list[zipfile.ZipInfo] = []
        has_dex = False
        with zipfile.ZipFile(apk) as z:
            entries = archive_entries(z, self.cfg)
            for info in entries:
                if info.is_dir(): continue
                name = info.filename
                if name.endswith('.dex'): has_dex = True
                if name.startswith('lib/') and name.endswith('.so'):
                    self.metadata['native_libraries'].append({'path':prefix+name,'bytes':info.file_size,'analysis':'not_performed'})
                if Path(name).suffix.lower() in TEXT_EXT and info.file_size <= self.cfg.max_file_bytes:
                    raw_sources.append(info)
                elif Path(name).suffix.lower() in TEXT_EXT:
                    self.warn('FILE_TOO_LARGE','Archive text file skipped by size limit.',prefix+name)
        jadx = self.cfg.jadx or shutil.which('jadx')
        apktool = self.cfg.apktool or shutil.which('apktool')
        decompiled = False

        def retain_manifest(out: Path) -> None:
            # Tool output normally supplies a decoded manifest. If it does not,
            # retain the APK manifest before a large source tree fills the budget.
            if any((out / name).is_file() for name in ('AndroidManifest.xml', 'resources/AndroidManifest.xml')):
                return
            if any(s.path.startswith(prefix) and s.path.endswith('/AndroidManifest.xml') for s in self.sources):
                return
            manifest = next((info for info in raw_sources if info.filename == 'AndroidManifest.xml'), None)
            if manifest is not None:
                with zipfile.ZipFile(apk) as z:
                    self._add(prefix + 'apk/AndroidManifest.xml', z.read(manifest))

        def skipped_tool(name: str) -> None:
            self.metadata.setdefault('tools', []).append({'name':name, 'status':'skipped_source_limit'})
            self.warn('TOOL_SKIPPED_SOURCE_LIMIT', f'{name} was skipped because the source collection limit was reached.', prefix)

        def tool_collection_full() -> bool:
            if not self._collection_stopped:
                if self.counts['selected_files'] >= self.cfg.max_files:
                    self._stop_collection('SOURCE_FILES_LIMIT', f'Source file limit reached (max_files={self.cfg.max_files}).', prefix)
                elif self.counts['source_bytes'] >= self.cfg.max_source_bytes:
                    self._stop_collection('SOURCE_BYTES_LIMIT', f'Source byte limit reached (max_source_bytes={self.cfg.max_source_bytes} bytes).', prefix)
            return self._collection_stopped

        if self.cfg.decompile and jadx:
            if tool_collection_full():
                skipped_tool('jadx')
            else:
                out = work/'jadx'
                try:
                    code, state = run_tool(tool_command(jadx,'jadx',['-d',str(out),str(apk)]),work,self.cfg.tool_timeout)
                except (OSError,ValueError):
                    self.warn('JADX_UNAVAILABLE','JADX could not be started. Check doctor and tool paths.',prefix)
                else:
                    self.metadata.setdefault('tools',[]).append({'name':'jadx','status':state,'exit_code':code})
                    if out.exists():
                        retain_manifest(out)
                        self._directory(out, prefix+'jadx/')
                        decompiled = any(s.language in ('java','kotlin') and s.path.startswith(prefix+'jadx/') for s in self.sources)
                    if code: self.warn('JADX_PARTIAL','JADX failed or produced partial output.',prefix)
        if has_dex and not decompiled:
            self.warn('DEX_NOT_ANALYZED','DEX code was not decompiled; code-rule coverage is incomplete. Install/configure JADX.',prefix)
        # A configured Apktool is optional for smali and decoded resources.
        if self.cfg.decompile and apktool:
            if tool_collection_full():
                skipped_tool('apktool')
            else:
                out = work/'apktool'
                try:
                    code, state = run_tool(tool_command(apktool,'apktool',['d','-f','-o',str(out),str(apk)]),work,self.cfg.tool_timeout)
                except (OSError,ValueError):
                    self.warn('APKTOOL_UNAVAILABLE','Apktool could not be started.',prefix)
                else:
                    self.metadata.setdefault('tools',[]).append({'name':'apktool','status':state,'exit_code':code})
                    if out.exists():
                        retain_manifest(out)
                        self._directory(out,prefix+'apktool/')
                    if code: self.warn('APKTOOL_PARTIAL','Apktool failed or produced partial output.',prefix)
        # Prefer decoded resources from tools over duplicate raw XML; retain text assets.
        if not self._collection_stopped:
            raw_names = {info.filename for info in raw_sources}
            duplicate_suffixes: set[str] = set()

            def index_source(path: str) -> None:
                if path.startswith(prefix):
                    for separator in re.finditer('/', path):
                        suffix = path[separator.end():]
                        if suffix in raw_names:
                            duplicate_suffixes.add(suffix)

            for source in self.sources:
                index_source(source.path)
            with zipfile.ZipFile(apk) as z:
                for info in sorted(raw_sources, key=lambda item: (item.filename != 'AndroidManifest.xml', item.filename)):
                    if info.filename in duplicate_suffixes:
                        continue
                    name = prefix + 'apk/' + info.filename
                    before = len(self.sources)
                    self._add(name, z.read(info))
                    if self._collection_stopped:
                        break
                    if len(self.sources) > before:
                        index_source(name)
        if self.metadata['native_libraries']:
            self.warn('NATIVE_NOT_ANALYZED','Native libraries are inventoried only; JNI/Flutter native behavior is outside this engine.',prefix)
