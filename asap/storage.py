from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid


class Store:
    """APK identities and local job metadata; raw source is never stored here."""
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = self.root / 'asap.sqlite3'
        with self.connect() as con:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('BEGIN IMMEDIATE')
            con.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, name TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, message TEXT NOT NULL DEFAULT "", active INTEGER DEFAULT NULL, coverage TEXT DEFAULT NULL)')
            con.execute('''CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY, sha256 TEXT UNIQUE, display_name TEXT NOT NULL,
                original_filename TEXT NOT NULL, size_bytes INTEGER,
                note TEXT NOT NULL DEFAULT '', archived INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                packages TEXT NOT NULL DEFAULT '[]', artifact_name TEXT,
                legacy INTEGER NOT NULL DEFAULT 1)''')
            if 'workspace_id' not in {r['name'] for r in con.execute('PRAGMA table_info(jobs)')}:
                con.execute('ALTER TABLE jobs ADD COLUMN workspace_id TEXT REFERENCES workspaces(id)')
            con.execute('CREATE INDEX IF NOT EXISTS jobs_workspace_created ON jobs(workspace_id, created_at)')
            for job in con.execute('SELECT * FROM jobs WHERE workspace_id IS NULL').fetchall():
                self._migrate_job(con, dict(job))
            con.execute('PRAGMA user_version=2')
            con.execute("UPDATE jobs SET state='interrupted', message='Previous process stopped before completion.' WHERE state IN ('uploading','queued','analyzing')")

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.db, timeout=20)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _input_path(self, artifact_name: str | None) -> Path | None:
        if not artifact_name or not re.fullmatch(r'[a-f0-9]{32}\.(?:apk|apks|xapk)', artifact_name):
            return None
        folder = self.root / 'uploads'
        path = folder / artifact_name
        try:
            if folder.is_symlink() or not folder.is_dir() or path.is_symlink():
                return None
            if not stat.S_ISREG(path.stat().st_mode):
                return None
            return path
        except OSError:
            return None

    @staticmethod
    def file_digest(path: Path) -> tuple[str, int]:
        digest = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('Input must be a regular file')
            size = 0
            while block := stream.read(1024 * 1024):
                digest.update(block)
                size += len(block)
        return digest.hexdigest(), size

    def _insert_workspace(self, con, name: str, created_at: str, updated_at: str) -> str:
        workspace_id = uuid.uuid4().hex
        con.execute('INSERT INTO workspaces (id,display_name,original_filename,created_at,updated_at) VALUES (?,?,?,?,?)',
                    (workspace_id, name, name, created_at, updated_at))
        return workspace_id

    def _migrate_job(self, con, job: dict) -> None:
        artifact_name = None
        digest = None
        size = None
        if re.fullmatch(r'[a-f0-9]{32}', job['id']):
            for suffix in ('.apk', '.apks', '.xapk'):
                candidate = job['id'] + suffix
                path = self._input_path(candidate)
                if path:
                    try:
                        digest, size = self.file_digest(path)
                        artifact_name = candidate
                        break
                    except (OSError, ValueError):
                        continue
        row = con.execute('SELECT id FROM workspaces WHERE sha256=?', (digest,)).fetchone() if digest else None
        workspace_id = row['id'] if row else self._insert_workspace(con, job['name'], job['created_at'], job['updated_at'])
        if not row and digest:
            con.execute('UPDATE workspaces SET sha256=?,size_bytes=?,artifact_name=?,legacy=0 WHERE id=?',
                        (digest, size, artifact_name, workspace_id))
        con.execute('UPDATE jobs SET workspace_id=? WHERE id=?', (workspace_id, job['id']))
        con.execute('UPDATE workspaces SET created_at=MIN(created_at,?),updated_at=MAX(updated_at,?) WHERE id=?',
                    (job['created_at'], job['updated_at'], workspace_id))

    def create(self, id: str, name: str, state: str = 'uploading', workspace_id: str | None = None) -> str:
        now = self.now()
        with self.connect() as con:
            if workspace_id is None:
                workspace_id = self._insert_workspace(con, name, now, now)
            con.execute('INSERT INTO jobs (id,name,state,created_at,updated_at,workspace_id) VALUES (?,?,?,?,?,?)',
                        (id, name, state, now, now, workspace_id))
            con.execute('UPDATE workspaces SET updated_at=? WHERE id=?', (now, workspace_id))
        return workspace_id

    def attach_upload(self, job_id: str, digest: str, size: int, artifact_name: str) -> str:
        """Promote the upload's provisional workspace or join its exact APK identity."""
        if not re.fullmatch(r'[a-f0-9]{64}', digest) or self._input_path(artifact_name) is None:
            raise ValueError('Invalid uploaded artifact')
        now = self.now()
        with self.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            job = con.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            if job is None:
                raise ValueError('Missing upload job')
            previous_id = job['workspace_id']
            existing = con.execute('SELECT * FROM workspaces WHERE sha256=?', (digest,)).fetchone()
            if existing:
                workspace_id = existing['id']
                # The newly verified upload also repairs a missing or locally modified copy.
                con.execute('UPDATE workspaces SET artifact_name=? WHERE id=?', (artifact_name, workspace_id))
                con.execute('UPDATE jobs SET workspace_id=? WHERE id=?', (workspace_id, job_id))
                if previous_id != workspace_id:
                    # Only discard this upload's empty provisional metadata, never jobs or reports.
                    con.execute('''DELETE FROM workspaces WHERE id=? AND sha256 IS NULL AND note='' AND archived=0
                                   AND display_name=original_filename
                                   AND NOT EXISTS (SELECT 1 FROM jobs WHERE workspace_id=?)''', (previous_id, previous_id))
            else:
                workspace_id = previous_id
                con.execute('UPDATE workspaces SET sha256=?,size_bytes=?,artifact_name=?,legacy=0 WHERE id=?',
                            (digest, size, artifact_name, workspace_id))
            con.execute('UPDATE workspaces SET updated_at=? WHERE id=?', (now, workspace_id))
        return workspace_id

    def update(self, id: str, state: str, message: str = '', active: int | None = None, coverage: str | None = None) -> None:
        now = self.now()
        with self.connect() as con:
            con.execute('UPDATE jobs SET state=?,message=?,active=?,coverage=?,updated_at=? WHERE id=?',
                        (state, message, active, coverage, now, id))
            con.execute('UPDATE workspaces SET updated_at=? WHERE id=(SELECT workspace_id FROM jobs WHERE id=?)', (now, id))

    def get(self, id: str) -> dict | None:
        with self.connect() as con:
            row = con.execute('SELECT * FROM jobs WHERE id=?', (id,)).fetchone()
            return dict(row) if row else None

    def list(self) -> list[dict]:
        with self.connect() as con:
            return [dict(r) for r in con.execute('SELECT * FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT 100')]

    def pending(self) -> int:
        with self.connect() as con:
            return con.execute("SELECT COUNT(*) FROM jobs WHERE state IN ('uploading','queued','analyzing')").fetchone()[0]

    def _workspace_public(self, con, row) -> dict:
        data = dict(row)
        artifact_name = data.pop('artifact_name')
        data['scan_available'] = bool(data['sha256'] and self._input_path(artifact_name))
        data['archived'] = bool(data['archived'])
        data['legacy'] = bool(data['legacy'])
        data['packages'] = json.loads(data['packages'])
        names = sorted({p['name'] for p in data['packages'] if p.get('name')})
        data['package_name'] = names[0] if len(names) == 1 else None
        data['job_count'] = con.execute('SELECT COUNT(*) FROM jobs WHERE workspace_id=?', (data['id'],)).fetchone()[0]
        latest = con.execute('SELECT * FROM jobs WHERE workspace_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1', (data['id'],)).fetchone()
        data['latest_job'] = dict(latest) if latest else None
        return data

    def workspaces(self) -> list[dict]:
        with self.connect() as con:
            return [self._workspace_public(con, row) for row in con.execute('SELECT * FROM workspaces ORDER BY updated_at DESC, id DESC').fetchall()]

    def workspace(self, id: str) -> dict | None:
        with self.connect() as con:
            row = con.execute('SELECT * FROM workspaces WHERE id=?', (id,)).fetchone()
            return self._workspace_public(con, row) if row else None

    def workspace_jobs(self, id: str) -> list[dict]:
        with self.connect() as con:
            return [dict(row) for row in con.execute('SELECT * FROM jobs WHERE workspace_id=? ORDER BY created_at DESC, rowid DESC', (id,))]

    def edit_workspace(self, id: str, changes: dict) -> dict | None:
        if not changes or set(changes) - {'display_name', 'note', 'archived'}:
            raise ValueError('Use display_name, note or archived fields')
        if 'display_name' in changes:
            name = changes['display_name']
            if not isinstance(name, str) or not name.strip() or len(name) > 200 or any(ord(c) < 32 for c in name):
                raise ValueError('Display name must contain 1–200 printable characters')
            changes = {**changes, 'display_name': name.strip()}
        if 'note' in changes:
            note = changes['note']
            if not isinstance(note, str) or len(note) > 4000 or any(ord(c) < 32 and c not in '\n\r\t' for c in note):
                raise ValueError('Note must contain at most 4000 characters')
        if 'archived' in changes and type(changes['archived']) is not bool:
            raise ValueError('Archived must be a boolean')
        try:
            for key in ('display_name', 'note'):
                if key in changes:
                    changes[key].encode('utf-8')
        except UnicodeError:
            raise ValueError('Text must contain valid Unicode characters') from None
        columns = ','.join(key + '=?' for key in changes)
        with self.connect() as con:
            con.execute(f'UPDATE workspaces SET {columns},updated_at=? WHERE id=?', (*changes.values(), self.now(), id))
        return self.workspace(id)

    def update_packages(self, id: str, manifests: list[dict]) -> None:
        packages = []
        for manifest in manifests:
            name = manifest.get('package')
            if not isinstance(name, str) or not name or len(name) > 300:
                continue
            item = {'name': name}
            for key in ('min_sdk', 'target_sdk'):
                value = manifest.get(key)
                item[key] = value if type(value) is int and 0 <= value <= 100000 else None
            if item not in packages:
                packages.append(item)
        packages.sort(key=lambda item: (item['name'], item['min_sdk'] or -1, item['target_sdk'] or -1))
        with self.connect() as con:
            con.execute('UPDATE workspaces SET packages=?,updated_at=? WHERE id=?',
                        (json.dumps(packages, ensure_ascii=False), self.now(), id))

    def workspace_input(self, id: str, verify: bool = False) -> Path | None:
        with self.connect() as con:
            row = con.execute('SELECT sha256,artifact_name FROM workspaces WHERE id=?', (id,)).fetchone()
        if not row or not row['sha256']:
            return None
        path = self._input_path(row['artifact_name'])
        if path and verify:
            try:
                if self.file_digest(path)[0] != row['sha256']:
                    return None
            except (OSError, ValueError):
                return None
        return path
