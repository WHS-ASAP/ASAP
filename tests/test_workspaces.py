"""APK workspace isolation and migration tests using original synthetic inputs."""
from io import BytesIO
import hashlib
import http.client
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import threading
import time
import unittest
import uuid
from unittest.mock import patch
import zipfile

from asap.config import Config
from asap.server import make_server
from asap.storage import Store


def synthetic_apk(marker='first', package='example.workspace'):
    stream = BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr(zipfile.ZipInfo('AndroidManifest.xml'), f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}"><uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/><application android:label="{marker}"/></manifest>')
    return stream.getvalue()


class WorkspaceStoreTests(unittest.TestCase):
    def test_exact_bytes_join_workspace_despite_different_name(self):
        with TemporaryDirectory() as td:
            store = Store(Path(td))
            folder = store.root / 'uploads'
            folder.mkdir()
            identities = []
            for name in ('first.apk', 'renamed.apk'):
                job = uuid.uuid4().hex
                store.create(job, name)
                artifact = folder / (job + '.apk')
                artifact.write_bytes(b'synthetic identical bytes')
                digest, size = store.file_digest(artifact)
                identities.append(store.attach_upload(job, digest, size, artifact.name))
            self.assertEqual(identities[0], identities[1])
            self.assertEqual(len(store.workspaces()), 1)
            self.assertEqual(store.workspace(identities[0])['job_count'], 2)
            self.assertEqual(store.workspace(identities[0])['original_filename'], 'first.apk')

    def test_same_name_different_apk_bytes_remain_separate(self):
        with TemporaryDirectory() as td:
            store = Store(Path(td))
            (store.root / 'uploads').mkdir()
            identities = []
            for data in (b'first synthetic APK', b'second synthetic APK'):
                job = uuid.uuid4().hex
                store.create(job, 'same.apk')
                artifact = store.root / 'uploads' / (job + '.apk')
                artifact.write_bytes(data)
                digest, size = store.file_digest(artifact)
                identities.append(store.attach_upload(job, digest, size, artifact.name))
                store.update_packages(identities[-1], [{'package': 'same.package', 'min_sdk': 26, 'target_sdk': 35}])
            self.assertNotEqual(*identities)
            self.assertEqual([w['job_count'] for w in store.workspaces()], [1, 1])
            self.assertTrue(all(w['package_name'] == 'same.package' for w in store.workspaces()))

    def test_package_ambiguity_and_edit_types(self):
        with TemporaryDirectory() as td:
            store = Store(Path(td))
            workspace_id = store.create(uuid.uuid4().hex, 'fixture.apks')
            store.update_packages(workspace_id, [{'package': 'first.package', 'min_sdk': 26, 'target_sdk': 35},
                                                   {'package': 'second.package', 'min_sdk': 24, 'target_sdk': 34}])
            workspace = store.edit_workspace(workspace_id, {'display_name': '  Review  ', 'note': 'Line one\nLine two', 'archived': True})
            self.assertIsNone(workspace['package_name'])
            self.assertEqual(len(workspace['packages']), 2)
            self.assertEqual(workspace['display_name'], 'Review')
            self.assertIs(workspace['archived'], True)
            for changes in ({}, {'archived': 1}, {'note': None}, {'display_name': ''}, {'display_name': 'a' * 201}, {'note': 'a' * 4001}, {'sha256': 'a' * 64}):
                with self.assertRaises(ValueError):
                    store.edit_workspace(workspace_id, changes)

    def test_migration_retains_reports_groups_known_bytes_and_isolates_missing_inputs(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / 'uploads').mkdir()
            jobs = [uuid.uuid4().hex for _ in range(4)]
            with sqlite3.connect(root / 'asap.sqlite3') as con:
                con.execute('CREATE TABLE jobs (id TEXT PRIMARY KEY,name TEXT NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,message TEXT NOT NULL DEFAULT "",active INTEGER DEFAULT NULL,coverage TEXT DEFAULT NULL)')
                con.execute('PRAGMA user_version=1')
                for index, job in enumerate(jobs):
                    con.execute('INSERT INTO jobs (id,name,state,created_at,updated_at) VALUES (?,?,?,?,?)', (job, 'same.apk', 'completed' if index < 3 else 'queued', f'2026-01-0{index + 1}', f'2026-01-0{index + 1}'))
            for job in jobs[:2]:
                (root / 'uploads' / (job + '.apk')).write_bytes(b'original synthetic retained APK')
            report_dir = root / 'reports' / jobs[0]
            report_dir.mkdir(parents=True)
            report = report_dir / 'report.json'
            report.write_text('{"kept":"original report bytes"}')
            before = report.read_bytes()
            store = Store(root)
            self.assertEqual(len(store.workspaces()), 3)
            self.assertTrue(all('artifact_name' not in item for item in store.workspaces()))
            self.assertEqual(store.get(jobs[0])['workspace_id'], store.get(jobs[1])['workspace_id'])
            self.assertNotEqual(store.get(jobs[2])['workspace_id'], store.get(jobs[3])['workspace_id'])
            self.assertEqual(store.get(jobs[3])['state'], 'interrupted')
            self.assertEqual(report.read_bytes(), before)
            identity = store.get(jobs[0])['workspace_id']
            self.assertTrue(store.workspace(identity)['scan_available'])
            self.assertIsNone(store.workspace(store.get(jobs[2])['workspace_id'])['sha256'])
            self.assertEqual(Store(root).get(jobs[0])['workspace_id'], identity)
            self.assertEqual(report.read_bytes(), before)

    def test_legacy_symlink_input_is_not_followed(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            job = uuid.uuid4().hex
            with sqlite3.connect(root / 'asap.sqlite3') as con:
                con.execute('CREATE TABLE jobs (id TEXT PRIMARY KEY,name TEXT NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,message TEXT NOT NULL DEFAULT "",active INTEGER DEFAULT NULL,coverage TEXT DEFAULT NULL)')
                con.execute('INSERT INTO jobs (id,name,state,created_at,updated_at) VALUES (?,?,?,?,?)', (job, 'fixture.apk', 'completed', '2026-01-01', '2026-01-01'))
            (root / 'uploads').mkdir()
            target = root / 'outside.apk'
            target.write_bytes(b'synthetic symlink target')
            (root / 'uploads' / (job + '.apk')).symlink_to(target)
            store = Store(root)
            workspace = store.workspace(store.get(job)['workspace_id'])
            self.assertTrue(workspace['legacy'])
            self.assertFalse(workspace['scan_available'])
            self.assertIsNone(workspace['sha256'])


class WorkspaceWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.server = make_server(Path(self.tmp.name), 0, Config(decompile=False))
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=.01), daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.auth = {'X-ASAP-Token': self.server.app.token}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server.app.pool.shutdown(wait=True)
        self.thread.join()
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        output = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return output

    def upload(self, data=None, name='fixture.apk'):
        status, _, body = self.request('POST', '/api/upload?name=' + name, data if data is not None else synthetic_apk(), self.auth)
        self.assertEqual(status, 202, body)
        result = json.loads(body)
        self.assertRegex(result['workspace_id'], r'^[a-f0-9]{32}$')
        self.wait_job(result['id'])
        return result

    def wait_job(self, job_id):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            job = self.server.app.store.get(job_id)
            if job['state'] in ('completed', 'failed'):
                self.assertEqual(job['state'], 'completed', job)
                return job
            time.sleep(.01)
        self.fail('Synthetic job timed out')

    def test_uploads_scoped_history_and_report_identity(self):
        first = self.upload(synthetic_apk('first'))
        duplicate = self.upload(synthetic_apk('first'), 'renamed.apk')
        second = self.upload(synthetic_apk('second'))
        self.assertEqual(first['workspace_id'], duplicate['workspace_id'])
        self.assertNotEqual(first['workspace_id'], second['workspace_id'])
        status, _, body = self.request('GET', '/api/workspaces/' + first['workspace_id'])
        self.assertEqual(status, 200)
        detail = json.loads(body)
        self.assertEqual({job['id'] for job in detail['jobs']}, {first['id'], duplicate['id']})
        self.assertEqual(detail['workspace']['job_count'], 2)
        self.assertEqual(detail['workspace']['latest_job']['id'], duplicate['id'])
        self.assertEqual(detail['workspace']['package_name'], 'example.workspace')
        self.assertNotIn('artifact_name', detail['workspace'])
        self.assertEqual(len(json.loads(self.request('GET', '/api/workspaces')[2])), 2)
        report = json.loads(self.request('GET', '/reports/' + first['id'] + '/report.json')[2])
        self.assertEqual(report['scan']['workspace_id'], first['workspace_id'])
        self.assertEqual(report['scan']['apk_sha256'], detail['workspace']['sha256'])
        self.assertEqual(report['scan']['apk_sha256'], hashlib.sha256(synthetic_apk('first')).hexdigest())
        self.assertTrue(all(job['workspace_id'] for job in json.loads(self.request('GET', '/api/jobs')[2])))

    def test_edit_and_rescan_preserve_identity_and_metadata(self):
        initial = self.upload()
        path = '/api/workspaces/' + initial['workspace_id']
        headers = {**self.auth, 'Content-Type': 'application/json'}
        changes = {'display_name': 'APK review', 'note': 'Retain this review\nNext step', 'archived': True}
        status, _, body = self.request('POST', path, json.dumps(changes), headers)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)['workspace']['note'], changes['note'])
        status, _, body = self.request('POST', path + '/scan', b'', self.auth)
        self.assertEqual(status, 202, body)
        again = json.loads(body)
        self.wait_job(again['id'])
        self.assertEqual(again['workspace_id'], initial['workspace_id'])
        self.assertNotEqual(again['id'], initial['id'])
        detail = json.loads(self.request('GET', path)[2])
        self.assertEqual(detail['workspace']['display_name'], 'APK review')
        self.assertTrue(detail['workspace']['archived'])
        self.assertEqual(detail['workspace']['job_count'], 2)
        self.assertEqual(len(list((Path(self.tmp.name) / 'uploads').iterdir())), 1)

    def test_edit_and_rescan_require_csrf_origin_and_host(self):
        initial = self.upload()
        path = '/api/workspaces/' + initial['workspace_id']
        for route in (path, path + '/scan'):
            for headers in ({'Content-Type': 'application/json'},
                            {**self.auth, 'Content-Type': 'application/json', 'Origin': 'https://other.invalid'},
                            {**self.auth, 'Content-Type': 'application/json', 'Host': 'other.invalid'}):
                self.assertEqual(self.request('POST', route, b'{}', headers)[0], 403)

    def test_edit_json_is_bounded_and_strict(self):
        initial = self.upload()
        path = '/api/workspaces/' + initial['workspace_id']
        headers = {**self.auth, 'Content-Type': 'application/json'}
        invalid = [b'[]', b'null', b'{}', b'{"archived":1}', b'{"note":null}', b'{"note":NaN}',
                   b'{"note":Infinity}', b'{"note":1e999}', b'{"archived":false,"archived":true}',
                   b'{"path":"outside.apk"}', b'{"display_name":""}', b'{"note":"\\ud800"}', b'\xff',
                   json.dumps({'note': 'a' * 4001}).encode(), json.dumps({'display_name': 'a' * 201}).encode()]
        for payload in invalid:
            self.assertEqual(self.request('POST', path, payload, headers)[0], 400, payload[:100])
        self.assertEqual(self.request('POST', path, b'x' * (16 * 1024 + 1), headers)[0], 413)
        self.assertEqual(self.request('POST', path, b'{"note":"text"}', self.auth)[0], 415)
        self.assertEqual(self.request('POST', path, b'{}', {**headers, 'Content-Encoding': 'gzip'})[0], 400)
        self.assertEqual(self.request('POST', path, b'{}', {**headers, 'Content-Length': '+2'})[0], 400)
        self.assertEqual(self.request('POST', path + '/scan', b'{"path":"outside.apk"}', headers)[0], 400)

    def test_missing_or_modified_artifact_cannot_be_rescanned(self):
        initial = self.upload()
        identity = initial['workspace_id']
        artifact = self.server.app.store.workspace_input(identity)
        original = artifact.read_bytes()
        artifact.write_bytes(b'changed synthetic input')
        self.assertEqual(self.request('POST', '/api/workspaces/' + identity + '/scan', b'', self.auth)[0], 409)
        artifact.unlink()
        self.assertEqual(self.request('POST', '/api/workspaces/' + identity + '/scan', b'', self.auth)[0], 409)
        self.assertFalse(self.server.app.store.workspace(identity)['scan_available'])
        restored = self.upload(original)
        self.assertEqual(restored['workspace_id'], identity)
        self.assertTrue(self.server.app.store.workspace(identity)['scan_available'])
        self.assertEqual(self.server.app.store.workspace(identity)['job_count'], 2)

    def test_queue_bound_applies_to_rescans_and_uploads(self):
        initial = self.upload()
        with patch.object(self.server.app.store, 'pending', return_value=8):
            self.assertEqual(self.request('POST', '/api/workspaces/' + initial['workspace_id'] + '/scan', b'', self.auth)[0], 429)
            self.assertEqual(self.request('POST', '/api/upload?name=fixture.apk', synthetic_apk(), self.auth)[0], 429)
        self.assertEqual(self.server.app.store.workspace(initial['workspace_id'])['job_count'], 1)

    def test_unknown_and_invalid_workspace_ids_are_not_found(self):
        for identity in ('0' * 32, '../reports', 'x' * 32, '0' * 33):
            self.assertEqual(self.request('GET', '/api/workspaces/' + identity)[0], 404)
            self.assertEqual(self.request('POST', '/api/workspaces/' + identity + '/scan', b'', self.auth)[0], 404)

    def test_workspace_page_substitution_and_csp(self):
        initial = self.upload()
        status, headers, body = self.request('GET', '/workspaces/' + initial['workspace_id'])
        self.assertEqual(status, 200)
        self.assertIn(self.server.app.token.encode(), body)
        self.assertIn(initial['workspace_id'].encode(), body)
        self.assertIn('Content-Security-Policy', headers)
        self.assertEqual(self.request('GET', '/static/workspace.js')[0], 200)
