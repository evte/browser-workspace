"""API regressions run in subprocesses so import-time DB setup stays isolated."""
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest

PROJECT = Path(__file__).resolve().parents[1]
PREAMBLE = '''
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
import importlib
manager = importlib.import_module('backend.app')
client = TestClient(manager.app)
assert client.post('/api/register', json={
    'email': 'owner@example.test', 'name': 'Owner',
    'password': 'test-api-password-only', 'setup_key': 'test-api-password-only'}).status_code == 200

def import_proxy(address='example.com:8080:user:private-test-password'):
    response = client.post('/api/proxies/import', json={
        'text': address, 'format': 'host_port_auth', 'protocol': 'http'})
    assert response.status_code == 200, response.text
    return response.json()['proxies'][0]
'''


class ProxyAPITests(unittest.TestCase):
    def run_isolated(self, script, legacy_rows=None):
        with tempfile.TemporaryDirectory(prefix='proxy-api-') as root:
            data = Path(root) / 'data'
            novnc = Path(root) / 'novnc'
            data.mkdir()
            novnc.mkdir()
            if legacy_rows is not None:
                with sqlite3.connect(data / 'profiles.sqlite3') as conn:
                    conn.execute('CREATE TABLE profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL, proxy TEXT NOT NULL DEFAULT "")')
                    conn.executemany('INSERT INTO profiles VALUES (?, ?, ?)', legacy_rows)
            env = {**os.environ, 'DATA_DIR': str(data), 'NOVNC_DIR': str(novnc),
                   'ACCESS_PASSWORD': 'test-api-password-only', 'PYTHONPATH': str(PROJECT)}
            result = subprocess.run([sys.executable, '-c', PREAMBLE + textwrap.dedent(script)],
                                    cwd=PROJECT, env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_auth_import_atomicity_and_safe_errors(self):
        self.run_isolated('''
            anonymous = TestClient(manager.app)
            payload = {'text':'example.com:8080:u:s', 'format':'host_port_auth', 'protocol':'http'}
            assert anonymous.get('/api/proxies').status_code == 401
            assert anonymous.post('/api/proxies/import', json=payload).status_code == 401
            assert anonymous.patch('/api/profiles/missing/proxy', json={'proxy_id':None}).status_code == 401
            assert client.post('/api/proxies/import', json=payload,
                headers={'Origin':'https://other.example'}).status_code == 403
            secret = 'private-test-password'
            response = client.post('/api/proxies/import', json={
                'text': 'valid.example:8080:u:' + secret + '\\ninvalid.example:70000:u:' + secret,
                'format':'host_port_auth', 'protocol':'http'})
            assert response.status_code == 422
            assert response.json()['detail']['errors'][0]['line'] == 2
            assert secret not in response.text
            assert client.get('/api/proxies').json() == []
            response = client.post('/api/proxies/import', json={
                'text': {'password':secret}, 'format':'url', 'protocol':'http'})
            assert response.status_code == 422
            assert secret not in response.text
            proxy = import_proxy()
            public = client.get('/api/proxies').json()[0]
            assert proxy['id'] == public['id']
            assert public['has_password'] is True
            assert 'password' not in public and secret not in str(public)
            again = client.post('/api/proxies/import', json={
                'text':'http://user:private-test-password@example.com:8080', 'format':'url', 'protocol':'http'})
            assert again.json()['imported'] == 0 and again.json()['skipped'] == 1
        ''')

    def test_bind_unbind_and_running_conflict(self):
        self.run_isolated('''
            proxy = import_proxy()
            response = client.post('/api/profiles', json={'name':'bound', 'proxy_id':proxy['id']})
            assert response.status_code == 200, response.text
            profile = response.json()
            pid = profile['id']
            assert profile['proxy_id'] == proxy['id']
            assert profile['proxy_display'] == 'http://example.com:8080'
            assert 'private-test-password' not in response.text
            assert 'private-test-password' not in client.get('/api/profiles').text
            response = client.patch(f'/api/profiles/{pid}/proxy', json={'proxy_id':None})
            assert response.status_code == 200
            assert response.json()['proxy_id'] is None and response.json()['proxy_display'] == ''
            response = client.patch(f'/api/profiles/{pid}/proxy', json={'proxy_id':'missing'})
            assert response.status_code == 404
            assert manager.profile_record(pid)['proxy_id'] is None
            response = client.patch(f'/api/profiles/{pid}/proxy', json={'proxy_id':proxy['id']})
            assert response.status_code == 200 and response.json()['proxy_id'] == proxy['id']
            fake_process = Mock()
            fake_process.poll.return_value = None
            manager.running[pid] = {'processes':[fake_process]}
            try:
                response = client.patch(f'/api/profiles/{pid}/proxy', json={'proxy_id':None})
                assert response.status_code == 409
                assert manager.profile_record(pid)['proxy_id'] == proxy['id']
            finally:
                manager.running.clear()
            response = client.post('/api/profiles', json={
                'name':'legacy-caller', 'proxy':'https://user:private-test-password@example.com:443'})
            assert response.status_code == 200 and response.json()['proxy_id']
            assert 'private-test-password' not in response.text
        ''')

    def test_unavailable_isolation_refuses_before_any_process(self):
        self.run_isolated('''
            proxy = import_proxy()
            profile = client.post('/api/profiles', json={'name':'protected', 'proxy_id':proxy['id']}).json()
            with patch.object(manager.sys, 'platform', 'darwin'), patch.object(manager.subprocess, 'Popen') as launch:
                response = client.post(f"/api/profiles/{profile['id']}/start")
                assert response.status_code == 503, response.text
                launch.assert_not_called()
            with patch.object(manager.sys, 'platform', 'linux'), patch.object(manager.os, 'geteuid', return_value=0), \\
                    patch.object(manager.shutil, 'which', return_value=None), patch.object(manager.subprocess, 'Popen') as launch:
                response = client.post(f"/api/profiles/{profile['id']}/start")
                assert response.status_code == 503, response.text
                launch.assert_not_called()
            assert profile['id'] not in manager.running
            assert manager.profile_record(profile['id'])['proxy_id'] == proxy['id']
        ''')

    def test_unreachable_proxy_keeps_binding_and_blocks_browser(self):
        self.run_isolated('''
            import time
            proxy = import_proxy()
            profile = client.post('/api/profiles', json={'name':'protected', 'proxy_id':proxy['id']}).json()
            manager.RUNTIME = manager.DATA / 'runtime'
            with patch.object(manager.sys, 'platform', 'linux'), patch.object(manager.os, 'geteuid', return_value=0), \
                    patch.object(manager.shutil, 'which', return_value='/usr/bin/tool'), patch.object(manager.os, 'chown'), \
                    patch.object(manager.kernels, 'ensure_kernel', return_value='/test/chromium'), \
                    patch.object(manager, 'GatewayRuntime', side_effect=RuntimeError('upstream failed')), \
                    patch.object(manager.subprocess, 'Popen') as launch:
                response = client.post(f"/api/profiles/{profile['id']}/start")
                assert response.status_code == 200, response.text
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    current = client.get('/api/profiles').json()[0]
                    if current['status'] == 'error':
                        break
                    time.sleep(.01)
                assert current['status'] == 'error', current
                launch.assert_not_called()
            current = client.get('/api/profiles').json()[0]
            assert current['status'] == 'error'
            assert current['proxy_id'] == proxy['id']
            assert current['last_error'] and not current['view_url']
            assert profile['id'] not in manager.running
        ''')

    def test_old_schema_and_proxy_migration(self):
        self.run_isolated('''
            profiles = {row['id']:row for row in client.get('/api/profiles').json()}
            assert profiles['old']['proxy_id']
            assert profiles['duplicate']['proxy_id'] == profiles['old']['proxy_id']
            assert profiles['direct']['proxy_id'] is None
            assert 'legacy-private-password' not in str(profiles)
            assert len(client.get('/api/proxies').json()) == 1
            with manager.db() as conn:
                row = conn.execute('SELECT proxy FROM profiles WHERE id = ?', ('old',)).fetchone()
                assert row['proxy'] == ''
                assert (manager.DATA / 'profiles.sqlite3').stat().st_mode & 0o777 == 0o600
            # Import the module twice to verify migration is idempotent.
            manager = importlib.reload(manager)
            client = TestClient(manager.app)
            client.post('/api/login', json={'email':'owner@example.test', 'password':'test-api-password-only'})
            assert len(client.get('/api/proxies').json()) == 1
            assert len(client.get('/api/profiles').json()) == 3
        ''', legacy_rows=[
            ('old', 'Old profile', 'http://user:legacy-private-password@example.com:8080'),
            ('duplicate', 'Same upstream', 'http://user:legacy-private-password@example.com:8080'),
            ('direct', 'Direct profile', ''),
        ])

    def test_malformed_legacy_url_does_not_break_service_start(self):
        self.run_isolated('''
            response = client.get('/api/profiles')
            assert response.status_code == 200
            assert response.json()[0]['status'] == 'error'
            assert client.post('/api/profiles/malformed/start').status_code == 409
        ''', legacy_rows=[('malformed', 'Invalid IPv6 URL', 'http://[bad:80')])

    def test_invalid_legacy_proxy_refuses_start_without_leaking_secret(self):
        self.run_isolated('''
            response = client.get('/api/profiles')
            assert response.status_code == 200
            assert 'legacy-private-password' not in response.text
            assert response.json()[0]['status'] == 'error'
            with patch.object(manager.subprocess, 'Popen') as launch:
                response = client.post('/api/profiles/old/start')
                assert response.status_code == 409
                launch.assert_not_called()
            assert client.patch('/api/profiles/old/proxy', json={'proxy_id':None}).status_code == 200
            assert manager.profile_record('old')['proxy'] == ''
        ''', legacy_rows=[('old', 'Invalid', 'invalid://user:legacy-private-password@host:1234')])


if __name__ == '__main__':
    unittest.main()
