"""Identity persistence and asynchronous startup regressions, without downloads."""
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
import hashlib
import importlib
import io
import json
import tarfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from backend.kernels import KernelError, KernelStore

manager = importlib.import_module('backend.app')
# Every test is offline, including accidental calls outside a mock's scope.
patch('backend.kernels.urllib.request.urlopen', side_effect=AssertionError('Unexpected network access')).start()
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w:xz') as archive:
    item = tarfile.TarInfo('browser/chrome')
    content = b'offline test browser'
    item.size = len(content)
    item.mode = 0o755
    archive.addfile(item, io.BytesIO(content))
archive_data = buffer.getvalue()
KERNEL_ID = 'test-fingerprint-arm64'
catalog = [{
    'id': KERNEL_ID, 'name': 'Offline fingerprint kernel', 'version': '153.0.1.0',
    'architecture': 'arm64', 'engine': 'fingerprint-chromium', 'platforms': ['linux'],
    'supported_platforms': ['linux', 'windows', 'macos'],
    'url': 'https://github.com/babelcloud/fingerprint-chromium-arm64/releases/download/test/browser.tar.xz',
    'sha256': hashlib.sha256(archive_data).hexdigest(), 'download_size': len(archive_data),
    'executable': 'browser/chrome',
}]

def configure_client():
    global client
    manager.kernels = KernelStore(manager.DATA / 'kernels', catalog, 'arm64', 'linux')
    client = TestClient(manager.app)
    if client.get('/api/session').json()['setup_required']:
        response = client.post('/api/register', json={
            'email': 'owner@example.test', 'name': 'Owner',
            'password': 'test-api-password-only', 'setup_key': 'test-api-password-only'})
    else:
        response = client.post('/api/login', json={
            'email': 'owner@example.test', 'password': 'test-api-password-only'})
    assert response.status_code == 200, response.text

configure_client()

def create(name='Profile', **fields):
    response = client.post('/api/profiles', json={'name': name, **fields})
    assert response.status_code == 200, response.text
    return response.json()

def current(profile_id):
    return next(row for row in client.get('/api/profiles').json() if row['id'] == profile_id)

def wait_until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('Timed out waiting for asynchronous startup')

def worker(profile_id):
    name = 'start-' + profile_id[:8]
    return next(thread for thread in threading.enumerate() if thread.name == name)
'''


class FingerprintAPITests(unittest.TestCase):
    def run_isolated(self, script, legacy_rows=None):
        with tempfile.TemporaryDirectory(prefix='fingerprint-api-') as root:
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

    def test_new_identity_is_persisted_and_survives_service_reload(self):
        self.run_isolated('''
            with patch('backend.fingerprints.secrets.randbelow', side_effect=[100, 200]):
                first = create('First')
                second = create('Second')
            assert first['fingerprint']['seed'] == 101
            assert second['fingerprint']['seed'] == 201
            assert first['kernel_id'] == KERNEL_ID
            for profile in (first, second):
                assert current(profile['id'])['fingerprint'] == profile['fingerprint']
                assert manager.profile_record(profile['id'])['fingerprint'] == profile['fingerprint']
            manager = importlib.reload(manager)
            configure_client()
            for profile in (first, second):
                assert current(profile['id'])['fingerprint'] == profile['fingerprint']
        ''')

    def test_legacy_profiles_receive_one_stable_identity_without_switching_kernel(self):
        self.run_isolated('''
            before = {row['id']: row for row in client.get('/api/profiles').json()}
            assert set(before) == {'old-one', 'old-two'}
            for row in before.values():
                assert row['kernel_id'] == 'chromium-system'
                assert 1 <= row['fingerprint']['seed'] <= 2**32 - 1
                assert row['fingerprint']['timezone'] == 'UTC'
            manager = importlib.reload(manager)
            configure_client()
            after = {row['id']: row for row in client.get('/api/profiles').json()}
            for profile_id in before:
                assert after[profile_id]['fingerprint'] == before[profile_id]['fingerprint']
                assert after[profile_id]['kernel_id'] == 'chromium-system'
        ''', legacy_rows=[('old-one', 'One', ''), ('old-two', 'Two', '')])

    def test_partial_settings_preserve_seed_binding_and_unspecified_fields(self):
        self.run_isolated('''
            response = client.post('/api/proxies/import', json={
                'text': 'proxy.example:8080', 'format': 'host_port', 'protocol': 'http'})
            assert response.status_code == 200, response.text
            proxy_id = response.json()['proxies'][0]['id']
            identity = {'seed': 424242, 'platform': 'windows', 'language': 'en-US',
                        'timezone': 'America/New_York', 'hardware_concurrency': 12,
                        'width': 1920, 'height': 1080}
            profile = create(fingerprint=identity, proxy_id=proxy_id)
            pid = profile['id']
            for payload in ({}, {'fingerprint': {}}, {'kernel_id': KERNEL_ID}):
                response = client.patch(f'/api/profiles/{pid}/settings', json=payload)
                assert response.status_code == 200, response.text
                assert response.json()['fingerprint'] == identity
                assert response.json()['proxy_id'] == proxy_id
            response = client.patch(f'/api/profiles/{pid}/settings', json={
                'fingerprint': {'language': 'zh-CN', 'timezone': 'Asia/Shanghai'}})
            assert response.status_code == 200, response.text
            identity.update(language='zh-CN', timezone='Asia/Shanghai')
            assert response.json()['fingerprint'] == identity
            assert response.json()['proxy_id'] == proxy_id
            response = client.patch(f'/api/profiles/{pid}/settings', json={'proxy_id': None})
            assert response.json()['proxy_id'] is None
            assert response.json()['fingerprint'] == identity
            assert manager.profile_record(pid)['fingerprint'] == identity
        ''')

    def test_invalid_identity_and_unknown_kernel_do_not_modify_stored_profile(self):
        self.run_isolated('''
            profile = create(fingerprint={'seed': 12345})
            pid = profile['id']
            invalid = [{'seed': 0}, {'seed': 2**32}, {'platform': 'android'},
                       {'language': 'en-US --flag'}, {'timezone': 'Not/A-Timezone'},
                       {'hardware_concurrency': 0}, {'width': 799}, {'height': 2161}]
            for fingerprint in invalid:
                response = client.post('/api/profiles', json={'name': 'Invalid', 'fingerprint': fingerprint})
                assert response.status_code == 422, (fingerprint, response.text)
                response = client.patch(f'/api/profiles/{pid}/settings', json={'fingerprint': fingerprint})
                assert response.status_code == 422, (fingerprint, response.text)
                assert manager.profile_record(pid)['fingerprint'] == profile['fingerprint']
            response = client.patch(f'/api/profiles/{pid}/settings', json={
                'kernel_id': 'unknown-kernel', 'fingerprint': {'seed': 999}})
            assert response.status_code == 422
            assert manager.profile_record(pid)['kernel_id'] == KERNEL_ID
            assert manager.profile_record(pid)['fingerprint'] == profile['fingerprint']
            assert len(client.get('/api/profiles').json()) == 1
        ''')

    def test_unrelated_settings_do_not_remove_legacy_proxy_guard(self):
        self.run_isolated('''
            pid = 'legacy-protected'
            original = manager.profile_record(pid)
            assert original['proxy'] and original['proxy_id'] is None
            for payload in ({}, {'fingerprint': {'language': 'zh-CN'}}, {'kernel_id': KERNEL_ID}):
                response = client.patch(f'/api/profiles/{pid}/settings', json=payload)
                assert response.status_code == 200, response.text
                assert manager.profile_record(pid)['proxy'] == original['proxy']
                assert response.json()['proxy_needs_configuration'] is True
                assert response.json()['last_error']
                assert 'legacy-private-password' not in response.text
                with patch.object(manager.kernels, 'ensure_kernel') as install, \\
                        patch.object(manager.subprocess, 'Popen') as launch:
                    assert client.post(f'/api/profiles/{pid}/start').status_code == 409
                    install.assert_not_called()
                    launch.assert_not_called()
            # An explicit unbind is the only settings operation that removes the guard.
            response = client.patch(f'/api/profiles/{pid}/settings', json={'proxy_id': None})
            assert response.status_code == 200
            assert manager.profile_record(pid)['proxy'] == ''
            assert response.json()['proxy_needs_configuration'] is False
            assert response.json()['last_error'] is None
        ''', legacy_rows=[('legacy-protected', 'Protected', 'invalid://user:legacy-private-password@host:1234')])

    def test_launch_flags_keep_ua_version_and_persisted_identity_together(self):
        self.run_isolated('''
            profile = create(fingerprint={'seed': 424242, 'platform': 'linux',
                             'language': 'zh-CN', 'timezone': 'Asia/Shanghai'})
            kernel = manager.kernels.get_kernel(KERNEL_ID)
            flags = manager.browser_flags(kernel, profile['fingerprint'])
            assert '--fingerprint=424242' in flags
            assert '--fingerprint-platform=linux' in flags
            assert '--fingerprint-brand=Chrome' in flags
            assert '--fingerprint-brand-version=153.0.1.0' in flags
            assert '--accept-lang=zh-CN,zh' in flags
            assert '--timezone=Asia/Shanghai' in flags
            assert not any(flag.startswith('--user-agent=') for flag in flags)
            assert manager.browser_flags(kernel, manager.profile_record(profile['id'])['fingerprint']) == flags
        ''')

    def test_duplicate_start_and_cancel_do_not_launch_after_download_finishes(self):
        self.run_isolated('''
            profile = create()
            pid = profile['id']
            entered, release = threading.Event(), threading.Event()
            def ensure(kernel_id):
                assert kernel_id == KERNEL_ID
                entered.set()
                assert release.wait(5)
                return '/test/fingerprint-chrome'
            with patch.object(manager.kernels, 'ensure_kernel', side_effect=ensure) as install, \\
                    patch.object(manager, '_launch_profile') as launch:
                try:
                    response = client.post(f'/api/profiles/{pid}/start')
                    assert response.status_code == 200, response.text
                    assert response.json()['status'] == 'downloading'
                    assert entered.wait(2)
                    thread = worker(pid)
                    assert client.post(f'/api/profiles/{pid}/start').status_code == 200
                    assert install.call_count == 1
                    assert client.patch(f'/api/profiles/{pid}/settings', json={'fingerprint': {'seed': 999}}).status_code == 409
                    assert client.patch(f'/api/profiles/{pid}/proxy', json={'proxy_id': None}).status_code == 409
                    assert client.delete(f'/api/profiles/{pid}').status_code == 409
                    response = client.post(f'/api/profiles/{pid}/stop')
                    assert response.status_code == 200 and response.json()['status'] == 'stopped'
                finally:
                    release.set()
                    thread.join(3)
                assert not thread.is_alive()
                launch.assert_not_called()
            assert current(pid)['status'] == 'stopped'
            assert manager.profile_record(pid)['fingerprint'] == profile['fingerprint']
        ''')

    def test_cancel_then_restart_does_not_allow_stale_job_to_launch_or_clear_new_job(self):
        self.run_isolated('''
            pid = create()['id']
            entered = [threading.Event(), threading.Event()]
            release = [threading.Event(), threading.Event()]
            calls = []
            def ensure(kernel_id):
                index = len(calls)
                calls.append(kernel_id)
                entered[index].set()
                assert release[index].wait(5)
                return '/test/fingerprint-chrome'
            with patch.object(manager.kernels, 'ensure_kernel', side_effect=ensure), \\
                    patch.object(manager, '_launch_profile') as launch:
                threads = []
                try:
                    assert client.post(f'/api/profiles/{pid}/start').status_code == 200
                    assert entered[0].wait(2)
                    threads.append(worker(pid))
                    assert client.post(f'/api/profiles/{pid}/stop').status_code == 200
                    assert client.post(f'/api/profiles/{pid}/start').status_code == 200
                    assert entered[1].wait(2)
                    threads.append(next(t for t in threading.enumerate() if t.name == 'start-' + pid[:8] and t is not threads[0]))
                    release[0].set()
                    threads[0].join(3)
                    assert pid in manager.starting
                    launch.assert_not_called()
                    release[1].set()
                    threads[1].join(3)
                    launch.assert_called_once_with(pid, '/test/fingerprint-chrome')
                    assert pid not in manager.starting
                finally:
                    for event in release:
                        event.set()
                    for thread in threads:
                        thread.join(3)
        ''')

    def test_kernel_failure_is_visible_and_never_falls_back_to_system_chromium(self):
        self.run_isolated('''
            profile = create()
            pid = profile['id']
            with patch.object(manager.kernels, 'ensure_kernel', side_effect=KernelError('固定内核校验失败')) as install, \\
                    patch.object(manager, '_launch_profile') as launch, \\
                    patch.object(manager.subprocess, 'Popen') as process:
                response = client.post(f'/api/profiles/{pid}/start')
                assert response.status_code == 200, response.text
                wait_until(lambda: current(pid)['status'] == 'error')
                install.assert_called_once_with(KERNEL_ID)
                launch.assert_not_called()
                process.assert_not_called()
            result = current(pid)
            assert result['last_error'] == '固定内核校验失败'
            assert result['kernel_id'] == KERNEL_ID
            assert result['fingerprint'] == profile['fingerprint']
            assert result['view_url'] is None
        ''')

    def test_browser_startup_failure_does_not_retry_with_a_different_kernel(self):
        self.run_isolated('''
            pid = create()['id']
            with patch.object(manager.kernels, 'ensure_kernel', return_value='/test/fingerprint-chrome') as install, \\
                    patch.object(manager, '_launch_profile', side_effect=manager.HTTPException(503, 'Browser startup failed')) as launch, \\
                    patch.object(manager.subprocess, 'Popen') as process:
                assert client.post(f'/api/profiles/{pid}/start').status_code == 200
                wait_until(lambda: current(pid)['status'] == 'error')
                install.assert_called_once_with(KERNEL_ID)
                launch.assert_called_once_with(pid, '/test/fingerprint-chrome')
                process.assert_not_called()
            result = current(pid)
            assert result['last_error'] == 'Browser startup failed'
            assert result['kernel_id'] == KERNEL_ID and result['view_url'] is None
        ''')

    def test_shared_kernel_download_does_not_block_list_and_cancel_only_affects_one_profile(self):
        self.run_isolated('''
            first, second = create('First'), create('Second')
            entered, release = threading.Event(), threading.Event()
            def download(entry, target):
                entered.set()
                assert release.wait(5)
                target.write_bytes(archive_data)
            real_ensure = manager.kernels.ensure_kernel
            with patch.object(manager.kernels, '_download', side_effect=download) as download_mock, \\
                    patch.object(manager.kernels, '_verify_binary'), \\
                    patch.object(manager.kernels, 'ensure_kernel', wraps=real_ensure) as ensure, \\
                    patch.object(manager, '_launch_profile') as launch:
                threads = []
                try:
                    assert client.post(f"/api/profiles/{first['id']}/start").status_code == 200
                    assert entered.wait(2)
                    threads.append(worker(first['id']))
                    assert client.post(f"/api/profiles/{second['id']}/start").status_code == 200
                    threads.append(worker(second['id']))
                    wait_until(lambda: ensure.call_count == 2)
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        response = pool.submit(client.get, '/api/profiles').result(timeout=1)
                    assert response.status_code == 200
                    assert {row['status'] for row in response.json()} == {'downloading'}
                    assert client.get('/api/kernels').status_code == 200
                    assert client.post(f"/api/profiles/{first['id']}/stop").status_code == 200
                    assert current(second['id'])['status'] == 'downloading'
                finally:
                    release.set()
                    for thread in threads:
                        thread.join(3)
                assert all(not thread.is_alive() for thread in threads)
                assert download_mock.call_count == 1
                assert launch.call_count == 1
                assert launch.call_args.args[0] == second['id']
                assert current(first['id'])['status'] == 'stopped'
                assert manager.kernels.get_kernel(KERNEL_ID)['state'] == 'ready'
        ''')


if __name__ == '__main__':
    unittest.main()
