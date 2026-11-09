"""Team/profile authorization boundaries; all DBs and browser runtimes are isolated.

Password hashing has its own real-scrypt tests. These authorization scenarios use
a cheap test-only hash so membership and concurrent revocation checks stay fast.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

PROJECT = Path(__file__).resolve().parents[1]
PREAMBLE = '''
import asyncio
import hashlib
import hmac
import importlib
import threading
import time
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

account_module = importlib.import_module('backend.accounts')
def quick_hash(password):
    return 'test-only$' + hashlib.sha256(password.encode()).hexdigest()
patch.object(account_module, 'hash_password', side_effect=quick_hash).start()
patch.object(account_module, 'verify_password', side_effect=lambda password, stored: hmac.compare_digest(quick_hash(password), stored)).start()
patch('backend.kernels.urllib.request.urlopen', side_effect=AssertionError('Unexpected network access')).start()
manager = importlib.import_module('backend.app')
PASSWORD = 'team-test-password-only'

def register(name, first=False):
    client = TestClient(manager.app)
    payload = {'name': name, 'email': name.lower() + '@example.test', 'password': PASSWORD}
    if first:
        payload['setup_key'] = PASSWORD
    response = client.post('/api/register', json=payload)
    assert response.status_code == 200, response.text
    session = response.json()
    client.headers['X-Team-ID'] = session['active_team_id']
    return client, session['user'], session['active_team_id']

owner, owner_user, team = register('Owner', first=True)
outsider, outsider_user, other_team = register('Outsider')
member, member_user, member_home = register('Member')

def join(client, user, role='member'):
    response = owner.post(f'/api/teams/{team}/invitations', json={'email': user['email'], 'role': role})
    assert response.status_code == 200, response.text
    accepted = client.post('/api/invitations/accept', json={'token': response.json()['token']})
    assert accepted.status_code == 200, accepted.text
    client.headers['X-Team-ID'] = team

join(member, member_user)

def create(client=owner, **fields):
    payload = {'name': 'Private environment', 'kernel_id': 'chromium-system', **fields}
    response = client.post('/api/profiles', json=payload)
    assert response.status_code == 200, response.text
    return response.json()

def assign(profile_ids, user_ids):
    return owner.post('/api/profiles/assign', json={'profile_ids': profile_ids, 'user_ids': user_ids})

def row(profile_id, client=owner):
    response = client.get(f'/api/profiles/{profile_id}')
    assert response.status_code == 200, response.text
    return response.json()

def proxy(client=owner):
    response = client.post('/api/proxies/import', json={
        'text': 'shared.example:8080:user:private-proxy-password',
        'format': 'host_port_auth', 'protocol': 'http'})
    assert response.status_code == 200, response.text
    return response.json()['proxies'][0]

def denied_socket(client, profile_id):
    try:
        with client.websocket_connect(f'/api/profiles/{profile_id}/ws', headers={'Origin': 'http://testserver'}):
            raise AssertionError('Unauthorized WebSocket accepted')
    except WebSocketDisconnect as exc:
        assert exc.code == 1008, exc.code

def wait_until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('Timed out waiting for permission revocation')

class FakeUpstream:
    def __init__(self):
        self.frames = 0
        self.sent = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, *exc):
        return False
    def __aiter__(self):
        return self
    async def __anext__(self):
        if not self.frames:
            self.frames += 1
            return b'authorized-frame'
        await asyncio.Future()
    async def send(self, data):
        self.sent.append(data)

def active_runtime(profile_id):
    process = Mock()
    process.poll.return_value = None
    manager.running[profile_id] = {'processes': [process], 'port': 19999,
        'generation': 'test-generation', 'user_id': owner_user['id'], 'started_by': owner_user['id']}
'''


class TeamAccessTests(unittest.TestCase):
    def run_isolated(self, script):
        with tempfile.TemporaryDirectory(prefix='team-access-') as root:
            data, novnc = Path(root) / 'data', Path(root) / 'novnc'
            data.mkdir()
            novnc.mkdir()
            env = {**os.environ, 'DATA_DIR': str(data), 'NOVNC_DIR': str(novnc),
                   'ACCESS_PASSWORD': 'team-test-password-only', 'PYTHONPATH': str(PROJECT)}
            result = subprocess.run([sys.executable, '-c', PREAMBLE + textwrap.dedent(script)],
                                    cwd=PROJECT, env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cross_team_ids_never_read_or_mutate_environments(self):
        self.run_isolated('''
            protected = create(notes='private team note', tags=['private-team'])
            foreign = create(outsider, name='Other team')
            pid = protected['id']
            assert protected['team_id'] == team and foreign['team_id'] == other_team
            assert {p['id'] for p in outsider.get('/api/profiles').json()} == {foreign['id']}
            assert outsider.get('/api/profiles', headers={'X-Team-ID': team}).status_code in (403, 404)
            requests = [
                ('GET', f'/api/profiles/{pid}', None),
                ('PATCH', f'/api/profiles/{pid}/metadata', {'tags': ['stolen'], 'notes': 'changed'}),
                ('PATCH', f'/api/profiles/{pid}/settings', {'name': 'changed'}),
                ('PATCH', f'/api/profiles/{pid}/proxy', {'proxy_id': None}),
                ('POST', f'/api/profiles/{pid}/start', None),
                ('POST', f'/api/profiles/{pid}/stop', None),
                ('DELETE', f'/api/profiles/{pid}', None),
            ]
            with patch.object(manager.kernels, 'ensure_kernel') as install, patch.object(manager, 'stop_running') as stop:
                for method, path, body in requests:
                    response = outsider.request(method, path, json=body)
                    assert response.status_code == 404, (method, path, response.status_code, response.text)
                    assert 'private team note' not in response.text
                install.assert_not_called()
                stop.assert_not_called()
            active_runtime(pid)
            try:
                with patch.object(manager.websockets, 'connect', return_value=FakeUpstream()) as connect:
                    denied_socket(outsider, pid)
                    connect.assert_not_called()
            finally:
                manager.running.clear()
            assert row(pid)['name'] == protected['name'] and row(pid)['notes'] == 'private team note'
        ''')

    def test_member_only_sees_assigned_profiles_and_can_edit_metadata(self):
        self.run_isolated('''
            visible = create(name='Assigned')
            hidden = create(name='Unassigned')
            assert member.get('/api/profiles').json() == []
            assert member.get(f"/api/profiles/{visible['id']}").status_code == 404
            assert assign([visible['id']], [member_user['id']]).status_code == 200
            profiles = member.get('/api/profiles').json()
            assert {p['id'] for p in profiles} == {visible['id']}
            assert profiles[0]['can_manage'] is False
            assert member.get(f"/api/profiles/{hidden['id']}").status_code == 404
            pid = visible['id']
            response = member.patch(f'/api/profiles/{pid}/metadata', json={'tags': [' member ', 'member'], 'notes': 'Follow up tomorrow'})
            assert response.status_code == 200, response.text
            assert row(pid)['tags'] == ['member'] and row(pid)['notes'] == 'Follow up tomorrow'
            assert member.post(f'/api/profiles/{pid}/stop').status_code == 200
            for method, path, payload in [
                ('POST', '/api/profiles', {'name': 'forbidden'}),
                ('PATCH', f'/api/profiles/{pid}/settings', {'notes': 'bypass metadata'}),
                ('PATCH', f'/api/profiles/{pid}/proxy', {'proxy_id': None}),
                ('DELETE', f'/api/profiles/{pid}', None),
                ('GET', '/api/proxies', None),
                ('POST', '/api/proxies/import', {'text': 'p.example:8080', 'format': 'host_port', 'protocol': 'http'}),
                ('POST', '/api/profiles/assign', {'profile_ids': [pid], 'user_ids': [member_user['id']]}),
            ]:
                response = member.request(method, path, json=payload)
                assert response.status_code == 403, (method, path, response.status_code, response.text)
            assert row(pid)['notes'] == 'Follow up tomorrow'
            active_runtime(hidden['id'])
            try:
                with patch.object(manager.websockets, 'connect', return_value=FakeUpstream()) as connect:
                    denied_socket(member, hidden['id'])
                    connect.assert_not_called()
            finally:
                manager.running.clear()
        ''')

    def test_same_proxy_import_is_separate_per_team_and_binding_cannot_cross_teams(self):
        self.run_isolated('''
            own_proxy, other_proxy = proxy(), proxy(outsider)
            assert own_proxy['id'] != other_proxy['id']
            assert {p['id'] for p in owner.get('/api/proxies').json()} == {own_proxy['id']}
            assert {p['id'] for p in outsider.get('/api/proxies').json()} == {other_proxy['id']}
            profile = create(proxy_id=own_proxy['id'])
            pid = profile['id']
            for path in ('proxy', 'settings'):
                response = owner.patch(f'/api/profiles/{pid}/{path}', json={'proxy_id': other_proxy['id']})
                assert response.status_code == 404, response.text
                assert row(pid)['proxy_id'] == own_proxy['id']
            response = owner.post('/api/profiles', json={'name': 'Invalid binding', 'proxy_id': other_proxy['id']})
            assert response.status_code == 404
            assert len(owner.get('/api/profiles').json()) == 1
            assert 'private-proxy-password' not in str(owner.get('/api/profiles').json())
            assert 'private-proxy-password' not in str(member.get('/api/profiles').json())
        ''')

    def test_assignment_validation_and_bulk_changes_are_atomic(self):
        self.run_isolated('''
            first, second = create(name='One'), create(name='Two')
            foreign = create(outsider)
            ids = [first['id'], second['id']]
            assert assign(ids, [member_user['id']]).status_code == 200
            assert {p['id'] for p in member.get('/api/profiles').json()} == set(ids)
            for requested_profiles, users in [
                ([first['id'], foreign['id']], []),
                ([first['id'], 'missing-environment'], []),
                (ids, [outsider_user['id']]),
                (ids, ['missing-user']),
            ]:
                response = assign(requested_profiles, users)
                assert response.status_code in (400, 403, 404, 422), response.text
                assert all(row(pid)['assigned_user_ids'] == [member_user['id']] for pid in ids)
            response = owner.patch(f"/api/profiles/{first['id']}/settings", json={
                'name': 'Should not change', 'assigned_user_ids': [outsider_user['id']]})
            assert response.status_code in (400, 403, 404, 422)
            assert row(first['id'])['name'] == 'One'
            assert assign(ids, []).status_code == 200
            assert member.get('/api/profiles').json() == []
            assert all(row(pid)['assigned_user_ids'] == [] for pid in ids)
        ''')

    def test_tags_notes_are_validated_normalized_and_persisted(self):
        self.run_isolated('''
            profile = create(tags=[' Sales ', '', 'Sales', 'Review'], notes='Original note')
            pid = profile['id']
            assert profile['tags'] == ['Sales', 'Review']
            response = owner.patch(f'/api/profiles/{pid}/metadata', json={'tags': ['Active']})
            assert response.status_code == 200
            assert row(pid)['notes'] == 'Original note'
            response = owner.patch(f'/api/profiles/{pid}/metadata', json={'notes': '<b>plain note</b>'})
            assert response.status_code == 200
            assert row(pid)['tags'] == ['Active'] and row(pid)['notes'] == '<b>plain note</b>'
            for payload in ({'tags': [str(i) for i in range(21)]}, {'tags': ['x' * 33]}, {'notes': 'x' * 2001}, {'tags': 'not-a-list'}):
                assert owner.patch(f'/api/profiles/{pid}/metadata', json=payload).status_code == 422
                assert owner.post('/api/profiles', json={'name': 'Invalid', **payload}).status_code == 422
                assert row(pid)['tags'] == ['Active'] and row(pid)['notes'] == '<b>plain note</b>'
            response = owner.patch(f'/api/profiles/{pid}/metadata', json={'notes': '', 'tags': []})
            assert response.status_code == 200 and row(pid)['notes'] == '' and row(pid)['tags'] == []
        ''')

    def test_member_removal_revokes_http_socket_and_assignments(self):
        self.run_isolated('''
            pid = create(assigned_user_ids=[member_user['id']])['id']
            assert row(pid, member)['id'] == pid
            response = owner.delete(f"/api/teams/{team}/members/{member_user['id']}")
            assert response.status_code == 200, response.text
            assert row(pid)['assigned_user_ids'] == []
            assert member.get('/api/profiles').status_code in (403, 404)
            assert member.get(f'/api/profiles/{pid}').status_code == 404
            assert member.post(f'/api/profiles/{pid}/start').status_code == 404
            denied_socket(member, pid)
            session = member.get('/api/session').json()
            assert session['authenticated'] is True
            assert team not in {t['id'] for t in session['teams']}
        ''')

    def test_unassignment_closes_an_already_connected_remote_session(self):
        self.run_isolated('''
            pid = create(assigned_user_ids=[member_user['id']])['id']
            active_runtime(pid)
            upstream = FakeUpstream()
            with patch.object(manager.websockets, 'connect', return_value=upstream), \\
                    patch.object(manager, 'terminate'):
                try:
                    with member.websocket_connect(f'/api/profiles/{pid}/ws', headers={'Origin': 'http://testserver'}) as socket:
                        assert socket.receive_bytes() == b'authorized-frame'
                        response = assign([pid], [])
                        assert response.status_code == 200, response.text
                        socket.send_bytes(b'input-after-revocation')
                        message = socket.receive()
                        assert message['type'] == 'websocket.close', message
                        assert message['code'] == 1008, message
                finally:
                    manager.running.clear()
            assert b'input-after-revocation' not in upstream.sent
            denied_socket(member, pid)
        ''')

    def test_logout_closes_an_already_connected_remote_session(self):
        self.run_isolated('''
            pid = create(assigned_user_ids=[member_user['id']])['id']
            active_runtime(pid)
            upstream = FakeUpstream()
            with patch.object(manager.websockets, 'connect', return_value=upstream), \\
                    patch.object(manager, 'terminate'):
                try:
                    with member.websocket_connect(f'/api/profiles/{pid}/ws', headers={'Origin': 'http://testserver'}) as socket:
                        assert socket.receive_bytes() == b'authorized-frame'
                        assert member.post('/api/logout').status_code == 200
                        message = socket.receive()
                        assert message['type'] == 'websocket.close' and message['code'] == 1008, message
                finally:
                    manager.running.clear()
            assert member.get('/api/profiles').status_code == 401
            denied_socket(member, pid)
        ''')

    def test_losing_assignment_cancels_a_downloaded_pending_launch(self):
        self.run_isolated('''
            pid = create(assigned_user_ids=[member_user['id']])['id']
            entered, release = threading.Event(), threading.Event()
            def install(kernel_id):
                entered.set()
                assert release.wait(5)
                return '/test/browser'
            with patch.object(manager.kernels, 'ensure_kernel', side_effect=install), \\
                    patch.object(manager, '_launch_profile') as launch:
                thread = None
                try:
                    response = member.post(f'/api/profiles/{pid}/start')
                    assert response.status_code == 200, response.text
                    assert entered.wait(2)
                    thread = next(t for t in threading.enumerate() if t.name == 'start-' + pid[:8])
                    assert assign([pid], []).status_code == 200
                    assert pid not in manager.starting
                finally:
                    release.set()
                    if thread:
                        thread.join(3)
                launch.assert_not_called()
            assert row(pid)['status'] not in ('running', 'starting', 'downloading')
        ''')

    def test_team_removal_cancels_pending_launch_and_cannot_be_replayed(self):
        self.run_isolated('''
            pid = create(assigned_user_ids=[member_user['id']])['id']
            entered, release = threading.Event(), threading.Event()
            def install(kernel_id):
                entered.set()
                assert release.wait(5)
                return '/test/browser'
            with patch.object(manager.kernels, 'ensure_kernel', side_effect=install), \\
                    patch.object(manager, '_launch_profile') as launch:
                thread = None
                try:
                    assert member.post(f'/api/profiles/{pid}/start').status_code == 200
                    assert entered.wait(2)
                    thread = next(t for t in threading.enumerate() if t.name == 'start-' + pid[:8])
                    assert owner.delete(f"/api/teams/{team}/members/{member_user['id']}").status_code == 200
                    assert pid not in manager.starting
                finally:
                    release.set()
                    if thread:
                        thread.join(3)
                launch.assert_not_called()
            assert member.post(f'/api/profiles/{pid}/start').status_code == 404
        ''')


if __name__ == '__main__':
    unittest.main()
