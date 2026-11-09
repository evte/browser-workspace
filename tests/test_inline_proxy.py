"""Creating an environment and its inline proxy is one authorized transaction."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


PROJECT = Path(__file__).resolve().parents[1]
PREAMBLE = '''
import hashlib
import hmac
import importlib
from unittest.mock import patch
from fastapi.testclient import TestClient

account_module = importlib.import_module('backend.accounts')
def quick_hash(password):
    return 'test-only$' + hashlib.sha256(password.encode()).hexdigest()
patch.object(account_module, 'hash_password', side_effect=quick_hash).start()
patch.object(account_module, 'verify_password', side_effect=lambda password, stored: hmac.compare_digest(quick_hash(password), stored)).start()
patch('backend.kernels.urllib.request.urlopen', side_effect=AssertionError('Unexpected download')).start()
manager = importlib.import_module('backend.app')
PASSWORD = 'inline-proxy-test-password'
SECRET = 'private-test-proxy-password'

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
invitation = owner.post(f'/api/teams/{team}/invitations', json={'email': member_user['email'], 'role': 'member'})
assert invitation.status_code == 200, invitation.text
accepted = member.post('/api/invitations/accept', json={'token': invitation.json()['token']})
assert accepted.status_code == 200, accepted.text
member.headers['X-Team-ID'] = team

def inline(text=None, format='host_port_auth', protocol='http'):
    return {'text': text if text is not None else 'proxy.example:8080:user:' + SECRET,
            'format': format, 'protocol': protocol}

def create(client=owner, **fields):
    response = client.post('/api/profiles', json={'name': 'Inline proxy environment',
        'kernel_id': 'chromium-system', **fields})
    assert response.status_code == 200, response.text
    no_secret(response)
    return response.json()

def counts():
    with manager.db() as conn:
        return tuple(conn.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                     for table in ('profiles', 'proxies', 'profile_assignments'))

def no_secret(response):
    assert SECRET not in response.text, response.text
    assert 'no-store' in response.headers.get('cache-control', ''), response.headers

def stored_proxy(profile):
    with manager.db() as conn:
        row = dict(conn.execute('SELECT * FROM proxies WHERE id = ?', (profile['proxy_id'],)).fetchone())
        environment = dict(conn.execute('SELECT * FROM profiles WHERE id = ?', (profile['id'],)).fetchone())
        assert environment['proxy'] == '' and environment['proxy_id'] == row['id']
        assert environment['team_id'] == row['team_id']
        return row
'''


class InlineProxyTests(unittest.TestCase):
    def run_isolated(self, script):
        with tempfile.TemporaryDirectory(prefix='inline-proxy-') as root:
            data, novnc = Path(root) / 'data', Path(root) / 'novnc'
            data.mkdir()
            novnc.mkdir()
            env = {**os.environ, 'DATA_DIR': str(data), 'NOVNC_DIR': str(novnc),
                   'ACCESS_PASSWORD': 'inline-proxy-test-password', 'PYTHONPATH': str(PROJECT)}
            result = subprocess.run([sys.executable, '-c', PREAMBLE + textwrap.dedent(script)],
                                    cwd=PROJECT, env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_all_protocols_and_formats_create_and_bind_real_proxy_records(self):
        self.run_isolated('''
            for protocol in ('http', 'https', 'socks4', 'socks5'):
                for format in ('host_port', 'host_port_auth', 'auth_host_port', 'url'):
                    host = protocol + '-' + format.replace('_', '-') + '.example'
                    password = '' if protocol == 'socks4' or format == 'host_port' else SECRET
                    username = '' if format == 'host_port' else 'user'
                    values = {
                        'host_port': f'{host}:1080',
                        'host_port_auth': f'{host}:1080:user:{password}',
                        'auth_host_port': f'user:{password}@{host}:1080',
                        'url': f'{protocol}://user:{password}@{host}:1080'}
                    profile = create(inline_proxy=inline(values[format], format, protocol))
                    row = stored_proxy(profile)
                    assert row['protocol'] == protocol and row['host'] == host and row['port'] == 1080
                    assert row['username'] == username and row['password'] == password
                    assert profile['proxy_display'] == f'{protocol}://{host}:1080'
            ipv6 = create(inline_proxy=inline('[2001:db8::1]:1080:user:' + SECRET, protocol='socks5'))
            assert stored_proxy(ipv6)['host'] == '2001:db8::1'
            assert counts() == (17, 17, 0), counts()
            for response in (owner.get('/api/profiles'), owner.get('/api/proxies')):
                assert response.status_code == 200
                no_secret(response)
            assert all('password' not in item for item in owner.get('/api/proxies').json())
        ''')

    def test_equivalent_proxy_reuses_only_within_team_and_matching_credentials(self):
        self.run_isolated('''
            imported = owner.post('/api/proxies/import', json=inline('Proxy.Example.:8080:user:' + SECRET))
            assert imported.status_code == 200, imported.text
            original_id = imported.json()['proxies'][0]['id']
            normalized = create(inline_proxy=inline('http://user:' + SECRET + '@proxy.example:8080', 'url'))
            again = create(inline_proxy=inline())
            assert normalized['proxy_id'] == original_id == again['proxy_id']
            different = create(inline_proxy=inline('proxy.example:8080:user:changed-test-password'))
            foreign = create(outsider, inline_proxy=inline())
            assert len({original_id, different['proxy_id'], foreign['proxy_id']}) == 3
            assert stored_proxy(foreign)['team_id'] == other_team
            assert counts() == (4, 3, 0), counts()
            assert len(owner.get('/api/proxies').json()) == 2
            assert len(outsider.get('/api/proxies').json()) == 1
        ''')

    def test_invalid_inline_proxy_never_writes_or_echoes_credentials(self):
        self.run_isolated('''
            invalid = [
                inline('proxy.example:0:user:' + SECRET),
                inline('proxy.example:65536:user:' + SECRET),
                inline('proxy.example:8080:user:' + SECRET + '\\nsecond.example:8081:user:' + SECRET),
                inline('https://user:' + SECRET + '@proxy.example:443', 'url', 'http'),
                inline('proxy.example:1080:user:' + SECRET, protocol='socks4'),
                inline('', 'host_port'),
                inline('   ', 'host_port'),
                inline(format='unsupported'),
                inline(protocol='ftp'),
                inline({'password': SECRET}),
                inline('x' * 2049),
                {'format': 'url', 'protocol': 'http'},
            ]
            for value in invalid:
                response = owner.post('/api/profiles', json={'name': 'Must not exist',
                    'kernel_id': 'chromium-system', 'inline_proxy': value})
                assert response.status_code == 422, response.text
                no_secret(response)
                assert counts() == (0, 0, 0), (value['format'], counts())
        ''')

    def test_inline_existing_and_legacy_inputs_are_mutually_exclusive(self):
        self.run_isolated('''
            original = create(inline_proxy=inline())
            before = counts()
            for fields in (
                {'inline_proxy': inline('other.example:8080:user:' + SECRET), 'proxy_id': original['proxy_id']},
                {'inline_proxy': inline(), 'proxy': 'http://user:' + SECRET + '@legacy.example:8080'},
                {'proxy_id': original['proxy_id'], 'proxy': 'http://user:' + SECRET + '@legacy.example:8080'},
            ):
                response = owner.post('/api/profiles', json={'name': 'Ambiguous', 'kernel_id': 'chromium-system', **fields})
                assert response.status_code == 422, response.text
                no_secret(response)
                assert counts() == before
        ''')

    def test_permissions_are_checked_before_creating_any_proxy(self):
        self.run_isolated('''
            payload = {'name': 'Forbidden', 'kernel_id': 'chromium-system', 'inline_proxy': inline()}
            anonymous = TestClient(manager.app)
            assert anonymous.post('/api/profiles', json=payload).status_code == 401
            assert member.post('/api/profiles', json=payload).status_code == 403
            assert outsider.post('/api/profiles', json=payload, headers={'X-Team-ID': team}).status_code == 404
            assert counts() == (0, 0, 0)
            foreign = create(outsider, inline_proxy=inline())
            before = counts()
            assert owner.post('/api/profiles', json={'name': 'Cross-team binding',
                'kernel_id': 'chromium-system', 'proxy_id': foreign['proxy_id']}).status_code == 404
            assert counts() == before
            promoted = owner.patch(f'/api/teams/{team}/members/{member_user["id"]}', json={'role': 'admin'})
            assert promoted.status_code == 200, promoted.text
            managed = create(member, inline_proxy=inline())
            assert stored_proxy(managed)['team_id'] == team
            assert managed['proxy_id'] != foreign['proxy_id']
        ''')

    def test_profile_or_assignment_insert_failure_rolls_back_new_proxy(self):
        self.run_isolated('''
            quiet = TestClient(manager.app, raise_server_exceptions=False)
            quiet.cookies.update(owner.cookies)
            quiet.headers.update(owner.headers)
            with manager.db() as conn:
                conn.execute("CREATE TRIGGER refuse_profile BEFORE INSERT ON profiles BEGIN SELECT RAISE(ABORT, 'test profile insertion failure'); END")
            response = quiet.post('/api/profiles', json={'name': 'Rolled back',
                'kernel_id': 'chromium-system', 'inline_proxy': inline()})
            assert response.status_code == 500, response.text
            assert SECRET not in response.text and counts() == (0, 0, 0)
            with manager.db() as conn:
                conn.execute('DROP TRIGGER refuse_profile')
                conn.execute("CREATE TRIGGER refuse_assignment BEFORE INSERT ON profile_assignments BEGIN SELECT RAISE(ABORT, 'test assignment insertion failure'); END")
            response = quiet.post('/api/profiles', json={'name': 'Rolled back too',
                'kernel_id': 'chromium-system', 'inline_proxy': inline(), 'assigned_user_ids': [member_user['id']]})
            assert response.status_code == 500, response.text
            assert SECRET not in response.text and counts() == (0, 0, 0)
        ''')

    def test_direct_existing_and_legacy_creation_remain_compatible(self):
        self.run_isolated('''
            direct = create()
            assert direct['proxy_id'] is None and direct['proxy_display'] == ''
            explicit_direct = create(proxy_id=None, inline_proxy=None)
            assert explicit_direct['proxy_id'] is None
            legacy = create(proxy='http://user:' + SECRET + '@proxy.example:8080')
            existing = create(proxy_id=legacy['proxy_id'])
            automatic = create(inline_proxy=inline())
            assert legacy['proxy_id'] == existing['proxy_id'] == automatic['proxy_id']
            assert counts() == (5, 1, 0)
            before = counts()
            multiline = owner.post('/api/profiles', json={'name': 'Legacy multiline forbidden',
                'kernel_id': 'chromium-system',
                'proxy': 'http://user:' + SECRET + '@one.example:8080\\nhttp://user:' + SECRET + '@two.example:8080'})
            assert multiline.status_code == 400, multiline.text
            no_secret(multiline)
            assert counts() == before
        ''')

    def test_inline_proxy_keeps_fail_closed_start_preflight(self):
        self.run_isolated('''
            profile = create(inline_proxy=inline())
            with patch.object(manager.sys, 'platform', 'darwin'), patch.object(manager.subprocess, 'Popen') as launch:
                response = owner.post(f'/api/profiles/{profile["id"]}/start')
                assert response.status_code == 503, response.text
                launch.assert_not_called()
            current = manager.profile_record(profile['id'])
            assert current['proxy_id'] == profile['proxy_id']
            assert manager.bound_proxy(current)['password'] == SECRET
            assert profile['id'] not in manager.running and profile['id'] not in manager.starting
            no_secret(response)
        ''')
