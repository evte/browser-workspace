"""TOTP lifecycle and authorization tests use isolated DBs, never real accounts."""
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
import re
import time
from pathlib import Path
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient

account_module = importlib.import_module('backend.accounts')
def quick_hash(password):
    return 'test-only$' + hashlib.sha256(password.encode()).hexdigest()
patch.object(account_module, 'hash_password', side_effect=quick_hash).start()
patch.object(account_module, 'verify_password', side_effect=lambda password, stored: hmac.compare_digest(quick_hash(password), stored)).start()
patch('backend.kernels.urllib.request.urlopen', side_effect=AssertionError('Unexpected network access')).start()
manager = importlib.import_module('backend.app')
PASSWORD = 'totp-test-password-only'
SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
OTHER_SECRET = 'JBSWY3DPEHPK3PXP'

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

def create(client=owner, **fields):
    response = client.post('/api/profiles', json={'name': 'TOTP environment', 'kernel_id': 'chromium-system', **fields})
    assert response.status_code == 200, response.text
    return response.json()

def codes(profile_ids, client=owner):
    return client.post('/api/totp/codes', json={'profile_ids': profile_ids})

def row(pid, client=owner):
    response = client.get(f'/api/profiles/{pid}')
    assert response.status_code == 200, response.text
    return response.json()

def ciphertext(pid):
    with manager.db() as conn:
        return conn.execute('SELECT totp_encrypted FROM profiles WHERE id = ?', (pid,)).fetchone()[0]

def no_secret(response):
    assert SECRET not in response.text and OTHER_SECRET not in response.text, response.text
    assert 'totp_encrypted' not in response.text and 'totp_secret' not in response.text, response.text
    assert 'no-store' in response.headers.get('cache-control', ''), response.headers
'''


class TotpApiTests(unittest.TestCase):
    def run_isolated(self, script):
        with tempfile.TemporaryDirectory(prefix='totp-api-') as root:
            data, novnc = Path(root) / 'data', Path(root) / 'novnc'
            data.mkdir()
            novnc.mkdir()
            env = {**os.environ, 'DATA_DIR': str(data), 'NOVNC_DIR': str(novnc),
                   'ACCESS_PASSWORD': 'totp-test-password-only', 'PYTHONPATH': str(PROJECT)}
            result = subprocess.run([sys.executable, '-c', PREAMBLE + textwrap.dedent(script)],
                                    cwd=PROJECT, env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_create_batch_codes_and_public_responses_hide_secret_and_ciphertext(self):
        self.run_isolated('''
            protected = create(totp_secret=SECRET)
            plain = create(name='No 2FA')
            pid = protected['id']
            assert protected['has_totp'] is True and plain['has_totp'] is False
            encrypted = ciphertext(pid)
            assert encrypted and SECRET not in encrypted
            assert not ciphertext(plain['id'])
            for response in (owner.get('/api/profiles'), owner.get(f'/api/profiles/{pid}'),
                             owner.patch(f'/api/profiles/{pid}/settings', json={'notes': 'Updated'}),
                             owner.patch(f'/api/profiles/{pid}/metadata', json={'tags': ['TOTP']}),
                             owner.post(f'/api/profiles/{pid}/stop')):
                assert response.status_code == 200, response.text
                no_secret(response)
                assert encrypted not in response.text
            response = codes([pid, plain['id']])
            assert response.status_code == 200, response.text
            no_secret(response)
            result = response.json()
            assert isinstance(result['server_time'], int)
            assert abs(result['server_time'] - int(time.time() * 1000)) < 3000
            assert len(result['codes']) == 1
            entry = result['codes'][0]
            assert entry['profile_id'] == pid and re.fullmatch(r'\d{6}', entry['code'])
            assert entry['period'] == 30
            assert entry['valid_from'] <= result['server_time'] < entry['valid_until']
            assert entry['valid_until'] - entry['valid_from'] == 30000
        ''')

    def test_empty_omitted_replace_and_clear_have_distinct_meanings(self):
        self.run_isolated('''
            profile = create(totp_secret=SECRET)
            pid = profile['id']
            original = ciphertext(pid)
            for payload in ({'notes': 'Still configured'}, {'totp_secret': ''}, {'totp_secret': '  '}, {'totp_secret': None}):
                response = owner.patch(f'/api/profiles/{pid}/settings', json=payload)
                assert response.status_code == 200, response.text
                assert response.json()['has_totp'] is True
                assert ciphertext(pid) == original
                no_secret(response)
            conflict = owner.patch(f'/api/profiles/{pid}/settings', json={'totp_secret': OTHER_SECRET, 'clear_totp': True, 'notes': 'Do not commit'})
            assert conflict.status_code == 422, conflict.text
            assert ciphertext(pid) == original and row(pid)['notes'] == 'Still configured'
            replaced = owner.patch(f'/api/profiles/{pid}/settings', json={'totp_secret': OTHER_SECRET})
            assert replaced.status_code == 200, replaced.text
            assert replaced.json()['has_totp'] is True and ciphertext(pid) != original
            cleared = owner.patch(f'/api/profiles/{pid}/settings', json={'clear_totp': True})
            assert cleared.status_code == 200, cleared.text
            assert cleared.json()['has_totp'] is False and not ciphertext(pid)
            assert codes([pid]).json()['codes'] == []
        ''')

    def test_totp_can_change_while_environment_is_running(self):
        self.run_isolated('''
            profile = create()
            pid = profile['id']
            process = Mock()
            process.poll.return_value = None
            manager.running[pid] = {'processes': [process], 'port': 19999, 'started_by': owner_user['id']}
            try:
                response = owner.patch(f'/api/profiles/{pid}/settings', json={'totp_secret': SECRET})
                assert response.status_code == 200, response.text
                assert response.json()['has_totp'] is True and response.json()['status'] == 'running'
                assert len(codes([pid]).json()['codes']) == 1
                no_secret(response)
                blocked = owner.patch(f'/api/profiles/{pid}/settings', json={'fingerprint': {'language': 'en-US'}})
                assert blocked.status_code == 409, blocked.text
                clear = owner.patch(f'/api/profiles/{pid}/settings', json={'clear_totp': True})
                assert clear.status_code == 200 and clear.json()['has_totp'] is False
            finally:
                manager.running.clear()
        ''')

    def test_assigned_member_can_view_but_cannot_set_or_clear_secret(self):
        self.run_isolated('''
            profile = create(totp_secret=SECRET, assigned_user_ids=[member_user['id']])
            pid = profile['id']
            original = ciphertext(pid)
            response = codes([pid], member)
            assert response.status_code == 200, response.text
            no_secret(response)
            assert response.json()['codes'][0]['profile_id'] == pid
            for payload in ({'totp_secret': OTHER_SECRET}, {'clear_totp': True}):
                denied = member.patch(f'/api/profiles/{pid}/settings', json=payload)
                assert denied.status_code == 403, denied.text
                assert ciphertext(pid) == original
            # Metadata endpoint must not accidentally become a secret-edit bypass.
            response = member.patch(f'/api/profiles/{pid}/metadata', json={'notes': 'Allowed', 'clear_totp': True, 'totp_secret': OTHER_SECRET})
            assert response.status_code in (200, 422), response.text
            assert ciphertext(pid) == original
        ''')

    def test_foreign_unassigned_and_revoked_access_cannot_read_codes(self):
        self.run_isolated('''
            assigned = create(totp_secret=SECRET, assigned_user_ids=[member_user['id']])
            hidden = create(totp_secret=OTHER_SECRET)
            foreign = create(outsider, totp_secret=OTHER_SECRET)
            pid = assigned['id']
            assert codes([pid], TestClient(manager.app)).status_code == 401
            for client, ids in ((outsider, [pid]), (member, [hidden['id']]),
                                (owner, [foreign['id']]), (member, [pid, hidden['id']]),
                                (owner, [pid, 'missing-environment'])):
                denied = codes(ids, client)
                assert denied.status_code in (403, 404), denied.text
                assert 'codes' not in denied.json() and SECRET not in denied.text
            assert codes([pid], member).status_code == 200
            revoked = owner.post('/api/profiles/assign', json={'profile_ids': [pid], 'user_ids': []})
            assert revoked.status_code == 200
            assert codes([pid], member).status_code == 404
            assert owner.post('/api/profiles/assign', json={'profile_ids': [pid], 'user_ids': [member_user['id']]}).status_code == 200
            assert codes([pid], member).status_code == 200
            assert owner.delete(f"/api/teams/{team}/members/{member_user['id']}").status_code == 200
            assert codes([pid], member).status_code in (403, 404)
        ''')

    def test_validation_rejects_invalid_secret_without_partial_update_or_echo(self):
        self.run_isolated('''
            profile = create(totp_secret=SECRET)
            pid = profile['id']
            original = ciphertext(pid)
            bad_values = ['private-secret-not-base32!',
                          'otpauth://totp/account?secret=' + SECRET + '&algorithm=MD5',
                          'otpauth://totp/account?secret=' + SECRET + '&digits=9',
                          'otpauth://totp/account?secret=' + SECRET + '&period=0',
                          'otpauth://totp/account?secret=' + SECRET + '&secret=' + SECRET,
                          SECRET * 200]
            for value in bad_values:
                response = owner.patch(f'/api/profiles/{pid}/settings', json={'totp_secret': value, 'name': 'Must not change'})
                assert response.status_code == 422, response.text
                assert value not in response.text and SECRET not in response.text
                assert row(pid)['name'] == profile['name'] and ciphertext(pid) == original
                created = owner.post('/api/profiles', json={'name': 'Invalid', 'kernel_id': 'chromium-system', 'totp_secret': value})
                assert created.status_code == 422, created.text
                assert value not in created.text and SECRET not in created.text
            assert len(owner.get('/api/profiles').json()) == 1
            assert codes([pid] * 101).status_code == 422
        ''')

    def test_secret_and_master_key_survive_app_restart(self):
        self.run_isolated('''
            profile = create(totp_secret=SECRET)
            pid = profile['id']
            encrypted = ciphertext(pid)
            key_path = manager.DATA / 'totp.key'
            saved_key = key_path.read_bytes()
            assert key_path.stat().st_mode & 0o777 == 0o600
            manager = importlib.reload(manager)
            restored = TestClient(manager.app)
            restored.cookies.update(owner.cookies)
            restored.headers['X-Team-ID'] = team
            response = codes([pid], restored)
            assert response.status_code == 200, response.text
            assert len(response.json()['codes']) == 1
            assert key_path.read_bytes() == saved_key and ciphertext(pid) == encrypted
            no_secret(response)
        ''')

    def test_corrupt_ciphertext_fails_without_returning_a_code(self):
        self.run_isolated('''
            profile = create(totp_secret=SECRET)
            pid = profile['id']
            with manager.db() as conn:
                conn.execute('UPDATE profiles SET totp_encrypted = ? WHERE id = ?', ('damaged-secret-token', pid))
            response = codes([pid])
            assert response.status_code == 503, response.text
            assert 'codes' not in response.json()
            assert SECRET not in response.text and 'damaged-secret-token' not in response.text
            assert 'no-store' in response.headers.get('cache-control', '')
        ''')


if __name__ == '__main__':
    unittest.main()
