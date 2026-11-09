"""Account/team boundaries, one-time invitations and persisted session regression."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.accounts import Accounts, hash_password, verify_password

PASSWORD = 'test-password-strong'
SETUP_KEY = 'test-installation-key'


def quick_hash(value):
    return 'test-only$' + hashlib.sha256(value.encode()).hexdigest()


class PasswordStorageTests(unittest.TestCase):
    def test_real_password_hash_is_salted_and_verifies(self):
        first, second = hash_password(PASSWORD), hash_password(PASSWORD)
        self.assertNotEqual(first, second)
        expected_algorithm = 'scrypt$131072$8$1$' if hasattr(hashlib, 'scrypt') else 'pbkdf2-sha256$600000$'
        self.assertTrue(first.startswith(expected_algorithm))
        self.assertNotIn(PASSWORD, first)
        self.assertTrue(verify_password(PASSWORD, first))
        self.assertFalse(verify_password('incorrect-password', first))


class AccountsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='account-boundaries-')
        self.path = Path(self.directory.name) / 'accounts.sqlite3'
        def db():
            conn = sqlite3.connect(self.path, timeout=10)
            conn.row_factory = sqlite3.Row
            return conn
        self.db = db
        with db() as conn:
            conn.executescript('''
                CREATE TABLE profiles (id TEXT PRIMARY KEY, team_id TEXT);
                CREATE TABLE proxies (id TEXT PRIMARY KEY, team_id TEXT);
                CREATE TABLE profile_assignments (profile_id TEXT, user_id TEXT, PRIMARY KEY(profile_id, user_id));
                INSERT INTO profiles VALUES ('legacy-profile', NULL);
                INSERT INTO proxies VALUES ('legacy-proxy', NULL);
            ''')
        self.accounts = Accounts(db, SETUP_KEY)
        self.app = FastAPI()
        self.accounts.mount(self.app)
        self.owner = TestClient(self.app)
        self.hash_patch = patch('backend.accounts.hash_password', side_effect=quick_hash)
        self.verify_patch = patch('backend.accounts.verify_password', side_effect=lambda password, stored: quick_hash(password) == stored)
        self.hash_patch.start()
        self.verify_patch.start()
        self.addCleanup(self.hash_patch.stop)
        self.addCleanup(self.verify_patch.stop)
        self.addCleanup(self.directory.cleanup)

    def register(self, email='owner@example.test', name='Owner', client=None):
        client = client or TestClient(self.app)
        response = client.post('/api/register', json={
            'email': email, 'name': name, 'password': PASSWORD, 'setup_key': SETUP_KEY})
        self.assertEqual(response.status_code, 200, response.text)
        return client, response.json()

    def invite(self, owner, team, email, role='member'):
        response = owner.post(f'/api/teams/{team}/invitations', json={'email': email, 'role': role})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def join(self, owner, team, email='member@example.test', role='member'):
        member, details = self.register(email, 'Member')
        invite = self.invite(owner, team, email, role)
        response = member.post('/api/invitations/accept', json={'token': invite['token']})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['active_team_id'], team)
        return member, details

    def test_bootstrap_requires_old_key_and_claims_data_only_once(self):
        self.assertTrue(self.owner.get('/api/session').json()['setup_required'])
        payload = {'name': 'First', 'email': 'first@example.test', 'password': PASSWORD}
        self.assertEqual(self.owner.post('/api/register', json=payload).status_code, 403)
        self.assertEqual(self.owner.post('/api/register', json={**payload, 'setup_key': 'bad-key'}).status_code, 403)
        with self.db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM users').fetchone()[0], 0)
            self.assertIsNone(conn.execute('SELECT team_id FROM profiles').fetchone()[0])
        owner, details = self.register(client=self.owner)
        team = details['active_team_id']
        self.assertEqual(details['teams'][0]['role'], 'owner')
        second = TestClient(self.app)
        self.assertEqual(second.post('/api/register', json={**payload, 'email': 'second@example.test'}).status_code, 200)
        with self.db() as conn:
            self.assertEqual(conn.execute('SELECT team_id FROM profiles').fetchone()[0], team)
            self.assertEqual(conn.execute('SELECT team_id FROM proxies').fetchone()[0], team)
        self.assertFalse(second.get('/api/session').json()['setup_required'])
        self.assertEqual(TestClient(self.app).post('/api/login', json={'password': SETUP_KEY}).status_code, 422)

    def test_sessions_persist_are_hashed_expire_and_logout_revokes(self):
        owner, details = self.register('  Owner@Example.Test  ', client=self.owner)
        cookie = owner.cookies.get('session')
        self.assertEqual(details['user']['email'], 'owner@example.test')
        with self.db() as conn:
            stored = dict(conn.execute('SELECT * FROM user_sessions').fetchone())
            self.assertNotEqual(cookie, stored['token_hash'])
            self.assertNotIn(cookie, str(stored))
        reloaded = Accounts(self.db, SETUP_KEY)
        self.assertEqual(reloaded.resolve_session(cookie)['user_id'], details['user']['id'])
        self.assertEqual(owner.post('/api/logout').status_code, 200)
        self.assertIsNone(reloaded.resolve_session(cookie))
        self.assertFalse(owner.get('/api/session').json()['authenticated'])
        wrong = owner.post('/api/login', json={'email': 'owner@example.test', 'password': 'incorrect'})
        missing = owner.post('/api/login', json={'email': 'missing@example.test', 'password': 'incorrect'})
        self.assertEqual((wrong.status_code, wrong.json()), (missing.status_code, missing.json()))
        login = owner.post('/api/login', json={'email': 'OWNER@EXAMPLE.TEST', 'password': PASSWORD})
        self.assertEqual(login.status_code, 200)
        self.assertNotEqual(owner.cookies.get('session'), cookie)
        self.assertIn('HttpOnly', login.headers['set-cookie'])
        self.assertIn('SameSite=strict', login.headers['set-cookie'])
        with self.db() as conn:
            conn.execute('UPDATE user_sessions SET expires_at = ?', (time.time() - 1,))
        self.assertFalse(owner.get('/api/session').json()['authenticated'])
        self.assertEqual(owner.get('/api/teams').status_code, 401)

    def test_invitation_bound_to_email_one_time_and_never_disclosed_again(self):
        owner, details = self.register(client=self.owner)
        team = details['active_team_id']
        invite = self.invite(owner, team, 'member@example.test')
        wrong, wrong_details = self.register('wrong@example.test')
        self.assertEqual(wrong.post('/api/invitations/accept', json={'token': invite['token']}).status_code, 400)
        self.assertEqual(wrong.get(f'/api/teams/{team}/members').status_code, 404)
        listed = owner.get(f'/api/teams/{team}/invitations').json()
        self.assertNotIn(invite['token'], str(listed))
        with self.db() as conn:
            row = dict(conn.execute('SELECT * FROM team_invitations').fetchone())
            self.assertNotIn(invite['token'], str(row))
        member, member_details = self.register('member@example.test')
        accepted = member.post('/api/invitations/accept', json={'token': invite['token']})
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json()['active_team_id'], team)
        self.assertEqual(member.post('/api/invitations/accept', json={'token': invite['token']}).status_code, 400)
        self.assertEqual(member.get(f'/api/teams/{team}/invitations').status_code, 403)
        self.assertEqual(member.post(f'/api/teams/{team}/invitations', json={'email': 'other@example.test'}).status_code, 403)
        self.assertEqual(owner.get(f'/api/teams/{team}/invitations').json()[0]['status'], 'accepted')

    def test_expired_revoked_replaced_and_demoted_inviter_tokens_rejected(self):
        owner, details = self.register(client=self.owner)
        team = details['active_team_id']
        target, _ = self.register('target@example.test')
        old = self.invite(owner, team, 'target@example.test')
        newer = self.invite(owner, team, 'target@example.test')
        self.assertEqual(target.post('/api/invitations/accept', json={'token': old['token']}).status_code, 400)
        with self.db() as conn:
            conn.execute('UPDATE team_invitations SET expires_at = ? WHERE id = ?', (time.time() - 1, newer['id']))
        self.assertEqual(target.post('/api/invitations/accept', json={'token': newer['token']}).status_code, 400)
        revoked = self.invite(owner, team, 'target@example.test')
        self.assertEqual(owner.delete(f"/api/teams/{team}/invitations/{revoked['id']}").status_code, 200)
        self.assertEqual(target.post('/api/invitations/accept', json={'token': revoked['token']}).status_code, 400)
        admin, admin_details = self.join(owner, team, 'admin@example.test', 'admin')
        issued = self.invite(admin, team, 'target@example.test')
        self.assertEqual(owner.patch(f"/api/teams/{team}/members/{admin_details['user']['id']}", json={'role': 'member'}).status_code, 200)
        self.assertEqual(target.post('/api/invitations/accept', json={'token': issued['token']}).status_code, 400)
        self.assertEqual(owner.patch(f"/api/teams/{team}/members/{admin_details['user']['id']}", json={'role': 'admin'}).status_code, 200)
        self.assertEqual(target.post('/api/invitations/accept', json={'token': issued['token']}).status_code, 400)

    def test_roles_cannot_escalate_owner_protected_and_removal_scoped(self):
        owner, details = self.register(client=self.owner)
        team, owner_id = details['active_team_id'], details['user']['id']
        admin, admin_details = self.join(owner, team, 'admin@example.test', 'admin')
        member, member_details = self.join(owner, team)
        admin_id, member_id = admin_details['user']['id'], member_details['user']['id']
        for target in (owner_id, admin_id, member_id):
            self.assertEqual(admin.patch(f'/api/teams/{team}/members/{target}', json={'role': 'admin'}).status_code, 403)
        self.assertEqual(admin.post(f'/api/teams/{team}/invitations', json={'email': 'more@example.test', 'role': 'admin'}).status_code, 403)
        self.assertEqual(admin.delete(f'/api/teams/{team}/members/{owner_id}').status_code, 403)
        self.assertEqual(owner.delete(f'/api/teams/{team}/members/{owner_id}').status_code, 403)
        self.assertEqual(owner.patch(f'/api/teams/{team}/members/{owner_id}', json={'role': 'member'}).status_code, 403)
        other_team = member_details['active_team_id']
        with self.db() as conn:
            conn.execute('INSERT INTO profiles VALUES (?, ?)', ('assigned-here', team))
            conn.execute('INSERT INTO profiles VALUES (?, ?)', ('assigned-elsewhere', other_team))
            conn.executemany('INSERT INTO profile_assignments VALUES (?, ?)',
                             [('assigned-here', member_id), ('assigned-elsewhere', member_id)])
        callback = self.accounts.on_access_changed = Mock()
        self.assertEqual(admin.delete(f'/api/teams/{team}/members/{member_id}').status_code, 200)
        callback.assert_called_once_with(team, member_id)
        self.assertEqual(member.get(f'/api/teams/{team}/members').status_code, 404)
        self.assertEqual(member.get('/api/session').json()['active_team_id'], other_team)
        with self.db() as conn:
            self.assertEqual([tuple(row) for row in conn.execute('SELECT * FROM profile_assignments')], [('assigned-elsewhere', member_id)])
        callback.reset_mock()
        self.assertEqual(owner.patch(f'/api/teams/{team}/members/{admin_id}', json={'role': 'member'}).status_code, 200)
        callback.assert_called_once_with(team, admin_id)

    def test_new_team_and_switch_require_membership(self):
        owner, details = self.register(client=self.owner)
        old_team = details['active_team_id']
        created = owner.post('/api/teams', json={'name': 'Second team'})
        self.assertEqual(created.status_code, 200, created.text)
        self.assertEqual(len(created.json()['teams']), 2)
        new_team = created.json()['active_team_id']
        self.assertNotEqual(new_team, old_team)
        outsider, outsider_details = self.register('outsider@example.test')
        self.assertEqual(outsider.post(f'/api/teams/{new_team}/select').status_code, 404)
        self.assertEqual(owner.post(f'/api/teams/{old_team}/select').json()['active_team_id'], old_team)
        self.assertEqual(outsider.get('/api/session').json()['active_team_id'], outsider_details['active_team_id'])

    def test_concurrent_accept_consumes_invitation_once(self):
        owner, details = self.register(client=self.owner)
        team = details['active_team_id']
        target, target_details = self.register('target@example.test')
        another = TestClient(self.app)
        self.assertEqual(another.post('/api/login', json={'email': 'target@example.test', 'password': PASSWORD}).status_code, 200)
        invite = self.invite(owner, team, 'target@example.test')
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda client: client.post('/api/invitations/accept', json={'token': invite['token']}).status_code,
                                         [target, another]))
        self.assertEqual(sorted(outcomes), [200, 400])
        with self.db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM team_members WHERE team_id = ? AND user_id = ?',
                                          (team, target_details['user']['id'])).fetchone()[0], 1)

    def test_login_attempts_are_bounded(self):
        for _ in range(20):
            self.assertEqual(self.owner.post('/api/login', json={'email': 'unknown@example.test', 'password': 'wrong'}).status_code, 401)
        limited = self.owner.post('/api/login', json={'email': 'unknown@example.test', 'password': 'wrong'})
        self.assertEqual(limited.status_code, 429)
        self.assertIn('retry-after', limited.headers)


if __name__ == '__main__':
    unittest.main()
