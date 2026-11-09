"""Account, team and invitation boundaries for the browser workspace.

Passwords use salted scrypt; bearer session/invitation values are never stored.
The owner of the old installation must explicitly claim it with its setup key.
"""
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from typing import Literal, Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

SESSION_SECONDS = 24 * 60 * 60
INVITATION_SECONDS = 7 * 24 * 60 * 60
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1
PBKDF2_ITERATIONS = 600_000
_HASH_SLOTS = threading.BoundedSemaphore(2)
_DUMMY_HASH = ((f'scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}$' if hasattr(hashlib, 'scrypt')
                else f'pbkdf2-sha256${PBKDF2_ITERATIONS}$') + '00' * 16 + '$' + '00' * 32)


def token_hash(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def hash_password(password):
    salt = secrets.token_bytes(16)
    with _HASH_SLOTS:
        if not hasattr(hashlib, 'scrypt'):
            # Some macOS developer Python builds omit OpenSSL scrypt. Keep a
            # slow salted standard-library fallback; Docker uses scrypt above.
            digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt,
                                         PBKDF2_ITERATIONS, dklen=32)
            return f'pbkdf2-sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}'
        digest = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=SCRYPT_N,
                                r=SCRYPT_R, p=SCRYPT_P, dklen=32, maxmem=256 * 1024 * 1024)
    return f'scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}'


def verify_password(password, stored):
    try:
        if stored.startswith('pbkdf2-sha256$'):
            _, iterations, salt, expected = stored.split('$')
            if int(iterations) != PBKDF2_ITERATIONS:
                return False
            with _HASH_SLOTS:
                actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt),
                                             PBKDF2_ITERATIONS, dklen=32)
            return hmac.compare_digest(actual, bytes.fromhex(expected))
        algorithm, n, r, p, salt, expected = stored.split('$')
        if (algorithm != 'scrypt' or not hasattr(hashlib, 'scrypt')
                or (int(n), int(r), int(p)) != (SCRYPT_N, SCRYPT_R, SCRYPT_P)):
            return False
        with _HASH_SLOTS:
            actual = hashlib.scrypt(password.encode('utf-8'), salt=bytes.fromhex(salt),
                                    n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                                    dklen=32, maxmem=256 * 1024 * 1024)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def normalize_email(value):
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
        raise ValueError('请填写有效的邮箱地址')
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ValueError('邮箱地址含无效字符')
    return value


class EmailModel(BaseModel):
    email: str = Field(min_length=3, max_length=254)

    @field_validator('email')
    @classmethod
    def email_format(cls, value):
        return normalize_email(value)


class LoginInput(EmailModel):
    password: str = Field(min_length=1, max_length=128)


class RegisterInput(EmailModel):
    name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=12, max_length=128)
    setup_key: Optional[str] = Field(default=None, max_length=512)

    @field_validator('name')
    @classmethod
    def visible_name(cls, value):
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError('姓名不能为空或包含控制字符')
        return value


class TeamInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)

    @field_validator('name')
    @classmethod
    def team_name(cls, value):
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError('团队名称无效')
        return value


class RoleInput(BaseModel):
    role: Literal['admin', 'member']


class InvitationInput(EmailModel):
    role: Literal['admin', 'member'] = 'member'


class AcceptInput(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class Accounts:
    def __init__(self, db_factory, setup_password):
        self.db = db_factory
        self.setup_password = setup_password
        self.on_access_changed = lambda team_id, user_id: None
        self._rate_lock = threading.Lock()
        self._attempts = defaultdict(deque)
        with self.db() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL, password_hash TEXT NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS teams (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS team_members (
                    team_id TEXT NOT NULL, user_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
                    joined_at REAL NOT NULL, PRIMARY KEY(team_id, user_id),
                    FOREIGN KEY(team_id) REFERENCES teams(id), FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS team_invitations (
                    id TEXT PRIMARY KEY, team_id TEXT NOT NULL, email TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'member')),
                    token_hash TEXT NOT NULL UNIQUE, created_by TEXT NOT NULL,
                    created_at REAL NOT NULL, expires_at REAL NOT NULL,
                    accepted_at REAL, revoked_at REAL,
                    FOREIGN KEY(team_id) REFERENCES teams(id)
                );
                CREATE TABLE IF NOT EXISTS user_sessions (
                    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                    active_team_id TEXT, created_at REAL NOT NULL, expires_at REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE INDEX IF NOT EXISTS team_members_user ON team_members(user_id);
                CREATE INDEX IF NOT EXISTS invitations_team ON team_invitations(team_id);
                CREATE INDEX IF NOT EXISTS sessions_user ON user_sessions(user_id);
            ''')

    def setup_required(self):
        with self.db() as conn:
            return conn.execute('SELECT 1 FROM users LIMIT 1').fetchone() is None

    @staticmethod
    def _public_user(row):
        return {key: row[key] for key in ('id', 'email', 'name')}

    def _limit(self, request, action):
        # X-Forwarded-For is deliberately not trusted. A reverse proxy can enforce
        # stricter upstream limits; the application also limits the actual peer.
        peer = request.client.host if request.client else 'unknown'
        key = (action, peer)
        now = time.monotonic()
        period, limit = (600, 8) if action == 'register' else (300, 20)
        with self._rate_lock:
            if len(self._attempts) > 4096:
                self._attempts = defaultdict(deque, {k: v for k, v in self._attempts.items()
                                                   if v and v[-1] > now - 600})
                if len(self._attempts) > 4096:
                    raise HTTPException(429, '请求过于频繁，请稍后重试')
            attempts = self._attempts[key]
            while attempts and attempts[0] <= now - period:
                attempts.popleft()
            if len(attempts) >= limit:
                raise HTTPException(429, '请求过于频繁，请稍后重试', headers={'Retry-After': '300'})
            attempts.append(now)

    def resolve_session(self, cookie):
        if not cookie or not isinstance(cookie, str) or len(cookie) > 256:
            return None
        digest = token_hash(cookie)
        with self.db() as conn:
            row = conn.execute('''SELECT s.token_hash, s.user_id, s.active_team_id, s.expires_at,
                                  u.id, u.email, u.name FROM user_sessions s
                                  JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?''', (digest,)).fetchone()
            if not row or row['expires_at'] <= time.time():
                return None
            active = row['active_team_id']
            if not conn.execute('SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?',
                                (active, row['user_id'])).fetchone():
                fallback = conn.execute('SELECT team_id FROM team_members WHERE user_id = ? ORDER BY joined_at, team_id LIMIT 1',
                                        (row['user_id'],)).fetchone()
                active = fallback['team_id'] if fallback else None
            return {'token_hash': digest, 'user_id': row['user_id'], 'user': self._public_user(row),
                    'active_team_id': active, 'expires_at': row['expires_at']}

    def _require_session(self, request):
        session = self.resolve_session(request.cookies.get('session'))
        if session is None:
            raise HTTPException(401, '请先登录')
        return session

    def _teams(self, conn, user_id):
        return [dict(row) for row in conn.execute('''SELECT t.id, t.name, m.role FROM teams t
                    JOIN team_members m ON m.team_id = t.id WHERE m.user_id = ?
                    ORDER BY m.joined_at, t.id''', (user_id,))]

    def session_payload(self, cookie):
        session = self.resolve_session(cookie)
        if session is None:
            return {'authenticated': False, 'user': None, 'teams': [], 'active_team_id': None,
                    'setup_required': self.setup_required()}
        with self.db() as conn:
            teams = self._teams(conn, session['user_id'])
        return {'authenticated': True, 'user': session['user'], 'teams': teams,
                'active_team_id': session['active_team_id'], 'setup_required': False}

    def member_role(self, team_id, user_id):
        with self.db() as conn:
            row = conn.execute('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?',
                               (team_id, user_id)).fetchone()
            return row['role'] if row else None

    def require_team(self, session, team_id=None, manage=False):
        if not session:
            raise HTTPException(401, '请先登录')
        team_id = team_id or session.get('active_team_id')
        with self.db() as conn:
            return self._require_team(conn, session['user_id'], team_id, manage)

    @staticmethod
    def _require_team(conn, user_id, team_id, manage=False):
        row = conn.execute('''SELECT t.id, t.name, m.role FROM teams t
                              JOIN team_members m ON m.team_id = t.id
                              WHERE t.id = ? AND m.user_id = ?''', (team_id, user_id)).fetchone()
        if row is None:
            raise HTTPException(404, '团队不存在或无权访问')
        if manage and row['role'] not in ('owner', 'admin'):
            raise HTTPException(403, '需要团队管理员权限')
        return dict(row)

    @staticmethod
    def _create_team(conn, user_id, name, now):
        team_id = uuid4().hex
        conn.execute('INSERT INTO teams (id, name, created_at) VALUES (?, ?, ?)', (team_id, name, now))
        conn.execute('INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)',
                     (team_id, user_id, 'owner', now))
        return {'id': team_id, 'name': name, 'role': 'owner'}

    def _issue_session(self, conn, user_id, team_id, request, response):
        now = time.time()
        token = secrets.token_urlsafe(32)
        old = request.cookies.get('session')
        if old and len(old) <= 256:
            conn.execute('DELETE FROM user_sessions WHERE token_hash = ?', (token_hash(old),))
        conn.execute('DELETE FROM user_sessions WHERE expires_at <= ?', (now,))
        conn.execute('INSERT INTO user_sessions VALUES (?, ?, ?, ?, ?)',
                     (token_hash(token), user_id, team_id, now, now + SESSION_SECONDS))
        secure = request.url.scheme == 'https' or request.headers.get('x-forwarded-proto') == 'https'
        response.set_cookie('session', token, httponly=True, samesite='strict', secure=secure,
                            max_age=SESSION_SECONDS, path='/')
        return token

    @staticmethod
    def _tables(conn):
        return {row['name'] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    @staticmethod
    def _invitation_public(row, now=None):
        now = now or time.time()
        state = ('revoked' if row['revoked_at'] else 'accepted' if row['accepted_at']
                 else 'expired' if row['expires_at'] <= now else 'pending')
        return {key: row[key] for key in ('id', 'team_id', 'email', 'role', 'created_at', 'expires_at')} | {'status': state}

    def mount(self, app: FastAPI):
        @app.get('/api/session')
        def session(request: Request):
            return self.session_payload(request.cookies.get('session'))

        @app.post('/api/register')
        def register(body: RegisterInput, request: Request, response: Response):
            self._limit(request, 'register')
            # Reject invalid setup claims before spending memory on a password hash.
            if self.setup_required() and (not body.setup_key or not hmac.compare_digest(body.setup_key.encode(), self.setup_password.encode())):
                raise HTTPException(403, '首次注册需要服务器的初始化密钥')
            password_hash = hash_password(body.password)
            user_id, now = uuid4().hex, time.time()
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                first = conn.execute('SELECT 1 FROM users LIMIT 1').fetchone() is None
                if first and (not body.setup_key or not hmac.compare_digest(body.setup_key.encode(), self.setup_password.encode())):
                    raise HTTPException(403, '首次注册需要服务器的初始化密钥')
                try:
                    conn.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?)',
                                 (user_id, body.email, body.name, password_hash, now))
                except sqlite3.IntegrityError:
                    raise HTTPException(409, '该邮箱无法注册，请尝试登录') from None
                team = self._create_team(conn, user_id, body.name + '的团队', now)
                if first:
                    for table in ('profiles', 'proxies'):
                        if table in self._tables(conn):
                            columns = {row['name'] for row in conn.execute(f'PRAGMA table_info({table})')}
                            if 'team_id' in columns:
                                conn.execute(f'UPDATE {table} SET team_id = ? WHERE team_id IS NULL', (team['id'],))
                cookie = self._issue_session(conn, user_id, team['id'], request, response)
            return self.session_payload(cookie)

        @app.post('/api/login')
        def login(body: LoginInput, request: Request, response: Response):
            self._limit(request, 'login')
            with self.db() as conn:
                user = conn.execute('SELECT * FROM users WHERE email = ?', (body.email,)).fetchone()
            valid = verify_password(body.password, user['password_hash'] if user else _DUMMY_HASH)
            if not user or not valid:
                raise HTTPException(401, '邮箱或密码不正确')
            with self.db() as conn:
                teams = self._teams(conn, user['id'])
                cookie = self._issue_session(conn, user['id'], teams[0]['id'] if teams else None, request, response)
            return self.session_payload(cookie)

        @app.post('/api/logout')
        def logout(request: Request, response: Response):
            cookie = request.cookies.get('session')
            if cookie and len(cookie) <= 256:
                with self.db() as conn:
                    conn.execute('DELETE FROM user_sessions WHERE token_hash = ?', (token_hash(cookie),))
            response.delete_cookie('session', path='/')
            return {'ok': True}

        @app.get('/api/teams')
        def teams(request: Request):
            current = self._require_session(request)
            with self.db() as conn:
                return self._teams(conn, current['user_id'])

        @app.post('/api/teams')
        def create_team(body: TeamInput, request: Request):
            current = self._require_session(request)
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                team = self._create_team(conn, current['user_id'], body.name, time.time())
                conn.execute('UPDATE user_sessions SET active_team_id = ? WHERE token_hash = ?',
                             (team['id'], current['token_hash']))
            return self.session_payload(request.cookies.get('session'))

        @app.post('/api/teams/{team_id}/select')
        def select_team(team_id: str, request: Request):
            current = self._require_session(request)
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                self._require_team(conn, current['user_id'], team_id)
                conn.execute('UPDATE user_sessions SET active_team_id = ? WHERE token_hash = ?',
                             (team_id, current['token_hash']))
            return self.session_payload(request.cookies.get('session'))

        @app.get('/api/teams/{team_id}/members')
        def members(team_id: str, request: Request):
            current = self._require_session(request)
            with self.db() as conn:
                self._require_team(conn, current['user_id'], team_id)
                return [dict(row) for row in conn.execute('''SELECT u.id, u.name, u.email, m.role, m.joined_at
                    FROM users u JOIN team_members m ON m.user_id = u.id WHERE m.team_id = ?
                    ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, m.joined_at''', (team_id,))]

        @app.patch('/api/teams/{team_id}/members/{user_id}')
        def change_role(team_id: str, user_id: str, body: RoleInput, request: Request):
            current = self._require_session(request)
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                actor = self._require_team(conn, current['user_id'], team_id, True)
                target = conn.execute('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?',
                                      (team_id, user_id)).fetchone()
                if target is None:
                    raise HTTPException(404, '成员不存在')
                if target['role'] == 'owner' or actor['role'] != 'owner':
                    raise HTTPException(403, '只有团队所有者可以调整成员角色，所有者角色不能修改')
                old_role = target['role']
                conn.execute('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?',
                             (body.role, team_id, user_id))
                if old_role == 'admin' and body.role == 'member':
                    # A later re-promotion must not reactivate old invitation links.
                    conn.execute('UPDATE team_invitations SET revoked_at = ? WHERE team_id = ? AND created_by = ? AND accepted_at IS NULL AND revoked_at IS NULL',
                                 (time.time(), team_id, user_id))
            if old_role == 'admin' and body.role == 'member':
                self.on_access_changed(team_id, user_id)
            return {'ok': True, 'role': body.role}

        @app.delete('/api/teams/{team_id}/members/{user_id}')
        def remove_member(team_id: str, user_id: str, request: Request):
            current = self._require_session(request)
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                actor = self._require_team(conn, current['user_id'], team_id, True)
                target = conn.execute('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?',
                                      (team_id, user_id)).fetchone()
                if target is None:
                    raise HTTPException(404, '成员不存在')
                if target['role'] == 'owner' or (actor['role'] != 'owner' and target['role'] != 'member'):
                    raise HTTPException(403, '无权移除此成员')
                tables = self._tables(conn)
                if {'profile_assignments', 'profiles'} <= tables:
                    conn.execute('''DELETE FROM profile_assignments WHERE user_id = ?
                                    AND profile_id IN (SELECT id FROM profiles WHERE team_id = ?)''', (user_id, team_id))
                conn.execute('DELETE FROM team_members WHERE team_id = ? AND user_id = ?', (team_id, user_id))
                conn.execute('UPDATE user_sessions SET active_team_id = NULL WHERE user_id = ? AND active_team_id = ?',
                             (user_id, team_id))
                # Previously issued admin invitations must not outlive the inviter's membership.
                conn.execute('UPDATE team_invitations SET revoked_at = ? WHERE team_id = ? AND created_by = ? AND accepted_at IS NULL AND revoked_at IS NULL',
                             (time.time(), team_id, user_id))
            self.on_access_changed(team_id, user_id)
            return {'ok': True}

        @app.get('/api/teams/{team_id}/invitations')
        def invitations(team_id: str, request: Request):
            current = self._require_session(request)
            with self.db() as conn:
                self._require_team(conn, current['user_id'], team_id, True)
                return [self._invitation_public(row) for row in conn.execute(
                    'SELECT * FROM team_invitations WHERE team_id = ? ORDER BY created_at DESC', (team_id,))]

        @app.post('/api/teams/{team_id}/invitations')
        def invite(team_id: str, body: InvitationInput, request: Request):
            current = self._require_session(request)
            now, raw_token, invitation_id = time.time(), secrets.token_urlsafe(32), uuid4().hex
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                actor = self._require_team(conn, current['user_id'], team_id, True)
                if body.role == 'admin' and actor['role'] != 'owner':
                    raise HTTPException(403, '只有团队所有者可以邀请管理员')
                if conn.execute('''SELECT 1 FROM team_members m JOIN users u ON u.id = m.user_id
                                   WHERE m.team_id = ? AND u.email = ?''', (team_id, body.email)).fetchone():
                    raise HTTPException(409, '该用户已经是团队成员')
                conn.execute('''UPDATE team_invitations SET revoked_at = ? WHERE team_id = ? AND email = ?
                                AND accepted_at IS NULL AND revoked_at IS NULL''', (now, team_id, body.email))
                conn.execute('''INSERT INTO team_invitations
                    (id, team_id, email, role, token_hash, created_by, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (invitation_id, team_id, body.email, body.role, token_hash(raw_token), current['user_id'], now, now + INVITATION_SECONDS))
                row = conn.execute('SELECT * FROM team_invitations WHERE id = ?', (invitation_id,)).fetchone()
            return {**self._invitation_public(row), 'token': raw_token}

        @app.delete('/api/teams/{team_id}/invitations/{invitation_id}')
        def revoke_invitation(team_id: str, invitation_id: str, request: Request):
            current = self._require_session(request)
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                actor = self._require_team(conn, current['user_id'], team_id, True)
                row = conn.execute('SELECT * FROM team_invitations WHERE id = ? AND team_id = ?',
                                   (invitation_id, team_id)).fetchone()
                if row is None:
                    raise HTTPException(404, '邀请不存在')
                if row['role'] == 'admin' and actor['role'] != 'owner':
                    raise HTTPException(403, '只有团队所有者可以撤销管理员邀请')
                if row['accepted_at']:
                    raise HTTPException(409, '邀请已使用，请在成员列表中管理权限')
                conn.execute('UPDATE team_invitations SET revoked_at = ? WHERE id = ?', (time.time(), invitation_id))
            return {'ok': True}

        @app.post('/api/invitations/accept')
        def accept_invitation(body: AcceptInput, request: Request):
            current = self._require_session(request)
            now = time.time()
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                row = conn.execute('SELECT * FROM team_invitations WHERE token_hash = ?', (token_hash(body.token),)).fetchone()
                if (row is None or row['accepted_at'] or row['revoked_at'] or row['expires_at'] <= now
                        or row['email'] != current['user']['email']):
                    raise HTTPException(400, '邀请无效、已失效或与当前登录邮箱不匹配')
                inviter = conn.execute('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?',
                                       (row['team_id'], row['created_by'])).fetchone()
                if inviter is None or inviter['role'] not in ('owner', 'admin') or (row['role'] == 'admin' and inviter['role'] != 'owner'):
                    raise HTTPException(400, '邀请已失效，请联系团队管理员重新邀请')
                if conn.execute('SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?',
                                (row['team_id'], current['user_id'])).fetchone():
                    raise HTTPException(409, '你已经是该团队成员')
                conn.execute('INSERT INTO team_members VALUES (?, ?, ?, ?)',
                             (row['team_id'], current['user_id'], row['role'], now))
                conn.execute('UPDATE team_invitations SET accepted_at = ? WHERE id = ?', (now, row['id']))
                conn.execute('UPDATE user_sessions SET active_team_id = ? WHERE token_hash = ?',
                             (row['team_id'], current['token_hash']))
            return self.session_payload(request.cookies.get('session'))
