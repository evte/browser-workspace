import asyncio
import base64
import contextlib
import json
import os
import secrets
import signal
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import sys
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4
from typing import Literal, Optional

import websockets
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from . import proxies
from .proxy_runtime import GatewayRuntime
from .proxy_gateway import ProxyFailure
from .fingerprints import Fingerprint, browser_flags
from .kernels import KernelStore, KernelError
from .accounts import Accounts
from .totp import TotpStore, TotpError
from .runtime_identity import allocate_identity, prepare_profile_identity, create_xauthority, RuntimeIdentityError
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

DATA = Path(os.environ.get('DATA_DIR', '/data'))
DATA.mkdir(parents=True, exist_ok=True)
(DATA / 'profiles').mkdir(exist_ok=True)
PASSWORD = os.environ.get('ACCESS_PASSWORD', '')
if len(PASSWORD) < 12:
    raise RuntimeError('ACCESS_PASSWORD must be at least 12 characters')

app = FastAPI()
lock = threading.RLock()
running = {}
starting = {}
last_errors = {}
monitor_stop = threading.Event()
RUNTIME = Path(os.environ.get('PROXY_RUNTIME_DIR', '/run/browser-gateways'))
kernels = KernelStore(DATA / 'kernels')


def db():
    conn = sqlite3.connect(DATA / 'profiles.sqlite3', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

with db() as conn:
    conn.execute('CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL, proxy TEXT NOT NULL DEFAULT "")')
    if 'proxy_id' not in {row['name'] for row in conn.execute('PRAGMA table_info(profiles)')}:
        conn.execute('ALTER TABLE profiles ADD COLUMN proxy_id TEXT REFERENCES proxies(id)')
    columns = {row['name'] for row in conn.execute('PRAGMA table_info(profiles)')}
    if 'kernel_id' not in columns:
        conn.execute("ALTER TABLE profiles ADD COLUMN kernel_id TEXT NOT NULL DEFAULT 'chromium-system'")
    if 'fingerprint' not in columns:
        conn.execute("ALTER TABLE profiles ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '{}'")
    for name, declaration in [('team_id', 'TEXT'), ('tags', "TEXT NOT NULL DEFAULT '[]'"), ('notes', "TEXT NOT NULL DEFAULT ''"), ('runtime_uid', 'INTEGER'), ('totp_encrypted', "TEXT NOT NULL DEFAULT ''")]:
        if name not in columns:
            conn.execute(f'ALTER TABLE profiles ADD COLUMN {name} {declaration}')
    conn.execute('CREATE INDEX IF NOT EXISTS profiles_team ON profiles(team_id)')
    conn.execute('''CREATE TABLE IF NOT EXISTS profile_assignments (
        profile_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (profile_id, user_id))''')
    conn.execute('CREATE INDEX IF NOT EXISTS assignments_user ON profile_assignments(user_id, profile_id)')
    for row in conn.execute("SELECT id FROM profiles WHERE fingerprint = '{}' ").fetchall():
        conn.execute('UPDATE profiles SET fingerprint = ? WHERE id = ?', (Fingerprint().model_dump_json(), row['id']))
    proxies.initialize(conn)
    # Upgrade previously configured proxies so old environments also get the network guard.
    for row in conn.execute("SELECT id, proxy, team_id FROM profiles WHERE proxy != '' AND proxy_id IS NULL").fetchall():
        try:
            protocol = urlparse(row['proxy']).scheme
            proxies.import_proxies(conn, row['proxy'], 'url', protocol, row['team_id'])
            parsed = proxies.parse_import(row['proxy'], 'url', protocol)[0]
            candidates = conn.execute('SELECT * FROM proxies WHERE team_id IS ?', (row['team_id'],)).fetchall()
            proxy_id = next(item['id'] for item in candidates if all(item[k] == v for k, v in parsed.items()))
            conn.execute("UPDATE profiles SET proxy_id = ?, proxy = '' WHERE id = ?", (proxy_id, row['id']))
        except (ValueError, StopIteration):
            # Preserve the old configuration and refuse startup until it is explicitly replaced.
            last_errors[row['id']] = '旧代理配置无效，请重新绑定代理'
(DATA / 'profiles.sqlite3').chmod(0o600)
if os.geteuid() == 0:
    # Older images owned the entire data volume as the browser user.
    for path in (DATA, DATA / 'profiles'):
        os.chown(path, 0, 0)
        path.chmod(0o755)
    os.chown(DATA / 'profiles.sqlite3', 0, 0)

with db() as conn:
    totp_store = TotpStore(DATA / 'totp.key', encrypted_present=bool(
        conn.execute("SELECT 1 FROM profiles WHERE totp_encrypted != '' LIMIT 1").fetchone()))


accounts = Accounts(db, PASSWORD)
accounts.mount(app)


def check_origin(origin, host):
    if origin and urlparse(origin).netloc != host:
        raise HTTPException(403, 'Origin mismatch')


@app.middleware('http')
async def security(request: Request, call_next):
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        try:
            check_origin(request.headers.get('origin'), request.headers.get('host'))
        except HTTPException:
            return Response(status_code=403)
    if request.url.path.startswith('/api/'):
        request.state.account = accounts.resolve_session(request.cookies.get('session'))
        if request.url.path not in ('/api/login', '/api/session', '/api/register') and not request.state.account:
            return Response(status_code=401)
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            if request.headers.get('sec-fetch-site') == 'cross-site':
                return Response(status_code=403)
            # Mutating endpoints consume JSON; rejecting browser form content types
            # prevents cross-site form posts even when Origin is absent.
            if request.headers.get('content-length', '0') != '0' and 'application/json' not in request.headers.get('content-type', ''):
                return Response(status_code=415)
    response = await call_next(request)
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    elif request.method in ('GET', 'HEAD') and request.url.path in ('/', '/index.html', '/app.js', '/style.css'):
        # Revalidate the app shell and its assets together after an update,
        # including 304 responses that would otherwise retain stale cache rules.
        response.headers['Cache-Control'] = 'no-cache, max-age=0, must-revalidate'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # FastAPI's default includes request input, which may contain imported proxy passwords.
    return JSONResponse({'detail': '请求字段无效，请检查格式、必填项和内容长度'}, status_code=422)


class ProxyImport(BaseModel):
    text: str = Field(max_length=1_000_000)
    format: str
    protocol: str


def team_context(conn, request, manage=False):
    session = request.state.account
    team_id = request.headers.get('x-team-id') or session['active_team_id']
    team = conn.execute('''SELECT t.id, t.name, m.role FROM teams t JOIN team_members m ON m.team_id = t.id
                           WHERE t.id = ? AND m.user_id = ?''', (team_id, session['user_id'])).fetchone()
    if not team:
        raise HTTPException(404, '团队不存在或无权访问')
    if manage and team['role'] not in ('owner', 'admin'):
        raise HTTPException(403, '只有团队管理员可以执行此操作')
    return dict(team)


def profile_access(conn, profile_id, user_id, team_id=None, manage=False):
    row = conn.execute('SELECT * FROM profiles WHERE id = ?', (profile_id,)).fetchone()
    if not row or not row['team_id'] or (team_id is not None and row['team_id'] != team_id):
        raise HTTPException(404, '环境不存在或无权访问')
    member = conn.execute('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?',
                          (row['team_id'], user_id)).fetchone()
    assigned = conn.execute('SELECT 1 FROM profile_assignments WHERE profile_id = ? AND user_id = ?',
                            (profile_id, user_id)).fetchone()
    if not member or (member['role'] not in ('owner', 'admin') and not assigned):
        raise HTTPException(404, '环境不存在或未分配给你')
    if manage and member['role'] not in ('owner', 'admin'):
        raise HTTPException(403, '只有团队管理员可以修改环境配置')
    return {**dict(row), 'fingerprint': json.loads(row['fingerprint']), 'tags': json.loads(row['tags'])}


def authorized_profile(conn, request, profile_id, manage=False):
    team = team_context(conn, request)
    return profile_access(conn, profile_id, request.state.account['user_id'], team['id'], manage), team


def validate_assignees(conn, team_id, user_ids):
    user_ids = list(dict.fromkeys(user_ids))
    for user_id in user_ids:
        if not conn.execute('SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?', (team_id, user_id)).fetchone():
            raise HTTPException(422, '只能分配给本团队的现有成员')
    return user_ids


def replace_assignments(conn, profile_id, user_ids):
    conn.execute('DELETE FROM profile_assignments WHERE profile_id = ?', (profile_id,))
    conn.executemany('INSERT INTO profile_assignments (profile_id, user_id) VALUES (?, ?)',
                     [(profile_id, user_id) for user_id in user_ids])


@app.get('/api/proxies')
def proxy_list(request: Request):
    with db() as conn:
        team = team_context(conn, request, manage=True)
        return proxies.list_proxies(conn, team['id'])


@app.post('/api/proxies/import')
def proxy_import(body: ProxyImport, request: Request):
    try:
        with lock, db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            team = team_context(conn, request, manage=True)
            return proxies.import_proxies(conn, body.text, body.format, body.protocol, team['id'])
    except proxies.ImportValidationError as exc:
        raise HTTPException(422, {'message': '导入失败，整批未写入', 'errors': exc.errors}) from None


class MetadataInput(BaseModel):
    tags: Optional[list[str]] = Field(default=None, max_length=20)
    notes: Optional[str] = Field(default=None, max_length=2000)

    @field_validator('tags')
    @classmethod
    def normalize_tags(cls, value):
        if value is None:
            return None
        tags = []
        for tag in value:
            tag = tag.strip()
            if len(tag) > 32 or any(ord(char) < 32 or ord(char) == 127 for char in tag):
                raise ValueError('每个标签最多 32 字且不能包含控制字符')
            if tag and tag not in tags:
                tags.append(tag)
        return tags


class InlineProxyInput(BaseModel):
    text: str = Field(min_length=1, max_length=2048)
    format: Literal['host_port', 'host_port_auth', 'auth_host_port', 'url']
    protocol: Literal['http', 'https', 'socks4', 'socks5']


class ProfileInput(MetadataInput):
    name: str = Field(min_length=1, max_length=100)
    proxy_id: Optional[str] = None
    proxy: str = Field(default='', max_length=2048)
    inline_proxy: Optional[InlineProxyInput] = None
    kernel_id: Optional[str] = None
    fingerprint: Fingerprint = Field(default_factory=Fingerprint)
    assigned_user_ids: list[str] = Field(default_factory=list, max_length=100)
    totp_secret: Optional[str] = Field(default=None, max_length=4096)
    clear_totp: bool = False


class ProxyBinding(BaseModel):
    proxy_id: Optional[str] = None


class ProfileSettings(MetadataInput):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    proxy_id: Optional[str] = None
    kernel_id: Optional[str] = None
    fingerprint: Optional[Fingerprint] = None
    assigned_user_ids: Optional[list[str]] = Field(default=None, max_length=100)
    totp_secret: Optional[str] = Field(default=None, max_length=4096)
    clear_totp: bool = False


class TotpCodesInput(BaseModel):
    profile_ids: list[str] = Field(default_factory=list, max_length=100)


def updated_totp(body, previous=''):
    secret = body.totp_secret.strip() if body.totp_secret else ''
    if body.clear_totp and secret:
        raise HTTPException(422, '不能同时清除和设置 2FA 密钥')
    if body.clear_totp:
        return ''
    if not secret:
        return previous
    try:
        return totp_store.encrypt(secret)
    except TotpError as exc:
        raise HTTPException(422, str(exc)) from None


class AssignmentInput(BaseModel):
    profile_ids: list[str] = Field(min_length=1, max_length=1000)
    user_ids: list[str] = Field(default_factory=list, max_length=100)


@app.get('/api/kernels')
def kernel_list():
    return kernels.list_kernels()


def selected_kernel(kernel_id):
    try:
        kernel = kernels.get_kernel(kernel_id)
    except KernelError as exc:
        raise HTTPException(422, str(exc)) from None
    if kernel_id != 'chromium-system' and kernel['state'] == 'unavailable':
        raise HTTPException(422, '该内核不支持当前服务器架构')
    return kernel


def profile_record(profile_id):
    with db() as conn:
        row = conn.execute('SELECT * FROM profiles WHERE id = ?', (profile_id,)).fetchone()
    if row is None:
        raise HTTPException(404, 'Profile not found')
    return {**dict(row), 'fingerprint': json.loads(row['fingerprint']), 'tags': json.loads(row['tags'])}


def bound_proxy(row):
    if row['proxy_id']:
        with db() as conn:
            proxy = proxies.get_proxy(conn, row['proxy_id'], row['team_id'])
        if proxy is None:
            raise HTTPException(409, '绑定的代理不存在，请重新绑定')
        return proxy
    if row['proxy']:
        raise HTTPException(409, '旧代理配置无效，请重新绑定代理')
    return None


def record_status(row, role=None):
    with lock:
        active = row['id'] in running and all(p.poll() is None for p in running[row['id']]['processes'])
        error = last_errors.get(row['id'])
        job = starting.get(row['id'])
        pending_status = job['status'] if job else None
    fingerprint = row['fingerprint'] if isinstance(row['fingerprint'], dict) else json.loads(row['fingerprint'])
    kernel = kernels.get_kernel(row['kernel_id'])
    with db() as conn:
        proxy = proxies.get_proxy(conn, row['proxy_id'], row['team_id']) if row['proxy_id'] else None
        assigned = [dict(user) for user in conn.execute('''SELECT u.id, u.name, u.email FROM users u
            JOIN profile_assignments a ON a.user_id = u.id
            JOIN team_members m ON m.user_id = u.id AND m.team_id = ?
            WHERE a.profile_id = ? ORDER BY u.name, u.id''', (row['team_id'], row['id']))]
    display = proxies.public_proxy(proxy)['display'] if proxy else ''
    public_row = {key: value for key, value in row.items() if key not in ('runtime_uid', 'totp_encrypted')}
    return {**public_row, 'fingerprint': fingerprint, 'tags': row['tags'] if isinstance(row['tags'], list) else json.loads(row['tags']),
            'assigned_users': assigned, 'assigned_user_ids': [user['id'] for user in assigned],
            'has_totp': bool(row.get('totp_encrypted')),
            'can_manage': role in ('owner', 'admin'), 'kernel_name': kernel['name'],
            'kernel_state': kernel['state'], 'kernel_progress': kernel.get('progress'),
            'proxy_needs_configuration': bool(row['proxy']),
            'proxy': display, 'proxy_display': display, 'last_error': error,
            'status': 'running' if active else (pending_status or ('error' if error else 'stopped')),
            'view_url': f"/novnc/vnc.html?autoconnect=1&resize=scale&path=api/profiles/{row['id']}/ws" if active else None}


@app.get('/api/profiles')
def profiles(request: Request):
    with db() as conn:
        team = team_context(conn, request)
        sql = 'SELECT p.* FROM profiles p WHERE p.team_id = ?'
        params = [team['id']]
        if team['role'] == 'member':
            sql += ' AND EXISTS (SELECT 1 FROM profile_assignments a WHERE a.profile_id = p.id AND a.user_id = ?)'
            params.append(request.state.account['user_id'])
        rows = [dict(row) for row in conn.execute(sql + ' ORDER BY p.rowid DESC', params)]
    return [record_status(row, team['role']) for row in rows]


@app.get('/api/profiles/{profile_id}')
def profile_detail(profile_id: str, request: Request):
    with db() as conn:
        row, team = authorized_profile(conn, request, profile_id)
    return record_status(row, team['role'])


@app.post('/api/totp/codes')
def totp_codes(body: TotpCodesInput, request: Request):
    with db() as conn:
        # Keep authorization and retrieval in one snapshot. Validate the whole
        # batch before revealing any codes, including unknown/unassigned IDs.
        conn.execute('BEGIN')
        team = team_context(conn, request)
        rows = [profile_access(conn, profile_id, request.state.account['user_id'], team['id'])
                for profile_id in dict.fromkeys(body.profile_ids)]
        now = time.time()
        try:
            codes = [{'profile_id': row['id'], **totp_store.code(row['totp_encrypted'], now)}
                     for row in rows if row['totp_encrypted']]
        except TotpError as exc:
            raise HTTPException(503, str(exc)) from None
    return {'server_time': int(now * 1000), 'codes': codes}


@app.post('/api/profiles')
def create_profile(body: ProfileInput, request: Request):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, 'Name cannot be empty')
    if sum((bool(body.proxy_id), bool(body.proxy), body.inline_proxy is not None)) > 1:
        raise HTTPException(422, '已有代理和直接填写代理只能选择一种')
    kernel_id = body.kernel_id or next((k['id'] for k in kernels.list_kernels() if k.get('recommended') and k['state'] != 'unavailable'), 'chromium-system')
    selected_kernel(kernel_id)
    with lock, db() as conn:
        conn.execute('BEGIN IMMEDIATE')
        team = team_context(conn, request, manage=True)
        totp_encrypted = updated_totp(body)
        assignees = validate_assignees(conn, team['id'], body.assigned_user_ids)
        proxy_id = body.proxy_id
        if body.inline_proxy is not None:
            try:
                parsed = proxies.parse_single(body.inline_proxy.text, body.inline_proxy.format, body.inline_proxy.protocol)
            except proxies.ImportValidationError as exc:
                reason = exc.errors[0]['reason'] if exc.errors else '请检查代理格式'
                raise HTTPException(422, {'message': f'代理配置无效：{reason}', 'errors': exc.errors}) from None
            proxy_id, _ = proxies.ensure_proxy(conn, parsed, team['id'])
        elif body.proxy:
            # Preserve older API callers without returning their credentials.
            try:
                protocol = urlparse(body.proxy).scheme
                parsed = proxies.parse_single(body.proxy, 'url', protocol)
            except ValueError:
                raise HTTPException(400, '代理地址格式无效') from None
            proxy_id, _ = proxies.ensure_proxy(conn, parsed, team['id'])
        if proxy_id and not proxies.get_proxy(conn, proxy_id, team['id']):
            raise HTTPException(404, '代理不存在')
        profile_id = uuid4().hex
        conn.execute('''INSERT INTO profiles (id, name, proxy, proxy_id, kernel_id, fingerprint, team_id, tags, notes, totp_encrypted)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (profile_id, name, '', proxy_id, kernel_id, body.fingerprint.model_dump_json(), team['id'],
                      json.dumps(body.tags or []), body.notes or '', totp_encrypted))
        replace_assignments(conn, profile_id, assignees)
    return record_status(profile_record(profile_id), team['role'])


@app.patch('/api/profiles/{profile_id}/proxy')
def bind_proxy(profile_id: str, body: ProxyBinding, request: Request):
    with lock, db() as conn:
        conn.execute('BEGIN IMMEDIATE')
        _, team = authorized_profile(conn, request, profile_id, manage=True)
        if profile_id in running or profile_id in starting:
            raise HTTPException(409, '请先停止环境再更换代理')
        if body.proxy_id and not proxies.get_proxy(conn, body.proxy_id, team['id']):
            raise HTTPException(404, '代理不存在')
        conn.execute("UPDATE profiles SET proxy_id = ?, proxy = '' WHERE id = ?", (body.proxy_id, profile_id))
        last_errors.pop(profile_id, None)
    return record_status(profile_record(profile_id), team['role'])


@app.patch('/api/profiles/{profile_id}/settings')
def configure_profile(profile_id: str, body: ProfileSettings, request: Request):
    with lock, db() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row, team = authorized_profile(conn, request, profile_id, manage=True)
        totp_encrypted = updated_totp(body, row['totp_encrypted'])
        if (profile_id in running or profile_id in starting) and {'proxy_id', 'kernel_id', 'fingerprint'} & body.model_fields_set:
            raise HTTPException(409, '请先停止环境再修改配置')
        name = body.name.strip() if body.name is not None else row['name']
        if not name:
            raise HTTPException(422, '环境名称不能为空')
        kernel_id = body.kernel_id or row['kernel_id']
        selected_kernel(kernel_id)
        changes_proxy = 'proxy_id' in body.model_fields_set
        proxy_id = body.proxy_id if changes_proxy else row['proxy_id']
        legacy_proxy = '' if changes_proxy else row['proxy']
        identity = row['fingerprint']
        if body.fingerprint:
            # A partial settings update must not silently regenerate a browser identity.
            identity = Fingerprint(**{**identity, **body.fingerprint.model_dump(exclude_unset=True)}).model_dump()
        if proxy_id and not proxies.get_proxy(conn, proxy_id, team['id']):
            raise HTTPException(404, '代理不存在')
        if body.assigned_user_ids is not None:
            assignees = validate_assignees(conn, team['id'], body.assigned_user_ids)
            replace_assignments(conn, profile_id, assignees)
        conn.execute('''UPDATE profiles SET name = ?, proxy_id = ?, proxy = ?, kernel_id = ?, fingerprint = ?,
                        tags = ?, notes = ?, totp_encrypted = ? WHERE id = ?''',
                     (name, proxy_id, legacy_proxy, kernel_id, json.dumps(identity),
                      json.dumps(body.tags if body.tags is not None else row['tags']),
                      body.notes if body.notes is not None else row['notes'], totp_encrypted, profile_id))
        if not legacy_proxy:
            last_errors.pop(profile_id, None)
    reconcile_access(profile_id=profile_id)
    return record_status(profile_record(profile_id), team['role'])


@app.patch('/api/profiles/{profile_id}/metadata')
def update_metadata(profile_id: str, body: MetadataInput, request: Request):
    with lock, db() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row, team = authorized_profile(conn, request, profile_id)
        conn.execute('UPDATE profiles SET tags = ?, notes = ? WHERE id = ?',
                     (json.dumps(body.tags if body.tags is not None else row['tags']),
                      body.notes if body.notes is not None else row['notes'], profile_id))
    return record_status(profile_record(profile_id), team['role'])


@app.post('/api/profiles/assign')
def assign_profiles(body: AssignmentInput, request: Request):
    profile_ids = list(dict.fromkeys(body.profile_ids))
    with lock, db() as conn:
        conn.execute('BEGIN IMMEDIATE')
        team = team_context(conn, request, manage=True)
        user_ids = validate_assignees(conn, team['id'], body.user_ids)
        for profile_id in profile_ids:
            profile_access(conn, profile_id, request.state.account['user_id'], team['id'], manage=True)
        for profile_id in profile_ids:
            replace_assignments(conn, profile_id, user_ids)
    for profile_id in profile_ids:
        reconcile_access(profile_id=profile_id)
    return {'updated': len(profile_ids)}


def wait_port(port, processes, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('Browser service exited during startup')
        with socket.socket() as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(('127.0.0.1', port)) == 0:
                return
        time.sleep(.1)
    raise RuntimeError('Browser service startup timed out')


def terminate(processes):
    # A failed parent may still have descendants, so signal its entire group even after exit.
    for process in reversed(processes):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
    for process in processes:
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)


def stop_running(profile_id):
    item = running.pop(profile_id, None)
    if item:
        # Closing the gateway tears down all upstream connections before stopping Chromium.
        try:
            if item.get('gateway'):
                item['gateway'].close()
        finally:
            terminate(item['processes'])
            if item.get('directory'):
                shutil.rmtree(item['directory'], ignore_errors=True)


def user_can_access(profile_id, user_id):
    try:
        with db() as conn:
            profile_access(conn, profile_id, user_id)
        return True
    except HTTPException:
        return False


def reconcile_access(team_id=None, user_id=None, profile_id=None):
    """An old start request must not launch a browser after its access was revoked."""
    with lock:
        for pid in set(starting) | set(running):
            if profile_id and pid != profile_id:
                continue
            if team_id:
                with db() as conn:
                    row = conn.execute('SELECT team_id FROM profiles WHERE id = ?', (pid,)).fetchone()
                if not row or row['team_id'] != team_id:
                    continue
            job = starting.get(pid)
            if job and (not user_id or job.get('user_id') == user_id):
                if not user_can_access(pid, job.get('user_id')):
                    starting.pop(pid, None)
            item = running.get(pid)
            if item and item.get('started_by') and (not user_id or item['started_by'] == user_id):
                if not user_can_access(pid, item['started_by']):
                    stop_running(pid)


accounts.on_access_changed = reconcile_access


def proxy_failed(profile_id, generation, reason):
    def stop_failed():
        with lock:
            item = running.get(profile_id)
            if item and item['generation'] == generation:
                last_errors[profile_id] = reason
                stop_running(profile_id)
    threading.Thread(target=stop_failed, daemon=True).start()


def browser_user(args, uid=10001):
    if os.geteuid() == 0:
        return ['setpriv', f'--reuid={uid}', f'--regid={uid}', '--clear-groups',
                '--bounding-set=-all', '--no-new-privs', *args]
    return args


@app.post('/api/profiles/{profile_id}/start')
def start_profile(profile_id: str, request: Request):
    with lock:
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row, team = authorized_profile(conn, request, profile_id)
        existing = running.get(profile_id)
        if profile_id in starting or (existing and all(p.poll() is None for p in existing['processes'])):
            return record_status(row, team['role'])
        stop_running(profile_id)
        proxy = bound_proxy(row)
        if proxy and (sys.platform != 'linux' or os.geteuid() != 0 or not shutil.which('unshare') or not shutil.which('ip')):
            raise HTTPException(503, '浏览器保护需要 Linux 容器的网络隔离能力，请按新版 Compose 启动服务')
        if len(running) + len(starting) >= 20:
            raise HTTPException(409, '最多允许 20 个正在启动或运行的环境')
        kernel = selected_kernel(row['kernel_id'])
        job = {'status': 'starting' if kernel['state'] == 'ready' else 'downloading',
               'user_id': request.state.account['user_id'], 'cookie': request.cookies.get('session')}
        starting[profile_id] = job
        last_errors.pop(profile_id, None)

        def prepare():
            try:
                # Large downloads and per-kernel serialization never hold the profile lock.
                executable = kernels.ensure_kernel(row['kernel_id'])
                with lock:
                    if starting.get(profile_id) is not job:
                        return
                    if not accounts.resolve_session(job['cookie']) or not user_can_access(profile_id, job['user_id']):
                        return
                    job['status'] = 'starting'
                    _launch_profile(profile_id, executable)
                    if profile_id in running:
                        running[profile_id]['started_by'] = job['user_id']
            except Exception as exc:
                with lock:
                    if starting.get(profile_id) is job:
                        if isinstance(exc, KernelError):
                            last_errors[profile_id] = str(exc)
                        elif isinstance(exc, HTTPException):
                            last_errors[profile_id] = str(exc.detail)
                        else:
                            last_errors[profile_id] = '内核准备或浏览器启动失败，请检查服务器依赖后重试'
            finally:
                with lock:
                    if starting.get(profile_id) is job:
                        starting.pop(profile_id, None)
        threading.Thread(target=prepare, name=f'start-{profile_id[:8]}', daemon=True).start()
        return record_status(row, team['role'])


def _launch_profile(profile_id: str, executable: str):
    with lock:
        row = profile_record(profile_id)
        existing = running.get(profile_id)
        if existing and all(p.poll() is None for p in existing['processes']):
            return record_status(row)
        stop_running(profile_id)
        proxy = bound_proxy(row)
        if sys.platform != 'linux' or os.geteuid() != 0 or not shutil.which('unshare') or not shutil.which('ip'):
            raise HTTPException(503, '浏览器运行需要 Linux 容器的用户和网络隔离能力，请按新版 Compose 启动服务')
        used = {item['slot'] for item in running.values()}
        slot = next((i for i in range(20) if i not in used), None)
        if slot is None:
            raise HTTPException(409, 'Maximum of 20 concurrent profiles reached')
        display, vnc_port, ws_port = 100 + slot, 15900 + slot, 16000 + slot
        processes = []
        gateway = None
        directory = None
        generation = uuid4().hex
        last_errors.pop(profile_id, None)
        try:
            clean_env = {k: v for k, v in os.environ.items() if k not in ('ACCESS_PASSWORD', 'SESSION_SECRET') and 'proxy' not in k.lower()}
            def launch(args, env=None):
                p = subprocess.Popen(args, env=env or clean_env, start_new_session=True,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(p)
                return p
            profile_path = DATA / 'profiles' / profile_id
            with db() as conn:
                uid = allocate_identity(conn, profile_id)
            clean_env['HOME'] = str(prepare_profile_identity(profile_path, uid))
            RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o755)
            directory = RUNTIME / profile_id
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chown(directory, uid, uid)
            clean_env['XAUTHORITY'] = str(create_xauthority(directory / 'Xauthority', uid, display))
            desktop_secret = secrets.token_urlsafe(32)
            secret_path = directory / 'desktop-secret'
            secret_fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(secret_fd, 'w') as secret_file:
                secret_file.write(desktop_secret)
                os.fchown(secret_file.fileno(), uid, uid)
            gateway = GatewayRuntime(proxy, directory / 'proxy.sock',
                                     lambda reason: proxy_failed(profile_id, generation, reason))
            os.chown(directory / 'proxy.sock', uid, uid)
            fingerprint = row['fingerprint']
            kernel = kernels.get_kernel(row['kernel_id'])
            if kernel['engine'] == 'fingerprint-chromium':
                clean_env['TZ'] = fingerprint['timezone']
            screen = f"{fingerprint['width']}x{fingerprint['height']}x24"
            # The sticky directory must belong to the manager, not the first
            # browser UID (a directory owner can unlink other users' sockets).
            Path('/tmp/.X11-unix').mkdir(mode=0o1777, exist_ok=True)
            x11_dir = os.open('/tmp/.X11-unix', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchown(x11_dir, 0, 0)
                os.fchmod(x11_dir, 0o1777)
            finally:
                os.close(x11_dir)
            # This slot has no live desktop; remove stale files from a crash.
            for stale in (Path(f'/tmp/.X11-unix/X{display}'), Path(f'/tmp/.X{display}-lock')):
                with contextlib.suppress(FileNotFoundError):
                    stale.unlink()
            launch(browser_user(['Xvfb', f':{display}', '-screen', '0', screen, '-nolisten', 'tcp',
                                 '-auth', clean_env['XAUTHORITY']], uid))
            for _ in range(100):
                if Path(f'/tmp/.X11-unix/X{display}').exists():
                    break
                if processes[0].poll() is not None:
                    raise RuntimeError('Display failed to start')
                time.sleep(.05)
            else:
                raise RuntimeError('Display startup timed out')
            env = {**clean_env, 'DISPLAY': f':{display}'}
            launch(browser_user(['x11vnc', '-display', f':{display}', '-auth', clean_env['XAUTHORITY'],
                                 '-localhost', '-no6', '-forever', '-shared', '-nopw', '-rfbport', str(vnc_port)], uid))
            wait_port(vnc_port, processes)
            launch(browser_user(['websockify', '--auth-plugin', 'backend.desktop_auth.FileSecretAuth',
                                 '--auth-source', str(secret_path), f'127.0.0.1:{ws_port}', f'127.0.0.1:{vnc_port}'], uid),
                   {**clean_env, 'PYTHONPATH': str(Path(__file__).resolve().parents[1])})
            wait_port(ws_port, processes)
            # The plugin has loaded its credential before opening its listener.
            # Keep it only in server memory, not in the browser-readable runtime directory.
            secret_path.unlink()
            args = [executable, '--no-sandbox', '--no-first-run', '--no-default-browser-check',
                    '--disable-dev-shm-usage', f'--user-data-dir={profile_path}', *browser_flags(kernel, fingerprint)]
            args += ['--proxy-server=http://127.0.0.1:3128', '--proxy-bypass-list=<-loopback>',
                         '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
                         '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']
            args.append('about:blank')
            ready = directory / 'ready'
            env['BROWSER_PARENT_NETNS'] = os.readlink('/proc/self/ns/net')
            launch(['unshare', '--net', '--', sys.executable, str(Path(__file__).with_name('network_worker.py')),
                    '--uid', str(uid), '--socket', str(directory / 'proxy.sock'), '--ready', str(ready), '--', *args], env)
            for _ in range(120):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError('隔离环境启动失败，请检查容器 SYS_ADMIN/NET_ADMIN 权限')
                if ready.exists():
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('隔离环境启动超时')
            if gateway.gateway.tripped:
                raise RuntimeError('网络检测失败，已阻止环境联网')
            running[profile_id] = {'slot': slot, 'port': ws_port, 'processes': processes,
                                   'gateway': gateway, 'directory': directory, 'generation': generation,
                                   'desktop_secret': desktop_secret}
        except Exception as exc:
            try:
                if gateway:
                    gateway.close()
            finally:
                terminate(processes)
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)
            reason = str(exc) if isinstance(exc, (ProxyFailure, RuntimeIdentityError)) else ('代理不可用或网络隔离启动失败，环境已停止' if proxy else '浏览器启动失败，请检查服务端运行依赖')
            last_errors[profile_id] = reason
            raise HTTPException(503, reason) from None
    return record_status(row)


@app.post('/api/profiles/{profile_id}/stop')
def stop_profile(profile_id: str, request: Request):
    with lock:
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row, team = authorized_profile(conn, request, profile_id)
        # Cancel this profile's pending launch; a shared kernel download can finish for others.
        starting.pop(profile_id, None)
        stop_running(profile_id)
        last_errors.pop(profile_id, None)
    return record_status(row, team['role'])


@app.delete('/api/profiles/{profile_id}')
def delete_profile(profile_id: str, request: Request):
    with lock, db() as conn:
        conn.execute('BEGIN IMMEDIATE')
        authorized_profile(conn, request, profile_id, manage=True)
        if profile_id in starting:
            raise HTTPException(409, '请先停止启动任务再删除环境')
        if profile_id in running and all(p.poll() is None for p in running[profile_id]['processes']):
            raise HTTPException(409, 'Stop the profile before deleting it')
        stop_running(profile_id)
        # Delete data first so a failed removal can be retried from the UI.
        directory = DATA / 'profiles' / profile_id
        if directory.exists():
            shutil.rmtree(directory)
        conn.execute('DELETE FROM profile_assignments WHERE profile_id = ?', (profile_id,))
        conn.execute('DELETE FROM profiles WHERE id = ?', (profile_id,))
        last_errors.pop(profile_id, None)
    return {'ok': True}


@app.websocket('/api/profiles/{profile_id}/ws')
async def view(websocket: WebSocket, profile_id: str):
    cookie = websocket.cookies.get('session')
    session = accounts.resolve_session(cookie)
    if not session or not user_can_access(profile_id, session['user_id']):
        await websocket.close(code=1008)
        return
    try:
        check_origin(websocket.headers.get('origin'), websocket.headers.get('host'))
    except HTTPException:
        await websocket.close(code=1008)
        return
    with lock:
        item = running.get(profile_id)
        port = item['port'] if item and all(p.poll() is None for p in item['processes']) else None
    if not port:
        await websocket.close(code=1008)
        return

    def connection_authorized():
        # Re-check bearer revocation and membership/assignment, not only the
        # handshake. An open remote desktop must not survive removal or logout.
        fresh = accounts.resolve_session(cookie)
        if not fresh or not user_can_access(profile_id, fresh['user_id']):
            return False
        with lock:
            return running.get(profile_id) is item and all(p.poll() is None for p in item['processes'])

    try:
        authorization = base64.b64encode(('viewer:' + item.get('desktop_secret', '')).encode()).decode()
        async with websockets.connect(f'ws://127.0.0.1:{port}', max_size=None,
                                      additional_headers={'Authorization': 'Basic ' + authorization}) as upstream:
            # Slots can be reused while the connection awaits; never attach an old
            # profile URL to a different desktop that now occupies the same port.
            if not connection_authorized():
                await websocket.close(code=1008)
                return
            await websocket.accept()
            async def client_to_server():
                while True:
                    message = await websocket.receive()
                    if message['type'] == 'websocket.disconnect':
                        break
                    if not connection_authorized():
                        await websocket.close(code=1008)
                        return
                    if message.get('bytes') is not None:
                        await upstream.send(message['bytes'])
                    elif message.get('text') is not None:
                        await upstream.send(message['text'])
            async def server_to_client():
                async for message in upstream:
                    if isinstance(message, bytes):
                        await websocket.send_bytes(message)
                    else:
                        await websocket.send_text(message)
            async def check_access():
                while True:
                    await asyncio.sleep(1)
                    if not connection_authorized():
                        await websocket.close(code=1008)
                        return
            tasks = [asyncio.create_task(client_to_server()), asyncio.create_task(server_to_client()),
                     asyncio.create_task(check_access())]
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    except (OSError, WebSocketDisconnect, websockets.WebSocketException):
        with contextlib.suppress(Exception):
            await websocket.close()


@app.on_event('startup')
def startup():
    monitor_stop.clear()
    def monitor():
        while not monitor_stop.wait(1):
            with lock:
                for profile_id, item in list(running.items()):
                    if any(p.poll() is not None for p in item['processes']):
                        last_errors[profile_id] = '浏览器或连接服务已退出，环境已停止'
                        stop_running(profile_id)
    threading.Thread(target=monitor, daemon=True).start()


@app.on_event('shutdown')
def shutdown():
    monitor_stop.set()
    with lock:
        starting.clear()
        for profile_id in list(running):
            stop_running(profile_id)


app.mount('/novnc', StaticFiles(directory=os.environ.get('NOVNC_DIR', '/usr/share/novnc')), name='novnc')
FRONTEND = Path(os.environ.get('FRONTEND_DIR', str(Path(__file__).resolve().parents[1] / 'frontend')))
if FRONTEND.is_dir():
    app.mount('/', StaticFiles(directory=str(FRONTEND), html=True), name='frontend')
