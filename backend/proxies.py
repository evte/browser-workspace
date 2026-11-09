"""Parse and store proxy definitions without exposing secrets in errors or API records."""

import hashlib
import ipaddress
import json
import re
from urllib.parse import unquote, urlsplit
from uuid import uuid4

PROTOCOLS = {'http', 'https', 'socks4', 'socks5'}
FORMATS = {'host_port', 'host_port_auth', 'auth_host_port', 'url'}
COLUMNS = ('id', 'protocol', 'host', 'port', 'username', 'password')
MAX_LINES = 1000
MAX_TEXT_LENGTH = 1_000_000


class ImportValidationError(ValueError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__('代理导入校验失败')


def normalize_protocol(protocol):
    value = str(protocol).strip().lower()
    value = {'socket': 'socks5', 'socks': 'socks5'}.get(value, value)
    if value not in PROTOCOLS:
        raise ValueError('协议应为 HTTP、HTTPS、SOCKS4 或 SOCKS5')
    return value


def _hostname(host):
    if not host or any(char.isspace() or ord(char) < 32 for char in host):
        raise ValueError('代理主机无效')
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        if ':' in host or all(char.isdigit() or char == '.' for char in host):
            raise ValueError('IP 地址无效') from None
    try:
        host = host.removesuffix('.').encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('代理主机无效') from None
    label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    if len(host) > 253 or not all(re.fullmatch(label, part) for part in host.split('.')):
        raise ValueError('代理主机无效')
    return host


def _authority(value):
    match = re.fullmatch(r'(\[[^\]]+\]|[^:]+):([0-9]+)', value)
    if not match:
        raise ValueError('地址应为 host:port，IPv6 地址必须使用方括号')
    host, raw_port = match.groups()
    if host.startswith('['):
        try:
            host = ipaddress.IPv6Address(host[1:-1]).compressed
        except ValueError:
            raise ValueError('IPv6 地址无效') from None
    else:
        host = _hostname(host)
    # Bound the string before converting arbitrarily long user input to int.
    if len(raw_port) > 5 or not 1 <= int(raw_port) <= 65535:
        raise ValueError('端口必须在 1–65535 之间')
    return host, int(raw_port)


def _decode_url_credential(value):
    if re.search(r'%(?![0-9a-fA-F]{2})', value):
        raise ValueError('URL 凭据含无效百分号编码')
    try:
        return unquote(value, errors='strict')
    except UnicodeDecodeError:
        raise ValueError('URL 凭据编码无效') from None


def _credentials(username, password, protocol):
    if protocol in ('http', 'https') and ':' in username:
        raise ValueError('HTTP/HTTPS 代理的用户名不能包含冒号')
    if password and not username:
        raise ValueError('设置密码时必须填写用户名')
    if any(ord(char) < 32 or ord(char) == 127 for char in username + password):
        raise ValueError('凭据不能包含控制字符')
    if len(username.encode('utf-8')) > 255 or len(password.encode('utf-8')) > 255:
        raise ValueError('用户名或密码长度不能超过 255 字节')
    if protocol == 'socks4' and password:
        raise ValueError('SOCKS4 仅支持用户标识，不支持密码，请选择 SOCKS5')


def _parse_line(line, format, protocol):
    if any(ord(char) < 32 or ord(char) == 127 for char in line):
        raise ValueError('代理配置不能包含控制字符')
    username = password = ''
    if format == 'url':
        try:
            parts = urlsplit(line)
        except ValueError:
            raise ValueError('代理 URL 格式无效') from None
        if normalize_protocol(parts.scheme) != protocol:
            raise ValueError('URL 中的协议与所选协议不一致')
        if not parts.netloc or parts.path not in ('', '/') or parts.query or parts.fragment:
            raise ValueError('代理 URL 应仅包含协议、凭据、主机和端口')
        authority = parts.netloc
        if '@' in authority:
            credentials, authority = authority.rsplit('@', 1)
            username, separator, password = credentials.partition(':')
            username = _decode_url_credential(username)
            password = _decode_url_credential(password)
    elif format == 'host_port_auth':
        match = re.fullmatch(r'(\[[^\]]+\]|[^:]+):([^:]+):([^:]*):(.*)', line)
        if not match:
            raise ValueError('格式应为 host:port:username:password')
        host, port, username, password = match.groups()
        authority = f'{host}:{port}'
    elif format == 'auth_host_port':
        if '@' not in line:
            raise ValueError('格式应为 username:password@host:port')
        credentials, authority = line.rsplit('@', 1)
        username, separator, password = credentials.partition(':')
        if not separator:
            raise ValueError('格式应为 username:password@host:port')
    else:
        authority = line
    host, port = _authority(authority)
    _credentials(username, password, protocol)
    return {'protocol': protocol, 'host': host, 'port': port,
            'username': username, 'password': password}


def parse_import(text, format, protocol):
    """Validate the entire batch before callers write any records."""
    if format not in FORMATS:
        raise ImportValidationError([{'line': 0, 'reason': '不支持的代理格式'}])
    try:
        protocol = normalize_protocol(protocol)
    except ValueError as exc:
        raise ImportValidationError([{'line': 0, 'reason': str(exc)}]) from None
    if not isinstance(text, str) or len(text) > MAX_TEXT_LENGTH:
        raise ImportValidationError([{'line': 0, 'reason': '导入内容过大'}])
    lines = [(number, line.strip()) for number, line in enumerate(text.splitlines(), 1) if line.strip()]
    if not lines:
        raise ImportValidationError([{'line': 0, 'reason': '请至少输入一条代理'}])
    if len(lines) > MAX_LINES:
        raise ImportValidationError([{'line': 0, 'reason': '每次最多导入 1000 条代理'}])
    errors, parsed = [], []
    for number, line in lines:
        try:
            parsed.append(_parse_line(line, format, protocol))
        except ValueError as exc:
            errors.append({'line': number, 'reason': str(exc)})
    if errors:
        raise ImportValidationError(errors)
    return parsed


def parse_single(text, format, protocol):
    """Use the same parser as bulk import, but never create a hidden extra proxy."""
    parsed = parse_import(text, format, protocol)
    if len(parsed) != 1:
        raise ImportValidationError([{'line': 0, 'reason': '新建环境只能填写一条代理'}])
    return parsed[0]


def initialize(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS proxies (
        id TEXT PRIMARY KEY,
        protocol TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        username TEXT NOT NULL DEFAULT '',
        password TEXT NOT NULL DEFAULT '',
        identity TEXT NOT NULL UNIQUE
    )''')
    if 'team_id' not in {row[1] for row in conn.execute('PRAGMA table_info(proxies)')}:
        conn.execute('ALTER TABLE proxies ADD COLUMN team_id TEXT')
    conn.execute('CREATE INDEX IF NOT EXISTS proxies_team ON proxies(team_id)')


def public_proxy(row):
    host = f"[{row['host']}]" if ':' in row['host'] else row['host']
    return {key: row[key] for key in ('id', 'protocol', 'host', 'port', 'username')} | {
        'has_password': bool(row['password']),
        'display': f"{row['protocol']}://{host}:{row['port']}",
    }


def get_proxy(conn, proxy_id, team_id=None):
    sql = 'SELECT id, protocol, host, port, username, password FROM proxies WHERE id = ?'
    params = [proxy_id]
    if team_id is not None:
        sql += ' AND team_id = ?'
        params.append(team_id)
    row = conn.execute(sql, params).fetchone()
    return dict(zip(COLUMNS, row)) if row is not None else None


def list_proxies(conn, team_id=None):
    sql = 'SELECT id, protocol, host, port, username, password FROM proxies'
    rows = conn.execute(sql + (' WHERE team_id = ?' if team_id is not None else '') + ' ORDER BY rowid DESC',
                        (team_id,) if team_id is not None else ())
    return [public_proxy(dict(zip(COLUMNS, row))) for row in rows]


def ensure_proxy(conn, proxy, team_id=None):
    """Return (id, created) for a parsed proxy within the caller's transaction."""
    # Match fields too, so installations upgraded from unscoped identities keep
    # deduplicating. Identical credentials in another team are never reused.
    existing = conn.execute('''SELECT id FROM proxies WHERE team_id IS ? AND protocol = ?
        AND host = ? AND port = ? AND username = ? AND password = ?''',
        (team_id, proxy['protocol'], proxy['host'], proxy['port'], proxy['username'], proxy['password'])).fetchone()
    if existing:
        return existing[0], False
    identity = hashlib.sha256(json.dumps({'team_id': team_id, 'proxy': proxy}, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    proxy_id = uuid4().hex
    conn.execute('INSERT INTO proxies (id, protocol, host, port, username, password, identity, team_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 (proxy_id, proxy['protocol'], proxy['host'], proxy['port'], proxy['username'], proxy['password'], identity, team_id))
    return proxy_id, True


def import_proxies(conn, text, format, protocol, team_id=None):
    parsed = parse_import(text, format, protocol)
    imported, skipped, records = 0, 0, []
    conn.execute('SAVEPOINT proxy_import')
    try:
        for proxy in parsed:
            proxy_id, created = ensure_proxy(conn, proxy, team_id)
            if not created:
                skipped += 1
                continue
            imported += 1
            records.append(public_proxy({'id': proxy_id, **proxy}))
    except Exception:
        conn.execute('ROLLBACK TO proxy_import')
        conn.execute('RELEASE proxy_import')
        raise
    conn.execute('RELEASE proxy_import')
    return {'imported': imported, 'skipped': skipped, 'proxies': records}
