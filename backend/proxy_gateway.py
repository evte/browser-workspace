"""One environment's forward proxy. All outbound connections go to its upstream.

Use on a dedicated asyncio loop. ``on_failure(reason)`` must return promptly;
run blocking browser shutdown on a different thread. A failure is latched until
this gateway is replaced. Destination hostnames are resolved by the upstream.
"""

import asyncio
import base64
import contextlib
import inspect
import ipaddress
import os
import ssl
import struct
from pathlib import Path
from urllib.parse import urlsplit


class ProxyFailure(Exception):
    """Safe, credential-free error suitable for a profile's status."""


class InvalidRequest(Exception):
    pass


class ProxyGateway:
    def __init__(self, proxy, socket_path, on_failure=None, *, timeout=8, check_interval=2):
        self.proxy = dict(proxy)
        self.socket_path = Path(socket_path)
        self.on_failure = on_failure
        self.timeout = timeout
        self.check_interval = check_interval
        self.tripped = False
        self.failure_reason = ''
        self._server = None
        self._monitor = None
        self._closed = False
        self._writers = set()
        self._handlers = set()
        self._owns_socket = False
        self._ssl_context = ssl.create_default_context() if proxy['protocol'] == 'https' else None
        if proxy['protocol'] not in ('http', 'https', 'socks4', 'socks5'):
            raise ProxyFailure('不支持的代理协议')
        if proxy['protocol'] == 'socks4' and proxy.get('password'):
            raise ProxyFailure('SOCKS4 不支持密码认证，请使用 SOCKS5')

    async def start(self):
        """Check the upstream before accepting any browser traffic."""
        if self._closed or self.tripped or self._server:
            raise ProxyFailure('代理网关无法重复启动')
        try:
            await self._probe()
        except ProxyFailure as exc:
            self.tripped = True
            self.failure_reason = str(exc)
            raise
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        # Refuse to replace an existing file or another live gateway's socket.
        if self.socket_path.exists():
            raise ProxyFailure('代理网关地址已被占用')
        self._server = await asyncio.start_unix_server(
            self._accept, path=str(self.socket_path), limit=65536)
        self._owns_socket = True
        os.chmod(self.socket_path, 0o600)
        self._monitor = asyncio.create_task(self._watch_upstream())
        return self

    async def close(self):
        self._closed = True
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        tasks = list(self._handlers)
        if self._monitor:
            tasks.append(self._monitor)
        current = asyncio.current_task()
        tasks = [task for task in tasks if task is not current]
        for task in tasks:
            task.cancel()
        writers = list(self._writers)
        for writer in writers:
            writer.transport.abort()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for writer in writers:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 1)
        if self._owns_socket:
            self.socket_path.unlink(missing_ok=True)
            self._owns_socket = False

    def _trip(self, reason):
        if self.tripped or self._closed:
            return
        self.tripped = True
        self.failure_reason = reason
        if self._server:
            self._server.close()
        # Close every established tunnel, including otherwise healthy requests.
        for writer in list(self._writers):
            writer.transport.abort()
        current = asyncio.current_task()
        for task in list(self._handlers):
            if task is not current:
                task.cancel()
        if self.on_failure:
            with contextlib.suppress(Exception):
                result = self.on_failure(reason)
                if inspect.isawaitable(result):
                    asyncio.create_task(result)

    async def _transport(self):
        if self.tripped or self._closed:
            raise ProxyFailure('代理已失效，环境连接已中断')
        try:
            options = {}
            if self._ssl_context:
                options = {'ssl': self._ssl_context, 'server_hostname': self.proxy['host']}
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.proxy['host'], self.proxy['port'], **options),
                self.timeout)
            if self.tripped or self._closed:
                writer.transport.abort()
                raise ProxyFailure('代理已失效，环境连接已中断')
            self._writers.add(writer)
            return reader, writer
        except (OSError, asyncio.TimeoutError) as exc:
            raise ProxyFailure('代理连接失败或超时，已中断环境连接') from exc

    async def _socks5_auth(self, reader, writer):
        username = (self.proxy.get('username') or '').encode('utf-8')
        password = (self.proxy.get('password') or '').encode('utf-8')
        method = 2 if username or password else 0
        writer.write(bytes([5, 1, method]))
        await writer.drain()
        if await reader.readexactly(2) != bytes([5, method]):
            raise ProxyFailure('SOCKS5 代理认证方式不匹配')
        if method == 2:
            if not 1 <= len(username) <= 255 or len(password) > 255:
                raise ProxyFailure('SOCKS5 用户名或密码长度无效')
            writer.write(bytes([1, len(username)]) + username + bytes([len(password)]) + password)
            await writer.drain()
            if await reader.readexactly(2) != b'\x01\x00':
                raise ProxyFailure('代理认证失败，已中断环境连接')

    async def _probe(self):
        """Probe transport/TLS and SOCKS5 auth, without sending target traffic.

        HTTP and SOCKS4 destination/auth failures are checked on actual requests.
        The periodic probe catches a dead upstream even while tunnels are idle.
        """
        writer = None
        try:
            reader, writer = await self._transport()
            if self.proxy['protocol'] == 'socks5':
                await asyncio.wait_for(self._socks5_auth(reader, writer), self.timeout)
        except ProxyFailure:
            raise
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            raise ProxyFailure('代理健康检查失败，已中断环境连接') from exc
        finally:
            if writer:
                writer.close()
                self._writers.discard(writer)

    async def _watch_upstream(self):
        while not self._closed and not self.tripped:
            await asyncio.sleep(self.check_interval)
            try:
                await self._probe()
            except ProxyFailure as exc:
                self._trip(str(exc))

    def _auth_header(self):
        if not self.proxy.get('username') and not self.proxy.get('password'):
            return b''
        raw = f"{self.proxy.get('username') or ''}:{self.proxy.get('password') or ''}".encode('utf-8')
        return b'Proxy-Authorization: Basic ' + base64.b64encode(raw) + b'\r\n'

    @staticmethod
    def _authority(host, port):
        return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'

    async def _tunnel(self, reader, writer, host, port):
        protocol = self.proxy['protocol']
        if protocol in ('http', 'https'):
            authority = self._authority(host, port).encode('ascii')
            writer.write(b'CONNECT ' + authority + b' HTTP/1.1\r\nHost: ' + authority + b'\r\n' + self._auth_header() + b'\r\n')
            await writer.drain()
            header = await reader.readuntil(b'\r\n\r\n')
            parts = header.split(b'\r\n', 1)[0].split(b' ', 2)
            if len(parts) < 2 or not parts[0].startswith(b'HTTP/') or parts[1] != b'200':
                raise ProxyFailure('代理拒绝连接或认证失败，已中断环境连接')
        elif protocol == 'socks5':
            await self._socks5_auth(reader, writer)
            try:
                address = ipaddress.ip_address(host)
                destination = bytes([1 if address.version == 4 else 4]) + address.packed
            except ValueError:
                domain = host.encode('idna')
                if not 1 <= len(domain) <= 255:
                    raise InvalidRequest()
                destination = bytes([3, len(domain)]) + domain
            writer.write(b'\x05\x01\x00' + destination + struct.pack('>H', port))
            await writer.drain()
            reply = await reader.readexactly(4)
            if reply[:3] != b'\x05\x00\x00':
                raise ProxyFailure('SOCKS5 代理连接被拒绝，已中断环境连接')
            if reply[3] == 1:
                await reader.readexactly(6)
            elif reply[3] == 4:
                await reader.readexactly(18)
            elif reply[3] == 3:
                await reader.readexactly((await reader.readexactly(1))[0] + 2)
            else:
                raise ProxyFailure('SOCKS5 代理响应无效')
        else:
            # SOCKS4a passes the hostname to the proxy for remote DNS resolution.
            username = (self.proxy.get('username') or '').encode('utf-8')
            if b'\x00' in username:
                raise ProxyFailure('SOCKS4 用户名格式无效')
            try:
                address = ipaddress.IPv4Address(host).packed
                domain = b''
            except ipaddress.AddressValueError:
                address = b'\x00\x00\x00\x01'
                domain = host.encode('idna') + b'\x00'
            writer.write(b'\x04\x01' + struct.pack('>H', port) + address + username + b'\x00' + domain)
            await writer.drain()
            reply = await reader.readexactly(8)
            if reply[:2] != b'\x00\x5a':
                raise ProxyFailure('SOCKS4 代理连接被拒绝，已中断环境连接')

    @staticmethod
    def _parse_request(header):
        try:
            lines = header[:-4].split(b'\r\n')
            method, target, version = lines[0].decode('ascii').split(' ')
            if not method.isalpha() or version not in ('HTTP/1.0', 'HTTP/1.1'):
                raise ValueError()
            parsed = urlsplit('//' + target if method == 'CONNECT' else target)
            if method != 'CONNECT' and parsed.scheme.lower() not in ('http', 'ws'):
                raise ValueError()
            if parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise ValueError()
            host = parsed.hostname
            port = parsed.port if parsed.port is not None else (443 if method == 'CONNECT' else 80)
            if not host or not 1 <= port <= 65535:
                raise ValueError()
            if method == 'CONNECT' and (parsed.path or parsed.query or parsed.port is None):
                raise ValueError()
            host = host.encode('idna').decode('ascii')
            if any(ord(c) <= 32 or ord(c) == 127 for c in host):
                raise ValueError()
            headers = []
            for line in lines[1:]:
                name, value = line.split(b':', 1)
                if not name or any(c <= 32 or c >= 127 for c in name):
                    raise ValueError()
                if any(c < 32 and c != 9 for c in value) or b'\x7f' in value:
                    raise ValueError()
                headers.append((name, value.strip()))
            lengths = [v for k, v in headers if k.lower() == b'content-length']
            encodings = [v for k, v in headers if k.lower() == b'transfer-encoding']
            if len(lengths) > 1 or (lengths and encodings) or (lengths and not lengths[0].isdigit()):
                raise ValueError()
            return method, target, parsed, host, port, headers
        except (ValueError, UnicodeError) as exc:
            raise InvalidRequest() from exc

    def _request_header(self, method, target, parsed, host, port, headers):
        is_http_proxy = self.proxy['protocol'] in ('http', 'https')
        destination = target if is_http_proxy else (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
        result = f'{method} {destination} HTTP/1.1\r\n'.encode('ascii')
        connection_tokens = set()
        for name, value in headers:
            if name.lower() == b'connection':
                connection_tokens.update(token.strip().lower() for token in value.split(b','))
        upgrade = b'upgrade' in connection_tokens and any(name.lower() == b'upgrade' and value.lower() == b'websocket' for name, value in headers)
        excluded = {b'proxy-authorization', b'proxy-connection', b'connection', b'host', b'keep-alive', b'upgrade'} | connection_tokens
        for name, value in headers:
            if name.lower() not in excluded:
                result += name + b': ' + value + b'\r\n'
        result += b'Host: ' + self._authority(host, port).encode('ascii') + b'\r\n'
        result += b'Connection: Upgrade\r\nUpgrade: websocket\r\n' if upgrade else b'Connection: close\r\n'
        if is_http_proxy:
            result += self._auth_header()
        return result + b'\r\n'

    async def _relay(self, client_reader, client_writer, remote_reader, remote_writer, inspect_response=False):
        async def outgoing():
            while True:
                try:
                    data = await client_reader.read(65536)
                except ConnectionError:
                    return
                if not data:
                    return
                try:
                    remote_writer.write(data)
                    await remote_writer.drain()
                except ConnectionError as exc:
                    raise ProxyFailure('代理通信失败，已中断环境连接') from exc

        async def incoming():
            if inspect_response:
                response = await asyncio.wait_for(remote_reader.readuntil(b'\r\n\r\n'), 60)
                status = response.split(b'\r\n', 1)[0].split(b' ', 2)
                if len(status) < 2 or not status[0].startswith(b'HTTP/'):
                    raise ProxyFailure('代理响应无效，已中断环境连接')
                if self.proxy['protocol'] in ('http', 'https') and status[1] in (b'407', b'502', b'503', b'504'):
                    raise ProxyFailure('代理认证或转发失败，已中断环境连接')
                client_writer.write(response)
                await client_writer.drain()
            while True:
                try:
                    data = await remote_reader.read(65536)
                except ConnectionError as exc:
                    raise ProxyFailure('代理通信失败，已中断环境连接') from exc
                if not data:
                    return
                try:
                    client_writer.write(data)
                    await client_writer.drain()
                except ConnectionError:
                    return
        tasks = [asyncio.create_task(outgoing()), asyncio.create_task(incoming())]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                exception = task.exception()
                if exception:
                    raise exception
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _accept(self, reader, writer):
        task = asyncio.current_task()
        self._handlers.add(task)
        self._writers.add(writer)
        remote = None
        try:
            if self.tripped or self._closed:
                return
            try:
                header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), self.timeout)
                method, target, parsed, host, port, headers = self._parse_request(header)
            except (InvalidRequest, ValueError, asyncio.LimitOverrunError, asyncio.IncompleteReadError, asyncio.TimeoutError):
                writer.write(b'HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                await writer.drain()
                return
            try:
                remote_reader, remote = await self._transport()
                if method == 'CONNECT' or self.proxy['protocol'] in ('socks4', 'socks5'):
                    await asyncio.wait_for(self._tunnel(remote_reader, remote, host, port), self.timeout)
                if method == 'CONNECT':
                    writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    await writer.drain()
                else:
                    remote.write(self._request_header(method, target, parsed, host, port, headers))
                    await remote.drain()
                await self._relay(reader, writer, remote_reader, remote, inspect_response=method != 'CONNECT')
            except (ProxyFailure, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
                reason = str(exc) if isinstance(exc, ProxyFailure) else '代理通信失败，已中断环境连接'
                self._trip(reason)
        except (ConnectionError, BrokenPipeError, InvalidRequest):
            pass
        finally:
            writer.close()
            self._writers.discard(writer)
            if remote:
                remote.close()
                self._writers.discard(remote)
            self._handlers.discard(task)
