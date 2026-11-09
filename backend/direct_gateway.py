"""Public-network egress for a browser with no configured upstream proxy.

The browser still lives in its own network namespace. This server-owned Unix
socket forwards HTTP, CONNECT and WebSocket traffic only to validated public IP
addresses, so localhost/private management services are never reachable through
the browser. DNS is resolved once and the actual dial uses the validated IP.
"""
import asyncio
import contextlib
import ipaddress
import os
import socket

from .proxy_gateway import InvalidRequest, ProxyFailure, ProxyGateway


class DestinationBlocked(Exception):
    """The requested destination is not an ordinary public Internet address."""


class DestinationUnavailable(Exception):
    """A single destination could not be resolved or connected."""


# Also reject special-purpose ranges whose classification differs between
# Python/ipaddress releases. Transition mechanisms can encode private IPv4.
_SPECIAL_V4 = tuple(ipaddress.ip_network(value) for value in (
    '0.0.0.0/8', '100.64.0.0/10', '192.0.0.0/24', '192.88.99.0/24',
    '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
))
_GLOBAL_V6 = ipaddress.ip_network('2000::/3')
_SPECIAL_V6 = tuple(ipaddress.ip_network(value) for value in (
    '2001::/23', '2002::/16',
))


def _public_address(value):
    if not isinstance(value, str) or '%' in value:
        raise DestinationBlocked('Scoped or invalid addresses are not permitted')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise DestinationBlocked('Destination is not an IP address') from None
    if address.version == 6 and address.ipv4_mapped is not None:
        # The mapped address reaches IPv4, so validate that destination as IPv4.
        _public_address(str(address.ipv4_mapped))
        return address
    if (not address.is_global or address.is_private or address.is_loopback
            or address.is_link_local or address.is_multicast
            or address.is_unspecified or address.is_reserved):
        raise DestinationBlocked('Non-public destination blocked')
    if address.version == 4:
        if any(address in network for network in _SPECIAL_V4):
            raise DestinationBlocked('Special-purpose destination blocked')
    elif (address.is_site_local or address not in _GLOBAL_V6
          or any(address in network for network in _SPECIAL_V6)):
        raise DestinationBlocked('Special-purpose destination blocked')
    return address


class DirectGateway(ProxyGateway):
    def __init__(self, socket_path, on_failure=None, *, timeout=8):
        # The existing header/relay code uses origin-form and no upstream
        # credentials for SOCKS. No SOCKS connection or handshake is performed.
        super().__init__({'protocol': 'socks5'}, socket_path, on_failure, timeout=timeout)

    async def start(self):
        if self._closed or self.tripped or self._server:
            raise ProxyFailure('直连网关无法重复启动')
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise ProxyFailure('直连网关地址已被占用')
        self._server = await asyncio.start_unix_server(
            self._accept, path=str(self.socket_path), limit=65536)
        self._owns_socket = True
        os.chmod(self.socket_path, 0o600)
        # There is no fixed upstream to probe. A site outage affects that request
        # only and must not tear down other tabs or the entire browser environment.
        return self

    async def _resolve_public_addresses(self, host, port):
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise DestinationBlocked('Invalid destination port')
        if not host or not isinstance(host, str) or len(host) > 253 or '%' in host:
            raise DestinationBlocked('Invalid destination host')
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            entries = await asyncio.get_running_loop().getaddrinfo(
                host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP)
        else:
            address = _public_address(str(literal))
            return [(socket.AF_INET if address.version == 4 else socket.AF_INET6, str(address))]
        addresses = []
        for family, socktype, protocol, _, sockaddr in entries:
            if (family not in (socket.AF_INET, socket.AF_INET6)
                    or socktype != socket.SOCK_STREAM or protocol not in (0, socket.IPPROTO_TCP)
                    or len(sockaddr) < 2 or sockaddr[1] != port):
                raise DestinationBlocked('Unexpected destination address')
            address = _public_address(sockaddr[0])
            if (family == socket.AF_INET) != (address.version == 4):
                raise DestinationBlocked('Destination address family mismatch')
            if family == socket.AF_INET6 and (len(sockaddr) != 4 or sockaddr[2] or sockaddr[3]):
                raise DestinationBlocked('Scoped destination address blocked')
            pair = (family, str(address))
            if pair not in addresses:
                addresses.append(pair)
        # All answers must be safe, rather than selecting a public answer from a
        # mixed public/private set and allowing inconsistent DNS policy results.
        if not addresses:
            raise DestinationUnavailable('No public destination address')
        return addresses

    async def _dial(self, host, port):
        if self._closed or self.tripped:
            raise DestinationUnavailable('Gateway is closed')

        async def connect():
            addresses = await self._resolve_public_addresses(host, port)
            for family, address in addresses:
                try:
                    # A numeric IP plus an explicit family bypasses hostname
                    # lookup during connect, preventing DNS rebinding here.
                    reader, writer = await asyncio.open_connection(
                        address, port, family=family, proto=socket.IPPROTO_TCP)
                except OSError:
                    continue
                if self._closed or self.tripped:
                    writer.transport.abort()
                    raise DestinationUnavailable('Gateway is closed')
                self._writers.add(writer)
                return reader, writer
            raise DestinationUnavailable('Destination connection failed')

        try:
            return await asyncio.wait_for(connect(), self.timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            raise DestinationUnavailable('Destination resolution or connection failed') from exc

    @staticmethod
    async def _error(writer, status):
        reason = {400: 'Bad Request', 403: 'Forbidden', 502: 'Bad Gateway'}[status]
        writer.write(f'HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'.encode('ascii'))
        await writer.drain()

    async def _accept(self, reader, writer):
        task = asyncio.current_task()
        self._handlers.add(task)
        self._writers.add(writer)
        remote = None
        relaying = False
        try:
            if self._closed or self.tripped:
                return
            try:
                header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), self.timeout)
                method, target, parsed, host, port, headers = self._parse_request(header)
            except (InvalidRequest, ValueError, asyncio.LimitOverrunError,
                    asyncio.IncompleteReadError, asyncio.TimeoutError):
                await self._error(writer, 400)
                return
            try:
                remote_reader, remote = await self._dial(host, port)
            except DestinationBlocked:
                await self._error(writer, 403)
                return
            except DestinationUnavailable:
                await self._error(writer, 502)
                return
            if method == 'CONNECT':
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                await writer.drain()
            else:
                remote.write(self._request_header(method, target, parsed, host, port, headers))
                await remote.drain()
            relaying = True
            await self._relay(reader, writer, remote_reader, remote, inspect_response=method != 'CONNECT')
        except (ProxyFailure, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError, InvalidRequest):
            # Once response/tunnel bytes may have been sent, close the stream;
            # injecting another HTTP response would corrupt the current protocol.
            if not relaying:
                with contextlib.suppress(ConnectionError, BrokenPipeError):
                    await self._error(writer, 502)
        finally:
            writer.close()
            self._writers.discard(writer)
            if remote:
                remote.close()
                self._writers.discard(remote)
            self._handlers.discard(task)
