import asyncio
import contextlib
import ipaddress
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from backend.direct_gateway import DestinationBlocked, DestinationUnavailable, DirectGateway, _public_address
from backend.proxy_gateway import ProxyFailure

PUBLIC = '93.184.216.34'


def answer(address, port=80):
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    sockaddr = (address, port) if ip.version == 4 else (address, port, 0, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', sockaddr


class PublicAddressTests(unittest.TestCase):
    def test_special_and_embedded_addresses_are_not_public_egress(self):
        blocked = [
            '0.0.0.0', '0.1.2.3', '10.0.0.1', '127.0.0.1', '127.255.255.254',
            '169.254.169.254', '172.16.0.1', '192.168.1.1', '100.64.0.1',
            '192.0.0.9', '192.88.99.1', '192.0.2.1', '198.18.0.1',
            '198.51.100.1', '203.0.113.1', '224.0.0.1', '240.0.0.1', '255.255.255.255',
            '::', '::1', '::ffff:127.0.0.1', '::ffff:10.1.1.1', '::ffff:169.254.169.254',
            'fc00::1', 'fe80::1', 'fe80::1%en0', 'fec0::1', 'ff02::1',
            '64:ff9b::7f00:1', '64:ff9b:1::a00:1', '2002:7f00:1::',
            '2001::1', '2001:db8::1', '100::1',
        ]
        for value in blocked:
            with self.subTest(address=value), self.assertRaises(DestinationBlocked):
                _public_address(value)
        for value in (PUBLIC, '8.8.8.8', '2606:4700:4700::1111', '::ffff:8.8.8.8'):
            self.assertEqual(_public_address(value), ipaddress.ip_address(value))


class DirectGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.gateways = []
        self.servers = []
        self.writers = set()
        self.events = []
        self.requests = []
        self.dials = []

    async def asyncTearDown(self):
        for gateway in self.gateways:
            await gateway.close()
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for writer in self.writers:
            writer.close()
        self.temp.cleanup()

    async def gateway(self, timeout=.5):
        gateway = DirectGateway(Path(self.temp.name) / f'{len(self.gateways)}.sock',
                                self.events.append, timeout=timeout)
        self.gateways.append(gateway)
        await gateway.start()
        return gateway

    async def serve(self, handler):
        async def wrapper(reader, writer):
            self.writers.add(writer)
            try:
                await handler(reader, writer)
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                self.writers.discard(writer)
        server = await asyncio.start_server(wrapper, '127.0.0.1', 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def client(self, gateway, request):
        reader, writer = await asyncio.open_unix_connection(str(gateway.socket_path))
        self.writers.add(writer)
        writer.write(request)
        await writer.drain()
        return reader, writer

    async def request(self, gateway, request):
        reader, writer = await self.client(gateway, request)
        try:
            return await asyncio.wait_for(reader.read(), 2)
        finally:
            writer.close()

    def fixture_dial(self, fixture_port):
        # Production validation still sees a public IP. Only this test connector
        # redirects an already-validated numeric dial to the offline fixture.
        real_open = asyncio.open_connection
        async def connect(host, port, **options):
            self.dials.append((host, port, options))
            self.assertEqual(host, PUBLIC)
            return await real_open('127.0.0.1', fixture_port)
        return connect

    async def echo(self, reader, writer):
        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()

    async def test_literal_private_targets_are_rejected_before_dns_or_dial(self):
        gateway = await self.gateway()
        loop = asyncio.get_running_loop()
        with patch.object(loop, 'getaddrinfo', new=AsyncMock()) as resolve, \
                patch('backend.direct_gateway.asyncio.open_connection', new=AsyncMock()) as dial:
            for host in ('127.0.0.1', '10.0.0.8', '172.18.0.1', '169.254.169.254',
                         '[::1]', '[::ffff:127.0.0.1]', '[fc00::1]', '[64:ff9b::7f00:1]'):
                response = await self.request(gateway, f'CONNECT {host}:8000 HTTP/1.1\r\n\r\n'.encode())
                self.assertTrue(response.startswith(b'HTTP/1.1 403'), (host, response))
            resolve.assert_not_called()
            dial.assert_not_called()
        self.assertFalse(gateway.tripped)
        self.assertEqual(gateway.failure_reason, '')
        self.assertEqual(self.events, [])

    async def test_dns_private_and_mixed_answers_fail_closed_without_any_dial(self):
        gateway = await self.gateway()
        loop = asyncio.get_running_loop()
        bad_sets = [[answer('127.0.0.1')], [answer(PUBLIC), answer('10.0.0.1')],
                    [answer('::ffff:127.0.0.1'), answer(PUBLIC)],
                    [answer(PUBLIC), answer('fe80::1')], [answer('192.168.1.1'), answer(PUBLIC)]]
        with patch('backend.direct_gateway.asyncio.open_connection', new=AsyncMock()) as dial:
            for addresses in bad_sets:
                with patch.object(loop, 'getaddrinfo', new=AsyncMock(return_value=addresses)) as resolve:
                    response = await self.request(gateway, b'GET http://mixed.example/ HTTP/1.1\r\n\r\n')
                    self.assertTrue(response.startswith(b'HTTP/1.1 403'), response)
                    self.assertEqual(resolve.await_count, 1)
            dial.assert_not_called()
        self.assertFalse(gateway.tripped)

    async def test_numeric_legacy_hostname_cannot_bypass_resolved_address_check(self):
        gateway = await self.gateway()
        loop = asyncio.get_running_loop()
        with patch.object(loop, 'getaddrinfo', new=AsyncMock(return_value=[answer('127.0.0.1')])), \
                patch('backend.direct_gateway.asyncio.open_connection', new=AsyncMock()) as dial:
            for host in ('2130706433', '127.1', '0x7f000001'):
                response = await self.request(gateway, f'GET http://{host}/ HTTP/1.1\r\n\r\n'.encode())
                self.assertTrue(response.startswith(b'HTTP/1.1 403'), response)
            dial.assert_not_called()

    async def test_http_uses_origin_form_preserves_host_and_streams_body(self):
        async def origin(reader, writer):
            self.requests.append(await reader.readuntil(b'\r\n\r\n'))
            self.requests.append(await reader.readexactly(4))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
            await writer.drain()
        port = await self.serve(origin)
        gateway = await self.gateway()
        loop = asyncio.get_running_loop()
        with patch.object(loop, 'getaddrinfo', new=AsyncMock(return_value=[answer(PUBLIC)])) as resolve, \
                patch('backend.direct_gateway.asyncio.open_connection', new=self.fixture_dial(port)):
            response = await self.request(gateway, b'POST http://destination.example/submit?q=1 HTTP/1.1\r\nHost: forged\r\nProxy-Authorization: secret\r\nContent-Length: 4\r\n\r\nDATA')
        self.assertTrue(response.endswith(b'OK'))
        self.assertTrue(self.requests[0].startswith(b'POST /submit?q=1 HTTP/1.1\r\n'))
        self.assertIn(b'Host: destination.example:80\r\n', self.requests[0])
        self.assertNotIn(b'forged', self.requests[0])
        self.assertNotIn(b'Proxy-Authorization', self.requests[0])
        self.assertEqual(self.requests[1], b'DATA')
        self.assertEqual(resolve.await_count, 1)
        self.assertEqual(self.dials, [(PUBLIC, 80, {'family': socket.AF_INET, 'proto': socket.IPPROTO_TCP})])

    async def test_connect_is_a_raw_tunnel_without_upstream_connect_request(self):
        port = await self.serve(self.echo)
        gateway = await self.gateway()
        loop = asyncio.get_running_loop()
        with patch.object(loop, 'getaddrinfo', new=AsyncMock(return_value=[answer(PUBLIC, 443)])), \
                patch('backend.direct_gateway.asyncio.open_connection', new=self.fixture_dial(port)):
            reader, writer = await self.client(gateway, b'CONNECT destination.example:443 HTTP/1.1\r\n\r\n')
            self.assertEqual(await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2), b'HTTP/1.1 200 Connection Established\r\n\r\n')
            writer.write(b'raw-tls-bytes')
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(13), 2), b'raw-tls-bytes')
            writer.close()
        self.assertFalse(gateway.tripped)

    async def test_websocket_upgrade_preserves_bidirectional_frames(self):
        async def origin(reader, writer):
            self.requests.append(await reader.readuntil(b'\r\n\r\n'))
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n')
            await writer.drain()
            await self.echo(reader, writer)
        port = await self.serve(origin)
        gateway = await self.gateway()
        loop = asyncio.get_running_loop()
        with patch.object(loop, 'getaddrinfo', new=AsyncMock(return_value=[answer(PUBLIC)])), \
                patch('backend.direct_gateway.asyncio.open_connection', new=self.fixture_dial(port)):
            reader, writer = await self.client(gateway, b'GET ws://destination.example/socket HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test\r\n\r\n')
            self.assertIn(b'101', await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2))
            writer.write(b'frame-data')
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(10), 2), b'frame-data')
            writer.close()
        self.assertTrue(self.requests[0].startswith(b'GET /socket HTTP/1.1'))
        self.assertIn(b'Connection: Upgrade\r\nUpgrade: websocket', self.requests[0])

    async def test_origin_503_is_forwarded_without_stopping_other_tunnels(self):
        async def origin(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            await writer.drain()
        http_port, echo_port = await self.serve(origin), await self.serve(self.echo)
        gateway = await self.gateway()
        loop = asyncio.get_running_loop()
        real_open = asyncio.open_connection
        async def connect(host, port, **options):
            return await real_open('127.0.0.1', echo_port if port == 443 else http_port)
        async def resolve(host, port, **options):
            return [answer(PUBLIC, port)]
        with patch.object(loop, 'getaddrinfo', new=resolve), \
                patch('backend.direct_gateway.asyncio.open_connection', new=connect):
            reader, writer = await self.client(gateway, b'CONNECT destination.example:443 HTTP/1.1\r\n\r\n')
            await reader.readuntil(b'\r\n\r\n')
            response = await self.request(gateway, b'GET http://destination.example/ HTTP/1.1\r\n\r\n')
            self.assertTrue(response.startswith(b'HTTP/1.1 503'))
            response = await self.request(gateway, b'GET http://127.0.0.1/ HTTP/1.1\r\n\r\n')
            self.assertTrue(response.startswith(b'HTTP/1.1 403'))
            writer.write(b'alive')
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(5), 2), b'alive')
            writer.close()
        self.assertFalse(gateway.tripped)
        self.assertEqual(self.events, [])

    async def test_dns_and_connection_failure_only_fail_the_current_request(self):
        gateway = await self.gateway(timeout=.05)
        loop = asyncio.get_running_loop()
        for resolve in (AsyncMock(side_effect=socket.gaierror('no record')), AsyncMock(return_value=[])):
            with patch.object(loop, 'getaddrinfo', new=resolve), \
                    patch('backend.direct_gateway.asyncio.open_connection', new=AsyncMock()) as dial:
                response = await self.request(gateway, b'GET http://missing.example/ HTTP/1.1\r\n\r\n')
                self.assertTrue(response.startswith(b'HTTP/1.1 502'), response)
                dial.assert_not_called()
        with patch.object(loop, 'getaddrinfo', new=AsyncMock(return_value=[answer(PUBLIC)])), \
                patch('backend.direct_gateway.asyncio.open_connection', new=AsyncMock(side_effect=ConnectionRefusedError())) as dial:
            response = await self.request(gateway, b'GET http://refused.example/ HTTP/1.1\r\n\r\n')
            self.assertTrue(response.startswith(b'HTTP/1.1 502'), response)
            self.assertEqual(dial.await_count, 1)
        async def slow(*args, **kwargs):
            await asyncio.Future()
        with patch.object(loop, 'getaddrinfo', new=slow):
            response = await self.request(gateway, b'GET http://slow.example/ HTTP/1.1\r\n\r\n')
            self.assertTrue(response.startswith(b'HTTP/1.1 502'), response)
        self.assertFalse(gateway.tripped)
        self.assertEqual(gateway.failure_reason, '')
        self.assertEqual(self.events, [])

    async def test_invalid_port_unix_scheme_and_malformed_headers_never_dial(self):
        gateway = await self.gateway()
        requests = [
            b'CONNECT destination.example:0 HTTP/1.1\r\n\r\n',
            b'CONNECT destination.example:65536 HTTP/1.1\r\n\r\n',
            b'CONNECT /var/run/docker.sock HTTP/1.1\r\n\r\n',
            b'GET http+unix://%2Fvar%2Frun%2Fdocker.sock/ HTTP/1.1\r\n\r\n',
            b'GET file:///etc/passwd HTTP/1.1\r\n\r\n',
            b'POST http://destination.example/ HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n',
        ]
        with patch('backend.direct_gateway.asyncio.open_connection', new=AsyncMock()) as dial:
            for request in requests:
                response = await self.request(gateway, request)
                self.assertTrue(response.startswith(b'HTTP/1.1 400'), response)
            dial.assert_not_called()
        self.assertFalse(gateway.tripped)

    async def test_late_dial_after_gateway_close_is_aborted(self):
        port = await self.serve(self.echo)
        gateway = await self.gateway()
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        entered, release = asyncio.Event(), asyncio.Event()
        async def delayed(*args, **kwargs):
            entered.set()
            await release.wait()
            return reader, writer
        with patch('backend.direct_gateway.asyncio.open_connection', new=delayed):
            task = asyncio.create_task(gateway._dial(PUBLIC, 443))
            await entered.wait()
            await gateway.close()
            release.set()
            with self.assertRaises(DestinationUnavailable):
                await task
        self.assertTrue(writer.is_closing())
        self.assertNotIn(writer, gateway._writers)

    async def test_start_never_replaces_an_existing_socket_path(self):
        path = Path(self.temp.name) / 'occupied.sock'
        path.write_text('preserve')
        gateway = DirectGateway(path)
        self.gateways.append(gateway)
        with self.assertRaises(ProxyFailure):
            await gateway.start()
        await gateway.close()
        self.assertEqual(path.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
