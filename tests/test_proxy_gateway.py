import asyncio
import base64
import contextlib
import os
import shutil
import ssl
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.proxy_gateway import ProxyFailure, ProxyGateway


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.gateways = []
        self.servers = []
        self.remote_writers = set()
        self.events = []
        self.reject = False
        self.requests = []

    async def asyncTearDown(self):
        for gateway in self.gateways:
            await gateway.close()
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for writer in self.remote_writers:
            writer.close()
        self.temp.cleanup()

    async def serve(self, handler, tls=None):
        async def wrapper(reader, writer):
            self.remote_writers.add(writer)
            try:
                await handler(reader, writer)
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                self.remote_writers.discard(writer)
        server = await asyncio.start_server(wrapper, '127.0.0.1', 0, ssl=tls)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def gateway(self, port, protocol='http', username='', password='', **options):
        proxy = dict(protocol=protocol, host='127.0.0.1', port=port, username=username, password=password)
        gateway = ProxyGateway(proxy, Path(self.temp.name) / f'{len(self.gateways)}.sock', self.events.append,
                               timeout=0.5, check_interval=0.05, **options)
        self.gateways.append(gateway)
        await gateway.start()
        return gateway

    async def client(self, gateway, request=b'CONNECT destination.invalid:443 HTTP/1.1\r\nHost: destination.invalid\r\n\r\n'):
        reader, writer = await asyncio.open_unix_connection(str(gateway.socket_path))
        writer.write(request)
        await writer.drain()
        return reader, writer

    async def echo(self, reader, writer):
        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()

    async def http_proxy(self, reader, writer):
        header = await reader.readuntil(b'\r\n\r\n')
        self.requests.append(header)
        if self.reject:
            writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n')
            await writer.drain()
            return
        if header.startswith(b'CONNECT'):
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
            await self.echo(reader, writer)
        else:
            if header.startswith(b'POST'):
                body = await reader.readexactly(4)
                self.requests.append(body)
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
            await writer.drain()

    async def assert_tunnel(self, gateway):
        reader, writer = await self.client(gateway)
        self.assertIn(b'200', await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2))
        writer.write(b'tunnel-data')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(11), 2), b'tunnel-data')
        writer.close()
        await writer.wait_closed()

    async def test_http_connect_auth_and_remote_hostname(self):
        port = await self.serve(self.http_proxy)
        gateway = await self.gateway(port, username='alice', password='p:a@ss')
        await self.assert_tunnel(gateway)
        self.assertIn(b'CONNECT destination.invalid:443 ', self.requests[0])
        expected = base64.b64encode(b'alice:p:a@ss')
        self.assertIn(b'Proxy-Authorization: Basic ' + expected, self.requests[0])
        self.assertFalse(gateway.tripped)

    async def test_http_post_body_and_proxy_auth_replacement(self):
        port = await self.serve(self.http_proxy)
        gateway = await self.gateway(port, username='alice', password='secret')
        reader, writer = await self.client(gateway, b'POST http://destination.invalid/submit?q=1 HTTP/1.1\r\nHost: wrong\r\nProxy-Authorization: forged\r\nContent-Length: 4\r\n\r\nDATA')
        response = await asyncio.wait_for(reader.read(), 2)
        self.assertTrue(response.endswith(b'OK'))
        self.assertIn(b'POST http://destination.invalid/submit?q=1 HTTP/1.1', self.requests[0])
        self.assertIn(b'Host: destination.invalid:80', self.requests[0])
        self.assertNotIn(b'forged', self.requests[0])
        self.assertEqual(self.requests[1], b'DATA')
        writer.close()

    async def test_socks5_auth_and_remote_dns(self):
        targets = []
        async def socks(reader, writer):
            self.assertEqual(await reader.readexactly(3), b'\x05\x01\x02')
            writer.write(b'\x05\x02')
            await writer.drain()
            version, length = await reader.readexactly(2)
            self.assertEqual(version, 1)
            self.assertEqual(await reader.readexactly(length), b'alice')
            length = (await reader.readexactly(1))[0]
            self.assertEqual(await reader.readexactly(length), b'secret')
            writer.write(b'\x01\x00')
            await writer.drain()
            # The health probe ends after authentication.
            greeting = await reader.readexactly(5)
            self.assertEqual(greeting[:4], b'\x05\x01\x00\x03')
            hostname = await reader.readexactly(greeting[4])
            port = struct.unpack('>H', await reader.readexactly(2))[0]
            targets.append((hostname, port))
            writer.write(b'\x05\x00\x00\x01' + bytes(6))
            await writer.drain()
            await self.echo(reader, writer)
        port = await self.serve(socks)
        gateway = await self.gateway(port, 'socks5', 'alice', 'secret')
        await self.assert_tunnel(gateway)
        self.assertEqual(targets, [(b'destination.invalid', 443)])

    async def test_socks4a_remote_dns(self):
        targets = []
        async def socks(reader, writer):
            header = await reader.readexactly(8)
            self.assertEqual(header[:2], b'\x04\x01')
            self.assertEqual(header[4:], b'\x00\x00\x00\x01')
            username = await reader.readuntil(b'\x00')
            hostname = await reader.readuntil(b'\x00')
            targets.append((username, hostname))
            writer.write(b'\x00\x5a' + bytes(6))
            await writer.drain()
            await self.echo(reader, writer)
        port = await self.serve(socks)
        gateway = await self.gateway(port, 'socks4', 'alice')
        await self.assert_tunnel(gateway)
        self.assertEqual(targets, [(b'alice\0', b'destination.invalid\0')])

    async def test_handshake_failure_closes_existing_connections_and_latches(self):
        port = await self.serve(self.http_proxy)
        gateway = await self.gateway(port)
        reader, writer = await self.client(gateway)
        await reader.readuntil(b'\r\n\r\n')
        self.reject = True
        failed_reader, failed_writer = await self.client(gateway)
        self.assertEqual(await asyncio.wait_for(failed_reader.read(), 2), b'')
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.assertTrue(gateway.tripped)
        self.assertEqual(len(self.events), 1)
        with self.assertRaises((ConnectionError, FileNotFoundError)):
            await asyncio.open_unix_connection(str(gateway.socket_path))
        writer.close()
        failed_writer.close()

    async def test_http_proxy_502_trips_all_tunnels(self):
        async def upstream(reader, writer):
            header = await reader.readuntil(b'\r\n\r\n')
            if header.startswith(b'CONNECT'):
                writer.write(b'HTTP/1.1 200 OK\r\n\r\n')
                await writer.drain()
                await self.echo(reader, writer)
            else:
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
                await writer.drain()
        port = await self.serve(upstream)
        gateway = await self.gateway(port)
        tunnel_reader, tunnel_writer = await self.client(gateway)
        await tunnel_reader.readuntil(b'\r\n\r\n')
        reader, writer = await self.client(gateway, b'GET http://destination.invalid/ HTTP/1.1\r\n\r\n')
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.assertEqual(await asyncio.wait_for(tunnel_reader.read(), 2), b'')
        self.assertTrue(gateway.tripped)
        writer.close()
        tunnel_writer.close()

    async def test_plain_websocket_upgrade_keeps_bidirectional_stream(self):
        async def upstream(reader, writer):
            header = await reader.readuntil(b'\r\n\r\n')
            self.requests.append(header)
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
            await writer.drain()
            await self.echo(reader, writer)
        port = await self.serve(upstream)
        gateway = await self.gateway(port)
        reader, writer = await self.client(gateway, b'GET http://destination.invalid/ws HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test\r\n\r\n')
        self.assertIn(b'101', await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2))
        self.assertIn(b'Connection: Upgrade\r\n', self.requests[0])
        self.assertIn(b'Upgrade: websocket\r\n', self.requests[0])
        self.assertNotIn(b'Connection: close', self.requests[0])
        writer.write(b'websocket-frame')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(15), 2), b'websocket-frame')
        self.assertFalse(gateway.tripped)
        writer.close()

    async def test_dial_finishing_after_trip_is_aborted(self):
        port = await self.serve(self.http_proxy)
        gateway = await self.gateway(port)
        real_reader, real_writer = await asyncio.open_connection('127.0.0.1', port)
        started = asyncio.Event()
        release = asyncio.Event()
        async def delayed_open(*args, **kwargs):
            started.set()
            await release.wait()
            return real_reader, real_writer
        with patch('backend.proxy_gateway.asyncio.open_connection', new=delayed_open):
            task = asyncio.create_task(gateway._transport())
            await started.wait()
            gateway._trip('测试断路')
            release.set()
            with self.assertRaises(ProxyFailure):
                await task
        self.assertTrue(real_writer.is_closing())
        self.assertNotIn(real_writer, gateway._writers)

    async def test_dead_upstream_closes_idle_connections(self):
        port = await self.serve(self.http_proxy)
        gateway = await self.gateway(port)
        reader, writer = await self.client(gateway)
        await reader.readuntil(b'\r\n\r\n')
        self.servers[0].close()
        await self.servers[0].wait_closed()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.assertTrue(gateway.tripped)
        writer.close()

    async def test_malformed_client_does_not_trip_environment(self):
        port = await self.serve(self.http_proxy)
        gateway = await self.gateway(port)
        reader, writer = await self.client(gateway, b'GET http://bad.invalid/ HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n')
        self.assertIn(b'400', await reader.read())
        self.assertFalse(gateway.tripped)
        self.assertEqual(self.requests, [])
        writer.close()

    async def test_unreachable_proxy_fails_before_listener(self):
        port = await self.serve(self.http_proxy)
        self.servers[0].close()
        await self.servers[0].wait_closed()
        with self.assertRaises(ProxyFailure):
            await self.gateway(port)
        self.assertFalse(self.gateways[0].socket_path.exists())

    @unittest.skipUnless(shutil.which('openssl'), 'openssl required for temporary TLS fixture')
    async def test_https_certificate_validation_and_tls_transport(self):
        cert = str(Path(self.temp.name) / 'cert.pem')
        key = str(Path(self.temp.name) / 'key.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
                        '-keyout', key, '-out', cert], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        port = await self.serve(self.http_proxy, tls)
        with self.assertRaises(ProxyFailure):
            await self.gateway(port, 'https')
        self.assertEqual(self.requests, [])
        trusted_context = ssl.create_default_context(cafile=cert)
        with patch('backend.proxy_gateway.ssl.create_default_context', return_value=trusted_context):
            gateway = await self.gateway(port, 'https')
        await self.assert_tunnel(gateway)


if __name__ == '__main__':
    unittest.main()
