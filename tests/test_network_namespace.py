"""Opt-in Linux integration test: run inside the Compose container with its capabilities."""
import asyncio
import os
from pathlib import Path
import tempfile
import unittest
from backend.proxy_gateway import ProxyGateway


@unittest.skipUnless(os.environ.get('RUN_NETWORK_NAMESPACE_TESTS') == '1', 'requires Linux network namespaces')
class NetworkIsolationTest(unittest.IsolatedAsyncioTestCase):
    async def test_proxy_only_egress_and_privilege_drop(self):
        async def upstream(reader, writer):
            try:
                await reader.readuntil(b'\r\n\r\n')
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nvia-proxy')
                await writer.drain()
            except asyncio.IncompleteReadError:
                pass  # transport-only health probes
            finally:
                writer.close()
        server = await asyncio.start_server(upstream, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        with tempfile.TemporaryDirectory(prefix='net-test-') as temporary:
            directory = Path(temporary)
            os.chown(directory, 10001, 10001)
            gateway = ProxyGateway({'protocol': 'http', 'host': '127.0.0.1', 'port': port}, directory / 'p.sock')
            await gateway.start()
            os.chown(directory / 'p.sock', 10001, 10001)
            code = '''
import os, socket, urllib.request, time
assert os.geteuid() == 10001
client = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://127.0.0.1:3128'}))
assert client.open('http://never-resolved.invalid/', timeout=3).read() == b'via-proxy'
for target in [('1.1.1.1', 443), ('127.0.0.1', 8000)]:
    try:
        socket.create_connection(target, timeout=1)
    except OSError:
        pass
    else:
        raise AssertionError('unexpected direct TCP connection')
for family, target in [(socket.AF_INET, ('1.1.1.1', 53)), (socket.AF_INET6, ('2606:4700:4700::1111', 53))]:
    with socket.socket(family, socket.SOCK_DGRAM) as udp:
        try:
            udp.sendto(b'no-egress-test', target)
        except OSError:
            pass
        else:
            raise AssertionError('unexpected UDP egress')
time.sleep(1)
'''
            env = {**os.environ, 'BROWSER_PARENT_NETNS': os.readlink('/proc/self/ns/net')}
            worker = Path(__file__).resolve().parents[1] / 'backend' / 'network_worker.py'
            process = await asyncio.create_subprocess_exec(
                'unshare', '--net', '--', 'python', str(worker), '--socket', str(directory / 'p.sock'),
                '--ready', str(directory / 'ready'), '--', 'python', '-c', code,
                env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                _, stderr = await asyncio.wait_for(process.communicate(), 15)
                self.assertEqual(process.returncode, 0, stderr.decode())
                self.assertTrue((directory / 'ready').exists())
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                await gateway.close()
                server.close()
                await server.wait_closed()
