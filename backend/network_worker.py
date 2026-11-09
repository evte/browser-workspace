"""Run inside an otherwise disconnected network namespace, bridging only to a Unix proxy."""
import argparse
import asyncio
import ctypes
import json
import os
from pathlib import Path
import socket
import subprocess


async def bridge(reader, writer, socket_path):
    upstream = None
    tasks = []
    try:
        remote, upstream = await asyncio.open_unix_connection(socket_path)
        async def copy(source, destination):
            while data := await source.read(65536):
                destination.write(data)
                await destination.drain()
        tasks = [asyncio.create_task(copy(reader, upstream)), asyncio.create_task(copy(remote, writer))]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (OSError, ConnectionError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        if upstream:
            upstream.close()


async def run(args):
    # Refuse to launch Chromium unless the namespace really changed and has only loopback.
    current = os.readlink('/proc/self/ns/net')
    if current == os.environ.get('BROWSER_PARENT_NETNS') or not os.environ.get('BROWSER_PARENT_NETNS'):
        raise RuntimeError('Browser network isolation was not established')
    # Some kernels create dormant tunnel devices in every namespace. They must
    # remain down, have no addresses and have no routes before privileges drop.
    links = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show']))
    if any(link['ifname'] != 'lo' and ('UP' in link['flags'] or link.get('addr_info')) for link in links):
        raise RuntimeError('Browser namespace contains an external network interface')
    for family in ('-4', '-6'):
        routes = json.loads(subprocess.check_output(['ip', '-j', family, 'route', 'show', 'table', 'all']))
        if routes:
            raise RuntimeError('Browser namespace has an external route')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    if not 10001 <= args.uid <= 2**31 - 1:
        raise RuntimeError('Invalid browser identity')
    os.setgroups([])
    os.setgid(args.uid)
    os.setuid(args.uid)
    # PR_SET_NO_NEW_PRIVS prevents descendants from acquiring privileges via executables.
    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:
        raise RuntimeError('Cannot restrict browser privileges')
    server = await asyncio.start_server(lambda r, w: bridge(r, w, args.socket), '127.0.0.1', 3128)
    async with server:
        browser = await asyncio.create_subprocess_exec(*args.command)
        await asyncio.sleep(0.7)
        if browser.returncode is not None:
            raise RuntimeError('Browser exited during isolated startup')
        Path(args.ready).write_text(current)
        await browser.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--uid', type=int, default=10001)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--ready', required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    options = parser.parse_args()
    if options.command[:1] == ['--']:
        options.command = options.command[1:]
    asyncio.run(run(options))
