import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from backend.kernels import KernelError, KernelStore, normalize_architecture


def archive_bytes(extra=()):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:xz') as archive:
        info = tarfile.TarInfo('browser/chrome')
        content = b'#!/bin/sh\necho Chromium 150.0.1.0\n'
        info.size = len(content)
        info.mode = 0o7777
        archive.addfile(info, io.BytesIO(content))
        for item, content in extra:
            archive.addfile(item, io.BytesIO(content) if content else None)
    return output.getvalue()


def catalog_for(data):
    return [{
        'id': 'test-browser-150-amd64', 'name': 'Test browser',
        'version': '150.0.1.0', 'architecture': 'amd64',
        'engine': 'fingerprint-chromium', 'platforms': ['linux'],
        'supported_platforms': ['linux', 'windows', 'macos'],
        'url': 'https://github.com/adryfish/fingerprint-chromium/releases/download/test/test.tar.xz',
        'sha256': hashlib.sha256(data).hexdigest(), 'download_size': len(data),
        'executable': 'browser/chrome',
    }]


class Response(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.headers = {'Content-Length': str(len(data))}

    def geturl(self):
        return 'https://release-assets.githubusercontent.com/test'


class KernelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.data = archive_bytes()
        self.catalog = catalog_for(self.data)
        self.kernel_id = self.catalog[0]['id']
        self.store = KernelStore(self.temp.name, self.catalog,
                                 architecture='x86_64', host_platform='linux')

    def tearDown(self):
        self.temp.cleanup()

    def install(self, data=None, store=None):
        with patch('backend.kernels.urllib.request.urlopen', return_value=Response(data or self.data)):
            return (store or self.store).ensure_kernel(self.kernel_id)

    def test_install_is_pinned_atomic_and_reused(self):
        self.assertEqual(self.store.get_kernel(self.kernel_id)['state'], 'missing')
        executable = Path(self.install())
        self.assertTrue(executable.is_file())
        self.assertEqual(executable.stat().st_mode & 0o7777, 0o755)
        metadata = json.loads((executable.parent.parent / '.kernel-install.json').read_text())
        self.assertEqual(metadata['sha256'], self.catalog[0]['sha256'])
        self.assertEqual(self.store.get_kernel(self.kernel_id)['state'], 'ready')
        with patch('backend.kernels.urllib.request.urlopen') as opener:
            self.assertEqual(self.store.ensure_kernel(self.kernel_id), str(executable))
            opener.assert_not_called()
        self.assertEqual(len(list(Path(self.temp.name).glob('*.download'))), 0)
        self.assertEqual(len(list(Path(self.temp.name).glob('*.installing'))), 0)

    def test_hash_failure_cleans_and_can_retry(self):
        self.store._catalog[self.kernel_id]['sha256'] = '0' * 64
        with self.assertRaisesRegex(KernelError, 'SHA-256'):
            self.install()
        self.assertEqual(self.store.get_kernel(self.kernel_id)['state'], 'error')
        self.assertFalse((Path(self.temp.name) / self.kernel_id).exists())
        self.assertFalse((Path(self.temp.name) / ('.' + self.kernel_id + '.download')).exists())
        self.store._catalog[self.kernel_id]['sha256'] = self.catalog[0]['sha256']
        self.install()
        self.assertEqual(self.store.get_kernel(self.kernel_id)['state'], 'ready')

    def test_limits_and_truncation_reject_before_install(self):
        for data in (self.data[:-5], self.data + b'bad'):
            with self.subTest(length=len(data)), self.assertRaises(KernelError):
                self.install(data)
        self.assertFalse((Path(self.temp.name) / self.kernel_id).exists())

    def test_unsafe_archive_paths_links_devices_and_duplicate_rejected(self):
        extras = []
        for name in ('../outside', '/tmp/kernel-escape', 'browser/../../outside', 'bad\\file'):
            info = tarfile.TarInfo(name)
            info.size = 1
            extras.append([(info, b'a')])
        for link in ('../../outside', '/tmp/outside', 'missing', 'chrome'):
            info = tarfile.TarInfo('browser/link')
            info.type = tarfile.SYMTYPE
            info.linkname = link
            rows = [(info, None)]
            if link == 'chrome':
                child = tarfile.TarInfo('browser/link/child')
                child.size = 1
                rows.append((child, b'a'))
            extras.append(rows)
        info = tarfile.TarInfo('browser/device')
        info.type = tarfile.CHRTYPE
        extras.append([(info, None)])
        duplicate = tarfile.TarInfo('browser/chrome')
        duplicate.size = 1
        extras.append([(duplicate, b'a')])
        for rows in extras:
            with self.subTest(names=[x[0].name for x in rows]):
                data = archive_bytes(rows)
                store = KernelStore(self.temp.name, catalog_for(data), 'amd64', 'linux')
                with self.assertRaises(KernelError):
                    self.install(data, store)
                self.assertFalse((Path(self.temp.name) / self.kernel_id).exists())

    def test_safe_relative_symlink_and_hardlink_are_preserved(self):
        link = tarfile.TarInfo('browser/chrome-link')
        link.type = tarfile.SYMTYPE
        link.linkname = 'chrome'
        hardlink = tarfile.TarInfo('browser/chrome-hardlink')
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = 'browser/chrome'
        data = archive_bytes([(link, None), (hardlink, None)])
        store = KernelStore(self.temp.name, catalog_for(data), 'amd64', 'linux')
        executable = Path(self.install(data, store))
        self.assertEqual((executable.parent / 'chrome-link').resolve(), executable.resolve())
        self.assertEqual((executable.parent / 'chrome-hardlink').stat().st_ino, executable.stat().st_ino)

    def test_incompatible_unknown_and_untrusted_entries_rejected(self):
        self.assertEqual(normalize_architecture('aarch64'), 'arm64')
        self.assertEqual(normalize_architecture('x86_64'), 'amd64')
        store = KernelStore(self.temp.name, self.catalog, 'arm64', 'linux')
        self.assertEqual(store.get_kernel(self.kernel_id)['state'], 'unavailable')
        with patch('backend.kernels.urllib.request.urlopen') as opener:
            with self.assertRaises(KernelError):
                store.ensure_kernel(self.kernel_id)
            with self.assertRaises(KernelError):
                store.ensure_kernel('../outside')
            opener.assert_not_called()
        self.catalog[0]['url'] = 'https://untrusted.example/chrome'
        with self.assertRaisesRegex(KernelError, '受信任'):
            KernelStore(self.temp.name, self.catalog)

    def test_concurrent_stores_download_once_with_filesystem_lock(self):
        second = KernelStore(self.temp.name, self.catalog, 'amd64', 'linux')
        barrier = threading.Barrier(2)
        def run(store):
            barrier.wait(timeout=5)
            return store.ensure_kernel(self.kernel_id)
        with patch('backend.kernels.urllib.request.urlopen', side_effect=lambda *a, **k: Response(self.data)) as opener:
            with ThreadPoolExecutor(max_workers=2) as pool:
                jobs = [pool.submit(run, store) for store in (self.store, second)]
                results = [job.result(timeout=10) for job in jobs]
        self.assertEqual(results[0], results[1])
        self.assertEqual(opener.call_count, 1)

    def test_stale_partial_directory_and_metadata_are_retried(self):
        root = Path(self.temp.name)
        (root / ('.' + self.kernel_id + '.download')).write_bytes(b'incomplete')
        staging = root / ('.' + self.kernel_id + '.installing')
        staging.mkdir()
        (staging / 'partial').write_bytes(b'partial')
        (root / self.kernel_id).mkdir()
        self.assertEqual(self.store.get_kernel(self.kernel_id)['state'], 'missing')
        executable = Path(self.install())
        executable.write_bytes(b'corrupted')
        self.assertEqual(self.store.get_kernel(self.kernel_id)['state'], 'missing')
        self.install()
        self.assertEqual(self.store.get_kernel(self.kernel_id)['state'], 'ready')

    def test_directory_permissions_do_not_depend_on_umask(self):
        previous = os.umask(0)
        try:
            executable = Path(self.install())
        finally:
            os.umask(previous)
        self.assertEqual(executable.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(executable.parent.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.store.get_kernel(self.kernel_id)['state'], 'ready')

    def test_broken_binary_never_becomes_ready(self):
        with patch.object(self.store, '_verify_binary', side_effect=KernelError('incompatible')):
            with self.assertRaisesRegex(KernelError, 'incompatible'):
                self.install()
        self.assertEqual(self.store.get_kernel(self.kernel_id)['state'], 'error')
        self.assertFalse((Path(self.temp.name) / self.kernel_id).exists())


if __name__ == '__main__':
    unittest.main()
