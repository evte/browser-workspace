"""Stable Linux UID allocation and private runtime authentication files."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import patch

from backend.runtime_identity import (
    MAX_RUNTIME_UID, MIN_RUNTIME_UID, RuntimeIdentityError,
    allocate_identity, create_xauthority, prepare_profile_identity,
)


class RuntimeIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='runtime-identity-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db_path = self.root / 'profiles.sqlite3'
        with self.db() as conn:
            conn.execute('CREATE TABLE profiles (id TEXT PRIMARY KEY, runtime_uid INTEGER)')

    def db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def test_identity_is_stable_unique_and_deleted_ids_are_not_reused(self):
        with self.db() as conn:
            conn.executemany('INSERT INTO profiles VALUES (?, NULL)', [('one',), ('two',)])
        with self.db() as conn:
            first = allocate_identity(conn, 'one')
            second = allocate_identity(conn, 'two')
        self.assertGreaterEqual(first, MIN_RUNTIME_UID)
        self.assertNotEqual(first, second)
        with self.db() as conn:
            self.assertEqual(allocate_identity(conn, 'one'), first)
            conn.execute('DELETE FROM profiles WHERE id = ?', ('two',))
            conn.execute('INSERT INTO profiles VALUES (?, NULL)', ('three',))
            third = allocate_identity(conn, 'three')
        self.assertGreater(third, second)

    def test_parallel_connections_allocate_without_collision(self):
        with self.db() as conn:
            conn.executemany('INSERT INTO profiles VALUES (?, NULL)', [(str(i),) for i in range(12)])
        def reserve(profile_id):
            with self.db() as conn:
                return allocate_identity(conn, profile_id)
        with ThreadPoolExecutor(max_workers=4) as executor:
            values = list(executor.map(reserve, map(str, range(12))))
        self.assertEqual(len(set(values)), 12)
        self.assertEqual(set(values), set(range(MIN_RUNTIME_UID, MIN_RUNTIME_UID + 12)))

    def test_invalid_and_exhausted_ids_are_rejected(self):
        with self.db() as conn:
            conn.executemany('INSERT INTO profiles VALUES (?, ?)', [('bad', 10001), ('maximum', MAX_RUNTIME_UID), ('new', None)])
        with self.db() as conn:
            with self.assertRaises(RuntimeIdentityError):
                allocate_identity(conn, 'bad')
        with self.db() as conn:
            with self.assertRaises(RuntimeIdentityError):
                allocate_identity(conn, 'new')
        with self.db() as conn:
            with self.assertRaises(RuntimeIdentityError):
                allocate_identity(conn, 'missing')

    def test_xauthority_is_standard_random_private_and_replaces_symlink(self):
        # Ownership changes are exercised against real distinct UIDs in the
        # Linux container integration. This portable test checks the file format.
        directory = self.root / 'runtime'
        directory.mkdir()
        outside = self.root / 'outside.txt'
        outside.write_text('unchanged')
        path = directory / 'Xauthority'
        path.symlink_to(outside)
        with patch('backend.runtime_identity.os.geteuid', return_value=0), patch('backend.runtime_identity.os.fchown'):
            self.assertEqual(create_xauthority(path, MIN_RUNTIME_UID, 207), str(path))
        first = path.read_bytes()
        self.assertEqual(outside.read_text(), 'unchanged')
        self.assertFalse(path.is_symlink())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(struct.unpack('!H', first[:2])[0], 65535)
        offset, fields = 2, []
        for _ in range(4):
            length = struct.unpack('!H', first[offset:offset+2])[0]
            offset += 2
            fields.append(first[offset:offset+length])
            offset += length
        self.assertEqual(fields[:3], [b'', b'207', b'MIT-MAGIC-COOKIE-1'])
        self.assertEqual(len(fields[3]), 16)
        self.assertEqual(offset, len(first))
        with patch('backend.runtime_identity.os.geteuid', return_value=0), patch('backend.runtime_identity.os.fchown'):
            create_xauthority(path, MIN_RUNTIME_UID, 207)
        self.assertNotEqual(first, path.read_bytes())

    def test_profile_and_runtime_symlink_roots_are_refused(self):
        outside = self.root / 'outside'
        outside.mkdir()
        link = self.root / 'link'
        link.symlink_to(outside, target_is_directory=True)
        with patch('backend.runtime_identity.os.geteuid', return_value=0):
            with self.assertRaises(RuntimeIdentityError):
                prepare_profile_identity(link, MIN_RUNTIME_UID)
            with self.assertRaises(RuntimeIdentityError):
                create_xauthority(link / 'Xauthority', MIN_RUNTIME_UID, 100)
        self.assertEqual(list(outside.iterdir()), [])

    def test_migration_does_not_follow_links_and_rejects_hardlinks(self):
        profile = self.root / 'profile'
        profile.mkdir()
        nested = profile / 'nested'
        nested.mkdir()
        (nested / 'cookie-file').write_text('test-cookie')
        outside = self.root / 'outside'
        outside.mkdir()
        external = outside / 'secret'
        external.write_text('external')
        original_mode = external.stat().st_mode
        (profile / 'external-file').symlink_to(external)
        (profile / 'external-directory').symlink_to(outside, target_is_directory=True)
        with patch('backend.runtime_identity.os.geteuid', return_value=0), patch('backend.runtime_identity.os.fchown') as chown:
            home = prepare_profile_identity(profile, MIN_RUNTIME_UID)
        self.assertEqual(home, profile / 'home')
        self.assertEqual(home.stat().st_mode & 0o777, 0o700)
        self.assertEqual(nested.stat().st_mode & 0o777, 0o700)
        self.assertEqual(external.stat().st_mode, original_mode)
        self.assertEqual(external.read_text(), 'external')
        self.assertTrue((profile / 'external-file').is_symlink())
        self.assertGreaterEqual(chown.call_count, 4)
        os.link(external, profile / 'external-hardlink')
        with patch('backend.runtime_identity.os.geteuid', return_value=0), patch('backend.runtime_identity.os.fchown'):
            with self.assertRaises(RuntimeIdentityError):
                prepare_profile_identity(profile, MIN_RUNTIME_UID)
        self.assertEqual(external.stat().st_mode, original_mode)

    def test_prepared_profile_skips_large_tree_migration(self):
        profile = self.root / 'profile'
        profile.mkdir()
        # Simulate ownership already matching a reserved UID; actual chown is
        # not available on developer hosts running as a normal user.
        matching = type('Stat', (), {'st_uid': MIN_RUNTIME_UID, 'st_gid': MIN_RUNTIME_UID})()
        with patch('backend.runtime_identity.os.geteuid', return_value=0), \
                patch('backend.runtime_identity.os.fstat', return_value=matching), \
                patch('backend.runtime_identity.os.fchown'), \
                patch('backend.runtime_identity._migrate_tree') as migrate:
            prepare_profile_identity(profile, MIN_RUNTIME_UID)
            migrate.assert_not_called()


if __name__ == '__main__':
    unittest.main()
