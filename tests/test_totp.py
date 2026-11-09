"""RFC 6238 interoperability and server-side secret storage regression tests."""
import base64
import os
from pathlib import Path
import stat
import tempfile
import unittest

from backend.totp import TotpError, TotpStore, generate_code, parse_totp


SECRET = base64.b32encode(b'12345678901234567890').decode().rstrip('=')
# RFC 6238, Appendix B (https://www.rfc-editor.org/rfc/rfc6238#appendix-B).
# SHA256 and SHA512 use the 32/64-byte keys specified in Appendix A.
VECTORS = [
    (59, '94287082', '46119246', '90693936'),
    (1111111109, '07081804', '68084774', '25091201'),
    (1111111111, '14050471', '67062674', '99943326'),
    (1234567890, '89005924', '91819424', '93441116'),
    (2000000000, '69279037', '90698825', '38618901'),
    (20000000000, '65353130', '77737706', '47863826'),
]


class TotpAlgorithmTests(unittest.TestCase):
    def test_rfc6238_vectors_all_three_algorithms(self):
        for index, (algorithm, length) in enumerate((('SHA1', 20), ('SHA256', 32), ('SHA512', 64)), 1):
            secret = base64.b32encode((b'1234567890' * 7)[:length]).decode().rstrip('=')
            config = parse_totp(f'otpauth://totp/Example?secret={secret}&algorithm={algorithm}&digits=8')
            for vector in VECTORS:
                with self.subTest(algorithm=algorithm, timestamp=vector[0]):
                    self.assertEqual(generate_code(config, vector[0]), vector[index])

    def test_raw_secret_normalizes_spacing_case_and_defaults(self):
        raw = ' \t' + ' '.join(SECRET.lower()[i:i + 4] for i in range(0, len(SECRET), 4)) + '\n'
        self.assertEqual(parse_totp(raw), {'secret': SECRET, 'algorithm': 'SHA1', 'digits': 6, 'period': 30})
        self.assertEqual(generate_code(parse_totp(raw), 59), '287082')
        self.assertEqual(generate_code(parse_totp(raw), 1111111109), '081804')
        padded = base64.b32encode(b'12345678901').decode()
        self.assertEqual(parse_totp(padded)['secret'], padded.rstrip('='))

    def test_uri_preserves_algorithm_digits_and_custom_period(self):
        parsed = parse_totp(f'otpauth://totp/Example%3Aaccount?secret={SECRET}&issuer=Example&algorithm=SHA256&digits=8&period=60')
        self.assertEqual(parsed, {'secret': SECRET, 'algorithm': 'SHA256', 'digits': 8, 'period': 60})
        defaults = parse_totp('otpauth://totp/account?secret=' + SECRET)
        self.assertEqual(defaults, parse_totp(SECRET))

    def test_invalid_secrets_and_ambiguous_uris_are_rejected_without_echo(self):
        invalid = [
            '', 'SHORT', '0000000000000000', 'JBSWY3DPEHPK3PX!',
            SECRET + '=INVALID', 'A' * 4096,
            'https://example.test/?secret=' + SECRET,
            'otpauth://hotp/account?secret=' + SECRET + '&counter=1',
            'otpauth://totp/account',
            'otpauth://totp/account?secret=' + SECRET + '&secret=' + SECRET,
            'otpauth://totp/account?secret=' + SECRET + '&algorithm=MD5',
            'otpauth://totp/account?secret=' + SECRET + '&digits=7',
            'otpauth://totp/account?secret=' + SECRET + '&period=0',
            'otpauth://totp/account?secret=' + SECRET + '&period=14',
            'otpauth://totp/account?secret=' + SECRET + '&period=121',
            'otpauth://totp/account?secret=' + SECRET + '&period=30.5',
            'otpauth://totp/account?secret=' + SECRET + '&digits=6&digits=8',
        ]
        for value in invalid:
            with self.subTest(value=value[:70]):
                with self.assertRaises(TotpError) as raised:
                    parse_totp(value)
                self.assertNotIn(SECRET, str(raised.exception))
                if len(value) > 20:
                    self.assertNotIn(value, str(raised.exception))


class TotpStorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='totp-storage-')
        self.addCleanup(self.directory.cleanup)
        self.key_path = Path(self.directory.name) / 'totp.key'

    def test_encrypted_randomized_storage_and_restart_keep_codes(self):
        store = TotpStore(self.key_path)
        first, second = store.encrypt(SECRET), store.encrypt(SECRET)
        self.assertNotEqual(first, second)
        self.assertNotIn(SECRET, first)
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)
        key = self.key_path.read_bytes()
        self.assertNotIn(SECRET.encode(), key)
        reloaded = TotpStore(self.key_path, encrypted_present=True)
        self.assertEqual(self.key_path.read_bytes(), key)
        self.assertEqual(reloaded.decrypt(first), parse_totp(SECRET))
        self.assertEqual(reloaded.code(first, 59)['code'], '287082')

    def test_windows_use_epoch_milliseconds_and_switch_on_boundary(self):
        store = TotpStore(self.key_path)
        token = store.encrypt(SECRET)
        previous = store.code(token, 59.999)
        current = store.code(token, 60)
        self.assertEqual(previous, {'code': '287082', 'period': 30, 'valid_from': 30000, 'valid_until': 60000})
        self.assertEqual(current['valid_from'], 60000)
        self.assertEqual(current['valid_until'], 90000)
        self.assertNotEqual(previous['code'], current['code'])
        custom = store.encrypt(f'otpauth://totp/account?secret={SECRET}&period=60&digits=8')
        self.assertEqual(store.code(custom, 119.999),
                         {'code': '94287082', 'period': 60, 'valid_from': 60000, 'valid_until': 120000})

    def test_missing_master_key_with_existing_ciphertext_fails_closed(self):
        store = TotpStore(self.key_path)
        store.encrypt(SECRET)
        self.key_path.unlink()
        with self.assertRaises(TotpError):
            TotpStore(self.key_path, encrypted_present=True)
        self.assertFalse(self.key_path.exists())

    def test_tampered_ciphertext_and_wrong_master_key_fail_without_secret(self):
        store = TotpStore(self.key_path)
        token = store.encrypt(SECRET)
        wrong_store = TotpStore(self.key_path.with_name('different.key'))
        for target, value in ((store, token[:40] + ('A' if token[40] != 'A' else 'B') + token[41:]),
                              (store, 'not-an-encrypted-token'), (wrong_store, token)):
            with self.subTest(value=value[:20]):
                with self.assertRaises(TotpError) as raised:
                    target.decrypt(value)
                self.assertNotIn(SECRET, str(raised.exception))
                self.assertNotIn(token, str(raised.exception))

    def test_existing_key_with_unsafe_permissions_or_links_is_rejected(self):
        TotpStore(self.key_path)
        original = self.key_path.read_bytes()
        self.key_path.chmod(0o644)
        with self.assertRaises(TotpError):
            TotpStore(self.key_path)
        self.key_path.chmod(0o600)
        linked = self.key_path.with_name('linked.key')
        linked.symlink_to(self.key_path)
        with self.assertRaises(TotpError):
            TotpStore(linked)
        linked.unlink()
        os.link(self.key_path, linked)
        with self.assertRaises(TotpError):
            TotpStore(linked)
        self.assertEqual(self.key_path.read_bytes(), original)

    def test_corrupt_master_key_is_not_silently_replaced(self):
        TotpStore(self.key_path)
        corrupted = b'broken-master-key'
        self.key_path.write_bytes(corrupted)
        with self.assertRaises(TotpError):
            TotpStore(self.key_path)
        self.assertEqual(self.key_path.read_bytes(), corrupted)


if __name__ == '__main__':
    unittest.main()
