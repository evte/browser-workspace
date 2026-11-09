import json
import sqlite3
import unittest

from backend.proxies import (ImportValidationError, get_proxy, import_proxies,
                             initialize, list_proxies, parse_import)


class ProxyImportTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(':memory:')
        initialize(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_all_formats_and_protocols(self):
        cases = [
            ('Example.COM:80', 'host_port', 'HTTP', 'http', 'example.com', '', ''),
            ('[2001:db8::1]:1080:user:pa:ss@word', 'host_port_auth', 'socket', 'socks5', '2001:db8::1', 'user', 'pa:ss@word'),
            ('user:pa:ss@word@localhost:8080', 'auth_host_port', 'https', 'https', 'localhost', 'user', 'pa:ss@word'),
            ('socks4://id@proxy.example:1080', 'url', 'socks4', 'socks4', 'proxy.example', 'id', ''),
            ('socks5://u%3Aser:p%40ss%3Aword@proxy.example:443/', 'url', 'socks5', 'socks5', 'proxy.example', 'u:ser', 'p@ss:word'),
        ]
        for text, fmt, protocol, expected_protocol, host, user, password in cases:
            with self.subTest(fmt=fmt, protocol=protocol):
                row = parse_import(text, fmt, protocol)[0]
                self.assertEqual((row['protocol'], row['host'], row['username'], row['password']),
                                 (expected_protocol, host, user, password))

    def test_atomic_validation_and_safe_errors(self):
        secret = 'secret-p@ssword'
        text = '\nvalid.example:8080:user:' + secret + '\ninvalid.example:70000:user:' + secret
        with self.assertRaises(ImportValidationError) as raised:
            import_proxies(self.conn, text, 'host_port_auth', 'http')
        self.assertEqual(raised.exception.errors[0]['line'], 3)
        self.assertNotIn(secret, json.dumps(raised.exception.errors))
        self.assertEqual(list_proxies(self.conn), [])

    def test_duplicates_normalized_and_secrets_stay_private(self):
        result = import_proxies(self.conn, 'EXAMPLE.com:80:user:secret\nexample.com:80:user:secret', 'host_port_auth', 'http')
        self.assertEqual((result['imported'], result['skipped']), (1, 1))
        row = result['proxies'][0]
        self.assertTrue(row['has_password'])
        self.assertNotIn('secret', json.dumps(result))
        self.assertNotIn('password', row)
        self.assertEqual(get_proxy(self.conn, row['id'])['password'], 'secret')
        self.assertIsNone(get_proxy(self.conn, 'missing'))
        second = import_proxies(self.conn, 'http://user:secret@example.com:80', 'url', 'http')
        self.assertEqual((second['imported'], second['skipped']), (0, 1))
        third = import_proxies(self.conn, 'http://user:changed@example.com:80', 'url', 'http')
        self.assertEqual(third['imported'], 1)

    def test_rejects_invalid_or_ambiguous_input(self):
        cases = [
            ('example.com:0', 'host_port', 'http'),
            ('example.com:65536', 'host_port', 'http'),
            ('2001:db8::1:8080', 'host_port', 'http'),
            ('[127.0.0.1]:8080', 'host_port', 'http'),
            ('https://example.com:443', 'url', 'http'),
            ('https://u%3Aser:p%40ss@example.com:443', 'url', 'https'),
            ('http://u%3Aser:p%40ss@example.com:80', 'url', 'http'),
            ('http://u:p%0Asecret@example.com:80', 'url', 'http'),
            ('http://u:p%zz@example.com:80', 'url', 'http'),
            ('http://example.com:80/extra', 'url', 'http'),
            ('http://example.com:80?x=1', 'url', 'http'),
            ('localhost:1080:u:password', 'host_port_auth', 'socks4'),
            ('999.1.1.1:80', 'host_port', 'http'),
            ('bad host:80', 'host_port', 'http'),
            ('host..:80', 'host_port', 'http'),
            ('http://user:pa\tss@example.com:80', 'url', 'http'),
            ('example.com:80::password', 'host_port_auth', 'http'),
        ]
        for text, fmt, protocol in cases:
            with self.subTest(text=text):
                with self.assertRaises(ImportValidationError):
                    parse_import(text, fmt, protocol)

    def test_limits_and_blank_lines(self):
        self.assertEqual(len(parse_import('\nexample.com:80\n\n', 'host_port', 'http')), 1)
        for text in ('  \n ', 'example.com:80\n' * 1001):
            with self.assertRaises(ImportValidationError):
                parse_import(text, 'host_port', 'http')


if __name__ == '__main__':
    unittest.main()
