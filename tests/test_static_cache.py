"""App updates revalidate cached assets without relaxing API cache protection."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


PROJECT = Path(__file__).resolve().parents[1]
PREAMBLE = '''
import importlib
from fastapi.testclient import TestClient
manager = importlib.import_module('backend.app')
client = TestClient(manager.app)
'''


class StaticCacheTests(unittest.TestCase):
    def run_isolated(self, script):
        with tempfile.TemporaryDirectory(prefix='static-cache-') as root:
            data, novnc = Path(root) / 'data', Path(root) / 'novnc'
            data.mkdir()
            novnc.mkdir()
            env = {**os.environ, 'DATA_DIR': str(data), 'NOVNC_DIR': str(novnc),
                   'ACCESS_PASSWORD': 'static-cache-test-password', 'PYTHONPATH': str(PROJECT),
                   'FRONTEND_DIR': str(PROJECT / 'frontend')}
            result = subprocess.run([sys.executable, '-c', PREAMBLE + textwrap.dedent(script)],
                                    cwd=PROJECT, env=env, text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_shell_and_versioned_assets_revalidate_for_200_and_304(self):
        self.run_isolated('''
            policy = 'no-cache, max-age=0, must-revalidate'
            for path in ('/', '/index.html', '/app.js', '/style.css', '/app.js?v=test-build', '/style.css?v=test-build'):
                response = client.get(path)
                assert response.status_code == 200, (path, response.status_code)
                assert response.headers['cache-control'] == policy, path
                etag = response.headers['etag']
                cached = client.get(path, headers={'If-None-Match': etag})
                assert cached.status_code == 304, (path, cached.status_code)
                assert cached.headers['cache-control'] == policy, path
                head = client.head(path)
                assert head.status_code == 200 and head.headers['cache-control'] == policy, path
        ''')

    def test_api_success_and_validation_error_remain_no_store(self):
        self.run_isolated('''
            session = client.get('/api/session')
            assert session.status_code == 200 and session.headers['cache-control'] == 'no-store'
            invalid = client.post('/api/login', json={})
            assert invalid.status_code == 422 and invalid.headers['cache-control'] == 'no-store'
        ''')


if __name__ == '__main__':
    unittest.main()
