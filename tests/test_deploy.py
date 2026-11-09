"""Deployment contract tests. Fake Docker/Git never touch a running service."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FAKE_DOCKER = r'''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['DEPLOY_TEST_LOG'], 'a') as log:
    log.write(json.dumps({'tool': 'docker', 'args': args, 'cwd': os.getcwd(),
        'ambient': {key: os.environ.get(key) for key in
        ['COMPOSE_FILE', 'COMPOSE_PROJECT_NAME', 'COMPOSE_PROFILES', 'COMPOSE_ENV_FILES',
         'BROWSER_BIND_ADDRESS', 'BROWSER_PORT']},
        'ambient_has_password': 'ACCESS_PASSWORD' in os.environ}) + '\n')
if args == ['info']:
    sys.exit(1 if os.environ.get('DEPLOY_TEST_DAEMON_DOWN') else 0)
if args == ['compose', 'version']:
    print('Docker Compose version v2.39.2'); sys.exit(0)
if args == ['compose', 'up', '--help']:
    if not os.environ.get('DEPLOY_TEST_OLD_COMPOSE'):
        print('--wait --wait-timeout')
    sys.exit(0)
assert args[0] == 'compose', args
i = 1
options = {}
while i < len(args) and args[i].startswith('-'):
    options[args[i]] = args[i + 1]; i += 2
command = args[i]
if command == os.environ.get('DEPLOY_TEST_FAIL'):
    print('simulated failure'); sys.exit(3)
if command == 'config':
    env = pathlib.Path(options['--env-file']).read_text()
    if not any(line.startswith('ACCESS_PASSWORD=') and len(line.split('=', 1)[1]) for line in env.splitlines()):
        print('invalid config: NEVER_ECHO_THIS_SECRET', file=sys.stderr); sys.exit(2)
if command == 'exec':
    print('runtime-initial-password-for-test-only')
'''
FAKE_GIT = r'''
import json, os, sys
args = sys.argv[1:]
with open(os.environ['DEPLOY_TEST_LOG'], 'a') as log:
    log.write(json.dumps({'tool': 'git', 'args': args}) + '\n')
command = args[2]
if command == 'rev-parse':
    print('true')
elif command == 'status':
    print(os.environ.get('DEPLOY_TEST_GIT_DIRTY', ''), end='')
elif command == 'pull':
    assert args[3:] == ['--ff-only'], args
    if os.environ.get('DEPLOY_TEST_GIT_FAIL'):
        sys.exit(1)
else:
    raise AssertionError(args)
'''


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='browser-workspace-deploy-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'project with spaces'
        self.root.mkdir()
        self.script = self.root / 'deploy.sh'
        shutil.copy2(PROJECT_ROOT / 'deploy.sh', self.script)
        shutil.copy2(PROJECT_ROOT / 'compose.yaml', self.root / 'compose.yaml')
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        for name, source in [('docker', FAKE_DOCKER), ('git', FAKE_GIT)]:
            program = self.bin / name
            program.write_text('#!' + sys.executable + '\n' + source)
            program.chmod(0o755)
        self.journal = self.base / 'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        DEPLOY_TEST_LOG=str(self.journal))

    def run_deploy(self, *args, extra_env=None):
        env = self.env.copy()
        env.update(extra_env or {})
        return subprocess.run(['bash', str(self.script), *args], cwd=self.base,
                              env=env, capture_output=True, text=True, timeout=15)

    def calls(self):
        return [json.loads(line) for line in self.journal.read_text().splitlines()] if self.journal.exists() else []

    def compose_calls(self, command):
        return [call for call in self.calls() if call['tool'] == 'docker'
                and '--project-directory' in call['args'] and command in call['args']]

    def seed_env(self, text='COMPOSE_PROJECT_NAME=existing-workspace\nACCESS_PASSWORD=test-password-long-enough\n'):
        path = self.root / '.env'
        path.write_text(text)
        path.chmod(0o600)
        return path

    def test_fresh_up_from_another_directory_and_repeat_preserve_secret(self):
        first = self.run_deploy()
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        config = self.root / '.env'
        first_bytes = config.read_bytes()
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        password = next(line.split('=', 1)[1] for line in config.read_text().splitlines()
                        if line.startswith('ACCESS_PASSWORD='))
        self.assertRegex(password, r'^[0-9a-f]{48}$')
        self.assertNotIn(password, first.stdout + first.stderr)
        second = self.run_deploy('up')
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_bytes, config.read_bytes())
        self.assertFalse(list(self.root.glob('.env.tmp.*')))
        for call in self.compose_calls('up'):
            self.assertEqual(call['args'][call['args'].index('--project-directory') + 1], str(self.root))
            self.assertEqual(call['args'][call['args'].index('--project-name') + 1], 'browser-workspace')
            self.assertIn('--wait', call['args'])
            self.assertIn('--wait-timeout', call['args'])

    def test_existing_config_never_executes_shell_and_ambient_settings_are_ignored(self):
        marker = self.base / 'should-not-exist'
        text = 'COMPOSE_PROJECT_NAME="kept-project" # comment\nACCESS_PASSWORD=existing-long-password\nSIDE_EFFECT=$(touch "' + str(marker) + '")\n'
        config = self.seed_env(text)
        result = self.run_deploy('up', extra_env={
            'COMPOSE_FILE': '/unrelated/compose.yaml', 'COMPOSE_PROJECT_NAME': 'wrong',
            'COMPOSE_PROFILES': 'dangerous', 'COMPOSE_ENV_FILES': '/unrelated/.env',
            'ACCESS_PASSWORD': 'ambient-test-secret', 'BROWSER_PORT': '9999',
            'BROWSER_BIND_ADDRESS': '0.0.0.0'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(config.read_text(), text)
        self.assertFalse(marker.exists())
        for call in self.compose_calls('up') + self.compose_calls('config'):
            self.assertTrue(all(value is None for value in call['ambient'].values()))
            self.assertFalse(call['ambient_has_password'])
            self.assertEqual(call['args'][call['args'].index('--project-name') + 1], 'kept-project')

    def test_custom_env_and_project_use_callers_relative_path(self):
        config = self.base / 'server.env'
        config.write_text('ACCESS_PASSWORD=existing-long-password\nCOMPOSE_PROJECT_NAME=env-project\n')
        result = self.run_deploy('up', '--env-file', 'server.env', '--project-name', 'custom-project',
                                 '--wait-timeout', '45')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / '.env').exists())
        call = self.compose_calls('up')[0]['args']
        self.assertEqual(call[call.index('--env-file') + 1], str(config))
        self.assertEqual(call[call.index('--project-name') + 1], 'custom-project')
        self.assertEqual(call[call.index('--wait-timeout') + 1], '45')

    def test_build_failure_does_not_recreate_running_service(self):
        self.seed_env()
        result = self.run_deploy('up', extra_env={'DEPLOY_TEST_FAIL': 'build'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.compose_calls('up'), [])
        self.assertTrue((self.root / '.env').exists())

    def test_health_failure_is_nonzero_and_does_not_delete_data(self):
        self.seed_env()
        result = self.run_deploy('up', extra_env={'DEPLOY_TEST_FAIL': 'up'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('健康启动', result.stderr)
        for call in self.calls():
            self.assertNotIn('down', call['args'])
            self.assertNotIn('-v', call['args'])

    def test_invalid_config_does_not_leak_parser_output(self):
        self.seed_env('ACCESS_PASSWORD=\n')
        result = self.run_deploy('up')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('NEVER_ECHO_THIS_SECRET', result.stdout + result.stderr)
        self.assertEqual(self.compose_calls('build'), [])

    def test_dirty_update_rejects_pull_and_deploy(self):
        self.seed_env()
        result = self.run_deploy('update', extra_env={'DEPLOY_TEST_GIT_DIRTY': ' M README.md\n'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('未提交修改', result.stderr)
        self.assertFalse(any('pull' in call['args'] for call in self.calls()))
        self.assertEqual(self.compose_calls('build'), [])

    def test_update_pulls_fast_forward_before_build_and_keeps_config(self):
        config = self.seed_env()
        before = config.read_bytes()
        result = self.run_deploy('update', '--project-name', 'explicit-project')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        pull = next(i for i, call in enumerate(calls) if call['tool'] == 'git' and 'pull' in call['args'])
        build = next(i for i, call in enumerate(calls) if call['tool'] == 'docker' and 'build' in call['args'])
        self.assertLess(pull, build)
        self.assertEqual(config.read_bytes(), before)
        self.assertEqual(self.compose_calls('up')[0]['args'][-1], 'browser')
        self.assertIn('explicit-project', self.compose_calls('up')[0]['args'])

    def test_failed_pull_does_not_build(self):
        self.seed_env()
        result = self.run_deploy('update', extra_env={'DEPLOY_TEST_GIT_FAIL': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.compose_calls('build'), [])

    def test_stop_preserves_volume_and_password_is_explicit(self):
        self.seed_env()
        stop = self.run_deploy('stop')
        self.assertEqual(stop.returncode, 0, stop.stderr)
        self.assertTrue(self.compose_calls('stop'))
        self.assertFalse(any('down' in call['args'] for call in self.calls()))
        password = self.run_deploy('password')
        self.assertEqual(password.returncode, 0, password.stderr)
        self.assertIn('runtime-initial-password-for-test-only', password.stdout)
        self.assertTrue(self.compose_calls('exec'))

    def test_missing_config_read_commands_do_not_create_it(self):
        result = self.run_deploy('status')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / '.env').exists())

    def test_invalid_project_name_and_symlink_are_rejected(self):
        result = self.run_deploy('up', '--project-name', '../wrong')
        self.assertNotEqual(result.returncode, 0)
        target = self.base / 'outside.env'
        target.write_text('ACCESS_PASSWORD=outside-long-password\n')
        (self.root / '.env').symlink_to(target)
        result = self.run_deploy('up')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('符号链接', result.stderr)
        self.assertEqual(target.read_text(), 'ACCESS_PASSWORD=outside-long-password\n')

    def test_old_compose_fails_before_build(self):
        self.seed_env()
        result = self.run_deploy('up', extra_env={'DEPLOY_TEST_OLD_COMPOSE': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.compose_calls('build'), [])


if __name__ == '__main__':
    unittest.main()
