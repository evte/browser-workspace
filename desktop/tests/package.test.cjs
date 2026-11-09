'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { createRequire, isBuiltin } = require('node:module');
const { createPackageOptions } = require('../package.cjs');
const { ignorePackagePath } = require('../package-files.cjs');

test('the real packager copy filter and ASAR preserve the client without arbitrary server files', async t => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'browser-workspace-package-test-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const source = path.join(temporary, 'source');
  const staging = path.join(temporary, 'staging');
  const archive = path.join(temporary, 'app.asar');
  const root = path.resolve(__dirname, '../..');
  await fs.mkdir(source);
  await fs.copyFile(path.join(root, 'package.json'), path.join(source, 'package.json'));
  await fs.cp(path.join(root, 'desktop'), path.join(source, 'desktop'), { recursive: true });

  const secretMarker = 'TEST_ONLY_SECRET_MUST_NEVER_ENTER_THE_DESKTOP_ARCHIVE';
  const serverFiles = [
    'production.env', 'arbitrary-config.local', '.env', '.env.production',
    'database', 'workspace.sqlite', 'totp.key', 'deploy.sh',
    'backups/snapshot.tar', 'data/accounts.sqlite', 'browser_data/profile/Cookies',
    'desktop/private.pem', 'desktop/main.cjs.bak', 'desktop/connection.html.old',
    'desktop/assets/app-icon.png.backup', 'desktop/assets/icon-prompt.txt',
    'desktop/assets/production.env', 'desktop/backups/server.env',
    'node_modules/private-config/index.js',
  ];
  for (const file of serverFiles) {
    const destination = path.join(source, file);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, secretMarker);
  }

  // Exercise the same options factory used by npm run pack, including packager's
  // root-relative path conversion and directory traversal. No Electron download.
  const packagerDirectory = path.dirname(require.resolve('@electron/packager'));
  const { userPathFilter, populateIgnoredPaths } = await import(
    pathToFileURL(path.join(packagerDirectory, 'copy-filter.js')).href
  );
  const options = createPackageOptions(source);
  Object.assign(options, populateIgnoredPaths(options));
  await fs.cp(source, staging, {
    recursive: true,
    dereference: true,
    filter: userPathFilter(options),
  });
  const { createPackage, listPackage, extractFile } = await import('@electron/asar');
  await createPackage(staging, archive);

  const runtimeFiles = [
    'package.json', 'desktop/main.cjs', 'desktop/preload.cjs', 'desktop/policy.cjs',
    'desktop/connection.cjs', 'desktop/connection.html', 'desktop/connection.css',
    'desktop/connection.js', 'desktop/assets/app-icon.png',
    'desktop/assets/app-icon.icns', 'desktop/assets/app-icon.ico',
  ];
  const entries = listPackage(archive).map(file => file.replaceAll('\\', '/'));
  assert.deepEqual(entries.slice().sort(), [
    '/desktop', '/desktop/assets', ...runtimeFiles.map(file => `/${file}`),
  ].sort());
  assert.equal((await fs.readFile(archive)).includes(Buffer.from(secretMarker)), false);
  for (const file of serverFiles) {
    assert.equal(entries.includes(`/${file}`), false, `${file} must be excluded`);
  }
  for (const file of runtimeFiles) {
    assert.deepEqual(extractFile(archive, file), await fs.readFile(path.join(source, file)), file);
  }

  const manifest = JSON.parse(extractFile(archive, 'package.json').toString('utf8'));
  assert.equal(manifest.main, 'desktop/main.cjs');
  const resolvedStaging = await fs.realpath(staging);
  for (const file of runtimeFiles.filter(file => file.endsWith('.cjs'))) {
    const packagedPath = path.join(staging, file);
    const packagedRequire = createRequire(packagedPath);
    const code = extractFile(archive, file).toString('utf8');
    for (const [, , dependency] of code.matchAll(/require\(\s*(['"])([^'"]+)\1\s*\)/g)) {
      if (dependency.startsWith('.')) {
        const resolved = packagedRequire.resolve(dependency);
        const relative = path.relative(resolvedStaging, resolved).split(path.sep).join('/');
        assert.ok(entries.includes(`/${relative}`), `${file} requires ${dependency}`);
      } else {
        assert.ok(isBuiltin(dependency) || dependency === 'electron', `${file} requires ${dependency}`);
      }
    }
  }
  // These modules must load from the staged app without reaching back into the source.
  assert.equal(typeof require(path.join(staging, 'desktop/connection.cjs')).probeServer, 'function');
  assert.equal(typeof require(path.join(staging, 'desktop/policy.cjs')).normalizeServerUrl, 'function');
  const html = extractFile(archive, 'desktop/connection.html').toString('utf8');
  for (const [, , reference] of html.matchAll(/(?:src|href)=(['"])([^'"]+)\1/g)) {
    assert.ok(entries.includes(`/desktop/${reference}`), `Connection page needs ${reference}`);
  }
});

test('the allowlist accepts Windows separators without opening up sibling paths', () => {
  assert.equal(ignorePackagePath(''), false);
  assert.equal(ignorePackagePath('\\desktop'), false);
  assert.equal(ignorePackagePath('\\desktop\\assets'), false);
  assert.equal(ignorePackagePath('\\desktop\\main.cjs'), false);
  assert.equal(ignorePackagePath('\\desktop\\assets\\app-icon.ico'), false);
  assert.equal(ignorePackagePath('\\desktop\\assets\\production.env'), true);
  assert.equal(ignorePackagePath('\\desktop\\main.cjs.bak'), true);
  assert.equal(ignorePackagePath('/desktop/../production.env'), true);
});
