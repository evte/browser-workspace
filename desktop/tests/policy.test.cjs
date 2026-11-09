'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeServerUrl,
  isSameOriginNavigation,
  desktopTarget,
  isTrustedLocalFrame,
  isAllowedPermission,
  isAllowedRequest,
} = require('../policy.cjs');

const origin = 'https://workspace.example.test';
const profileId = '0123456789abcdef0123456789abcdef';
const desktopUrl = `${origin}/novnc/vnc.html?autoconnect=1&resize=scale&path=api/profiles/${profileId}/ws`;

test('server addresses normalize to an origin and support HTTPS or explicit local HTTP', () => {
  const cases = [
    ['https://WORKSPACE.example.test/', origin],
    [' https://workspace.example.test:8443/ ', `${origin}:8443`],
    ['http://127.0.0.1:8000/', 'http://127.0.0.1:8000'],
    ['http://localhost:8000', 'http://localhost:8000'],
    ['http://[::1]:8000', 'http://[::1]:8000'],
  ];
  for (const [input, expected] of cases) {
    assert.equal(normalizeServerUrl(input), expected, input);
  }
});

test('server settings reject remote cleartext, credentials, URLs with app state, and executable schemes', () => {
  const rejected = [
    '', null, undefined, {}, 8000,
    'workspace.example.test',
    'http://workspace.example.test',
    'http://localhost.evil.test:8000',
    'http://127.0.0.1.evil.test:8000',
    'http://192.168.1.10:8000',
    'http://0.0.0.0:8000',
    'file:///etc/passwd',
    'javascript:alert(1)',
    'data:text/html,test',
    'ftp://workspace.example.test',
    'https://user:password@workspace.example.test',
    'https://workspace.example.test@evil.test',
    `${origin}/api/session`,
    `${origin}/?token=not-a-setting`,
    `${origin}/#invite=not-a-setting`,
    'https://workspace.example.test:99999',
  ];
  for (const input of rejected) {
    assert.throws(() => normalizeServerUrl(input), undefined, String(input));
  }
});

test('workspace navigation stays on the selected origin and app routes', () => {
  for (const url of [`${origin}/`, `${origin}/index.html`, `${origin}/#environment-panel`, desktopUrl]) {
    assert.equal(isSameOriginNavigation(url, origin), true, url);
  }
  for (const url of [
    'https://other.example.test/',
    'https://workspace.example.test.evil.test/',
    'https://sub.workspace.example.test/',
    'http://workspace.example.test/',
    'https://workspace.example.test:8443/',
    `${origin}/api/session`,
    `${origin}/untrusted.html`,
    'https://user:password@workspace.example.test/',
    'file:///tmp/connection.html',
    'javascript:alert(1)',
    '//workspace.example.test/',
  ]) {
    assert.equal(isSameOriginNavigation(url, origin), false, url);
  }
});

test('desktop windows are keyed by the authorized environment WebSocket route', () => {
  const target = desktopTarget(desktopUrl, origin);
  assert.equal(target.key, profileId);
  assert.equal(new URL(target.url).origin, origin);
  assert.equal(new URL(target.url).pathname, '/novnc/vnc.html');
  assert.equal(new URL(target.url).searchParams.get('path'), `api/profiles/${profileId}/ws`);
  assert.equal(desktopTarget(`${origin}/novnc/vnc.html?path=api/profiles/${profileId}/ws`, origin).key, profileId);
});

test('desktop URLs cannot redirect VNC to another server, route, or query option', () => {
  const rejected = [
    desktopUrl.replace(origin, 'https://evil.test'),
    desktopUrl.replace(origin, 'https://workspace.example.test.evil.test'),
    desktopUrl.replace(origin, 'https://user:pass@workspace.example.test'),
    desktopUrl.replace('/novnc/vnc.html', '/novnc/vnc_lite.html'),
    `${origin}/novnc/vnc.html`,
    `${origin}/novnc/vnc.html?path=wss://evil.test/ws`,
    `${origin}/novnc/vnc.html?path=//evil.test/ws`,
    `${origin}/novnc/vnc.html?path=api/profiles/../admin/ws`,
    `${origin}/novnc/vnc.html?path=api/profiles/${profileId}/ws/extra`,
    `${origin}/novnc/vnc.html?path=api/profiles/not-an-id/ws`,
    `${desktopUrl}&host=evil.test`,
    `${desktopUrl}&port=443`,
    `${desktopUrl}&encrypt=0`,
    `${desktopUrl}&password=unexpected`,
    `${desktopUrl}&path=api/profiles/${profileId}/ws`,
    `${desktopUrl}&autoconnect=0`,
    `${desktopUrl}#untrusted`,
    desktopUrl.replace('resize=scale', 'resize=invalid'),
    desktopUrl.replace('autoconnect=1', 'autoconnect=yes'),
    desktopUrl.replace('api/profiles/', 'api%252fprofiles%252f'),
  ];
  for (const url of rejected) {
    assert.equal(desktopTarget(url, origin), null, url);
  }
});

test('local IPC is available only to the exact bundled connection page', () => {
  const localPage = 'file:///Applications/Browser%20Workspace.app/Contents/Resources/app/desktop/connection.html';
  assert.equal(isTrustedLocalFrame(localPage, localPage), true);
  for (const frame of [
    `${localPage}?server=evil`, `${localPage}#frame`,
    localPage.replace('connection.html', 'other.html'),
    `${origin}/connection.html`,
    'about:blank', '',
  ]) {
    assert.equal(isTrustedLocalFrame(frame, localPage), false, frame);
  }
});

test('clipboard writes are the only permission allowed, and only for the trusted app', () => {
  assert.equal(isAllowedPermission('clipboard-sanitized-write', `${origin}/`, origin), true);
  for (const permission of ['media', 'geolocation', 'notifications', 'midiSysex', 'display-capture', 'clipboard-read']) {
    assert.equal(isAllowedPermission(permission, `${origin}/`, origin), false, permission);
  }
  assert.equal(isAllowedPermission('clipboard-sanitized-write', 'https://evil.test/', origin), false);
  assert.equal(isAllowedPermission('clipboard-sanitized-write', 'https://workspace.example.test.evil.test/', origin), false);
});

test('resource and WebSocket requests cannot leave the configured server or downgrade its transport', () => {
  assert.equal(isAllowedRequest(`${origin}/app.js`, origin), true);
  assert.equal(isAllowedRequest(`wss://workspace.example.test/api/profiles/${profileId}/ws`, origin), true);
  assert.equal(isAllowedRequest('ws://127.0.0.1:8000/api/profiles/test/ws', 'http://127.0.0.1:8000'), true);
  for (const url of [
    'https://evil.test/app.js',
    'https://workspace.example.test.evil.test/app.js',
    'http://workspace.example.test/app.js',
    'https://workspace.example.test:8443/app.js',
    'ws://workspace.example.test/api/profiles/test/ws',
    'wss://evil.test/api/profiles/test/ws',
    'wss://workspace.example.test:8443/api/profiles/test/ws',
    'https://user:password@workspace.example.test/app.js',
    'wss://user:password@workspace.example.test/ws',
    'file:///tmp/private.txt',
  ]) {
    assert.equal(isAllowedRequest(url, origin), false, url);
  }
});
