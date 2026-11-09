'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { probeServer } = require('../connection.cjs');

async function withServer(handler, check) {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    await check(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}

test('connection probe uses the public session endpoint and accepts a logged-out server', async () => {
  let observed;
  await withServer((request, response) => {
    observed = { method: request.method, url: request.url, cookie: request.headers.cookie };
    response.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ authenticated: false, user: null, teams: [], setup_required: false }));
  }, async origin => {
    await assert.doesNotReject(probeServer(origin));
  });
  assert.deepEqual(observed, { method: 'GET', url: '/api/session', cookie: undefined });
});

test('connection probe never follows redirects, including redirects on the same host', async () => {
  let requests = 0;
  await withServer((request, response) => {
    requests += 1;
    response.writeHead(302, { Location: '/redirect-target' });
    response.end();
  }, async origin => {
    await assert.rejects(probeServer(origin));
  });
  assert.equal(requests, 1);
});

test('wrong services and invalid session response shapes are rejected', async () => {
  const cases = [
    [503, 'application/json', '{"authenticated":false}'],
    [200, 'text/html', '<html>Sign in to another service</html>'],
    [200, 'application/json', 'not-json'],
    [200, 'application/json', '{}'],
    [200, 'application/json', '{"authenticated":"false"}'],
    [200, 'application/json', '[{"authenticated":false}]'],
    [200, 'application/json', 'null'],
  ];
  for (const [status, contentType, body] of cases) {
    await withServer((request, response) => {
      response.writeHead(status, { 'Content-Type': contentType });
      response.end(body);
    }, async origin => {
      await assert.rejects(probeServer(origin), undefined, `${status} ${body}`);
    });
  }
});

test('an oversized service response is rejected even when it is otherwise valid JSON', async () => {
  await withServer((request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ authenticated: false, unexpected: 'x'.repeat(70 * 1024) }));
  }, async origin => {
    await assert.rejects(probeServer(origin));
  });
});

test('a server that never responds is cancelled within the connection deadline', async () => {
  await withServer(() => {}, async origin => {
    const started = Date.now();
    await assert.rejects(probeServer(origin, { timeoutMs: 40 }));
    assert.ok(Date.now() - started < 2000, 'Probe must not leave the connection form waiting indefinitely');
  });
});
