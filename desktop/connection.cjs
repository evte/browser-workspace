'use strict';

const http = require('node:http');
const https = require('node:https');
const { normalizeServerUrl } = require('./policy.cjs');

function probeServer(value, { timeoutMs = 5000 } = {}) {
  const origin = normalizeServerUrl(value);
  return new Promise((resolve, reject) => {
    const target = new URL('/api/session', origin);
    let settled = false;
    let request;
    let timer;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolve();
    };
    timer = setTimeout(() => {
      finish(new Error('连接超时，请检查服务器地址和网络后重试'));
      request?.destroy();
    }, timeoutMs);
    request = (target.protocol === 'https:' ? https : http).request(target, {
      method: 'GET', headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
    }, response => {
      if (response.statusCode !== 200 || !/^application\/json(?:\s*;|$)/i.test(response.headers['content-type'] || '')) {
        finish(new Error('该地址未返回有效的工作区服务，请检查服务器地址'));
        response.destroy(); request.destroy(); return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 65536) {
          finish(new Error('服务器返回的数据异常，请检查地址'));
          response.destroy(); request.destroy();
        } else chunks.push(chunk);
      });
      response.on('end', () => {
        if (settled) return;
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!data || typeof data !== 'object' || Array.isArray(data) || typeof data.authenticated !== 'boolean') throw new Error();
          finish();
        } catch { finish(new Error('该地址不是有效的 Browser Workspace 服务')); }
      });
      response.on('error', () => finish(new Error('服务器连接中断，请重试')));
    });
    request.on('error', error => {
      const tlsFailure = /CERT|TLS|SSL|SELF_SIGNED/.test(error.code || '');
      finish(new Error(tlsFailure ? 'HTTPS 证书校验失败，请检查服务器证书' : '无法连接服务器，请确认地址正确且服务已启动'));
    });
    request.end();
  });
}

module.exports = { probeServer };
