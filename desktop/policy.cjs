'use strict';

const DEFAULT_SERVER = 'http://127.0.0.1:8000';
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function normalizeServerUrl(value) {
  if (typeof value !== 'string' || value.length > 2048 || !value.trim()
      || /[\u0000-\u0020\u007f\\]/.test(value.trim())) {
    throw new Error('请输入完整的服务器地址，例如 http://127.0.0.1:8000');
  }
  let url;
  try { url = new URL(value.trim()); } catch {
    throw new Error('服务器地址格式无效');
  }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname
      || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('请只填写服务器地址和端口，不要包含账号、路径、参数或片段');
  }
  if (url.protocol === 'http:' && !LOOPBACK_HOSTS.has(url.hostname)) {
    throw new Error('远程服务器需要 HTTPS；HTTP 仅用于本机 localhost、127.0.0.1 或 ::1');
  }
  // Do not silently accept numeric, escaped or dot-segment authority aliases.
  const authority = value.trim().match(/^https?:\/\/([^/]+)\/?$/i)?.[1];
  if (!authority || authority.includes('%') || authority.includes('@') || value.trim().includes('?') || value.trim().includes('#')) {
    throw new Error('请填写标准的服务器地址');
  }
  if (url.protocol === 'http:') {
    const host = authority.replace(/:\d+$/, '').toLowerCase();
    if (!LOOPBACK_HOSTS.has(host)) throw new Error('请使用标准的本机地址');
  }
  return url.origin;
}

function parseUrl(value, origin) {
  try {
    if (typeof value !== 'string' || /[\u0000-\u0020\u007f\\]/.test(value)) return null;
    const url = new URL(value);
    if (url.origin !== normalizeServerUrl(origin) || url.username || url.password) return null;
    return url;
  } catch { return null; }
}

function desktopTarget(value, origin) {
  const url = parseUrl(value, origin);
  if (!url || url.pathname !== '/novnc/vnc.html' || url.hash) return null;
  // URL() normalizes dot segments; reject them in the original path as well.
  if (value.split('?')[0] !== `${url.origin}/novnc/vnc.html`) return null;
  const allowed = new Set(['autoconnect', 'resize', 'path']);
  const seen = new Set();
  for (const [key] of url.searchParams) {
    if (!allowed.has(key) || seen.has(key)) return null;
    seen.add(key);
  }
  const path = url.searchParams.get('path') || '';
  const match = /^api\/profiles\/([a-f0-9]{32})\/ws$/.exec(path);
  if (!match) return null;
  if (url.searchParams.has('autoconnect') && !['0', '1'].includes(url.searchParams.get('autoconnect'))) return null;
  if (url.searchParams.has('resize') && !['scale', 'remote', 'off'].includes(url.searchParams.get('resize'))) return null;
  // Construct a known noVNC URL instead of forwarding arbitrary parameters.
  const result = new URL('/novnc/vnc.html', url.origin);
  result.searchParams.set('autoconnect', '1');
  result.searchParams.set('resize', url.searchParams.get('resize') || 'scale');
  result.searchParams.set('path', path);
  return { key: match[1], url: result.href };
}

function isSameOriginNavigation(value, origin) {
  const url = parseUrl(value, origin);
  if (!url) return false;
  if (url.pathname === '/' || url.pathname === '/index.html') {
    const rawPath = value.slice(value.indexOf('://') + 3).replace(/^[^/]+/, '').split(/[?#]/)[0] || '/';
    return !url.search && (rawPath === '/' || rawPath === '/index.html');
  }
  return desktopTarget(value, origin) !== null;
}

function isTrustedLocalFrame(value, connectionFileUrl) {
  return typeof value === 'string' && value === connectionFileUrl && value.startsWith('file://');
}

function isAllowedPermission(permission, value, origin) {
  return permission === 'clipboard-sanitized-write' && parseUrl(value, origin) !== null;
}

function isAllowedRequest(value, origin) {
  try {
    const url = new URL(value);
    const server = new URL(normalizeServerUrl(origin));
    if (url.username || url.password) return false;
    if (['ws:', 'wss:'].includes(url.protocol)) {
      return url.host === server.host && url.protocol === (server.protocol === 'https:' ? 'wss:' : 'ws:');
    }
    return url.origin === server.origin;
  } catch { return false; }
}

module.exports = { DEFAULT_SERVER, normalizeServerUrl, desktopTarget, isSameOriginNavigation,
  isTrustedLocalFrame, isAllowedPermission, isAllowedRequest };
