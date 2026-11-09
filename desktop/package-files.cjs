'use strict';

// Packager calls ignore with a root-relative path (the root itself is '').
// Keep directories explicit so new server files cannot enter the desktop app.
const packagePaths = new Set([
  '',
  '/',
  '/package.json',
  '/desktop',
  '/desktop/main.cjs',
  '/desktop/preload.cjs',
  '/desktop/policy.cjs',
  '/desktop/connection.cjs',
  '/desktop/connection.html',
  '/desktop/connection.css',
  '/desktop/connection.js',
  '/desktop/assets',
  '/desktop/assets/app-icon.png',
  '/desktop/assets/app-icon.icns',
  '/desktop/assets/app-icon.ico',
]);

function ignorePackagePath(file) {
  return typeof file !== 'string' || !packagePaths.has(file.replaceAll('\\', '/'));
}

module.exports = { ignorePackagePath };
