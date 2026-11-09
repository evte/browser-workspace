const path = require('node:path');
const fs = require('node:fs');

(async () => {
  const { packager } = await import('@electron/packager');
  const root = path.resolve(__dirname, '..');
  const extension = process.platform === 'darwin' ? 'icns' : process.platform === 'win32' ? 'ico' : 'png';
  const icon = path.join(__dirname, 'assets', `app-icon.${extension}`);
  for (const asset of new Set([icon, path.join(__dirname, 'assets', 'app-icon.png')])) {
    if (!fs.existsSync(asset) || !fs.statSync(asset).isFile()) {
      throw new Error(`缺少软件图标：${path.relative(root, asset)}，请先生成图标文件再打包。`);
    }
  }
  const result = await packager({
    dir: root,
    name: 'Browser Workspace',
    executableName: 'Browser Workspace',
    appBundleId: 'com.browserworkspace.desktop',
    icon,
    appVersion: require('../package.json').version,
    electronVersion: require('../package.json').devDependencies.electron,
    platform: process.platform,
    arch: process.arch,
    out: path.join(root, 'dist'),
    overwrite: true,
    asar: true,
    prune: true,
    ignore: [
      /^\/(backend|frontend|tests|node_modules|dist)(\/|$)/,
      /^\/desktop\/(tests|package\.cjs|dev\.cjs)(\/|$)/,
      /^\/\.(git|env|dockerignore|gitignore)(\/|$)/,
      /^\/(Dockerfile|compose\.yaml|package-lock\.json)$/,
      /__pycache__/,
    ],
  });
  result.forEach(file => console.log(`Desktop package: ${file}`));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
