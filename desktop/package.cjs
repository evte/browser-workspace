const path = require('node:path');
const fs = require('node:fs');
const { ignorePackagePath } = require('./package-files.cjs');

function createPackageOptions(root = path.resolve(__dirname, '..')) {
  const extension = process.platform === 'darwin' ? 'icns' : process.platform === 'win32' ? 'ico' : 'png';
  const assets = path.join(root, 'desktop', 'assets');
  const icon = path.join(assets, `app-icon.${extension}`);
  for (const asset of new Set([icon, path.join(assets, 'app-icon.png')])) {
    if (!fs.existsSync(asset) || !fs.statSync(asset).isFile()) {
      throw new Error(`缺少软件图标：${path.relative(root, asset)}，请先生成图标文件再打包。`);
    }
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  return {
    dir: root,
    name: 'Browser Workspace',
    executableName: 'Browser Workspace',
    appBundleId: 'com.browserworkspace.desktop',
    icon,
    appVersion: manifest.version,
    electronVersion: manifest.devDependencies.electron,
    platform: process.platform,
    arch: process.arch,
    out: path.join(root, 'dist'),
    overwrite: true,
    asar: true,
    prune: true,
    ignore: ignorePackagePath,
  };
}

async function main() {
  const { packager } = await import('@electron/packager');
  const result = await packager(createPackageOptions());
  result.forEach(file => console.log(`Desktop package: ${file}`));
}

if (require.main === module) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}

module.exports = { createPackageOptions };
