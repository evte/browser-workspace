const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const assetsDir = path.join(__dirname, 'assets');
const source = path.join(assetsDir, 'app-icon.png');
const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function buildIco(images) {
  const directory = Buffer.alloc(6 + images.length * 16);
  directory.writeUInt16LE(1, 2);
  directory.writeUInt16LE(images.length, 4);
  let imageOffset = directory.length;
  images.forEach(({ size, data }, index) => {
    const entryOffset = 6 + index * 16;
    directory[entryOffset] = size === 256 ? 0 : size;
    directory[entryOffset + 1] = size === 256 ? 0 : size;
    directory.writeUInt16LE(1, entryOffset + 4);
    directory.writeUInt16LE(32, entryOffset + 6);
    directory.writeUInt32LE(data.length, entryOffset + 8);
    directory.writeUInt32LE(imageOffset, entryOffset + 12);
    imageOffset += data.length;
  });
  return Buffer.concat([directory, ...images.map(image => image.data)]);
}

function main() {
  if (process.platform !== 'darwin') {
    throw new Error('图标生成需要 macOS 自带的 sips 和 iconutil；其他平台可直接使用已生成的图标打包。');
  }
  if (!fs.existsSync(source) || !fs.statSync(source).isFile()) {
    throw new Error('缺少 desktop/assets/app-icon.png，请先放入至少 1024×1024 的正方形 PNG。');
  }
  const sourceData = fs.readFileSync(source);
  if (sourceData.length < 24 || !sourceData.subarray(0, 8).equals(pngSignature)
    || sourceData.toString('ascii', 12, 16) !== 'IHDR') {
    throw new Error('desktop/assets/app-icon.png 必须是有效的 PNG 文件。');
  }
  const width = sourceData.readUInt32BE(16);
  const height = sourceData.readUInt32BE(20);
  if (width !== height || width < 1024) {
    throw new Error(`源图标为 ${width}×${height}，请使用至少 1024×1024 的正方形 PNG。`);
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'browser-workspace-icons-'));
  try {
    const resized = new Map();
    for (const size of [16, 32, 48, 64, 128, 256, 512, 1024]) {
      const destination = path.join(tempDir, `${size}.png`);
      execFileSync('/usr/bin/sips', ['-z', String(size), String(size), source, '--out', destination], {
        stdio: 'pipe',
      });
      resized.set(size, destination);
    }

    const iconsetDir = path.join(tempDir, 'AppIcon.iconset');
    fs.mkdirSync(iconsetDir);
    for (const size of [16, 32, 128, 256, 512]) {
      fs.copyFileSync(resized.get(size), path.join(iconsetDir, `icon_${size}x${size}.png`));
      fs.copyFileSync(resized.get(size * 2), path.join(iconsetDir, `icon_${size}x${size}@2x.png`));
    }

    const icnsPath = path.join(tempDir, 'app-icon.icns');
    execFileSync('/usr/bin/iconutil', ['--convert', 'icns', '--output', icnsPath, iconsetDir], {
      stdio: 'pipe',
    });
    const icoPath = path.join(tempDir, 'app-icon.ico');
    const icoImages = [16, 32, 48, 64, 128, 256].map(size => ({
      size,
      data: fs.readFileSync(resized.get(size)),
    }));
    fs.writeFileSync(icoPath, buildIco(icoImages));

    for (const generated of [icnsPath, icoPath]) {
      const destination = path.join(assetsDir, path.basename(generated));
      fs.copyFileSync(generated, destination);
      console.log(`已生成软件图标：${destination}`);
    }
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(`生成软件图标失败：${error.message}`);
  process.exitCode = 1;
}
