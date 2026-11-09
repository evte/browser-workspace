const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
let executable;
try { executable = require('electron'); } catch { /* A package-only install can use its built runtime. */ }
if (!executable || !fs.existsSync(executable)) {
  const output = path.join(root, 'dist', `Browser Workspace-${process.platform}-${process.arch}`);
  executable = process.platform === 'darwin'
    ? path.join(output, 'Browser Workspace.app', 'Contents', 'MacOS', 'Browser Workspace')
    : path.join(output, process.platform === 'win32' ? 'Browser Workspace.exe' : 'Browser Workspace');
}
if (!fs.existsSync(executable)) {
  console.error('Electron runtime is missing. Run npm ci, or npm run pack first.');
  process.exit(1);
}
const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;
const child = spawn(executable, [root, ...process.argv.slice(2)], { cwd: root, env, stdio: 'inherit' });
child.on('error', error => { console.error(error.message); process.exitCode = 1; });
child.on('exit', code => { process.exitCode = code ?? 1; });
