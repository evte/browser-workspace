'use strict';

const { app, BrowserWindow, Menu, ipcMain, session, dialog } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { randomUUID } = require('node:crypto');
const { DEFAULT_SERVER, normalizeServerUrl, desktopTarget, isSameOriginNavigation,
  isTrustedLocalFrame, isAllowedPermission, isAllowedRequest } = require('./policy.cjs');
const { probeServer } = require('./connection.cjs');

app.setName('Browser Workspace');
const connectionFile = path.join(__dirname, 'connection.html');
const connectionUrl = pathToFileURL(connectionFile).href;
const appIcon = path.join(__dirname, 'assets', 'app-icon.png');
let connectionWindow = null;
let workspaceWindow = null;
let workspaceSession = null;
let settingsSession = null;
let activeOrigin = null;
let configuredOrigin = DEFAULT_SERVER;
let connecting = false;
let quitting = false;
let healthTimer = null;
let healthBusy = false;
let failedChecks = 0;
let lastStatus = null;
const desktopWindows = new Map();
const securePreferences = { nodeIntegration: false, nodeIntegrationInWorker: false,
  nodeIntegrationInSubFrames: false, contextIsolation: true, sandbox: true,
  webSecurity: true, allowRunningInsecureContent: false, webviewTag: false,
  spellcheck: false };

function readConfig() {
  try {
    const configPath = path.join(app.getPath('userData'), 'config.json');
    const metadata = fs.lstatSync(configPath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 4096) return DEFAULT_SERVER;
    return normalizeServerUrl(JSON.parse(fs.readFileSync(configPath, 'utf8')).serverUrl);
  } catch { return DEFAULT_SERVER; }
}

function saveConfig(serverUrl) {
  const folder = app.getPath('userData');
  fs.mkdirSync(folder, { recursive: true });
  const temporary = path.join(folder, `.config-${randomUUID()}.tmp`);
  try {
    fs.writeFileSync(temporary, JSON.stringify({ serverUrl }, null, 2), { mode: 0o600, flag: 'wx' });
    fs.renameSync(temporary, path.join(folder, 'config.json'));
  } finally {
    try { fs.unlinkSync(temporary); } catch { /* Renamed, or creation failed. */ }
  }
}

function status(state, message) {
  lastStatus = { status: state, message };
  if (connectionWindow && !connectionWindow.isDestroyed()) {
    connectionWindow.webContents.send('desktop:status', lastStatus);
  }
}

function lockLocalContents(contents) {
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  contents.on('will-navigate', (event, target) => {
    if (!isTrustedLocalFrame(target, connectionUrl)) event.preventDefault();
  });
  contents.on('will-redirect', (event, target) => {
    if (!isTrustedLocalFrame(target, connectionUrl)) event.preventDefault();
  });
  contents.on('will-attach-webview', event => event.preventDefault());
}

function showConnection(message) {
  if (quitting) return;
  if (!connectionWindow || connectionWindow.isDestroyed()) {
    connectionWindow = new BrowserWindow({ width: 760, height: 650, minWidth: 520, minHeight: 540,
      icon: appIcon,
      title: '连接服务器 · Browser Workspace', backgroundColor: '#f6f7fb', show: false,
      webPreferences: { ...securePreferences, session: settingsSession,
        preload: path.join(__dirname, 'preload.cjs') } });
    lockLocalContents(connectionWindow.webContents);
    connectionWindow.webContents.once('did-finish-load', () => {
      if (lastStatus) status(lastStatus.status, lastStatus.message);
      connectionWindow?.show();
    });
    connectionWindow.on('close', event => {
      if (!quitting && workspaceWindow && !workspaceWindow.isDestroyed()) {
        event.preventDefault(); connectionWindow.hide(); workspaceWindow.show();
      }
    });
    connectionWindow.on('closed', () => { connectionWindow = null; });
    connectionWindow.loadFile(connectionFile).catch(() => {
      dialog.showErrorBox('无法打开桌面应用', '连接页面无法加载，请重新安装或检查应用文件。');
      app.quit();
    });
  } else {
    if (connectionWindow.isMinimized()) connectionWindow.restore();
    connectionWindow.show(); connectionWindow.focus();
  }
  if (message) status('error', message);
}

function clearRemoteSession() {
  const previous = workspaceSession;
  workspaceSession = null;
  if (previous) {
    previous.closeAllConnections().catch(() => {});
    previous.clearStorageData().catch(() => {});
    previous.clearCache().catch(() => {});
  }
}

function destroyRemoteWindows() {
  clearInterval(healthTimer); healthTimer = null; failedChecks = 0;
  for (const win of desktopWindows.values()) if (!win.isDestroyed()) win.destroy();
  desktopWindows.clear();
  const previous = workspaceWindow;
  workspaceWindow = null;
  if (previous && !previous.isDestroyed()) previous.destroy();
}

function createRemoteSession(origin) {
  // No persist: prefix: management cookies and page storage remain in memory.
  const result = session.fromPartition(`workspace-${randomUUID()}`, { cache: false });
  result.setPermissionRequestHandler((contents, permission, callback, details) => {
    const target = details.requestingUrl || contents?.getURL() || '';
    callback(isAllowedPermission(permission, target, origin));
  });
  result.setPermissionCheckHandler((_contents, permission, requestingOrigin) =>
    isAllowedPermission(permission, requestingOrigin, origin));
  result.on('will-download', event => event.preventDefault());
  // Client pages contact only the configured management server, including VNC
  // WebSockets. Target websites are accessed by Chromium on that server.
  result.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, (details, callback) => {
    callback({ cancel: !isAllowedRequest(details.url, origin) });
  });
  return result;
}

function guardRemoteContents(win, origin, profileKey = null) {
  const contents = win.webContents;
  const allowed = target => profileKey
    ? desktopTarget(target, origin)?.key === profileKey
    : isSameOriginNavigation(target, origin);
  contents.on('will-navigate', (event, target) => { if (!allowed(target)) event.preventDefault(); });
  contents.on('will-redirect', (event, target) => { if (!allowed(target)) event.preventDefault(); });
  contents.on('will-attach-webview', event => event.preventDefault());
  contents.setWindowOpenHandler(details => {
    const target = desktopTarget(details.url, origin);
    if (target && activeOrigin === origin && workspaceSession && !profileKey) openDesktop(target, origin);
    return { action: 'deny' };
  });
  contents.on('render-process-gone', () => {
    if (!quitting) showConnection('页面进程已退出，请重新连接服务器。');
  });
  contents.on('did-fail-load', (_event, code, _description, _url, isMainFrame) => {
    if (isMainFrame && code !== -3 && !quitting) showConnection('页面加载失败，请检查服务端是否正在运行，然后重新连接。');
  });
}

function openDesktop(target, origin) {
  const existing = desktopWindows.get(target.key);
  if (existing && !existing.isDestroyed()) {
    if (existing.isMinimized()) existing.restore();
    existing.show(); existing.focus(); return;
  }
  const win = new BrowserWindow({ width: 1440, height: 940, minWidth: 800, minHeight: 600,
    icon: appIcon,
    title: '远程浏览器 · Browser Workspace', backgroundColor: '#24262d', show: false,
    webPreferences: { ...securePreferences, session: workspaceSession } });
  desktopWindows.set(target.key, win);
  guardRemoteContents(win, origin, target.key);
  win.once('ready-to-show', () => { if (!win.isDestroyed()) win.show(); });
  win.on('closed', () => { if (desktopWindows.get(target.key) === win) desktopWindows.delete(target.key); });
  win.loadURL(target.url).catch(() => {
    if (!win.isDestroyed()) win.destroy();
    showConnection('远程桌面无法连接，请确认环境已启动且仍有访问权限。');
  });
}

function startHealthChecks(origin) {
  clearInterval(healthTimer);
  healthTimer = setInterval(async () => {
    if (healthBusy || connecting || quitting || !workspaceWindow || activeOrigin !== origin) return;
    healthBusy = true;
    try {
      await probeServer(origin);
      if (activeOrigin === origin) failedChecks = 0;
    } catch {
      if (activeOrigin === origin && ++failedChecks === 2) {
        showConnection('服务器连接已中断。恢复服务后，点击连接工作区重试。');
      }
    } finally { healthBusy = false; }
  }, 10000);
  healthTimer.unref();
}

async function connectServer(value) {
  if (connecting) return { ok: false, error: '正在连接，请稍候。' };
  connecting = true;
  try {
    const origin = normalizeServerUrl(value);
    status('connecting', '正在检查服务器…');
    await probeServer(origin);
    if (quitting) return { ok: false, error: '应用正在退出。' };
    if (origin !== activeOrigin || !workspaceSession) {
      destroyRemoteWindows(); clearRemoteSession();
      activeOrigin = origin;
      workspaceSession = createRemoteSession(origin);
    } else {
      for (const win of desktopWindows.values()) if (!win.isDestroyed()) win.destroy();
      desktopWindows.clear();
    }
    if (!workspaceWindow || workspaceWindow.isDestroyed()) {
      const win = new BrowserWindow({ width: 1360, height: 900, minWidth: 1024, minHeight: 680,
        icon: appIcon,
        title: 'Browser Workspace', backgroundColor: '#f6f7fb', show: false,
        webPreferences: { ...securePreferences, session: workspaceSession } });
      workspaceWindow = win;
      guardRemoteContents(win, origin);
      win.on('closed', () => {
        if (workspaceWindow !== win) return;
        workspaceWindow = null;
        for (const desktop of desktopWindows.values()) if (!desktop.isDestroyed()) desktop.destroy();
        desktopWindows.clear(); clearInterval(healthTimer); healthTimer = null;
        if (!quitting) showConnection();
      });
    }
    await workspaceWindow.loadURL(origin + '/');
    configuredOrigin = origin;
    let saved = true;
    try { saveConfig(origin); } catch { saved = false; }
    failedChecks = 0;
    startHealthChecks(origin);
    status('ready', saved ? '已连接工作区。' : '已连接，但服务器地址未能保存；下次启动请重新填写。');
    workspaceWindow.show(); workspaceWindow.focus();
    connectionWindow?.hide();
    return { ok: true };
  } catch (error) {
    const message = error?.message && !error.message.includes('ERR_')
      ? error.message : '无法加载工作区，请检查服务器后重试。';
    showConnection(message);
    return { ok: false, error: message };
  } finally { connecting = false; }
}

function requireLocalSender(event) {
  if (!connectionWindow || connectionWindow.isDestroyed()
      || event.sender !== connectionWindow.webContents
      || event.senderFrame !== connectionWindow.webContents.mainFrame
      || !isTrustedLocalFrame(event.senderFrame.url, connectionUrl)) {
    throw new Error('不允许的桌面请求');
  }
}

function createMenu() {
  const application = { label: app.name, submenu: [
    { role: 'about', label: '关于 Browser Workspace' }, { type: 'separator' },
    { label: '服务器设置…', accelerator: 'CmdOrCtrl+,', click: () => showConnection() },
    { label: '重新连接工作区', accelerator: 'CmdOrCtrl+Shift+R', click: () => { void connectServer(configuredOrigin); } },
    { type: 'separator' }, { role: 'quit', label: '退出' },
  ] };
  const edit = { label: '编辑', submenu: [
    { role: 'undo', label: '撤销' }, { role: 'redo', label: '重做' }, { type: 'separator' },
    { role: 'cut', label: '剪切' }, { role: 'copy', label: '复制' },
    { role: 'paste', label: '粘贴' }, { role: 'selectAll', label: '全选' },
  ] };
  const view = { label: '视图', submenu: [
    { label: '刷新当前页面', accelerator: 'CmdOrCtrl+R', click: () => BrowserWindow.getFocusedWindow()?.webContents.reloadIgnoringCache() },
    { role: 'resetZoom', label: '实际大小' }, { role: 'zoomIn', label: '放大' }, { role: 'zoomOut', label: '缩小' },
    { type: 'separator' }, { role: 'togglefullscreen', label: '全屏' },
  ] };
  Menu.setApplicationMenu(Menu.buildFromTemplate([application, edit, view,
    { role: 'windowMenu', label: '窗口', submenu: [{ role: 'minimize', label: '最小化' }, { role: 'front', label: '置于前台' }] }]));
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (workspaceWindow && !workspaceWindow.isDestroyed()) {
      if (workspaceWindow.isMinimized()) workspaceWindow.restore();
      workspaceWindow.show(); workspaceWindow.focus();
    } else showConnection();
  });
  app.on('activate', () => {
    if (workspaceWindow && !workspaceWindow.isDestroyed()) workspaceWindow.show();
    else showConnection();
  });
  app.on('before-quit', () => {
    quitting = true; destroyRemoteWindows(); clearRemoteSession();
  });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
  app.whenReady().then(() => {
    settingsSession = session.fromPartition(`settings-${randomUUID()}`, { cache: false });
    settingsSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    settingsSession.setPermissionCheckHandler(() => false);
    settingsSession.on('will-download', event => event.preventDefault());
    configuredOrigin = readConfig();
    ipcMain.handle('desktop:get-config', event => {
      requireLocalSender(event);
      return { serverUrl: configuredOrigin, version: app.getVersion() };
    });
    ipcMain.handle('desktop:connect', (event, value) => {
      requireLocalSender(event);
      return connectServer(value);
    });
    createMenu(); showConnection();
  }).catch(() => {
    dialog.showErrorBox('桌面应用启动失败', '请重新打开应用；如果问题持续，请检查安装文件和本机可用磁盘空间。');
    app.quit();
  });
}
