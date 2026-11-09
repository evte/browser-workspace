'use strict';

const form = document.getElementById('connection-form');
const serverInput = document.getElementById('server-url');
const connectButton = document.getElementById('connect-button');
const connectLabel = document.getElementById('connect-label');
const statusEl = document.getElementById('connection-status');
let connecting = false;

function setConnecting(value) {
  connecting = value;
  serverInput.disabled = value;
  connectButton.disabled = value;
  connectLabel.textContent = value ? '正在连接…' : '连接工作区';
  form.setAttribute('aria-busy', String(value));
}

function showStatus(status, message) {
  statusEl.dataset.status = status;
  statusEl.textContent = typeof message === 'string' ? message : '';
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (connecting || !window.desktop?.connect) return;
  const serverUrl = serverInput.value.trim();
  if (!serverUrl) {
    serverInput.setAttribute('aria-invalid', 'true');
    showStatus('error', '请输入服务器地址。');
    serverInput.focus();
    return;
  }
  serverInput.value = serverUrl;
  serverInput.removeAttribute('aria-invalid');
  setConnecting(true);
  showStatus('connecting', '正在检查服务器，请稍候…');
  try {
    const result = await window.desktop.connect(serverUrl);
    if (result?.ok) showStatus('ready', '连接成功，正在打开工作区。');
    else showStatus('error', result?.error || '连接失败，请检查地址和服务器状态后重试。');
  } catch {
    showStatus('error', '暂时无法连接，请检查服务器地址和服务状态后重试。');
  } finally {
    setConnecting(false);
  }
});

serverInput.addEventListener('input', () => {
  serverInput.removeAttribute('aria-invalid');
  if (!connecting) showStatus('', '');
});

(async () => {
  if (!window.desktop?.getConfig || !window.desktop?.connect) {
    showStatus('error', '请从 Browser Workspace 桌面应用打开此窗口。');
    return;
  }
  if (typeof window.desktop.onStatus === 'function') {
    window.desktop.onStatus(payload => {
      if (!payload || !['connecting', 'ready', 'error'].includes(payload.status)) return;
      setConnecting(payload.status === 'connecting');
      showStatus(payload.status, payload.message);
    });
  }
  try {
    const config = await window.desktop.getConfig();
    if (typeof config?.serverUrl === 'string' && config.serverUrl) serverInput.value = config.serverUrl;
    if (typeof config?.version === 'string') document.getElementById('app-version').textContent = `v${config.version}`;
    showStatus('', '');
  } catch {
    showStatus('error', '未能读取连接设置，可填写服务器地址重新连接。');
  }
  setConnecting(false);
  serverInput.focus();
})();
