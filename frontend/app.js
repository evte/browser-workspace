const profilesEl = document.querySelector('#profiles');
const messageEl = document.querySelector('#message');
const proxyNotice = document.querySelector('#proxy-notice');
const createDialog = document.querySelector('#create-dialog');
const createForm = document.querySelector('#create-form');
const loginDialog = document.querySelector('#login-dialog');
const loginForm = document.querySelector('#login-form');
const importDialog = document.querySelector('#import-dialog');
const importForm = document.querySelector('#import-form');
const bindDialog = document.querySelector('#bind-dialog');
const busyIds = new Set();
let authenticated = false;
let sessionVersion = 0;
let profileRequest = 0;
let proxyList = [];
let kernelList = [];
let profileList = [];
let profilesPage = 1;
let pageSize = 50;
let boundProfile = null;
let loadingProfiles = false;
let createNetworkMode = null;
const totpCodes = new Map();
const totpCells = new Map();
let totpIds = [];
let totpGeneration = 0;
let totpController = null;
let totpNextFetch = 0;
let totpFailed = false;
let totpServerTime = Date.now();
let totpClockTime = performance.now();

const selectedProfiles = new Set();
let visibleProfiles = [];
let sessionData = null;
let activeTeamId = null;
let memberList = [];
let invitationList = [];
let authMode = 'login';
let setupRequired = false;
let switchingTeam = false;
let permissionsRefreshing = false;
let pendingInvite = new URLSearchParams(location.hash.slice(1)).get('invite') || '';
const $ = selector => document.querySelector(selector);
const roleLabels = { owner: '团队所有者', admin: '管理员', member: '普通成员' };
const currentTeam = () => sessionData?.teams?.find(team => team.id === activeTeamId);
const canManage = () => ['owner', 'admin'].includes(currentTeam()?.role);
const teamPath = () => `/api/teams/${encodeURIComponent(activeTeamId)}`;
const showError = (target, error) => { if (!error.stale) target.textContent = error.message; };
loginDialog.addEventListener('cancel', event => event.preventDefault());

function clearWorkspace() {
  sessionVersion += 1;
  profileRequest += 1;
  clearTotp();
  loadingProfiles = false;
  for (const dialog of document.querySelectorAll('dialog[open]')) if (dialog !== loginDialog) dialog.close();
  importForm.reset();
  createForm.reset(); updateCreateNetwork(); $('#bind-form').reset();
  proxyList = []; kernelList = []; memberList = []; invitationList = [];
  boundProfile = null;
  selectedProfiles.clear(); busyIds.clear();
  profilesPage = 1;
  $('#profile-search').value = '';
  $('#status-filter').value = 'all';
  $('#tag-filter').replaceChildren(new Option('全部标签', ''));
  $('#team-members').replaceChildren();
  $('#team-invitations').replaceChildren();
  $('#invite-link').value = '';
  $('#invite-result').hidden = true;
  messageEl.textContent = ''; proxyNotice.textContent = '';
  renderProfiles([]); renderProxies();
}

function renderAccount() {
  const select = $('#team-select');
  select.replaceChildren();
  for (const team of sessionData?.teams || []) select.add(new Option(team.name, team.id));
  select.value = activeTeamId || '';
  select.disabled = !authenticated;
  $('#current-user').textContent = sessionData?.user?.name || '';
  $('#current-user').title = sessionData?.user?.email || '';
  $('#visible-environments-label').textContent = canManage() ? '团队环境' : '分配给我';
  document.querySelectorAll('[data-manage]').forEach(el => { el.hidden = !canManage(); });
  $('#invite-role').querySelector('[value="admin"]').disabled = currentTeam()?.role !== 'owner';
  if (currentTeam()?.role !== 'owner') $('#invite-role').value = 'member';
}

function applySession(payload, force = false) {
  const oldKey = `${sessionData?.user?.id}/${activeTeamId}/${currentTeam()?.role}`;
  authenticated = !!payload.authenticated;
  setupRequired = !!payload.setup_required;
  sessionData = payload;
  activeTeamId = payload.active_team_id || payload.teams?.[0]?.id || null;
  const newKey = `${payload.user?.id}/${activeTeamId}/${currentTeam()?.role}`;
  if (force || oldKey !== newKey) clearWorkspace();
  renderAccount();
}

function setAuthMode(mode) {
  authMode = mode;
  const register = mode === 'register';
  $('#auth-title').textContent = register ? (setupRequired ? '创建首个账号' : '注册账号') : '登录工作区';
  $('#auth-description').textContent = register ? '创建个人账号，管理自己的团队或接受邀请。' : '使用个人账号登录，进入你的团队。';
  $('#register-name-field').hidden = !register;
  $('#register-name').required = register;
  $('#register-name').disabled = !register;
  $('#password-help').hidden = !register;
  $('#login-password').minLength = register ? 12 : 1;
  $('#login-password').autocomplete = register ? 'new-password' : 'current-password';
  $('#setup-key-field').hidden = !(register && setupRequired);
  $('#setup-key').required = register && setupRequired;
  $('#setup-key').disabled = !(register && setupRequired);
  $('#auth-invite-notice').hidden = !pendingInvite;
  $('#auth-login').classList.toggle('active', !register);
  $('#auth-register').classList.toggle('active', register);
  $('#login-submit').textContent = register ? '注册并进入工作区' : '登录';
  $('#login-error').textContent = '';
}

function showLogin() {
  authenticated = false;
  sessionData = null; activeTeamId = null;
  clearWorkspace(); renderAccount();
  setAuthMode(setupRequired ? 'register' : authMode);
  if (!loginDialog.open) loginDialog.showModal();
}

async function api(path, options = {}) {
  const version = sessionVersion;
  const team = activeTeamId;
  const response = await fetch(path, {
    credentials: 'same-origin', ...options,
    headers: { 'Content-Type': 'application/json', ...(team ? { 'X-Team-ID': team } : {}), ...options.headers },
  });
  let payload = null;
  if (response.status !== 204) {
    try { payload = await response.json(); } catch { /* Empty proxy response. */ }
  }
  if (version !== sessionVersion) {
    const error = new Error('工作区已切换'); error.stale = true; throw error;
  }
  if (response.status === 401 && !['/api/login', '/api/register'].includes(path)) {
    showLogin();
    throw new Error('登录已过期，请重新登录。');
  }
  if (!response.ok) {
    if (authenticated && [403, 404].includes(response.status) && path !== '/api/session') {
      clearTotp();
      queueMicrotask(recoverPermissions);
    }
    const detail = payload?.detail;
    const error = new Error(typeof detail === 'string' ? detail : detail?.message || `请求失败（${response.status}）`);
    error.lines = Array.isArray(detail?.errors) ? detail.errors : [];
    error.status = response.status;
    throw error;
  }
  return payload;
}

async function syncSession() {
  const payload = await api('/api/session');
  if (switchingTeam) return authenticated;
  if (!payload.authenticated) { setupRequired = !!payload.setup_required; showLogin(); return false; }
  applySession(payload);
  return true;
}

async function recoverPermissions() {
  if (permissionsRefreshing || switchingTeam || !authenticated) return;
  permissionsRefreshing = true;
  try { if (await syncSession()) await loadProfiles(); }
  catch (error) { showError(messageEl, error); }
  finally { permissionsRefreshing = false; }
}

function parseTags(value) {
  const tags = [...new Set(value.split(/[,，\n]/).map(tag => tag.trim()).filter(Boolean))];
  if (tags.length > 20 || tags.some(tag => tag.length > 32)) throw new Error('最多 20 个标签，每个标签最多 32 个字符。');
  return tags;
}

function renderMemberPicker(id, selected = []) {
  const target = document.getElementById(id);
  target.replaceChildren();
  for (const member of memberList) {
    const label = document.createElement('label'); label.className = 'member-choice';
    const input = document.createElement('input'); input.type = 'checkbox'; input.value = member.id;
    input.checked = selected.includes(member.id);
    const text = document.createElement('span');
    text.textContent = `${member.name} · ${roleLabels[member.role] || member.role}`;
    text.title = member.email;
    label.append(input, text); target.append(label);
  }
  if (!memberList.length) target.textContent = '暂无可分配成员，请先邀请成员加入团队。';
}

function selectedMembers(id) {
  return Array.from(document.getElementById(id).querySelectorAll('input:checked'), input => input.value);
}

async function loadMembers() {
  memberList = await api(`${teamPath()}/members`);
  return memberList;
}

function proxyLabel(proxy) {
  const address = proxy.host.includes(':') ? `[${proxy.host}]:${proxy.port}` : `${proxy.host}:${proxy.port}`;
  const authentication = proxy.username ? ` · ${proxy.username}` : '';
  return `${proxy.protocol.toUpperCase()} · ${address}${authentication}`;
}

function updateProxySelect(select, selected = '') {
  select.replaceChildren(new Option(select.id === 'profile-proxy' ? '请选择已有代理' : '服务器网络（直连）', ''));
  for (const proxy of proxyList) select.add(new Option(proxyLabel(proxy), proxy.id));
  select.value = selected || '';
}

function kernelStatus(kernel) {
  const progress = Number(kernel.progress);
  if (kernel.state === 'downloading' && Number.isFinite(progress)) return `下载中 ${Math.round(progress)}%`;
  return {
    ready: '已就绪', missing: '启动时自动下载', downloading: '下载中', extracting: '正在解压', verifying: '正在验证',
    error: '下载失败，可重试', unavailable: '当前服务器不可用',
  }[kernel.state] || kernel.state || '状态未知';
}

function updateKernelSelect(select, selected) {
  const options = [...kernelList];
  if (!options.some(kernel => kernel.id === 'chromium-system')) {
    options.push({ id: 'chromium-system', name: '系统 Chromium', engine: 'chromium', state: 'ready' });
  }
  if (selected && !options.some(kernel => kernel.id === selected)) {
    options.push({ id: selected, name: '当前内核', state: 'unavailable' });
  }
  select.replaceChildren();
  for (const kernel of options) {
    const version = kernel.version === 'system' ? '随系统镜像' : kernel.version;
    const label = `${kernel.name}${version ? ` ${version}` : ''} · ${kernelStatus(kernel)}`;
    const option = new Option(label, kernel.id);
    option.disabled = kernel.state === 'unavailable';
    select.add(option);
  }
  const recommended = options.find(kernel => kernel.recommended && kernel.state !== 'unavailable');
  select.value = selected || recommended?.id || 'chromium-system';
  if (!select.value) select.value = 'chromium-system';
}

function selectedKernel(selectId) {
  const id = document.getElementById(selectId).value;
  return kernelList.find(kernel => kernel.id === id) || {
    id, engine: 'chromium', state: id === 'chromium-system' ? 'ready' : 'unavailable',
  };
}

function updateKernelHelp(prefix) {
  const kernel = selectedKernel(`${prefix}-kernel`);
  const fingerprint = kernel?.engine === 'fingerprint-chromium';
  const fieldset = document.getElementById(prefix === 'profile' ? 'create-fingerprint' : 'bind-fingerprint');
  fieldset.hidden = !fingerprint;
  fieldset.disabled = !fingerprint;
  let message = fingerprint ? '设备指纹随环境保存。首次启动会自动下载尚未安装的内核。' : '使用原生浏览器信息。';
  if (kernel?.state === 'unavailable') message = kernel.message || '该内核不适用于当前服务器，请选择其他内核。';
  if (kernel && ['downloading', 'extracting', 'verifying'].includes(kernel.state)) message = `${kernelStatus(kernel)}，完成后可启动环境。`;
  if (kernel?.source) message += ` 来源：${kernel.source}`;
  document.getElementById(`${prefix}-kernel-help`).textContent = message;
}

function renderProxies() {
  const count = proxyList.length;
  for (const id of ['proxy-count', 'proxy-list-count', 'proxy-nav-count']) {
    document.getElementById(id).textContent = count;
  }
  const list = document.querySelector('#proxies');
  list.replaceChildren();
  if (!count) {
    const row = list.insertRow();
    const empty = row.insertCell();
    empty.colSpan = 3;
    empty.className = 'empty';
    empty.textContent = '还没有代理，点击「批量导入」添加。';
    return;
  }
  for (const proxy of proxyList) {
    const row = list.insertRow();
    row.className = 'proxy-row';
    const protocolCell = row.insertCell();
    const protocol = document.createElement('span');
    protocol.className = 'proxy-protocol';
    protocol.textContent = proxy.protocol.toUpperCase();
    protocolCell.append(protocol);
    const address = row.insertCell();
    address.className = 'proxy-address';
    address.textContent = proxy.host.includes(':') ? `[${proxy.host}]:${proxy.port}` : `${proxy.host}:${proxy.port}`;
    address.title = address.textContent;
    const auth = row.insertCell();
    auth.className = 'proxy-auth';
    auth.textContent = proxy.username ? `用户 ${proxy.username}${proxy.has_password ? ' · 密码已保存' : ''}` : '无需身份验证';
    auth.title = auth.textContent;
  }
}

function makeButton(text, className, handler) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `small-button ${className}`;
  button.textContent = text;
  button.addEventListener('click', handler);
  return button;
}

function totpNow() {
  return totpServerTime + performance.now() - totpClockTime;
}

function clearTotp() {
  totpGeneration += 1;
  totpController?.abort(); totpController = null;
  totpCodes.clear(); totpIds = []; totpNextFetch = 0; totpFailed = false;
  updateTotpCells();
}

function currentTotp(id) {
  const value = totpCodes.get(id);
  const now = totpNow();
  return value && now >= value.valid_from && now < value.valid_until ? value : null;
}

function updateTotpCells() {
  const now = totpNow();
  for (const [id, elements] of totpCells) {
    const value = currentTotp(id);
    const seconds = value ? Math.max(0, Math.ceil((value.valid_until - now) / 1000)) : 0;
    elements.code.textContent = value ? value.code.replace(/^(\d{3,4})(\d{3,4})$/, '$1 $2') : (totpFailed ? '暂不可用' : '更新中…');
    elements.code.disabled = !value;
    elements.code.title = value ? '点击复制验证码' : (totpFailed ? '获取失败，正在自动重试' : '正在获取当前验证码');
    elements.remaining.textContent = value ? `${seconds}s` : '—';
    elements.progress.hidden = !value;
    elements.progress.setAttribute('aria-valuemax', value?.period || 30);
    elements.progress.setAttribute('aria-valuenow', seconds);
    elements.progress.setAttribute('aria-valuetext', `剩余 ${seconds} 秒`);
    elements.fill.style.width = value ? `${Math.max(0, Math.min(100, (value.valid_until - now) / (value.period * 1000) * 100))}%` : '0%';
    elements.cell.classList.toggle('totp-expiring', !!value && seconds <= 5);
  }
}

function syncTotpRows() {
  const ids = visibleProfiles.filter(profile => profile.has_totp).map(profile => profile.id).sort();
  if (ids.join(',') !== totpIds.join(',')) {
    clearTotp();
    totpIds = ids;
  }
  updateTotpCells();
  if (authenticated && !document.hidden && totpIds.length && performance.now() >= totpNextFetch) refreshTotp();
}

async function refreshTotp() {
  if (totpController || !authenticated || document.hidden || !totpIds.length) return;
  const generation = totpGeneration;
  const ids = [...totpIds];
  const controller = new AbortController(); totpController = controller;
  const started = performance.now();
  const timeout = setTimeout(() => controller.abort(), 6000);
  try {
    const payload = await api('/api/totp/codes', { method: 'POST', body: JSON.stringify({ profile_ids: ids }), signal: controller.signal });
    if (generation !== totpGeneration || !authenticated) return;
    if (!Number.isFinite(payload?.server_time) || !Array.isArray(payload.codes)) throw new Error('验证码暂不可用');
    const finished = performance.now();
    totpServerTime = payload.server_time + (finished - started) / 2;
    totpClockTime = finished;
    totpCodes.clear();
    for (const value of payload.codes) {
      if (ids.includes(value.profile_id) && /^\d{6}(\d{2})?$/.test(value.code)
        && Number.isFinite(value.period) && value.period >= 15 && value.period <= 120
        && Number.isFinite(value.valid_from) && Number.isFinite(value.valid_until)
        && value.valid_until - value.valid_from === value.period * 1000) totpCodes.set(value.profile_id, value);
    }
    totpFailed = false;
    // Recheck access periodically, and refresh exactly when the current time step ends.
    const remaining = [...totpCodes.values()].map(value => value.valid_until - totpNow());
    totpNextFetch = finished + Math.max(250, Math.min(5000, ...remaining));
  } catch (error) {
    if (generation !== totpGeneration) return;
    totpCodes.clear(); totpFailed = true;
    totpNextFetch = performance.now() + 5000;
  } finally {
    clearTimeout(timeout);
    if (generation === totpGeneration) { totpController = null; updateTotpCells(); }
  }
}

async function copyTotp(profile) {
  const value = currentTotp(profile.id);
  if (!value) { updateTotpCells(); refreshTotp(); return; }
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value.code);
    else {
      const text = document.createElement('textarea'); text.value = value.code; text.className = 'clipboard-buffer';
      document.body.append(text); text.select();
      try { if (!document.execCommand('copy')) throw new Error('copy failed'); } finally { text.remove(); }
    }
    messageEl.textContent = `已复制 ${profile.name} 的验证码。`;
  } catch { messageEl.textContent = '无法自动复制，请选中验证码后手动复制。'; }
}

function addTotpCell(row, profile) {
  const cell = row.insertCell(); cell.className = 'totp-cell';
  if (!profile.has_totp) { const empty = document.createElement('span'); empty.className = 'totp-unset'; empty.textContent = '未设置'; cell.append(empty); return; }
  const line = document.createElement('div'); line.className = 'totp-line';
  const code = document.createElement('button'); code.type = 'button'; code.className = 'totp-code';
  code.setAttribute('aria-label', `复制 ${profile.name} 的 2FA 验证码`);
  code.addEventListener('click', () => copyTotp(profile));
  const remaining = document.createElement('span'); remaining.className = 'totp-remaining'; remaining.setAttribute('aria-hidden', 'true');
  const progress = document.createElement('div'); progress.className = 'totp-progress'; progress.setAttribute('role', 'progressbar');
  progress.setAttribute('aria-label', `${profile.name} 的验证码有效时间`); progress.setAttribute('aria-valuemin', '0');
  const fill = document.createElement('span'); progress.append(fill);
  line.append(code, remaining); cell.append(line, progress);
  totpCells.set(profile.id, { cell, code, remaining, progress, fill });
}

function renderProfiles(profiles = profileList) {
  profileList = profiles;
  document.querySelector('#total-count').textContent = profiles.length;
  document.querySelector('#running-count').textContent = profiles.filter(item => item.status === 'running').length;
  document.querySelector('#list-count').textContent = profiles.length;
  document.querySelector('#nav-count').textContent = profiles.length;
  const query = document.querySelector('#profile-search').value.trim().toLocaleLowerCase();
  const state = document.querySelector('#status-filter').value;
  const previousTag = $('#tag-filter').value;
  const tags = [...new Set(profiles.flatMap(profile => profile.tags || []))].sort();
  $('#tag-filter').replaceChildren(new Option('全部标签', ''), ...tags.map(tag => new Option(tag, tag)));
  $('#tag-filter').value = tags.includes(previousTag) ? previousTag : '';
  const tagFilter = $('#tag-filter').value;
  const validIds = new Set(profiles.filter(profile => profile.can_manage).map(profile => profile.id));
  for (const id of selectedProfiles) if (!validIds.has(id)) selectedProfiles.delete(id);
  const filtered = profiles.filter(profile => {
    const matchesState = state === 'all' || profile.status === state;
    const searchable = `${profile.name} ${profile.id} ${profile.proxy_display || ''} ${profile.kernel_name || ''} ${(profile.tags || []).join(' ')} ${profile.notes || ''} ${(profile.assigned_users || []).map(user => user.name).join(' ')}`.toLocaleLowerCase();
    return matchesState && (!tagFilter || (profile.tags || []).includes(tagFilter)) && searchable.includes(query);
  });
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  profilesPage = Math.min(profilesPage, pages);
  const offset = (profilesPage - 1) * pageSize;
  const visible = filtered.slice(offset, offset + pageSize);
  visibleProfiles = visible;
  updateSelection();
  document.querySelector('#page-summary').textContent = filtered.length
    ? `第 ${offset + 1}–${offset + visible.length} 条 · 共 ${filtered.length} 条${filtered.length !== profiles.length ? `（全部 ${profiles.length} 条）` : ''}`
    : '共 0 条';
  document.querySelector('#page-number').textContent = `${profilesPage} / ${pages}`;
  document.querySelector('#page-prev').disabled = profilesPage === 1;
  document.querySelector('#page-next').disabled = profilesPage === pages;
  profilesEl.replaceChildren();
  totpCells.clear();
  if (!visible.length) {
    const row = profilesEl.insertRow();
    const empty = row.insertCell();
    empty.colSpan = canManage() ? 8 : 7;
    empty.className = 'empty';
    empty.textContent = profiles.length ? '没有匹配的环境，请调整搜索或状态筛选。' : (canManage() ? '还没有浏览器环境，点击右上角创建一个。' : '暂无分配给你的环境，请联系团队管理员。');
    syncTotpRows(); return;
  }
  visible.forEach((profile, index) => {
    const running = profile.status === 'running';
    const active = ['running', 'downloading', 'starting'].includes(profile.status);
    const row = profilesEl.insertRow();
    row.className = 'profile-row';
    if (canManage()) {
      const cell = row.insertCell(); cell.className = 'select-cell';
      const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = selectedProfiles.has(profile.id);
      checkbox.setAttribute('aria-label', `选择环境 ${profile.name}`);
      checkbox.addEventListener('change', () => { checkbox.checked ? selectedProfiles.add(profile.id) : selectedProfiles.delete(profile.id); updateSelection(); });
      cell.append(checkbox);
    }
    const number = row.insertCell();
    number.className = 'row-number';
    number.textContent = offset + index + 1;
    const name = row.insertCell();
    name.className = 'name-cell';
    const nameLine = document.createElement('div'); nameLine.className = 'name-line';
    const nameText = document.createElement('span'); nameText.textContent = profile.name; nameLine.append(nameText);
    if (profile.notes) { const note = document.createElement('button'); note.type = 'button'; note.className = 'note-indicator'; note.textContent = '▤'; note.title = profile.notes; note.setAttribute('aria-label', `查看 ${profile.name} 的备注`); note.addEventListener('click', () => openMetadata(profile)); nameLine.append(note); }
    name.append(nameLine);
    if (profile.tags?.length) { const tags = document.createElement('div'); tags.className = 'profile-tags'; for (const tag of profile.tags) { const badge = document.createElement('span'); badge.className = 'tag-badge'; badge.textContent = tag; tags.append(badge); } tags.title = profile.tags.join(' · '); name.append(tags); }
    name.title = `${profile.name}${profile.kernel_name ? `\n内核：${profile.kernel_name}` : ''}`;
    const statusCell = row.insertCell();
    statusCell.className = 'status-cell';
    const status = document.createElement('span');
    status.className = 'profile-status';
    if (running) status.classList.add('running');
    if (['downloading', 'starting'].includes(profile.status)) status.classList.add('pending');
    if (profile.status === 'error') status.classList.add('error');
    status.textContent = { running: '运行中', stopped: '已停止', error: '已中断', downloading: '下载内核', starting: '启动中' }[profile.status] || profile.status;
    if (profile.status === 'downloading') {
      const progress = Number(profile.kernel_progress);
      status.textContent = { extracting: '解压中', verifying: '验证中' }[profile.kernel_state]
        || `下载 ${Number.isFinite(progress) ? Math.round(progress) + '%' : '中'}`;
    }
    if (profile.last_error) {
      status.title = profile.last_error;
      status.setAttribute('aria-label', `${status.textContent}，${profile.last_error}`);
      status.textContent += ' ⓘ';
      status.tabIndex = 0;
    }
    statusCell.append(status);
    const proxy = row.insertCell();
    proxy.className = 'proxy-cell';
    proxy.textContent = profile.proxy_display || (profile.proxy_id ? '已绑定代理' : '服务器网络（直连）');
    proxy.title = proxy.textContent;
    addTotpCell(row, profile);
    const assigned = row.insertCell(); assigned.className = 'assigned-cell';
    assigned.textContent = (profile.assigned_users || []).map(user => user.name).join('、') || '未分配'; assigned.title = assigned.textContent;
    const actionsCell = row.insertCell();
    actionsCell.className = 'actions-cell';
    const actions = document.createElement('div');
    actions.className = 'row-actions';
    if (running && profile.view_url) {
      const view = document.createElement('a');
      view.href = profile.view_url;
      view.target = '_blank';
      view.rel = 'noopener noreferrer';
      view.className = 'small-button open';
      view.textContent = '打开 ↗';
      actions.append(view);
    }
    const manage = !!profile.can_manage && canManage();
    const bind = makeButton(manage ? '配置' : '标签/备注', '', () => manage ? openBind(profile) : openMetadata(profile));
    bind.disabled = busyIds.has(profile.id);
    const toggle = makeButton(active ? '停止' : '启动', '', () => profileAction(profile, active ? 'stop' : 'start'));
    toggle.disabled = busyIds.has(profile.id);
    if (toggle.disabled) toggle.textContent = '处理中…';
    const remove = makeButton('删除', '', () => profileAction(profile, 'delete'));
    remove.disabled = active || busyIds.has(profile.id);
    if (active) remove.title = '请先停止环境';
    actions.append(bind, toggle);
    if (manage) actions.append(remove);
    actionsCell.append(actions);
  });
  syncTotpRows();
}

function resetProfilePage() {
  profilesPage = 1;
  renderProfiles();
  profilesEl.closest('.table-scroll')?.scrollTo({ top: 0 });
}

document.querySelector('#profile-search').addEventListener('input', resetProfilePage);
document.querySelector('#status-filter').addEventListener('change', resetProfilePage);
document.querySelector('#page-size').addEventListener('change', event => {
  pageSize = Number(event.target.value);
  resetProfilePage();
});
document.querySelector('#page-prev').addEventListener('click', () => {
  profilesPage = Math.max(1, profilesPage - 1);
  renderProfiles();
  profilesEl.closest('.table-scroll')?.scrollTo({ top: 0 });
});
document.querySelector('#page-next').addEventListener('click', () => {
  profilesPage += 1;
  renderProfiles();
  profilesEl.closest('.table-scroll')?.scrollTo({ top: 0 });
});

async function loadProfiles() {
  const version = sessionVersion;
  const request = ++profileRequest;
  loadingProfiles = true;
  try {
    const profiles = await api('/api/profiles');
    if (authenticated && version === sessionVersion && request === profileRequest) renderProfiles(profiles);
  } catch (error) {
    if (version === sessionVersion && request === profileRequest) { clearTotp(); totpFailed = true; updateTotpCells(); }
    showError(messageEl, error);
  } finally {
    if (request === profileRequest) loadingProfiles = false;
  }
}

async function loadProxies() {
  const version = sessionVersion;
  const proxies = await api('/api/proxies');
  if (!authenticated || version !== sessionVersion) return;
  proxyList = proxies;
  renderProxies();
}

async function loadKernels() {
  const version = sessionVersion;
  const kernels = await api('/api/kernels');
  if (!authenticated || version !== sessionVersion) return;
  kernelList = kernels;
  for (const [dialog, prefix] of [[createDialog, 'profile'], [bindDialog, 'bind']]) {
    if (!dialog.open) continue;
    const select = document.getElementById(`${prefix}-kernel`);
    updateKernelSelect(select, select.value);
    updateKernelHelp(prefix);
  }
}

async function refresh() {
  if (!authenticated) return;
  try { if (!await syncSession()) return; } catch (error) { showError(messageEl, error); return; }
  const jobs = [loadProfiles()];
  if (canManage()) jobs.push(loadKernels().catch(error => showError(messageEl, error)), loadProxies().catch(error => showError(proxyNotice, error)));
  await Promise.all(jobs);
}

function updateSelection() {
  const ids = visibleProfiles.filter(profile => profile.can_manage).map(profile => profile.id);
  const checked = ids.filter(id => selectedProfiles.has(id)).length;
  $('#select-page').checked = !!ids.length && checked === ids.length;
  $('#select-page').indeterminate = checked > 0 && checked < ids.length;
  $('#select-page').disabled = !ids.length;
  $('#selected-count').textContent = selectedProfiles.size;
  $('#batch-assign').disabled = !selectedProfiles.size;
}

async function profileAction(profile, action) {
  if (action === 'delete' && !window.confirm(`删除环境“${profile.name}”？环境及其浏览器数据将被删除。`)) return;
  busyIds.add(profile.id);
  messageEl.textContent = '';
  renderProfiles();
  try {
    const base = `/api/profiles/${encodeURIComponent(profile.id)}`;
    await api(action === 'delete' ? base : `${base}/${action}`, { method: action === 'delete' ? 'DELETE' : 'POST' });
  } catch (error) {
    showError(messageEl, error);
  } finally {
    busyIds.delete(profile.id);
    if (authenticated) await loadProfiles();
  }
}

async function openBind(profile) {
  document.querySelector('#bind-error').textContent = '';
  $('#bind-totp-secret').value = ''; $('#bind-clear-totp').checked = false;
  $('#bind-totp-secret').disabled = false;
  boundProfile = profile;
  document.querySelector('#bind-profile-name').textContent = profile.name;
  try {
    if (!canManage()) return openMetadata(profile);
    await Promise.all([loadProxies(), loadKernels(), loadMembers()]);
    if (!authenticated) return;
    $('#bind-manager-fields').hidden = false; $('#bind-manager-fields').disabled = false;
    const active = ['running', 'downloading', 'starting'].includes(profile.status);
    $('#bind-engine-fields').disabled = active;
    $('#bind-running-help').hidden = !active;
    $('#bind-totp-status').textContent = profile.has_totp ? '已设置' : '未设置';
    $('#bind-totp-remove-field').hidden = !profile.has_totp;
    $('#bind-assignment-field').hidden = false;
    $('#bind-name').value = profile.name;
    $('#bind-tags').value = (profile.tags || []).join(', ');
    $('#bind-notes').value = profile.notes || '';
    renderMemberPicker('bind-assignees', profile.assigned_user_ids || []);
    updateProxySelect(document.querySelector('#bind-proxy'), profile.proxy_id);
    if (profile.proxy_needs_configuration) {
      const legacy = new Option('旧代理配置无效，请重新选择', '__legacy__', true, true);
      legacy.disabled = true;
      document.querySelector('#bind-proxy').add(legacy);
      document.querySelector('#bind-proxy').value = '__legacy__';
    }
    updateKernelSelect(document.querySelector('#bind-kernel'), profile.kernel_id || 'chromium-system');
    const fingerprint = profile.fingerprint || {};
    document.querySelector('#bind-seed').value = fingerprint.seed ?? '';
    document.querySelector('#bind-platform').value = fingerprint.platform || 'linux';
    document.querySelector('#bind-language').value = fingerprint.language || 'en-US';
    document.querySelector('#bind-timezone').value = fingerprint.timezone || 'UTC';
    document.querySelector('#bind-hardware').value = fingerprint.hardware_concurrency ?? 8;
    document.querySelector('#bind-width').value = fingerprint.width ?? 1365;
    document.querySelector('#bind-height').value = fingerprint.height ?? 768;
    updateKernelHelp('bind');
    bindDialog.showModal();
  } catch (error) {
    showError(messageEl, error);
  }
}

function openMetadata(profile) {
  boundProfile = profile;
  $('#bind-error').textContent = '';
  $('#bind-profile-name').textContent = profile.name;
  $('#bind-manager-fields').hidden = true; $('#bind-manager-fields').disabled = true;
  $('#bind-totp-secret').value = ''; $('#bind-clear-totp').checked = false;
  $('#bind-assignment-field').hidden = true;
  $('#bind-tags').value = (profile.tags || []).join(', ');
  $('#bind-notes').value = profile.notes || '';
  bindDialog.showModal();
}

const examples = {
  host_port: 'proxy.example.com:8080',
  host_port_auth: 'proxy.example.com:8080:user:password',
  auth_host_port: 'user:password@proxy.example.com:8080',
};

function updateCreateProxyHelp() {
  const protocol = $('#profile-inline-protocol').value;
  const format = $('#profile-inline-format').value;
  let example = format === 'url' ? `${protocol}://user:password@proxy.example.com:8080` : examples[format];
  if (protocol === 'socks4') {
    if (format === 'url') example = 'socks4://user@proxy.example.com:1080';
    if (format === 'host_port_auth') example = 'proxy.example.com:1080:user:';
    if (format === 'auth_host_port') example = 'user:@proxy.example.com:1080';
  }
  $('#profile-inline-text').placeholder = example;
  let help = '仅填写一条代理，IPv6 地址请加方括号。';
  if (format === 'url') help += ' URL 协议需与所选协议一致，凭据中的特殊字符需百分号编码。';
  if (protocol === 'socks4') help += ' SOCKS4 只支持用户名，密码必须留空。';
  if (protocol === 'https') help += ' HTTPS 表示到代理服务器的连接使用 TLS。';
  $('#profile-inline-help').textContent = help;
}

function updateCreateNetwork(clearCredentials = false) {
  const mode = $('#profile-network-mode').value;
  const changed = mode !== createNetworkMode;
  createNetworkMode = mode;
  const existing = mode === 'existing';
  const inline = mode === 'inline';
  $('#create-existing-proxy').hidden = !existing;
  $('#create-existing-proxy').disabled = !existing;
  $('#profile-proxy').required = existing;
  $('#create-inline-proxy').hidden = !inline;
  $('#create-inline-proxy').disabled = !inline;
  $('#profile-inline-text').required = inline;
  if (clearCredentials && changed) $('#profile-inline-text').value = '';
  $('#profile-existing-help').textContent = proxyList.length ? '从当前团队的代理中选择。' : '当前团队还没有代理，可切换到「直接填写代理」。';
  updateCreateProxyHelp();
}

function createNetworkPayload() {
  const mode = $('#profile-network-mode').value;
  if (mode === 'inline') {
    const text = $('#profile-inline-text').value.trim();
    if (!text || /[\r\n]/.test(text)) throw new Error('请填写一条代理地址；多个代理请到代理管理中批量导入。');
    return { inline_proxy: { text, protocol: $('#profile-inline-protocol').value, format: $('#profile-inline-format').value } };
  }
  if (mode === 'existing') {
    const proxyId = $('#profile-proxy').value;
    if (!proxyId) throw new Error('请选择已有代理，或切换到其他访问网络方式。');
    return { proxy_id: proxyId };
  }
  return { proxy_id: null };
}

function updateImportHelp() {
  const protocol = document.querySelector('#proxy-protocol').value;
  const format = document.querySelector('#proxy-format').value;
  let example = format === 'url' ? `${protocol}://user:password@proxy.example.com:8080` : examples[format];
  if (protocol === 'socks4' && format === 'url') example = 'socks4://user@proxy.example.com:1080';
  if (protocol === 'socks4' && format === 'host_port_auth') example = 'proxy.example.com:1080:user:';
  if (protocol === 'socks4' && format === 'auth_host_port') example = 'user:@proxy.example.com:1080';
  document.querySelector('#proxy-text').placeholder = example;
  document.querySelector('#format-help').textContent = `示例 ${example}\nIPv6 地址请加方括号。URL 中用户名和密码的特殊字符需百分号编码。`;
  let help = '所选协议适用于本次导入的全部代理，完整 URL 中的协议也需与之保持一致。';
  if (protocol === 'https') help = 'HTTPS 表示到代理服务器的连接使用 TLS。代理 URL 中的协议需与所选协议一致。';
  if (protocol === 'socks4') help = 'SOCKS4 支持用户名（USERID），密码必须留空。';
  document.querySelector('#protocol-help').textContent = help;
}

for (const button of document.querySelectorAll('[data-close]')) {
  button.addEventListener('click', () => document.getElementById(button.dataset.close).close());
}
importDialog.addEventListener('close', () => importForm.reset());
createDialog.addEventListener('close', () => { createForm.reset(); updateCreateNetwork(true); });
bindDialog.addEventListener('close', () => {
  $('#bind-totp-secret').value = ''; $('#bind-clear-totp').checked = false; boundProfile = null;
});
$('#bind-clear-totp').addEventListener('change', event => {
  $('#bind-totp-secret').disabled = event.target.checked;
  if (event.target.checked) $('#bind-totp-secret').value = '';
});

document.querySelector('#new-profile').addEventListener('click', async () => {
  createForm.reset();
  updateCreateNetwork(true);
  document.querySelector('#form-error').textContent = '';
  try {
    if (!canManage()) return;
    await Promise.all([loadProxies(), loadKernels(), loadMembers()]);
    if (!authenticated) return;
    renderMemberPicker('create-assignees');
    updateProxySelect(document.querySelector('#profile-proxy'));
    updateCreateNetwork();
    updateKernelSelect(document.querySelector('#profile-kernel'));
    updateKernelHelp('profile');
    createDialog.showModal();
  } catch (error) {
    showError(messageEl, error);
  }
});
$('#profile-network-mode').addEventListener('change', () => updateCreateNetwork(true));
$('#profile-network-mode').addEventListener('input', () => updateCreateNetwork(true));
$('#profile-inline-protocol').addEventListener('change', updateCreateProxyHelp);
$('#profile-inline-format').addEventListener('change', updateCreateProxyHelp);
document.querySelector('#profile-kernel').addEventListener('change', () => updateKernelHelp('profile'));
document.querySelector('#bind-kernel').addEventListener('change', () => updateKernelHelp('bind'));
document.querySelector('#refresh').addEventListener('click', () => {
  messageEl.textContent = '';
  proxyNotice.textContent = '';
  refresh();
});
document.querySelector('#import-proxies').addEventListener('click', () => {
  importForm.reset();
  document.querySelector('#import-error').textContent = '';
  updateImportHelp();
  importDialog.showModal();
});
document.querySelector('#proxy-protocol').addEventListener('change', updateImportHelp);
document.querySelector('#proxy-format').addEventListener('change', updateImportHelp);
document.querySelector('#proxy-file').addEventListener('change', async event => {
  const file = event.target.files[0];
  if (!file) return;
  const errorEl = document.querySelector('#import-error');
  errorEl.textContent = '';
  if (file.size > 1000000) {
    errorEl.textContent = '文件超过 1 MB，请分批导入。';
    event.target.value = '';
    return;
  }
  try {
    const text = await file.text();
    if (importDialog.open && event.target.files[0] === file) document.querySelector('#proxy-text').value = text;
  } catch {
    errorEl.textContent = '读取文件失败，请重新选择或直接粘贴内容。';
  }
});

createForm.addEventListener('submit', async event => {
  event.preventDefault();
  const submit = document.querySelector('#create-submit');
  submit.disabled = true;
  document.querySelector('#form-error').textContent = '';
  try {
    await api('/api/profiles', { method: 'POST', body: JSON.stringify({
      name: document.querySelector('#profile-name').value.trim(),
      tags: parseTags($('#profile-tags').value), notes: $('#profile-notes').value,
      totp_secret: $('#profile-totp-secret').value.trim(),
      assigned_user_ids: selectedMembers('create-assignees'),
      ...createNetworkPayload(),
      kernel_id: document.querySelector('#profile-kernel').value,
      ...(selectedKernel('profile-kernel')?.engine === 'fingerprint-chromium' ? {
        fingerprint: {
          language: document.querySelector('#profile-language').value.trim(),
          timezone: document.querySelector('#profile-timezone').value.trim(),
        },
      } : {}),
    }) });
    createDialog.close();
    await Promise.all([loadProfiles(), loadProxies().catch(error => showError(proxyNotice, error))]);
  } catch (error) {
    const reasons = [...new Set((error.lines || []).map(item => item.reason).filter(reason => typeof reason === 'string' && !error.message.includes(reason)))].slice(0, 3);
    showError($('#form-error'), { stale: error.stale, message: [error.message, ...reasons].join(' ') });
  } finally {
    submit.disabled = false;
  }
});
document.querySelector('#bind-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!boundProfile) return;
  const submit = $('#bind-submit'); submit.disabled = true; $('#bind-error').textContent = '';
  const profile = boundProfile;
  try {
    const metadata = { tags: parseTags($('#bind-tags').value), notes: $('#bind-notes').value };
    const manage = canManage() && profile.can_manage && !$('#bind-manager-fields').hidden;
    let body = metadata;
    if (manage) {
      body = { ...metadata, name: $('#bind-name').value.trim(), assigned_user_ids: selectedMembers('bind-assignees'),
        totp_secret: $('#bind-totp-secret').value.trim(), clear_totp: $('#bind-clear-totp').checked };
      if (!$('#bind-engine-fields').disabled) {
        const proxyId = $('#bind-proxy').value || null;
        if (proxyId !== '__legacy__' && proxyId !== (profile.proxy_id || null)) body.proxy_id = proxyId;
        if ($('#bind-kernel').value !== profile.kernel_id) body.kernel_id = $('#bind-kernel').value;
        if (selectedKernel('bind-kernel')?.engine === 'fingerprint-chromium') {
          const fingerprint = { ...profile.fingerprint, platform: $('#bind-platform').value, language: $('#bind-language').value.trim(),
            timezone: $('#bind-timezone').value.trim(), hardware_concurrency: Number($('#bind-hardware').value), width: Number($('#bind-width').value), height: Number($('#bind-height').value) };
          if (Object.entries(fingerprint).some(([key, value]) => profile.fingerprint?.[key] !== value)) body.fingerprint = fingerprint;
        }
      }
    }
    await api(`/api/profiles/${encodeURIComponent(profile.id)}/${manage ? 'settings' : 'metadata'}`, { method: 'PATCH', body: JSON.stringify(body) });
    clearTotp();
    bindDialog.close(); await loadProfiles();
  } catch (error) { showError($('#bind-error'), error); }
  finally { submit.disabled = false; }
});
importForm.addEventListener('submit', async event => {
  event.preventDefault();
  const submit = document.querySelector('#import-submit');
  const errorEl = document.querySelector('#import-error');
  submit.disabled = true;
  errorEl.textContent = '';
  try {
    const result = await api('/api/proxies/import', { method: 'POST', body: JSON.stringify({
      protocol: document.querySelector('#proxy-protocol').value,
      format: document.querySelector('#proxy-format').value,
      text: document.querySelector('#proxy-text').value,
    }) });
    importForm.reset();
    importDialog.close();
    proxyNotice.classList.remove('error');
    proxyNotice.textContent = `已导入 ${result.imported} 个代理，跳过 ${result.skipped} 个重复项。可以在环境中点击「配置」绑定代理。`;
    await loadProxies();
  } catch (error) {
    const lines = Array.isArray(error.lines) ? error.lines : [];
    if (!error.stale) errorEl.textContent = [error.message, ...lines.map(item => `第 ${item.line} 行：${item.reason}`)].join('\n');
  } finally {
    submit.disabled = false;
  }
});

$('#tag-filter').addEventListener('change', resetProfilePage);
$('#select-page').addEventListener('change', event => {
  for (const profile of visibleProfiles) if (profile.can_manage) {
    event.target.checked ? selectedProfiles.add(profile.id) : selectedProfiles.delete(profile.id);
  }
  renderProfiles();
});
$('#batch-assign').addEventListener('click', async () => {
  if (!canManage() || !selectedProfiles.size) return;
  try {
    await loadMembers();
    renderMemberPicker('batch-assignees');
    $('#assignment-summary').textContent = `已选择 ${selectedProfiles.size} 个环境`;
    $('#assign-error').textContent = '';
    $('#assign-dialog').showModal();
  } catch (error) { showError(messageEl, error); }
});
$('#assign-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = $('#assign-submit'); submit.disabled = true;
  try {
    await api('/api/profiles/assign', { method: 'POST', body: JSON.stringify({ profile_ids: [...selectedProfiles], user_ids: selectedMembers('batch-assignees') }) });
    $('#assign-dialog').close(); selectedProfiles.clear(); await loadProfiles();
  } catch (error) { showError($('#assign-error'), error); }
  finally { submit.disabled = false; }
});

function renderTeamMembers() {
  const list = $('#team-members'); list.replaceChildren();
  const viewerRole = currentTeam()?.role;
  for (const member of memberList) {
    const row = list.insertRow();
    const identity = row.insertCell();
    const name = document.createElement('strong'); name.textContent = member.name;
    const email = document.createElement('small'); email.textContent = member.email;
    identity.append(name, email);
    const role = row.insertCell(); role.textContent = roleLabels[member.role] || member.role;
    const actions = row.insertCell();
    const mutable = member.id !== sessionData.user.id && member.role !== 'owner'
      && (viewerRole === 'owner' || (viewerRole === 'admin' && member.role === 'member'));
    if (mutable) {
      if (viewerRole === 'owner') actions.append(makeButton(member.role === 'admin' ? '设为成员' : '设为管理员', '',
        () => changeMember(member, member.role === 'admin' ? 'member' : 'admin')));
      actions.append(makeButton('移除', 'danger', () => removeMember(member)));
    } else if (member.id === sessionData.user.id) actions.textContent = '我';
    else actions.textContent = '—';
  }
}

function renderInvitations() {
  const list = $('#team-invitations'); list.replaceChildren();
  const active = invitationList.filter(invite => invite.status === 'pending');
  if (!active.length) { const empty = document.createElement('p'); empty.className = 'field-help'; empty.textContent = '暂无待接受邀请。'; list.append(empty); }
  for (const invite of active) {
    const row = document.createElement('div'); row.className = 'invitation-row';
    const text = document.createElement('div');
    const email = document.createElement('strong'); email.textContent = invite.email;
    const detail = document.createElement('small');
    const raw = invite.expires_at;
    const date = new Date(typeof raw === 'number' ? raw * (raw < 1e12 ? 1000 : 1) : raw);
    detail.textContent = `${roleLabels[invite.role] || invite.role} · ${Number.isNaN(date.getTime()) ? '7 天内有效' : date.toLocaleDateString() + ' 到期'}`;
    text.append(email, detail); row.append(text);
    if (currentTeam()?.role === 'owner' || invite.role === 'member') row.append(makeButton('撤销', '', async () => {
      try { await api(`${teamPath()}/invitations/${encodeURIComponent(invite.id)}`, { method: 'DELETE' }); await reloadTeamDetails(); }
      catch (error) { showError($('#team-error'), error); }
    }));
    list.append(row);
  }
}

async function reloadTeamDetails() {
  const jobs = [loadMembers()];
  if (canManage()) jobs.push(api(`${teamPath()}/invitations`).then(result => { invitationList = result; }));
  await Promise.all(jobs);
  $('#team-dialog-name').textContent = `${currentTeam()?.name || '团队'} · 成员`;
  $('#team-role-description').textContent = `${roleLabels[currentTeam()?.role] || ''} · 管理员可管理全部环境，成员只访问分配给自己的环境。`;
  renderTeamMembers(); renderInvitations();
}

async function changeMember(member, role) {
  try {
    await api(`${teamPath()}/members/${encodeURIComponent(member.id)}`, { method: 'PATCH', body: JSON.stringify({ role }) });
    await reloadTeamDetails(); await loadProfiles();
  } catch (error) { showError($('#team-error'), error); }
}

async function removeMember(member) {
  if (!window.confirm(`将“${member.name}”移出当前团队？该成员将立即失去此团队的环境访问权限。`)) return;
  try {
    await api(`${teamPath()}/members/${encodeURIComponent(member.id)}`, { method: 'DELETE' });
    await reloadTeamDetails(); await loadProfiles();
  } catch (error) { showError($('#team-error'), error); }
}

$('#team-select').addEventListener('change', async event => {
  const previous = activeTeamId;
  event.target.disabled = true; switchingTeam = true;
  try {
    const payload = await api(`/api/teams/${encodeURIComponent(event.target.value)}/select`, { method: 'POST' });
    applySession(payload, true); switchingTeam = false; await refresh();
  } catch (error) { event.target.value = activeTeamId || previous; showError(messageEl, error); }
  finally { switchingTeam = false; event.target.disabled = !authenticated; }
});
$('#team-settings').addEventListener('click', async () => {
  if (!authenticated) return;
  try {
    if (!await syncSession()) return;
    $('#team-error').textContent = '';
    $('#invite-result').hidden = true; $('#invite-link').value = ''; $('#copy-invite-status').textContent = '';
    $('#invite-form').reset(); renderAccount();
    await reloadTeamDetails(); $('#team-dialog').showModal();
  } catch (error) { showError(messageEl, error); }
});
$('#new-team').addEventListener('click', () => {
  $('#new-team-form').reset(); $('#new-team-error').textContent = ''; $('#new-team-dialog').showModal();
});
$('#new-team-form').addEventListener('submit', async event => {
  event.preventDefault(); const submit = $('#new-team-submit'); submit.disabled = true; switchingTeam = true;
  try {
    const payload = await api('/api/teams', { method: 'POST', body: JSON.stringify({ name: $('#team-name').value.trim() }) });
    applySession(payload, true); switchingTeam = false; $('#new-team-dialog').close(); await refresh();
  } catch (error) { showError($('#new-team-error'), error); }
  finally { switchingTeam = false; submit.disabled = false; }
});
$('#invite-form').addEventListener('submit', async event => {
  event.preventDefault(); const submit = $('#invite-submit'); submit.disabled = true;
  $('#team-error').textContent = '';
  try {
    const invitation = await api(`${teamPath()}/invitations`, { method: 'POST', body: JSON.stringify({ email: $('#invite-email').value.trim(), role: $('#invite-role').value }) });
    $('#invite-link').value = `${location.origin}/#invite=${encodeURIComponent(invitation.token)}`;
    $('#invite-result').hidden = false; $('#copy-invite-status').textContent = '';
    await reloadTeamDetails();
  } catch (error) { showError($('#team-error'), error); }
  finally { submit.disabled = false; }
});
$('#copy-invite').addEventListener('click', async () => {
  const input = $('#invite-link');
  try { await navigator.clipboard.writeText(input.value); $('#copy-invite-status').textContent = '链接已复制，请发送给受邀成员。'; }
  catch { input.focus(); input.select(); $('#copy-invite-status').textContent = '请按 Ctrl+C 或 ⌘C 复制已选中的链接。'; }
});

function openJoinTeam() {
  $('#join-error').textContent = ''; $('#join-token').value = pendingInvite;
  $('#join-team-dialog').showModal();
}
function invitationToken(value) {
  const trimmed = value.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    try { return new URLSearchParams(new URL(trimmed).hash.slice(1)).get('invite') || ''; }
    catch { return ''; }
  }
  return trimmed;
}
$('#join-team').addEventListener('click', openJoinTeam);
$('#join-team-form').addEventListener('submit', async event => {
  event.preventDefault(); const submit = $('#join-submit'); submit.disabled = true; switchingTeam = true;
  try {
    const token = invitationToken($('#join-token').value);
    if (!token) throw new Error('请输入有效的邀请链接或令牌。');
    const payload = await api('/api/invitations/accept', { method: 'POST', body: JSON.stringify({ token }) });
    pendingInvite = ''; history.replaceState(null, '', location.pathname + location.search);
    applySession(payload, true); switchingTeam = false; $('#join-team-dialog').close(); await refresh();
  } catch (error) { showError($('#join-error'), error); }
  finally { switchingTeam = false; submit.disabled = false; }
});
window.addEventListener('hashchange', () => {
  const token = new URLSearchParams(location.hash.slice(1)).get('invite');
  if (!token) return;
  pendingInvite = token;
  if (authenticated) openJoinTeam(); else $('#auth-invite-notice').hidden = false;
});

$('#auth-login').addEventListener('click', () => setAuthMode('login'));
$('#auth-register').addEventListener('click', () => setAuthMode('register'));
loginForm.addEventListener('submit', async event => {
  event.preventDefault(); const submit = $('#login-submit'); submit.disabled = true; $('#login-error').textContent = '';
  try {
    const body = { email: $('#login-email').value.trim(), password: $('#login-password').value };
    if (authMode === 'register') {
      body.name = $('#register-name').value.trim();
      if (setupRequired) body.setup_key = $('#setup-key').value;
    }
    const payload = await api(authMode === 'register' ? '/api/register' : '/api/login', { method: 'POST', body: JSON.stringify(body) });
    applySession(payload, true); loginForm.reset(); loginDialog.close(); await refresh();
    if (pendingInvite) openJoinTeam();
  } catch (error) { showError($('#login-error'), error); }
  finally { submit.disabled = false; }
});
$('#logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); loginForm.reset(); authMode = 'login'; showLogin(); }
  catch (error) { showError(messageEl, error); }
});

let polling = false;
setInterval(() => {
  // Native selects and restored form values can change without a change event.
  // Keep the visible, enabled fields aligned with the mode shown to the user.
  if (createDialog.open && $('#profile-network-mode').value !== createNetworkMode) updateCreateNetwork(true);
  updateTotpCells();
  if (authenticated && !document.hidden && performance.now() >= totpNextFetch) refreshTotp();
}, 250);
setInterval(async () => {
  if (!authenticated || document.hidden || loadingProfiles || busyIds.size || polling || switchingTeam) return;
  polling = true;
  try {
    if (!await syncSession()) return;
    await loadProfiles();
    if (canManage() && (createDialog.open || (bindDialog.open && !$('#bind-manager-fields').hidden))) await loadKernels();
  } catch (error) { showError(messageEl, error); }
  finally { polling = false; }
}, 5000);
document.addEventListener('visibilitychange', () => {
  // Resume with a fresh server time after tab suspension, and discard hidden codes.
  clearTotp();
  if (authenticated && !document.hidden && !loadingProfiles) refresh();
});
window.addEventListener('offline', () => { clearTotp(); totpFailed = true; updateTotpCells(); });
window.addEventListener('online', () => { if (authenticated && !document.hidden) refresh(); });
(async () => {
  try {
    const payload = await api('/api/session'); setupRequired = !!payload.setup_required;
    if (payload.authenticated) { applySession(payload, true); await refresh(); if (pendingInvite) openJoinTeam(); }
    else showLogin();
  } catch (error) { showLogin(); showError($('#login-error'), error); }
})();
