'use strict';

/* hushwire web UI - no build step, no dependencies. */

const TOKEN_KEY = 'hushwire.token';
const MODE_KEY = 'hushwire.mode';
const DUR_KEY = 'hushwire.duration';
const MAX_LOG_LINES = 600;

const $ = (sel, root = document) => root.querySelector(sel);

const state = {
  status: null,
  devices: [],
  blocks: [],
  selected: new Set(),
  filter: '',
  scanning: false,
  busy: false,
  es: null,
  cutSig: '',
  pollN: 0,
};

/* ---------- helpers ---------- */

const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function esc(v) {
  return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}

function fmtUptime(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function fmtDuration(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const mm = String(m).padStart(2, '0');
  const ss = String(s).padStart(2, '0');
  return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

function fmtTime(v) {
  const d = v ? new Date(v) : new Date();
  if (Number.isNaN(d.getTime())) return '--:--:--';
  return d.toLocaleTimeString([], { hour12: false });
}

function ipKey(ip) {
  const p = String(ip).split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isFinite(n))) return 0;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function fmtDate(v) {
  const d = v ? new Date(v) : null;
  if (!d || Number.isNaN(d.getTime())) return '-';
  return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function macKey(mac) {
  return String(mac || '').trim().toLowerCase();
}

function blockedMACs() {
  const set = new Set();
  for (const b of state.blocks) set.add(macKey(b.mac));
  return set;
}

let toastTimer = 0;

function toast(msg, kind) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast' + (kind ? ' ' + kind : '');
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3600);
}

/* ---------- token / fetch ---------- */

function token() {
  try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
}

function withToken(url) {
  const t = token();
  if (!t) return url;
  return url + (url.indexOf('?') === -1 ? '?' : '&') + 't=' + encodeURIComponent(t);
}

function showTokenBar() {
  const bar = $('#tokenBar');
  if (!bar.hidden) return;
  bar.hidden = false;
  const input = $('#tokenInput');
  input.value = token();
  input.focus();
}

async function api(path, opts) {
  const init = Object.assign({ credentials: 'same-origin' }, opts || {});
  if (init.body !== undefined && init.body !== null && !init.headers) {
    init.headers = { 'Content-Type': 'application/json' };
  }
  const res = await fetch(withToken(path), init);
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text.trim() }; }
  }
  if (res.status === 401) {
    showTokenBar();
    throw new Error('unauthorized - enter the access token');
  }
  if (!res.ok) {
    throw new Error((data && data.error) || `HTTP ${res.status}`);
  }
  return data;
}

/* ---------- rendering ---------- */

function setConn(text, kind) {
  const el = $('#connBadge');
  el.textContent = text;
  el.className = 'badge' + (kind ? ' ' + kind : '');
}

function renderStatus() {
  const s = state.status;
  if (!s) return;

  $('#ver').textContent = 'v' + s.version;

  const dot = $('#readyDot');
  dot.classList.toggle('ok', !!s.ready);
  dot.classList.toggle('bad', !s.ready);
  dot.title = s.ready
    ? 'gateway MAC resolved - poisoning possible'
    : 'gateway MAC unknown - cuts will fail';

  const chips = [
    ['iface', s.iface],
    ['self', s.selfIp],
    ['self mac', s.selfMac],
    ['gateway', s.gatewayIp],
    ['gw mac', s.gatewayMac || 'unknown'],
    ['subnet', s.cidr],
    ['re-poison', (s.intervalMs || 0) + ' ms'],
    ['uptime', fmtUptime(s.uptimeSec)],
  ];

  $('#strip').innerHTML = chips
    .map(([k, v]) => `<div class="chip"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`)
    .join('');
}

function activeCuts() {
  return (state.status && state.status.cuts) || [];
}

function matchesFilter(d) {
  const q = state.filter.trim().toLowerCase();
  if (!q) return true;
  return [d.ip, d.mac, d.vendor].some((v) => String(v || '').toLowerCase().includes(q));
}

function visibleDevices() {
  return state.devices.filter(matchesFilter);
}

function renderHosts() {
  const box = $('#hosts');
  const total = state.devices.length;
  const list = visibleDevices();

  $('#hostCount').textContent = state.filter.trim() && total ? `${list.length}/${total}` : String(total);
  $('#hostHead').hidden = !total;

  if (!total) {
    box.innerHTML = '<div class="empty">No hosts yet. Press Scan.</div>';
    renderSelection();
    return;
  }

  if (!list.length) {
    box.innerHTML = `<div class="empty">No host matches &ldquo;${esc(state.filter.trim())}&rdquo;.</div>`;
    renderSelection();
    return;
  }

  const cutSet = new Set(activeCuts().map((c) => c.ip));
  const blocked = blockedMACs();
  const gwIp = (state.status && state.status.gatewayIp) || '';
  const selfIp = (state.status && state.status.selfIp) || '';

  box.innerHTML = list
    .map((d) => {
      const sel = state.selected.has(d.ip);
      const cut = cutSet.has(d.ip);
      const isBlocked = blocked.has(macKey(d.mac));
      const isGateway = d.ip === gwIp;
      const isSelf = d.ip === selfIp;
      const ip = esc(d.ip);
      const mac = esc(d.mac);
      const pill = isBlocked
        ? '<span class="pill warn">blocked</span>'
        : isGateway
          ? '<span class="pill">gateway</span>'
          : isSelf
            ? '<span class="pill">self</span>'
            : cut
              ? '<span class="pill danger">cut</span>'
              : '<span class="pill">idle</span>';
      const act = isBlocked
        ? `<button class="mini" data-unblock="${mac}" title="remove from the block list and restore">unblock</button>`
        : isGateway || isSelf
          ? `<button class="mini warn" data-block="${mac}" data-ip="${ip}" title="auto re-cut whenever this device reappears">block</button>`
          : `<button class="mini" data-act="${cut ? 'restore' : 'cut'}" data-ip="${ip}">${cut ? 'restore' : 'cut'}</button>` +
            `<button class="mini warn" data-block="${mac}" data-ip="${ip}" title="auto re-cut whenever this device reappears">block</button>`;
      return (
        `<div class="host${sel ? ' sel' : ''}" data-ip="${ip}">` +
        `<label class="c-check"><input type="checkbox" data-check="${ip}"${sel ? ' checked' : ''} aria-label="select ${ip}"></label>` +
        `<div class="c-vendor">${esc(d.vendor || '-')}</div>` +
        `<div class="c-ip">${ip}</div>` +
        `<div class="c-mac">${mac}</div>` +
        `<div class="c-state">${pill}</div>` +
        `<div class="c-act">${act}</div>` +
        '</div>'
      );
    })
    .join('');

  renderSelection();
}

function renderBlocks() {
  const box = $('#blocks');
  const list = state.blocks || [];
  $('#blockCount').textContent = String(list.length);

  if (!list.length) {
    box.innerHTML = '<div class="empty">No blocked devices. A blocked MAC is re-cut whenever it shows up again, even after DHCP changes its address.</div>';
    return;
  }

  box.innerHTML = list
    .map((b) => {
      const mac = esc(b.mac);
      return (
        '<div class="block">' +
        '<div class="block-main">' +
        `<span class="mono">${mac}</span>` +
        `<span class="pill">${esc(b.mode || 'gateway')}</span>` +
        (b.label ? `<span class="muted">${esc(b.label)}</span>` : '') +
        (b.vendor ? `<span class="muted">${esc(b.vendor)}</span>` : '') +
        '</div>' +
        '<div class="block-meta">' +
        `<span class="mono muted">${esc(b.ip || 'no address yet')}</span>` +
        `<span class="muted">since ${esc(fmtDate(b.added))}</span>` +
        '</div>' +
        `<button class="mini" data-unblock="${mac}">unblock</button>` +
        '</div>'
      );
    })
    .join('');
}

function renderSelection() {
  const n = state.selected.size;
  $('#selLabel').textContent = String(n);
  $('#cutBtn').disabled = n === 0 || state.busy;
  $('#clearSel').disabled = n === 0;
  $('#scanBtn').disabled = state.scanning;
  $('#scanBtn').classList.toggle('busy', state.scanning);
  $('#scanLabel').textContent = state.scanning ? 'Scanning' : 'Scan';

  const sel = $('#selVisible');
  const candidates = selectableVisible();
  sel.disabled = candidates.length === 0 || state.busy;
  sel.textContent = candidates.length ? `Select all (${candidates.length})` : 'Select all';
}

function selectableVisible() {
  const gw = (state.status && state.status.gatewayIp) || '';
  const self = (state.status && state.status.selfIp) || '';
  return visibleDevices().filter((d) => d.ip !== gw && d.ip !== self && d.mac);
}

function selectVisible() {
  const before = state.selected.size;
  for (const d of selectableVisible()) state.selected.add(d.ip);
  renderHosts();
  const added = state.selected.size - before;
  if (added > 0) toast(`Selected ${added} host(s)`, 'ok');
  else toast('Everything visible is already selected', 'ok');
}

function renderCuts() {
  const cuts = activeCuts();
  $('#cutCount').textContent = String(cuts.length);

  const box = $('#cuts');
  if (!cuts.length) {
    box.innerHTML = '<div class="empty">Nothing cut right now.</div>';
  } else {
    box.innerHTML = cuts
      .map((c) => {
        const ip = esc(c.ip);
        return (
          '<div class="cut">' +
          '<div class="cut-main">' +
          `<span class="mono">${ip}</span>` +
          `<span class="mono muted">${esc(c.mac)}</span>` +
          `<span class="pill">${esc(c.mode)}</span>` +
          (c.vendor ? `<span class="muted">${esc(c.vendor)}</span>` : '') +
          '</div>' +
          '<div class="cut-meta">' +
          `<span class="countdown" data-expires="${esc(c.expires || '')}"></span>` +
          `<span class="muted">${Number(c.packets || 0).toLocaleString()} pkts</span>` +
          '</div>' +
          `<button class="mini" data-restore="${ip}">restore</button>` +
          '</div>'
        );
      })
      .join('');
  }

  tickCountdowns();

  const sig = cuts.map((c) => c.ip).sort().join(',');
  if (sig !== state.cutSig) {
    state.cutSig = sig;
    renderHosts();
  }
}

function tickCountdowns() {
  const now = Date.now();
  for (const el of document.querySelectorAll('.countdown')) {
    const raw = el.dataset.expires;
    if (!raw) {
      el.textContent = '∞';
      continue;
    }
    const t = Date.parse(raw);
    if (Number.isNaN(t)) {
      el.textContent = '--';
      continue;
    }
    el.textContent = fmtDuration(Math.round((t - now) / 1000));
  }
}

/* ---------- log console ---------- */

function clearConsole() {
  $('#console').innerHTML = '';
}

function appendLog(e) {
  const box = $('#console');
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 48;
  const level = String(e.level || 'info').toLowerCase();

  const div = document.createElement('div');
  div.className = 'log-line ' + level;
  div.innerHTML =
    `<span class="t">${esc(fmtTime(e.time))}</span>` +
    `<span class="l">${esc(level.toUpperCase())}</span>` +
    `<span class="m">${esc(e.msg)}</span>`;
  box.appendChild(div);

  while (box.childElementCount > MAX_LOG_LINES) {
    box.removeChild(box.firstElementChild);
  }
  if (atBottom) box.scrollTop = box.scrollHeight;
}

function connectEvents() {
  if (state.es) {
    state.es.close();
    state.es = null;
  }
  const es = new EventSource(withToken('/api/events'));
  state.es = es;

  es.onopen = () => {
    setConn('live', 'ok');
    clearConsole(); // the server replays its tail on connect
  };

  es.onerror = () => {
    setConn('offline', 'bad');
    if (es.readyState === EventSource.CLOSED) {
      setTimeout(connectEvents, 4000);
    }
  };

  es.onmessage = (ev) => {
    let e;
    try { e = JSON.parse(ev.data); } catch { return; }
    appendLog(e);
  };
}

/* ---------- actions ---------- */

async function refreshStatus() {
  try {
    state.status = await api('/api/status');
    renderStatus();
    renderCuts();
    if ($('#connBadge').textContent === 'connecting') setConn('live', 'ok');
  } catch (err) {
    if (!/unauthorized/.test(err.message)) setConn('stale', 'bad');
  }
}

async function refreshBlocks() {
  try {
    const d = await api('/api/blocks');
    state.blocks = (d && d.blocks) || [];
    renderBlocks();
    renderHosts();
  } catch (err) {
    if (!/unauthorized/.test(err.message)) {
      state.blocks = [];
      renderBlocks();
      renderHosts();
    }
  }
}

async function blockHost(mac, ip) {
  if (!mac) return;
  state.busy = true;
  renderSelection();
  try {
    await api('/api/blocks', {
      method: 'POST',
      body: JSON.stringify({ mac, ip, mode: currentMode(), label: '' }),
    });
    toast(`Blocked ${mac} - re-cut on sight`, 'ok');
    await refreshBlocks();
    await refreshStatus();
  } catch (err) {
    toast(err.message, 'bad');
  } finally {
    state.busy = false;
    renderSelection();
  }
}

async function unblockMAC(mac) {
  if (!mac) return;
  state.busy = true;
  renderSelection();
  try {
    const r = await api('/api/blocks/remove', {
      method: 'POST',
      body: JSON.stringify({ mac }),
    });
    const restored = (r && r.restored) || [];
    toast(restored.length
      ? `Unblocked ${mac} - restored ${restored.join(', ')}`
      : `Unblocked ${mac}`, 'ok');
    await refreshBlocks();
    await refreshStatus();
  } catch (err) {
    toast(err.message, 'bad');
  } finally {
    state.busy = false;
    renderSelection();
  }
}

async function scan() {
  if (state.scanning) return;
  state.scanning = true;
  renderSelection();
  try {
    const d = await api('/api/scan?timeout=3');
    const list = (d && d.devices) || [];
    list.sort((a, b) => ipKey(a.ip) - ipKey(b.ip));
    state.devices = list;

    const present = new Set(list.map((x) => x.ip));
    for (const ip of Array.from(state.selected)) {
      if (!present.has(ip)) state.selected.delete(ip);
    }

    renderHosts();
    const auto = (d && d.autoCut) || [];
    if (auto.length) toast(`Found ${list.length} host(s) - re-cut ${auto.length} blocked`, 'warn');
    else toast(`Found ${list.length} host(s)`, 'ok');
  } catch (err) {
    toast(err.message, 'bad');
  } finally {
    state.scanning = false;
    renderSelection();
  }
}

function currentMode() {
  const v = $('#mode').value;
  return v === 'both' ? 'both' : 'gateway';
}

function currentDuration() {
  const v = Number($('#duration').value);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : 0;
}

async function cutIPs(ips) {
  if (!ips.length) return;
  state.busy = true;
  renderSelection();
  try {
    const r = await api('/api/cut', {
      method: 'POST',
      body: JSON.stringify({ ips, mode: currentMode(), duration: currentDuration() }),
    });
    const started = (r && r.started) || [];
    const skipped = (r && r.skipped) || [];
    if (started.length) toast(`Cut ${started.length} host(s)`, 'ok');
    if (skipped.length) {
      toast(skipped.map((s) => `${s.ip}: ${s.reason}`).join('; '), 'bad');
    }
    for (const s of started) state.selected.delete(s.ip);
    await refreshStatus();
    renderHosts();
  } catch (err) {
    toast(err.message, 'bad');
  } finally {
    state.busy = false;
    renderSelection();
  }
}

async function restoreIPs(ips) {
  state.busy = true;
  renderSelection();
  try {
    const r = await api('/api/restore', {
      method: 'POST',
      body: JSON.stringify({ ips }),
    });
    if (r && r.restored === 'all') toast('All cuts restored', 'ok');
    else if (r && r.failed && r.failed.length) {
      toast(r.failed.map((f) => `${f.ip}: ${f.reason}`).join('; '), 'bad');
    } else toast('Restored', 'ok');
    await refreshStatus();
  } catch (err) {
    toast(err.message, 'bad');
  } finally {
    state.busy = false;
    renderSelection();
  }
}

/* ---------- events ---------- */

function bind() {
  $('#scanBtn').addEventListener('click', scan);
  $('#cutBtn').addEventListener('click', () => cutIPs(Array.from(state.selected)));
  $('#selVisible').addEventListener('click', selectVisible);
  $('#clearSel').addEventListener('click', () => {
    state.selected.clear();
    renderHosts();
  });
  $('#restoreAllBtn').addEventListener('click', () => restoreIPs([]));
  $('#clearLog').addEventListener('click', clearConsole);

  const filterEl = $('#filter');
  filterEl.addEventListener('input', () => {
    state.filter = filterEl.value;
    renderHosts();
  });

  document.addEventListener('keydown', (ev) => {
    const el = document.activeElement;
    const typing = el && /^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName);

    if (ev.key === '/' && !typing && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      ev.preventDefault();
      filterEl.focus();
      filterEl.select();
      return;
    }

    if (ev.key === 'Escape' && el === filterEl && filterEl.value) {
      filterEl.value = '';
      state.filter = '';
      renderHosts();
    }
  });

  $('#hosts').addEventListener('change', (ev) => {
    const cb = ev.target.closest('input[data-check]');
    if (!cb) return;
    const ip = cb.dataset.check;
    if (cb.checked) state.selected.add(ip);
    else state.selected.delete(ip);
    const row = cb.closest('.host');
    if (row) row.classList.toggle('sel', cb.checked);
    renderSelection();
  });

  $('#hosts').addEventListener('click', (ev) => {
    const un = ev.target.closest('button[data-unblock]');
    if (un) { unblockMAC(un.dataset.unblock); return; }
    const bl = ev.target.closest('button[data-block]');
    if (bl) { blockHost(bl.dataset.block, bl.dataset.ip || ''); return; }
    const btn = ev.target.closest('button[data-act]');
    if (!btn) return;
    const ip = btn.dataset.ip;
    if (btn.dataset.act === 'cut') cutIPs([ip]);
    else restoreIPs([ip]);
  });

  $('#blocks').addEventListener('click', (ev) => {
    const btn = ev.target.closest('button[data-unblock]');
    if (!btn) return;
    unblockMAC(btn.dataset.unblock);
  });

  $('#cuts').addEventListener('click', (ev) => {
    const btn = ev.target.closest('button[data-restore]');
    if (!btn) return;
    restoreIPs([btn.dataset.restore]);
  });

  $('#mode').addEventListener('change', () => {
    try { localStorage.setItem(MODE_KEY, currentMode()); } catch {}
  });
  $('#duration').addEventListener('change', () => {
    try { localStorage.setItem(DUR_KEY, String(currentDuration())); } catch {}
  });

  $('#tokenBtn').addEventListener('click', () => {
    const bar = $('#tokenBar');
    if (bar.hidden) showTokenBar();
    else bar.hidden = true;
  });

  $('#tokenSave').addEventListener('click', () => {
    const v = $('#tokenInput').value.trim();
    try {
      if (v) localStorage.setItem(TOKEN_KEY, v);
      else localStorage.removeItem(TOKEN_KEY);
    } catch {}
    $('#tokenBar').hidden = true;
    connectEvents();
    refreshStatus();
    refreshBlocks();
  });

  $('#tokenInput').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') $('#tokenSave').click();
  });
}

function restorePrefs() {
  try {
    const m = localStorage.getItem(MODE_KEY);
    if (m === 'gateway' || m === 'both') $('#mode').value = m;
    const d = localStorage.getItem(DUR_KEY);
    if (d !== null && d !== '') $('#duration').value = d;
  } catch {}
}

/* The server prints a ready-to-open URL with ?t=<token>. Absorb it into
   localStorage and strip it from the address bar so the secret does not stay
   in history, bookmarks or a screenshot. */
function absorbURLToken() {
  let url;
  try { url = new URL(window.location.href); } catch { return; }
  const t = url.searchParams.get('t');
  if (!t) return;
  try { localStorage.setItem(TOKEN_KEY, t); } catch {}
  url.searchParams.delete('t');
  const qs = url.searchParams.toString();
  const clean = url.pathname + (qs ? '?' + qs : '') + url.hash;
  try { window.history.replaceState(null, '', clean); } catch {}
}

function init() {
  absorbURLToken();
  bind();
  restorePrefs();
  renderHosts();
  renderCuts();

  refreshStatus();
  refreshBlocks();
  connectEvents();
  scan();

  setInterval(refreshStatus, 2000);
  setInterval(tickCountdowns, 1000);
  setInterval(refreshBlocks, 10000);
}

document.addEventListener('DOMContentLoaded', init);
