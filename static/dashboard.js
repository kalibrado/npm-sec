// ═══════════════════════════════════════════════════════════
//   NPM Security Dashboard · dashboard.js · PWA/mobile-first
//   14 features: favicon·theme·sparklines·choropleth·donut·
//   whois·floatingpill·SSE-backoff·heatmap·blocklist·
//   country-block·cursor-pagination·discord·stats-cache
// ═══════════════════════════════════════════════════════════

// ── État ──────────────────────────────────────────────────
let allLogs       = [];
let currentFilter = 'all';
let searchTerm    = '';
let serverTotal   = 0;
let serverPage    = 1;
let pageSize      = 100;
let searchTimer   = null;

// Cursor-based pagination
let cursorStack    = [];
let currentCursor  = null;

let globalStats = {
  total:0, blocked:0, allowed:0,
  top_countries:[], top_attackers:[], status_dist:[]
};

// Stats cache (mirrors backend TTL for SSE incremental updates)
let statsCache   = null;
let statsCacheTs = 0;
const STATS_TTL  = 10000;

// ── Chart instances ──────────────────────────────────────
let timelineChart = null;
let donutChart    = null;

// ── Map ──────────────────────────────────────────────────
let map, mapDotCount = 0;
const MAX_MAP_DOTS   = 600;
const mapMarkers     = [];

// Choropleth
let choroplethLayer  = null;
let choroplethActive = false;
let topoWorldData    = null;

// Sparklines
const sparklineCache = {};

// ═══════════════════════════════════════════════════════════
//  1. FAVICON BADGE
// ═══════════════════════════════════════════════════════════
let faviconCanvas, faviconCtx, faviconLink;
let lastFaviconCount = -1;

function initFavicon() {
  faviconCanvas = document.createElement('canvas');
  faviconCanvas.width = faviconCanvas.height = 32;
  faviconCtx = faviconCanvas.getContext('2d');
  faviconLink = document.querySelector("link[rel*='icon']");
  if (!faviconLink) {
    faviconLink = document.createElement('link');
    faviconLink.rel = 'icon'; document.head.appendChild(faviconLink);
  }
  updateFavicon(0);
}

function updateFavicon(blockedCount) {
  if (blockedCount === lastFaviconCount) return;
  lastFaviconCount = blockedCount;
  const ctx = faviconCtx;
  ctx.clearRect(0, 0, 32, 32);

  // Background
  ctx.fillStyle = '#080c14';
  ctx.beginPath(); ctx.roundRect(0, 0, 32, 32, 6); ctx.fill();

  // N letter
  ctx.fillStyle = '#3b9eff'; ctx.font = 'bold 20px monospace';
  ctx.textBaseline = 'top'; ctx.fillText('N', 4, 5);

  // Badge
  if (blockedCount > 0) {
    const label = blockedCount > 99 ? '9+' : String(blockedCount);
    ctx.fillStyle = '#ff4455';
    ctx.beginPath(); ctx.arc(24, 8, 9, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = '#fff';
    ctx.font = `bold ${label.length > 1 ? 9 : 11}px sans-serif`;
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText(label, 24, 8.5);
  }
  faviconLink.href = faviconCanvas.toDataURL();
}

// ═══════════════════════════════════════════════════════════
//  2. THEME TOGGLE (light / dark)
// ═══════════════════════════════════════════════════════════
function initTheme() {
  const saved = localStorage.getItem('npm-sec-theme') || 'dark';
  applyTheme(saved);
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = document.getElementById('theme-btn');
  if (btn) btn.textContent = theme === 'dark' ? '☀️' : '🌙';
  localStorage.setItem('npm-sec-theme', theme);
  // Refresh timeline colors after theme change
  setTimeout(() => loadTimeline(), 100);
}

document.getElementById('theme-btn').addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme');
  applyTheme(cur === 'dark' ? 'light' : 'dark');
});

// ═══════════════════════════════════════════════════════════
//  UTILS
// ═══════════════════════════════════════════════════════════
function flag(cc) {
  if (!cc || cc === 'XX') return '<img src="https://flagcdn.com/16x12/un.png" width="16" height="12" alt="?" style="vertical-align:middle">';
  const c = cc.toLowerCase();
  return `<img src="https://flagcdn.com/16x12/${c}.png" srcset="https://flagcdn.com/32x24/${c}.png 2x" width="16" height="12" alt="${cc}" style="vertical-align:middle">`;
}
function flagEmoji(cc) {
  if (!cc || cc === 'XX') return '🌍';
  try { return [...cc.toUpperCase()].map(c => String.fromCodePoint(c.charCodeAt(0)+127397)).join(''); }
  catch { return '🌍'; }
}
function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts); if (isNaN(d)) return ts;
  const hms = d.toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  const cs  = String(Math.floor(d.getMilliseconds() / 10)).padStart(2, '0');
  return `${hms}<span class="time-cs">.${cs}</span>`;
}
function fmtDateTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts); if (isNaN(d)) return ts;
  return d.toLocaleString('fr-FR');
}
function statusClass(s) {
  if (s===444) return 's444'; if (s===429) return 's429';
  if (s>=200&&s<300) return 's2xx'; if (s>=300&&s<400) return 's3xx';
  return 's4xx';
}
function isBlocked(log) { return log.blocked===true||log.blocked===1; }
function num(n) { return n==null?'—':Number(n).toLocaleString('fr-FR'); }
function trunc(s, n) { if (!s) return '—'; return String(s).length>n ? String(s).slice(0,n)+'…' : String(s); }
function esc(v) {
  return String(v ?? '—')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}
function jsArg(v) {
  return JSON.stringify(String(v ?? ''))
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll("'", '&#39;');
}
let currentUser = null;
const VIEWER_ALLOWED_VIEWS = new Set(['home', 'logs', 'map']);
function isAdminUser() { return currentUser?.role === 'admin'; }
function canAccessView(view) { return isAdminUser() || VIEWER_ALLOWED_VIEWS.has(view); }
function applyRoleAccess() {
  const role = currentUser?.role || 'anonymous';
  document.body.dataset.role = role;
  document.querySelectorAll('[data-admin-only], .admin-only').forEach(el => {
    el.hidden = !isAdminUser();
  });
  if (!canAccessView(document.body.dataset.view || 'home')) {
    setView('home');
  }
}
function adminOnlyHtml(html) { return isAdminUser() ? html : ''; }
function requireAdminClient() {
  if (isAdminUser()) return true;
  toast('Droits insuffisants: action réservée admin', 'danger');
  return false;
}

function createAuthOverlay() {
  if (document.getElementById('auth-overlay')) return;
  const el = document.createElement('div');
  el.id = 'auth-overlay';
  el.className = 'auth-overlay';
  el.innerHTML = `
    <div class="auth-card">
      <div class="auth-title">NPM Security Dashboard</div>
      <div class="auth-subtitle">Connexion requise. Oui, on a enfin remplacé le token navigateur par une vraie session.</div>
      <form class="auth-form" id="auth-form">
        <input class="search" id="auth-username" placeholder="Utilisateur" autocomplete="username" value="admin">
        <input class="search" id="auth-password" placeholder="Mot de passe" type="password" autocomplete="current-password">
        <div class="auth-error" id="auth-error"></div>
        <button class="apply-btn" type="submit">Se connecter</button>
      </form>
    </div>`;
  document.body.appendChild(el);
  document.getElementById('auth-form').addEventListener('submit', async e => {
    e.preventDefault();
    await loginUser();
  });
}

function showLogin() {
  createAuthOverlay();
  document.getElementById('auth-overlay').classList.add('open');
  setTimeout(() => document.getElementById('auth-password')?.focus(), 50);
}
function hideLogin() { document.getElementById('auth-overlay')?.classList.remove('open'); }
function updateUserBadge() {
  const btn = document.getElementById('user-btn');
  if (btn) {
    btn.textContent = currentUser ? (currentUser.role === 'admin' ? '👑' : '👤') : '🔐';
    btn.title = currentUser ? `${currentUser.username} (${currentUser.role})` : 'Connexion';
  }
  applyRoleAccess();
}
async function loginUser() {
  const username = document.getElementById('auth-username')?.value.trim();
  const password = document.getElementById('auth-password')?.value || '';
  const err = document.getElementById('auth-error');
  if (err) err.textContent = '';
  try {
    const r = await fetch('/auth/login', {
      method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username,password})
    });
    if (!r.ok) throw new Error('Identifiants invalides');
    const d = await r.json();
    currentUser = d.user;
    hideLogin(); updateUserBadge();
    toast(`Connecté: ${currentUser.username}`, 'success');
    if (isAdminUser()) loadUsers();
  } catch(e) { if (err) err.textContent = e.message || 'Connexion impossible'; }
}
async function logoutUser() {
  await fetch('/auth/logout', {method:'POST', credentials:'same-origin'}).catch(()=>{});
  currentUser = null; updateUserBadge(); showLogin();
}
async function initAuth() {
  createAuthOverlay();
  try {
    const r = await fetch('/auth/me', {credentials:'same-origin'});
    if (!r.ok) throw new Error('not-authenticated');
    const d = await r.json();
    currentUser = d.user;
    hideLogin();
  } catch { showLogin(); }
  updateUserBadge();
}
async function adminFetch(url, options={}) {
  const res = await fetch(url, {...options, credentials:'same-origin'});
  if (res.status === 401) { showLogin(); throw new Error('Connexion requise'); }
  if (res.status === 403) { throw new Error('Droits insuffisants'); }
  return res;
}

async function copyClip(text) {
  const value = String(text ?? '');

  // 1) Modern Clipboard API.
  // It is often undefined on HTTP, non-localhost, remote browser sessions, iframes,
  // or locked-down environments. So yes, copying text is now a security negotiation.
  try {
    const clip = window.navigator && window.navigator.clipboard;
    if (window.isSecureContext && clip && typeof clip.writeText === 'function') {
      await clip.writeText(value);
      toast('Copié !', 'success');
      return true;
    }
  } catch (err) {
    console.warn('clipboard API failed, trying legacy fallback:', err);
  }

  // 2) Legacy synchronous fallback. This must run directly from the click handler.
  try {
    const ta = document.createElement('textarea');
    ta.value = value;
    ta.setAttribute('readonly', '');
    ta.setAttribute('aria-hidden', 'true');
    ta.style.position = 'fixed';
    ta.style.left = '0';
    ta.style.top = '0';
    ta.style.width = '1px';
    ta.style.height = '1px';
    ta.style.opacity = '0';
    ta.style.pointerEvents = 'none';
    document.body.appendChild(ta);
    ta.focus({preventScroll:true});
    ta.select();
    ta.setSelectionRange(0, value.length);

    const ok = document.execCommand && document.execCommand('copy');
    ta.remove();

    if (ok) {
      toast('Copié !', 'success');
      return true;
    }
  } catch (err) {
    console.warn('legacy clipboard fallback failed:', err);
  }

  // 3) Last-resort manual fallback: show the value selected so Ctrl+C works.
  showManualCopyDialog(value);
  return false;
}

function showManualCopyDialog(value) {
  document.querySelector('.copy-fallback-overlay')?.remove();

  const overlay = document.createElement('div');
  overlay.className = 'copy-fallback-overlay';
  overlay.innerHTML = `
    <div class="copy-fallback-card" role="dialog" aria-modal="true" aria-label="Copie manuelle">
      <div class="copy-fallback-title">Copie manuelle requise</div>
      <div class="copy-fallback-text">
        Ton navigateur bloque l'API clipboard dans cet environnement. Sélectionne la valeur ci-dessous puis utilise Ctrl+C.
      </div>
      <input class="copy-fallback-input" value="${esc(value)}" readonly>
      <div class="copy-fallback-actions">
        <button class="action-btn" data-copy-select>Sélectionner</button>
        <button class="action-btn secondary" data-copy-close>Fermer</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
  const input = overlay.querySelector('.copy-fallback-input');
  const selectBtn = overlay.querySelector('[data-copy-select]');
  const closeBtn = overlay.querySelector('[data-copy-close]');

  const selectValue = () => {
    input.focus({preventScroll:true});
    input.select();
    input.setSelectionRange(0, input.value.length);
  };

  selectBtn.addEventListener('click', selectValue);
  closeBtn.addEventListener('click', () => overlay.remove());
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
  document.addEventListener('keydown', function onKey(e) {
    if (e.key === 'Escape') {
      overlay.remove();
      document.removeEventListener('keydown', onKey);
    }
  });

  setTimeout(selectValue, 50);
  toast('Clipboard bloqué : copie manuelle affichée', 'warning', 5000);
}

// ═══════════════════════════════════════════════════════════
//  TOAST
// ═══════════════════════════════════════════════════════════
function toast(msg, type='info', dur=3200) {
  const icons = {success:'✅',danger:'🚫',info:'ℹ️',warning:'⚠️'};
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-icon">${icons[type]||'•'}</span><span class="toast-text">${esc(msg)}</span>`;
  document.getElementById('toast-zone').appendChild(el);
  setTimeout(()=>{ el.classList.add('out'); setTimeout(()=>el.remove(),250); }, dur);
}

// Form errors must be visible in the page as well as in transient notifications.
function apiErrorMessage(data, fallback='Action impossible') {
  const detail = data?.detail || data?.error;
  if (Array.isArray(detail)) return detail.map(item => item.msg || String(item)).join(' ; ');
  return typeof detail === 'string' ? detail : fallback;
}
function formFeedback(id, message, state='info') {
  const target = document.getElementById(id);
  if (!target) return;
  target.textContent = message;
  target.dataset.state = state;
}
function requiredInput(inputId, feedbackId, message) {
  const input = document.getElementById(inputId);
  if (input && input.value.trim()) {
    input.removeAttribute('aria-invalid');
    return true;
  }
  if (input) {
    input.setAttribute('aria-invalid', 'true');
    input.focus();
  }
  formFeedback(feedbackId, message, 'error');
  toast(message, 'warning', 5500);
  return false;
}
async function withBusyButton(id, label, task) {
  const btn = document.getElementById(id);
  if (!btn || btn.disabled) return;
  const original = btn.textContent;
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  btn.textContent = label;
  try { await task(); }
  finally {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    btn.textContent = original;
  }
}
for (const [field, feedback] of [
  ['bl-input','bl-form-feedback'],
  ['trusted-input','trusted-form-feedback'],
  ['lists-block-input','lists-block-feedback'],
  ['lists-trusted-input','lists-trusted-feedback'],
]) {
  document.getElementById(field)?.addEventListener('input', event => {
    event.target.removeAttribute('aria-invalid');
    formFeedback(feedback, '');
  });
}
async function loadSecurityControl() {
  await Promise.all([
    loadSecurityControlOverview(),
    loadSecuritySuspects(),
    loadObservationIncidents(),
    loadPolicyModes()
  ]);
}

// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
//  MOBILE NAV
// ═══════════════════════════════════════════════════════════
function setView(v) {
  if (v==='search') { openSheet('search'); return; }
  if (v==='more') { if (!isAdminUser()) { toast('Droits insuffisants', 'danger'); return; } openSheet('more'); return; }
  if (!canAccessView(v)) { toast('Droits insuffisants', 'danger'); v = 'home'; }
  document.body.dataset.view = v;
  document.querySelectorAll('.nav-btn, .desktop-tab').forEach(b => b.classList.toggle('active', b.dataset.view===v));
  if (v==='home') loadHomeOverview();
  if (v==='map') { ensureMapHud(); setTimeout(()=> map&&map.invalidateSize(), 120); }
  if (v==='threats') loadThreats();
  if (v==='lists') loadSecurityLists();
  if (v==='control') loadSecurityControl();
  if (v==='health') loadNpmHealth();
  if (v==='config') { loadRuntimeConfig(); loadDetailedHealth(); loadPatch53Intel(); loadUsers(); loadSecurityProfile(); }
}
document.querySelectorAll('.nav-btn, .desktop-tab').forEach(b => b.addEventListener('click',()=>setView(b.dataset.view)));

// ═══════════════════════════════════════════════════════════
//  SHEETS
// ═══════════════════════════════════════════════════════════
function openSheet(name) {
  if ((name === 'blocklist' || name === 'more') && !isAdminUser()) { toast('Droits insuffisants', 'danger'); return; }
  document.getElementById(`${name}-sheet`)||document.getElementById(`${name}-drawer`)||null;
  const el = document.getElementById(`${name}-sheet`) || document.getElementById(`${name}-drawer`);
  const bd = document.getElementById(`${name}-backdrop`);
  if (!el) return;
  el.classList.add('open'); if (bd) bd.classList.add('open');
  if (name==='blocklist') { loadBlocklist(); loadTrusted(); }
}
function closeSheet(name) {
  const el = document.getElementById(`${name}-sheet`) || document.getElementById(`${name}-drawer`);
  const bd = document.getElementById(`${name}-backdrop`);
  if (el) el.classList.remove('open'); if (bd) bd.classList.remove('open');
}

document.getElementById('search-close').addEventListener('click', ()=>closeSheet('search'));
document.getElementById('search-backdrop').addEventListener('click', ()=>closeSheet('search'));
document.getElementById('more-close')?.addEventListener('click', ()=>closeSheet('more'));
document.getElementById('more-backdrop')?.addEventListener('click', ()=>closeSheet('more'));
document.querySelectorAll('[data-more-view]').forEach(btn => btn.addEventListener('click', () => {
  const view = btn.dataset.moreView;
  closeSheet('more');
  if (view === 'search') openSheet('search'); else setView(view);
}));
document.getElementById('more-logout')?.addEventListener('click', () => { closeSheet('more'); logoutUser(); });
document.getElementById('blocklist-close').addEventListener('click', ()=>closeSheet('blocklist'));
document.getElementById('blocklist-backdrop').addEventListener('click', ()=>closeSheet('blocklist'));
document.getElementById('blocklist-open-btn').addEventListener('click', ()=>openSheet('blocklist'));
const listsViewBtn = document.getElementById('lists-view-btn');
if (listsViewBtn) listsViewBtn.addEventListener('click', () => setView('lists'));
const healthViewBtn = document.getElementById('health-view-btn');
if (healthViewBtn) healthViewBtn.addEventListener('click', () => setView('health'));
const configViewBtn = document.getElementById('config-view-btn');
if (configViewBtn) configViewBtn.addEventListener('click', () => setView('config'));

// Sync mobile filter chips
document.querySelectorAll('[data-sf]').forEach(btn => {
  btn.addEventListener('click', ()=>{
    document.querySelectorAll('[data-sf]').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.sf;
    document.querySelectorAll('[data-f]').forEach(b=>b.classList.toggle('active',b.dataset.f===currentFilter));
  });
});
document.getElementById('search-apply').addEventListener('click', ()=>{
  searchTerm = document.getElementById('search-mobile').value.trim();
  document.getElementById('search').value = searchTerm;
  closeSheet('search'); setView('logs'); loadPage('first');
});
document.getElementById('search-mobile').addEventListener('input', e=>{
  document.getElementById('search').value = e.target.value;
});

// ═══════════════════════════════════════════════════════════
//  3. SPARKLINES
// ═══════════════════════════════════════════════════════════
function sparklineSVG(values, color='#ff4455') {
  if (!values||!values.length) return '';
  const W=44,H=14; const max=Math.max(...values,1);
  const step = W/Math.max(values.length-1,1);
  const pts = values.map((v,i)=>`${+(i*step).toFixed(1)},${+(H-(v/max)*H).toFixed(1)}`).join(' ');
  return `<svg class="sparkline-svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
    <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
  </svg>`;
}

async function loadSparklines() {
  const ips = [...new Set(allLogs.map(l=>l.ip))].filter(Boolean).slice(0,20);
  if (!ips.length) return;
  try {
    const r = await fetch(`/sparklines?ips=${ips.join(',')}`);
    const data = await r.json();
    Object.assign(sparklineCache, data);
    injectSparklines();
  } catch {}
}

function injectSparklines() {
  document.querySelectorAll('[data-sparkline]').forEach(cell => {
    const ip = cell.getAttribute('data-sparkline');
    const vals = sparklineCache[ip];
    if (vals && vals.length > 1) {
      const existing = cell.querySelector('.sparkline-svg');
      if (existing) existing.remove();
      cell.appendChild(document.createRange().createContextualFragment(sparklineSVG(vals)));
    }
  });
}

// ═══════════════════════════════════════════════════════════
//  TABLE
// ═══════════════════════════════════════════════════════════
// ── Shared row builder (used by renderTable + prependRow) ──
function buildRowHTML(l, idx) {
  const bl = isBlocked(l);
  const ip = esc(l.ip || '—');
  const cc = esc(l.country_code || '?');
  return `<tr class="${bl?'is-blocked':''}" onclick="showModal(${idx})">
    <td class="time-cell">${fmtTime(l.timestamp)}</td>
    <td class="ip-cell" data-sparkline="${ip}">${ip}</td>
    <td class="col-sm"><div class="country-cell">${flag(l.country_code)}<span style="font-size:10px;color:var(--muted);font-family:var(--mono)">${cc}</span></div></td>
    <td><span class="status-badge ${statusClass(l.status)}">${esc(l.status)}</span></td>
    <td class="col-md method-cell">${esc(l.method || '—')}</td>
    <td class="col-md host-cell" title="${esc(l.host || '')}">${esc(trunc(l.host,28))}</td>
    <td class="col-lg uri-cell"  title="${esc(l.uri || '')}">${esc(trunc(l.uri,38))}</td>
    <td class="col-xl isp-cell"  title="${esc(l.isp || '')}">${esc(trunc((l.isp||'').replace(/^AS\d+ /,''),22))}</td>
    <td><span class="result-badge ${bl?'r-blocked':'r-ok'}">${bl?'Bloqué':'OK'}</span></td>
  </tr>`;
}

function renderTable() {
  const tbody = document.getElementById('tbody');
  document.getElementById('row-count').textContent    = `${num(serverTotal)} résultats`;
  document.getElementById('s-shown').textContent      = num(allLogs.length);
  document.getElementById('s-page-info').textContent  = `page ${serverPage}`;
  document.getElementById('page-info').textContent    = `${serverPage} — ${num(serverTotal)} lignes`;
  document.getElementById('btn-prev').disabled = cursorStack.length===0;
  document.getElementById('btn-next').disabled = allLogs.length < pageSize;

  if (!allLogs.length) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="empty"><div class="empty-icon">🔍</div><p>Aucune requête trouvée</p></div></td></tr>`;
    return;
  }
  tbody.innerHTML = allLogs.map((l,idx) => buildRowHTML(l, idx)).join('');
  setTimeout(loadSparklines, 50);
}

// ── Slide-in a single new row at the top without full re-render ──
function prependRow(log) {
  // Only active on page 1 (no cursor) and no active filter/search
  if (serverPage!==1 || cursorStack.length>0) return;

  const tbody = document.getElementById('tbody');
  // If table shows the empty state, fall back to full render
  if (tbody.querySelector('.empty')) { loadPage('first'); return; }

  // Prepend to allLogs and trim to pageSize
  allLogs.unshift(log);
  if (allLogs.length > pageSize) allLogs.pop();
  serverTotal++;

  // Rebuild onclick indices (shift all existing rows by +1)
  tbody.querySelectorAll('tr[onclick]').forEach(tr => {
    const m = tr.getAttribute('onclick').match(/showModal\((\d+)\)/);
    if (m) tr.setAttribute('onclick', `showModal(${+m[1]+1})`);
  });

  // Create the new TR
  const tmp = document.createElement('tbody');
  tmp.innerHTML = buildRowHTML(log, 0);
  const tr = tmp.firstElementChild;
  tr.classList.add('row-slide-in');

  // Drop last row if over limit (smooth fade-out)
  const rows = tbody.querySelectorAll('tr');
  if (rows.length >= pageSize) {
    const last = rows[rows.length-1];
    last.classList.add('row-slide-out');
    setTimeout(() => last.remove(), 280);
  }

  tbody.insertBefore(tr, tbody.firstChild);

  // Update counters
  document.getElementById('row-count').textContent   = `${num(serverTotal)} résultats`;
  document.getElementById('s-shown').textContent     = num(allLogs.length);
  document.getElementById('s-page-info').textContent = `page ${serverPage}`;

  // Remove animation class after it plays (keeps DOM clean)
  tr.addEventListener('animationend', () => tr.classList.remove('row-slide-in'), {once:true});

  // Sparkline for new IP
  const ipCell = tr.querySelector('[data-sparkline]');
  const ip = ipCell?.getAttribute('data-sparkline');
  if (ip && sparklineCache[ip]) injectSparklines();
}

// ═══════════════════════════════════════════════════════════
//  12. CURSOR-BASED PAGINATION
// ═══════════════════════════════════════════════════════════
async function loadPage(direction='first') {
  let cursorParam = '';

  if (direction==='first') {
    cursorStack=[]; currentCursor=null; serverPage=1;
  } else if (direction==='next') {
    const ids = allLogs.map(l=>l.id).filter(n=>n!=null);
    if (ids.length) {
      const minId = Math.min(...ids);
      cursorStack.push(currentCursor);
      currentCursor = minId;
      cursorParam   = `&cursor=${minId}`;
      serverPage++;
    }
  } else if (direction==='prev') {
    currentCursor = cursorStack.pop()||null;
    if (currentCursor) cursorParam = `&cursor=${currentCursor}`;
    serverPage = Math.max(1, serverPage-1);
  }

  const bParam = currentFilter==='blocked' ? '&blocked_only=true' : '';
  const aParam = currentFilter==='allowed' ? '&allowed_only=true' : '';
  const sParam = searchTerm ? `&search=${encodeURIComponent(searchTerm)}` : '';

  try {
    const r = await fetch(`/history?limit=${pageSize}${cursorParam}${bParam}${aParam}${sParam}`);
    const d = await r.json();
    allLogs     = d.logs  || [];
    serverTotal = d.total ?? globalStats.total;
    renderTable();
  } catch(e) {
    console.error('loadPage:', e);
    document.getElementById('tbody').innerHTML =
      `<tr><td colspan="9"><div class="empty"><div class="empty-icon">⚠️</div><p>Erreur de chargement</p></div></td></tr>`;
  }
}

// Filter chips
document.querySelectorAll('[data-f]').forEach(btn=>{
  btn.addEventListener('click',()=>{
    document.querySelectorAll('[data-f]').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.f;
    document.querySelectorAll('[data-sf]').forEach(b=>b.classList.toggle('active',b.dataset.sf===currentFilter));
    loadPage('first');
  });
});

document.getElementById('search').addEventListener('input', e=>{
  searchTerm = e.target.value;
  document.getElementById('search-mobile').value = searchTerm;
  clearTimeout(searchTimer);
  searchTimer = setTimeout(()=>loadPage('first'), 420);
});

document.getElementById('btn-prev').addEventListener('click', ()=>loadPage('prev'));
document.getElementById('btn-next').addEventListener('click', ()=>loadPage('next'));
document.getElementById('page-size').addEventListener('change', e=>{ pageSize=parseInt(e.target.value); loadPage('first'); });

// Quick-filter helpers (called from sidebar + modal)
function filterByIP(ip) {
  searchTerm = `ip:${ip}`;
  document.getElementById('search').value = searchTerm;
  document.getElementById('search-mobile').value = searchTerm;
  setView('logs'); loadPage('first');
  toast(`Filtre actif: ip:${ip}`,'info');
}
function filterByCountry(cc) {
  searchTerm = `country_code:${cc}`;
  document.getElementById('search').value = searchTerm;
  document.getElementById('search-mobile').value = searchTerm;
  setView('logs'); loadPage('first');
  toast(`Filtre actif: pays ${cc}`,'info');
}
function filterByField(f, v) {
  searchTerm = `${f}:${v}`;
  document.getElementById('search').value = searchTerm;
  document.getElementById('search-mobile').value = searchTerm;
  loadPage('first');
}

function activityIcon(a) {
  const src = a?.source || '';
  const act = String(a?.action || '').toUpperCase();
  if (src === 'threat') return '🚨';
  if (act.includes('AUTO')) return '🤖';
  if (act.includes('BLOCK')) return '⛔';
  if (act.includes('TRUST')) return '✅';
  if (act.includes('EXPORT')) return '📤';
  return '•';
}
function activityCard(a) {
  const meta = a.source === 'threat'
    ? `${esc(a.action || 'threat')} · score ${esc(a.score ?? '—')}`
    : `${esc(a.action || 'event')} · ${esc(a.target || '—')}`;
  const details = Array.isArray(a.details) ? a.details.join(', ') : (a.details || a.uri || '');
  return `<div class="mobile-info-card">
    <div class="mobile-card-top"><strong>${activityIcon(a)} ${meta}</strong><span>${esc(fmtDateTime(a.created_at))}</span></div>
    <div class="mobile-card-meta">${esc(a.host || a.target || '')}</div>
    <div class="mobile-card-uri">${esc(trunc(details, 96))}</div>
  </div>`;
}
async function loadSecurityActivity() {
  const el = document.getElementById('home-activity-list');
  if (!el) return;
  try {
    const data = await fetch('/security-activity?limit=8').then(r=>r.json());
    el.innerHTML = Array.isArray(data) && data.length ? data.map(activityCard).join('') : '<div class="empty small">Aucune activité récente</div>';
  } catch(e) { el.innerHTML = '<div class="empty small">Activité indisponible</div>'; }
}
async function enableBrowserNotifications() {
  if (!('Notification' in window)) { toast('Notifications non supportées', 'danger'); return; }
  const perm = await Notification.requestPermission();
  toast(perm === 'granted' ? 'Notifications activées' : 'Notifications refusées', perm === 'granted' ? 'success' : 'danger');
}
function notifyThreat(log) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const score = log.threat_score || 0;
  if (score < 50 && !log.auto_blocked && !log.auto_block_dry_run) return;
  const title = log.auto_blocked ? 'IP auto-bloquée' : log.auto_block_dry_run ? 'Auto-ban dry-run' : 'Menace détectée';
  try { new Notification(title, { body: `${log.ip || '—'} · score ${score} · ${trunc(log.uri || '', 72)}`, tag: `npm-sec-${log.ip || Date.now()}` }); } catch {}
}
async function showIPProfile(ip) {
  const body = document.getElementById('modal-body');
  document.getElementById('modal-title').textContent = `🕵️ Fiche IP ${ip}`;
  body.innerHTML = '<div class="empty small">Chargement fiche IP…</div>';
  document.getElementById('overlay').classList.add('open');
  try {
    const d = await fetch(`/ip/${encodeURIComponent(ip)}/profile`).then(r=>r.json());
    if (d.detail) throw new Error(d.detail);
    const s = d.summary || {};
    body.innerHTML = `
      <div class="action-bar">
        <button class="action-btn" onclick='filterByIP(${jsArg(ip)});closeModal()'>Filtrer logs</button>
        ${adminOnlyHtml(`<button class="action-btn danger" onclick='blockIP(${jsArg(ip)})'>Bloquer</button>`)}
        <button class="action-btn" onclick='copyClip(${jsArg(ip)})'>Copier</button>
      </div>
      <div class="modal-grid">
        <div class="mcard"><div class="mcard-label">IP</div><div class="mcard-val accent">${esc(ip)}</div></div>
        <div class="mcard"><div class="mcard-label">État</div><div class="mcard-val">${d.is_blocked ? '⛔ bloquée' : d.is_trusted ? '✅ trusted' : 'neutre'}</div></div>
        <div class="mcard"><div class="mcard-label">Total</div><div class="mcard-val">${num(s.total || 0)}</div></div>
        <div class="mcard"><div class="mcard-label">Bloquées</div><div class="mcard-val">${num(s.blocked || 0)}</div></div>
        <div class="mcard"><div class="mcard-label">Pays</div><div class="mcard-val">${flag(s.country_code)} ${esc(s.country_name || '—')}</div></div>
        <div class="mcard"><div class="mcard-label">ISP / ASN</div><div class="mcard-val">${esc(s.isp || '—')} · ${esc(s.asn || '—')}</div></div>
      </div>
      <div class="modal-section-title">Top hosts</div>
      <div class="mobile-card-list">${(d.hosts||[]).slice(0,6).map(h=>`<div class="mobile-info-card"><div class="mobile-card-top"><strong>${esc(h.host||'—')}</strong><span>${num(h.count)}</span></div></div>`).join('') || '<div class="empty small">Aucun host</div>'}</div>
      <div class="modal-section-title">Menaces</div>
      <div class="mobile-card-list">${(d.threats||[]).slice(0,6).map(t=>`<div class="mobile-info-card danger"><div class="mobile-card-top"><strong>${esc(t.threat_type)}</strong><span class="score-pill ${threatClass(t.score)}">${esc(t.score)}</span></div><div class="mobile-card-meta">${esc(fmtDateTime(t.created_at))}</div><div class="mobile-card-uri">${esc((t.reasons||[]).join(', '))}</div></div>`).join('') || '<div class="empty small">Aucune menace</div>'}</div>
      <div class="modal-section-title">Derniers logs</div>
      <div class="mobile-card-list">${(d.logs||[]).slice(0,8).map(l=>`<div class="mobile-info-card"><div class="mobile-card-top"><strong>HTTP ${esc(l.status)}</strong><span>${esc(fmtTime(l.timestamp))}</span></div><div class="mobile-card-meta">${esc(l.host||'—')}</div><div class="mobile-card-uri">${esc(trunc(l.uri||'', 96))}</div></div>`).join('')}</div>`;
  } catch(e) { body.innerHTML = `<div class="empty small">Fiche IP indisponible: ${esc(e.message || e)}</div>`; }
}

// ═══════════════════════════════════════════════════════════
//  5. DONUT CHART (statuts HTTP)
// ═══════════════════════════════════════════════════════════
const STATUS_COLORS = {'2xx':'#22d67a','3xx':'#566a82','4xx':'#f5a623','444':'#ff4455','429':'#f5a623'};
const STATUS_FILTERS= {'2xx':'status:200','3xx':'status:301','4xx':'status:403','444':'status:444','429':'status:429'};

function renderDonut() {
  const { status_dist } = globalStats;
  if (!status_dist||!status_dist.length) return;

  const groups = {'444':0,'429':0,'2xx':0,'3xx':0,'4xx':0};
  status_dist.forEach(s=>{
    if (s.status===444) groups['444']+=s.count;
    else if (s.status===429) groups['429']+=s.count;
    else if (s.status>=200&&s.status<300) groups['2xx']+=s.count;
    else if (s.status>=300&&s.status<400) groups['3xx']+=s.count;
    else if (s.status>=400) groups['4xx']+=s.count;
  });

  const labels = Object.keys(groups).filter(k=>groups[k]>0);
  const data   = labels.map(k=>groups[k]);
  const colors = labels.map(k=>STATUS_COLORS[k]);
  const total  = data.reduce((a,b)=>a+b,0);

  if (donutChart) { donutChart.destroy(); donutChart=null; }
  const ctx = document.getElementById('donutChart');
  if (!ctx) return;

  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets:[{ data, backgroundColor:colors.map(c=>c+'bb'), borderColor:colors, borderWidth:1.5, hoverOffset:5 }] },
    options: {
      responsive:true, maintainAspectRatio:false, cutout:'70%',
      plugins: {
        legend:{display:false},
        tooltip:{ callbacks:{ label: ctx=>`${ctx.label}: ${ctx.parsed.toLocaleString('fr-FR')}` } }
      },
      onClick:(_,els)=>{
        if (!els.length) return;
        searchTerm = STATUS_FILTERS[labels[els[0].index]] || '';
        document.getElementById('search').value = searchTerm;
        setView('logs'); loadPage('first');
      }
    }
  });

  // Center label
  const dc = document.getElementById('donut-center');
  if (dc) dc.innerHTML = `<div class="donut-val">${num(total)}</div><div class="donut-lbl">requêtes</div>`;

  // Legend
  const legend = document.getElementById('donut-legend');
  if (legend) legend.innerHTML = labels.map((k,i)=>`
    <div class="donut-leg-item" onclick="searchTerm='${STATUS_FILTERS[k]}';document.getElementById('search').value=searchTerm;setView('logs');loadPage('first')">
      <div class="donut-leg-dot" style="background:${colors[i]}"></div>
      <span class="donut-leg-name">HTTP ${k}</span>
      <span class="donut-leg-val" style="color:${colors[i]}">${num(data[i])}</span>
    </div>
  `).join('');
}

// ═══════════════════════════════════════════════════════════
//  SIDEBAR
// ═══════════════════════════════════════════════════════════
function renderSidebar() {
  const { top_countries, top_attackers } = globalStats;

  // Countries (11. bulk block button added)
  const maxC = top_countries[0]?.count||1;
  document.getElementById('country-list').innerHTML = top_countries.slice(0,8).map(c=>{
    const bl = (c.blocked_count||0)>c.count/2;
    const w  = Math.round((c.count/maxC)*100);
    return `<div class="country-item">
      <span class="c-flag" onclick='filterByCountry(${jsArg(c.country_code)})'>${flag(c.country_code)}</span>
      <span class="c-name" onclick='filterByCountry(${jsArg(c.country_code)})'>${esc(c.country_name||c.country_code)}</span>
      <div class="c-bar-wrap"><div class="c-bar ${bl?'blocked-bar':'ok-bar'}" style="width:${w}%"></div></div>
      <span class="c-count">${c.count}</span>
      ${adminOnlyHtml(`<button class="c-block-btn" onclick='blockCountry(${jsArg(c.country_code)},${jsArg(c.country_name||c.country_code)})' title="Bloquer ce pays">🚫</button>`)}
    </div>`;
  }).join('');

  // Top IPs
  document.getElementById('ip-list').innerHTML = (top_attackers||[]).slice(0,6).map(ip=>`
    <div class="ip-item" onclick='filterByIP(${jsArg(ip.ip)})'>
      <div class="ip-item-row"><span class="ip-addr">${esc(ip.ip)}</span><span class="ip-hits">${esc(ip.count)}×</span></div>
      <div class="ip-meta">${flagEmoji(ip.country_code)} ${esc(ip.isp||'—')}</div>
    </div>
  `).join('');

  renderDonut();
}

function updateHeaderStats() {
  const { total, blocked, allowed } = globalStats;
  document.getElementById('s-total').textContent   = num(total);
  document.getElementById('s-blocked').textContent = num(blocked);
  document.getElementById('s-allowed').textContent = num(allowed);
  document.getElementById('s-block-rate').textContent = total ? `${((blocked/total)*100).toFixed(1)}%` : '0%';
  document.getElementById('s-ips').textContent = num((globalStats.top_attackers||[]).length);
  document.getElementById('s-countries').textContent = num((globalStats.top_countries||[]).filter(c=>c.blocked_count>0).length);
  updateFavicon(blocked);
}

// ── Stats (backend-cached, TTL 10s) ─────────────────────
async function loadStats(force=false) {
  const now = Date.now();
  if (!force && statsCache && now-statsCacheTs < STATS_TTL) {
    globalStats = statsCache; updateHeaderStats(); renderSidebar(); return;
  }
  try {
    const r = await fetch('/stats');
    globalStats = await r.json();
    statsCache = globalStats; statsCacheTs = now;
    updateHeaderStats(); renderSidebar();
  } catch(e) { console.error('stats:', e); }
}

// ── Timeline (fix: destroy before re-create) ─────────────
async function loadTimeline() {
  try {
    const r    = await fetch('/timeline');
    const data = await r.json();
    const labels  = data.map(d=>d.t).reverse();
    const blocked = data.map(d=>d.blocked||0).reverse();
    const total   = data.map(d=>d.total||0).reverse();

    if (timelineChart) { timelineChart.destroy(); timelineChart=null; }
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;

    timelineChart = new Chart(ctx, {
      type:'line',
      data:{
        labels,
        datasets:[
          { label:'Bloquées', data:blocked, borderColor:'#ff4455', backgroundColor:'rgba(255,68,85,.07)', tension:.35, pointRadius:0, borderWidth:1.5, fill:true },
          { label:'Total',    data:total,   borderColor:'#3b9eff', backgroundColor:'rgba(59,158,255,.04)', tension:.35, pointRadius:0, borderWidth:1, fill:true }
        ]
      },
      options:{
        responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ display:true, labels:{ color:'#566a82', font:{size:10}, boxWidth:10 } } },
        scales:{
          x:{ display:false },
          y:{ ticks:{color:'#566a82',font:{size:10}}, grid:{color:'rgba(30,45,66,.5)'} }
        }
      }
    });
  } catch(e) { console.error('timeline:', e); }
}

// ═══════════════════════════════════════════════════════════
//  9. HEATMAP 7 jours × 24h
// ═══════════════════════════════════════════════════════════
async function loadHeatmap() {
  try {
    const r = await fetch('/heatmap');
    const d = await r.json();
    renderHeatmap(d.matrix);
  } catch(e) { console.error('heatmap:', e); }
}

function renderHeatmap(matrix) {
  const el = document.getElementById('heatmap-grid');
  if (!el||!matrix) return;
  const DAYS = ['Dim','Lun','Mar','Mer','Jeu','Ven','Sam'];
  let maxVal = 0;
  matrix.forEach(day=>day.forEach(h=>{ if (h.blocked>maxVal) maxVal=h.blocked; }));

  const CS=10, GAP=2, LW=26, LH=14;
  const W = LW + 24*(CS+GAP);
  const H = 7*(CS+GAP) + LH;

  let svg = `<svg width="${W}" height="${H}" style="display:block">`;

  DAYS.forEach((d,i)=>{
    svg += `<text x="0" y="${i*(CS+GAP)+CS-1}" font-size="8" fill="var(--muted)" font-family="var(--mono)">${d}</text>`;
  });
  [0,6,12,18].forEach(h=>{
    svg += `<text x="${LW+h*(CS+GAP)}" y="${H}" font-size="8" fill="var(--muted)" font-family="var(--mono)">${String(h).padStart(2,'0')}h</text>`;
  });

  matrix.forEach((day,di)=>{
    day.forEach((cell,hi)=>{
      const intensity = maxVal>0 ? cell.blocked/maxVal : 0;
      let fill;
      if (cell.blocked===0 && cell.total===0) fill='rgba(30,45,66,0.3)';
      else if (cell.blocked===0) fill='rgba(34,214,122,0.2)';
      else { const a=0.1+intensity*0.88; fill=`rgba(255,68,85,${a.toFixed(2)})`; }
      const x = LW + hi*(CS+GAP);
      const y = di*(CS+GAP);
      svg += `<rect x="${x}" y="${y}" width="${CS}" height="${CS}" rx="2" fill="${fill}"><title>${DAYS[di]} ${String(hi).padStart(2,'0')}h : ${cell.blocked} bloquées / ${cell.total} total</title></rect>`;
    });
  });

  svg += '</svg>';
  el.innerHTML = svg;
}

// ═══════════════════════════════════════════════════════════
//  4. CHOROPLÈTHE (Leaflet + TopoJSON world-atlas)
// ═══════════════════════════════════════════════════════════
// ISO numeric → alpha-2 lookup (world-atlas uses numeric IDs)
const NUM_TO_A2={4:'AF',8:'AL',12:'DZ',20:'AD',24:'AO',28:'AG',32:'AR',36:'AU',40:'AT',44:'BS',48:'BH',50:'BD',52:'BB',56:'BE',64:'BT',68:'BO',70:'BA',72:'BW',76:'BR',84:'BZ',90:'SB',96:'BN',100:'BG',104:'MM',108:'BI',116:'KH',120:'CM',124:'CA',132:'CV',140:'CF',144:'LK',148:'TD',152:'CL',156:'CN',170:'CO',174:'KM',178:'CG',180:'CD',184:'CK',188:'CR',191:'HR',192:'CU',196:'CY',203:'CZ',204:'BJ',208:'DK',212:'DM',214:'DO',218:'EC',222:'SV',226:'GQ',231:'ET',233:'EE',242:'FJ',246:'FI',250:'FR',266:'GA',268:'GE',270:'GM',276:'DE',288:'GH',292:'GI',300:'GR',308:'GD',320:'GT',324:'GN',332:'HT',340:'HN',344:'HK',348:'HU',356:'IN',360:'ID',364:'IR',368:'IQ',372:'IE',376:'IL',380:'IT',388:'JM',392:'JP',398:'KZ',400:'JO',404:'KE',408:'KP',410:'KR',414:'KW',417:'KG',418:'LA',422:'LB',426:'LS',428:'LV',430:'LR',434:'LY',440:'LT',442:'LU',446:'MO',450:'MG',454:'MW',458:'MY',462:'MV',466:'ML',470:'MT',478:'MR',480:'MU',484:'MX',492:'MC',496:'MN',498:'MD',499:'ME',504:'MA',508:'MZ',516:'NA',524:'NP',528:'NL',554:'NZ',558:'NI',562:'NE',566:'NG',578:'NO',586:'PK',591:'PA',598:'PG',600:'PY',604:'PE',608:'PH',616:'PL',620:'PT',626:'TL',630:'PR',634:'QA',642:'RO',643:'RU',646:'RW',682:'SA',686:'SN',688:'RS',694:'SL',703:'SK',705:'SI',706:'SO',710:'ZA',716:'ZW',724:'ES',728:'SS',740:'SR',752:'SE',756:'CH',760:'SY',762:'TJ',764:'TH',768:'TG',780:'TT',788:'TN',792:'TR',795:'TM',800:'UG',804:'UA',784:'AE',818:'EG',826:'GB',834:'TZ',840:'US',858:'UY',860:'UZ',862:'VE',704:'VN',887:'YE',894:'ZM'};

async function initChoropleth() {
  try {
    topoWorldData = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json').then(r=>r.json());
  } catch(e) { console.warn('choropleth: could not load world atlas', e); }
}

function buildChoropleth() {
  if (!topoWorldData||!window.topojson) return;
  if (choroplethLayer) { map.removeLayer(choroplethLayer); choroplethLayer=null; }

  const byCode = {};
  (globalStats.top_countries||[]).forEach(c=>{ byCode[c.country_code]={total:c.count,blocked:c.blocked_count||0}; });

  const geojson = topojson.feature(topoWorldData, topoWorldData.objects.countries);
  choroplethLayer = L.geoJSON(geojson, {
    style: feature=>{
      const a2 = NUM_TO_A2[+feature.id];
      const st = a2 ? byCode[a2] : null;
      if (!st||!st.total) return {fillOpacity:0,weight:.3,color:'#1e2d42'};
      const ratio = st.blocked/st.total;
      const alpha = 0.12 + ratio*0.65;
      return {
        fillColor: ratio>.5 ? '#ff4455' : '#3b9eff',
        fillOpacity: alpha, weight:.5, color:'#1e2d42', opacity:.6
      };
    },
    onEachFeature:(feature,layer)=>{
      const a2 = NUM_TO_A2[+feature.id];
      const st = a2&&byCode[a2];
      if (st) {
        layer.bindTooltip(`${a2}: ${num(st.total)} req · ${num(st.blocked)} bloquées`,{className:'map-tooltip'});
        layer.on('click',()=>filterByCountry(a2));
      }
    }
  }).addTo(map);
}

function toggleChoropleth() {
  choroplethActive = !choroplethActive;
  document.getElementById('choropleth-btn').classList.toggle('active', choroplethActive);
  if (choroplethActive) buildChoropleth();
  else if (choroplethLayer) { map.removeLayer(choroplethLayer); choroplethLayer=null; }
}
document.getElementById('choropleth-btn').addEventListener('click', toggleChoropleth);

// ═══════════════════════════════════════════════════════════
//  6. WHOIS RAPIDE
// ═══════════════════════════════════════════════════════════
async function loadWhois(ip) {
  const el = document.getElementById('whois-body');
  if (!el) return;
  el.innerHTML = '<div style="padding:12px;color:var(--muted);font-size:12px;text-align:center">Chargement…</div>';
  try {
    const r = await fetch(`/whois/${ip}`);
    const d = await r.json();
    if (d.error) { el.innerHTML = `<div style="padding:12px;color:var(--danger);font-size:12px">Erreur: ${d.error}</div>`; return; }
    const rows = [
      ['Organisation', d.org||d.company],
      ['Réseau', d.network||d.subnet||d.prefix],
      ['Pays', d.country], ['Région', d.region], ['Ville', d.city],
      ['Hostname', d.hostname], ['Timezone', d.timezone],
      ['Abuse', d.abuse?.email]
    ].filter(([,v])=>v);
    el.innerHTML = `<div class="whois-body">${rows.map(([k,v])=>`
      <div class="whois-row"><span class="whois-key">${esc(k)}</span><span class="whois-val">${esc(v)}</span></div>`).join('')}</div>`;
  } catch { el.innerHTML = '<div style="padding:12px;color:var(--danger);font-size:12px">Erreur réseau</div>'; }
}

// ═══════════════════════════════════════════════════════════
//  ACTIONS (block IP / country)
// ═══════════════════════════════════════════════════════════
async function blockIP(ip) {
  if (!requireAdminClient()) return;
  try {
    const r = await adminFetch(`/block_ip/${encodeURIComponent(ip)}`,{method:'POST'});
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.detail || d.error || 'Blocage IP refusé');
    toast(`IP ${ip} enregistrée, déploiement Nginx en attente`, 'success');
    if (document.body.dataset.view === 'lists') loadSecurityLists();
  } catch (e) { toast(e.message || 'Erreur réseau', 'danger'); }
}

// 11. Bulk country block
async function blockCountry(cc, name) {
  if (!requireAdminClient()) return;
  try {
    const r = await adminFetch(`/block_country/${encodeURIComponent(cc)}`,{method:'POST'});
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.detail || d.error || 'Blocage pays refusé');
    toast(`Pays ${name||cc} enregistré, déploiement Nginx en attente`, 'success');
    if (document.body.dataset.view === 'lists') loadSecurityLists();
  } catch (e) { toast(e.message || 'Erreur réseau', 'danger'); }
}

// ═══════════════════════════════════════════════════════════
//  MODAL / BOTTOM SHEET
// ═══════════════════════════════════════════════════════════
function showModal(idx) {
  const l = allLogs[idx];
  if (!l) return;
  const bl = isBlocked(l);
  document.getElementById('modal-title').textContent = bl ? '🚫 Requête bloquée' : '✅ Requête autorisée';

  document.getElementById('modal-body').innerHTML = `
    <div class="action-bar">
      <button class="action-btn" onclick='copyClip(${jsArg(l.ip)})'>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copier IP
      </button>
      <button class="action-btn" onclick='filterByIP(${jsArg(l.ip)});closeModal()'>Filtrer IP</button>
      <button class="action-btn" onclick='showIPProfile(${jsArg(l.ip)})'>Fiche IP</button>
      ${l.host?`<button class="action-btn" onclick='filterByField(${jsArg('host')},${jsArg(l.host)});closeModal()'>Filtrer host</button>`:''}
      ${adminOnlyHtml(`<button class="action-btn danger" onclick='blockIP(${jsArg(l.ip)})'>Bloquer</button>`)}
    </div>

    <div class="modal-section-title">Géolocalisation</div>
    <div class="modal-grid">
      <div class="mcard"><div class="mcard-label">IP</div><div class="mcard-val accent">${esc(l.ip)}</div></div>
      <div class="mcard"><div class="mcard-label">Horodatage</div><div class="mcard-val">${esc(fmtDateTime(l.timestamp))}</div></div>
      <div class="mcard"><div class="mcard-label">Pays</div><div class="mcard-val">${flag(l.country_code)} ${esc(l.country_name||'—')}</div></div>
      <div class="mcard"><div class="mcard-label">Ville</div><div class="mcard-val">${esc(l.city||'—')}</div></div>
      <div class="mcard"><div class="mcard-label">ISP</div><div class="mcard-val">${esc(l.isp||'—')}</div></div>
      <div class="mcard"><div class="mcard-label">ASN</div><div class="mcard-val">${esc(l.asn||'—')}</div></div>
    </div>

    <div class="modal-section-title">Requête HTTP</div>
    <div class="modal-grid">
      <div class="mcard"><div class="mcard-label">Status</div><div class="mcard-val"><span class="status-badge ${statusClass(l.status)}">${esc(l.status)}</span></div></div>
      <div class="mcard"><div class="mcard-label">Temps</div><div class="mcard-val">${esc(parseFloat(l.request_time||0).toFixed(3))}s</div></div>
      <div class="mcard"><div class="mcard-label">Méthode</div><div class="mcard-val">${esc(l.method||'—')}</div></div>
      <div class="mcard"><div class="mcard-label">Host</div><div class="mcard-val">${esc(l.host||'—')}</div></div>
      <div class="mcard span2"><div class="mcard-label">URI</div><div class="mcard-val accent" style="font-size:11px;word-break:break-all">${esc(l.uri||'—')}</div></div>
      <div class="mcard span2"><div class="mcard-label">User-Agent</div><div class="mcard-val" style="font-size:10px;line-height:1.5">${esc(l.ua||'—')}</div></div>
    </div>

    <div class="modal-section-title">Détection menace</div>
    <div class="modal-grid">
      <div class="mcard"><div class="mcard-label">Type</div><div class="mcard-val">${esc(l.threat || 'normal')}</div></div>
      <div class="mcard"><div class="mcard-label">Score</div><div class="mcard-val accent">${esc(l.threat_score ?? 0)} / 100</div></div>
      <div class="mcard span2"><div class="mcard-label">Raisons</div><div class="mcard-val" style="font-size:10px;line-height:1.5">${esc((l.threat_reasons || []).join(', ') || '—')}</div></div>
    </div>

    <div class="modal-section-title">
      Whois
      <button class="action-btn" style="margin-left:auto;padding:3px 10px" onclick='loadWhois(${jsArg(l.ip)})'>Charger →</button>
    </div>
    <div id="whois-body" style="min-height:40px"></div>

    <div class="decision-row">
      <span class="result-badge ${bl?'r-blocked':'r-ok'}" style="font-size:13px;padding:8px 20px">${bl?'🚫 Requête bloquée':'✅ Requête autorisée'}</span>
    </div>`;

  document.getElementById('overlay').classList.add('open');
  loadWhois(l.ip);
}

function closeModal() { document.getElementById('overlay').classList.remove('open'); }
document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('overlay').addEventListener('click', e=>{ if(e.target===e.currentTarget) closeModal(); });

// ═══════════════════════════════════════════════════════════
//  7. FLOATING PILL (dernier événement SSE)
// ═══════════════════════════════════════════════════════════
let pillTimer = null;
function showFloatingPill(log) {
  const pill = document.getElementById('float-pill');
  if (!pill) return;
  const bl = isBlocked(log);
  pill.className = `float-pill ${bl?'danger':'ok'} visible`;
  pill.innerHTML = `
    <span class="pill-dot ${bl?'red':'green'}"></span>
    <span class="pill-ip">${log.ip}</span>
    <span class="pill-sep">·</span>
    <span class="pill-info">${log.country_code||'?'} ${trunc(log.uri,18)}</span>
    <span class="pill-status ${statusClass(log.status)}">${log.status}</span>`;
  pill.onclick = ()=>{
    const idx = allLogs.findIndex(l=>l.ip===log.ip&&l.timestamp===log.timestamp);
    if (idx>=0) showModal(idx); else { filterByIP(log.ip); }
  };
  clearTimeout(pillTimer);
  pillTimer = setTimeout(()=>pill.classList.remove('visible'), 7000);
}

// ═══════════════════════════════════════════════════════════
//  10. BLOCK LIST MANAGER
// ═══════════════════════════════════════════════════════════
async function loadBlocklist() {
  try {
    const r = await adminFetch('/blocklist');
    const items = await r.json();
    const cnt = document.getElementById('bl-count');
    if (cnt) cnt.textContent = `${items.length} entrée${items.length!==1?'s':''}`;
    const el = document.getElementById('bl-list');
    if (!el) return;
    if (!items.length) {
      el.innerHTML = '<div style="padding:20px;text-align:center;color:var(--muted);font-size:12px">Aucune entrée bloquée</div>';
      return;
    }
    el.innerHTML = items.map(item=>`
      <div class="bl-item">
        <div class="bl-item-head">
          <span class="bl-type ${esc(item.type)}">${esc(item.type)}</span>
          <span class="bl-value">${esc(item.value)}</span>
          <button class="bl-remove" onclick="removeBlock(${item.id})" title="Supprimer">✕</button>
        </div>
        <div class="bl-reason">Portée : ${item.host ? esc(item.host) : 'Global'}</div>
        ${item.reason?`<div class="bl-reason">${esc(item.reason)}</div>`:''}
        <div class="bl-date">${fmtDateTime(item.created_at)}</div>
      </div>`).join('');
  } catch(e) { console.error('blocklist:', e); }
}

async function addBlock() {
  if (!requireAdminClient()) return;
  if (!requiredInput('bl-input', 'bl-form-feedback', 'Renseigne une IP, un CIDR ou un code pays.')) return;
  await withBusyButton('bl-add', 'Ajout…', async () => {
    const value = document.getElementById('bl-input').value.trim();
    const reason = document.getElementById('bl-reason').value.trim();
    const host = document.getElementById('bl-host')?.value.trim() || null;
    const type = value.includes('/') ? 'cidr' : /^[A-Za-z]{2}$/.test(value) ? 'country' : 'ip';
    formFeedback('bl-form-feedback', 'Enregistrement de la règle…', 'loading');
    try {
      const r = await adminFetch('/blocklist', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({type, value, reason, host})
      });
      const d = await r.json();
      if (!r.ok || d.error) throw new Error(apiErrorMessage(d, 'Ajout de règle refusé'));
      document.getElementById('bl-input').value = '';
      document.getElementById('bl-reason').value = '';
      document.getElementById('bl-host').value = '';
      const message = `${value} enregistré pour ${host || 'tous les domaines'}. Application Nginx en attente.`;
      formFeedback('bl-form-feedback', message, 'success');
      toast(message, 'success');
      await loadBlocklist();
      if (document.body.dataset.view === 'lists') await loadSecurityLists();
      if (document.body.dataset.view === 'control') void loadSecurityControl();
    } catch (e) {
      formFeedback('bl-form-feedback', e.message || 'Ajout refusé', 'error');
      toast(e.message || 'Ajout refusé', 'danger');
    }
  });
}

async function removeBlock(id) {
  if (!requireAdminClient()) return;
  try {
    const r = await adminFetch(`/blocklist/${encodeURIComponent(id)}`, {method:'DELETE'});
    const data = await r.json();
    if (!r.ok || data.error) throw new Error(apiErrorMessage(data, 'Suppression refusée'));
    toast('Règle supprimée. Application Nginx en attente.', 'success');
    await loadBlocklist();
    if (document.body.dataset.view === 'lists') await loadSecurityLists();
    if (document.body.dataset.view === 'control') void loadSecurityControl();
  } catch (e) {
    toast(e.message || 'Suppression impossible', 'danger');
  }
}

document.getElementById('bl-add').addEventListener('click', addBlock);
document.getElementById('bl-input').addEventListener('keydown', e=>{ if(e.key==='Enter') addBlock(); });

// ═══════════════════════════════════════════════════════════
//  MAP
// ═══════════════════════════════════════════════════════════
function initMap() {
  map = L.map('map',{
    zoomControl:false, attributionControl:false, scrollWheelZoom:true,
    dragging:true, doubleClickZoom:true, center:[30,10], zoom:2, minZoom:2, maxZoom:8,
  });
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png',{maxZoom:19}).addTo(map);
  L.control.zoom({position:'bottomright'}).addTo(map);
  ensureMapHud();
}

function ensureMapHud() {
  const section = document.getElementById('map-section');
  if (!section || document.getElementById('map-live-hud')) return;
  section.insertAdjacentHTML('beforeend', `
    <div class="map-live-hud" id="map-live-hud">
      <div class="map-live-title"><span class="map-live-pulse ok" id="map-live-pulse"></span>Carte live</div>
      <div class="map-live-last" id="map-live-last">En attente d'une nouvelle tentative…</div>
      <div class="map-live-meta">
        <span><b class="c-green" id="map-ok-count">0</b> légitimes</span>
        <span><b class="c-red" id="map-blocked-count">0</b> bloquées</span>
      </div>
    </div>`);
}

function updateMapHud(log, blocked) {
  ensureMapHud();
  const pulse = document.getElementById('map-live-pulse');
  const last = document.getElementById('map-live-last');
  const okCount = document.getElementById('map-ok-count');
  const blockedCount = document.getElementById('map-blocked-count');
  if (pulse) {
    pulse.classList.toggle('blocked', !!blocked);
    pulse.classList.toggle('ok', !blocked);
    pulse.classList.remove('flash');
    void pulse.offsetWidth;
    pulse.classList.add('flash');
  }
  if (last) {
    const verdict = blocked ? 'Bloquée' : 'Légitime';
    const ip = log?.ip || 'IP inconnue';
    const status = log?.status ? `HTTP ${log.status}` : 'HTTP ?';
    const geo = log?.country_name || log?.country_code || '?';
    const host = log?.host || '-';
    last.textContent = `${verdict} · ${ip} · ${status} · ${geo} · ${host}`;
  }
  const ok = mapMarkers.filter(m => m?.options?.npmBlocked === false).length;
  const ko = mapMarkers.filter(m => m?.options?.npmBlocked === true).length;
  if (okCount) okCount.textContent = num(ok);
  if (blockedCount) blockedCount.textContent = num(ko);
}

function addMapDot(lat, lng, blocked, label, opts = {}) {
  if (!map||!lat||!lng||(lat===0&&lng===0)) return;
  const live = opts.live !== false;
  const type = blocked ? 'blocked' : 'ok';
  const size = blocked ? 16 : 14;
  const marker = L.marker([lat,lng], {
    keyboard:false,
    interactive:true,
    npmBlocked: !!blocked,
    icon: L.divIcon({
      className:'npm-map-dot-icon',
      html:`<span class="npm-map-dot ${type} ${live ? 'live' : 'history'}"></span>`,
      iconSize:[size,size],
      iconAnchor:[size/2,size/2],
    })
  }).addTo(map);

  marker.bindTooltip(label,{direction:'top',offset:[0,-8],className:'map-tooltip',opacity:.95});
  mapMarkers.push(marker); mapDotCount++;
  const counter = document.getElementById('map-counter');
  if (counter) counter.textContent=`${mapDotCount} pts`;

  if (live) {
    updateMapHud(opts.log || null, blocked);
    setTimeout(()=>{
      try {
        const el = marker.getElement()?.querySelector('.npm-map-dot');
        if (el) { el.classList.remove('live'); el.classList.add('settled'); }
      } catch {}
    }, 9000);
  }

  while(mapMarkers.length>MAX_MAP_DOTS){const old=mapMarkers.shift();try{map.removeLayer(old);}catch{}}

  // Keep the map readable: old live dots fade after 5 min. History dots stay until capped.
  if (live) {
    setTimeout(()=>{ try { map.removeLayer(marker); } catch {} }, 300000);
  }
}

function mapLabel(log) {
  return `${isBlocked(log)?'🚫 Bloqué':'🟢 Légitime'} ${esc(log.ip||'—')}<br>${esc(log.country_name||log.country_code||'?')} · ${esc((log.uri||'').substring(0,36))}`;
}

async function loadMapHistory() {
  try {
    const r = await fetch('/history?limit=300');
    const d = await r.json();
    (d.logs||[]).reverse().forEach(log=>addMapDot(parseFloat(log.latitude||0),parseFloat(log.longitude||0),isBlocked(log),mapLabel(log),{live:false,log}));
    updateMapHud(null, false);
  } catch(e) { console.error('map history:', e); }
}

// ═══════════════════════════════════════════════════════════
//  8. SSE WITH EXPONENTIAL BACKOFF
// ═══════════════════════════════════════════════════════════
function connectSSE() {
  let retryDelay = 1000;
  let lastEventId = null;
  const MAX_DELAY = 60000;

  function connect() {
    const dot  = document.getElementById('conn-dot');
    const text = document.getElementById('conn-text');
    const src  = new EventSource('/events' + (lastEventId !== null ? `?since_id=${lastEventId}` : ''));

    src.onopen = ()=>{
      dot.className=''; text.textContent='Connecté';
      retryDelay=1000;
      document.getElementById('last-update').textContent='';
    };

    src.onmessage = e=>{
      if (e.lastEventId) lastEventId = Number(e.lastEventId);
      const log = JSON.parse(e.data);
      retryDelay = 1000;

      addMapDot(parseFloat(log.latitude||0),parseFloat(log.longitude||0),isBlocked(log),mapLabel(log),{live:true,log});

      // Incremental stats (invalidate cache so next full load refreshes)
      globalStats.total++;
      if (isBlocked(log)) globalStats.blocked++; else globalStats.allowed++;
      statsCache = null;

      const cc = log.country_code;
      let found = globalStats.top_countries.find(c=>c.country_code===cc);
      if (found){found.count++;if(isBlocked(log))found.blocked_count++;}
      else globalStats.top_countries.push({country_code:cc,country_name:log.country_name,count:1,blocked_count:isBlocked(log)?1:0});
      globalStats.top_countries.sort((a,b)=>b.count-a.count);

      const sd = globalStats.status_dist.find(s=>s.status===log.status);
      if (sd) sd.count++; else globalStats.status_dist.push({status:log.status,count:1});

      updateHeaderStats();
      renderSidebar();

      // 7. Floating pill
      showFloatingPill(log);
      notifyThreat(log);
      loadSecurityActivity();

      // Slide new row in — no full table re-render on page 1
      if (serverPage===1 && cursorStack.length===0 && !searchTerm && currentFilter==='all') {
        prependRow(log);
      } else if (serverPage===1 && cursorStack.length===0) {
        loadPage('first');
      }
      document.getElementById('last-update').innerHTML=`· ${fmtTime(new Date().toISOString())}`;

      // Update choropleth if active
      if (choroplethActive && topoWorldData) buildChoropleth();
    };

    src.onerror = ()=>{
      dot.className='error';
      text.textContent=`Reconnexion ${Math.round(retryDelay/1000)}s…`;
      src.close();
      const delay=retryDelay;
      retryDelay=Math.min(retryDelay*2, MAX_DELAY);
      setTimeout(connect, delay);
    };
  }
  connect();
}


// ═══════════════════════════════════════════════════════════
//  PATCH 3 · THREATS / BAN HISTORY / EXPORTS
// ═══════════════════════════════════════════════════════════
function threatClass(score) {
  score = Number(score || 0);
  if (score >= 75) return 'threat-critical';
  if (score >= 50) return 'threat-high';
  if (score >= 25) return 'threat-mid';
  return 'threat-low';
}

async function loadThreats() {
  const tbody = document.getElementById('threat-tbody');
  if (!tbody) return;
  const minScore = document.getElementById('threat-min-score')?.value || '50';
  tbody.innerHTML = `<tr><td colspan="6"><div class="empty"><div class="empty-icon">⏳</div><p>Chargement des menaces…</p></div></td></tr>`;
  try {
    const r = await fetch(`/threats?limit=100&min_score=${encodeURIComponent(minScore)}`);
    const items = await r.json();
    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="6"><div class="empty"><div class="empty-icon">🧘</div><p>Aucune menace détectée pour ce seuil</p></div></td></tr>`;
      return;
    }
    tbody.innerHTML = items.map(t => `
      <tr>
        <td class="time-cell">${fmtTime(t.created_at)}</td>
        <td class="ip-cell">${esc(t.ip)}</td>
        <td><span class="threat-score ${threatClass(t.score)}">${esc(t.score)}</span></td>
        <td class="threat-type">${esc(t.threat_type)}</td>
        <td class="col-lg uri-cell" title="${esc(t.uri || '')}">${esc(trunc(t.uri || '—', 70))}</td>
        <td>
          <button class="action-btn" onclick='filterByIP(${jsArg(t.ip)})'>Filtrer</button>
          ${adminOnlyHtml(`<button class="action-btn danger" onclick='blockIP(${jsArg(t.ip)})'>Bloquer</button>`)}
        </td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty"><div class="empty-icon">⚠️</div><p>Erreur de chargement des menaces</p></div></td></tr>`;
  }
}

async function loadBanEvents() {
  const el = document.getElementById('ban-events-list');
  if (!el) return;
  const isOpen = el.style.display !== 'none';
  el.style.display = isOpen ? 'none' : 'block';
  if (isOpen) return;
  el.innerHTML = '<div class="ban-event">Chargement…</div>';
  try {
    const r = await adminFetch('/ban-events?limit=50');
    const items = await r.json();
    if (!items.length) {
      el.innerHTML = '<div class="ban-event">Aucun événement de bannissement</div>';
      return;
    }
    el.innerHTML = items.map(b => `
      <div class="ban-event">
        <div class="ban-event-main">
          <span class="ban-event-target">${esc(b.target)}</span>
          <span class="ban-event-action ${esc(String(b.action || '').toLowerCase())}">${esc(b.action)}</span>
        </div>
        <div class="ban-event-meta">${esc(b.type)} · ${esc(b.reason || '—')} · ${fmtDateTime(b.created_at)}</div>
      </div>`).join('');
  } catch {
    el.innerHTML = '<div class="ban-event">Erreur chargement historique</div>';
  }
}

function initLogPurge() {
  const dialog = document.getElementById('logs-purge-dialog');
  const opener = document.getElementById('logs-purge-open');
  const input = document.getElementById('logs-purge-confirm');
  const submit = document.getElementById('logs-purge-submit');
  const cancel = document.getElementById('logs-purge-cancel');
  const form = document.getElementById('logs-purge-form');
  const status = document.getElementById('logs-purge-dialog-status');
  if (!dialog || !opener || !input || !submit || !cancel || !form || !status) return;

  opener.addEventListener('click', () => {
    if (!requireAdminClient()) return;
    if (typeof dialog.showModal !== 'function') {
      toast('La confirmation de purge n’est pas prise en charge par ce navigateur.', 'danger');
      return;
    }
    input.value = '';
    submit.disabled = true;
    status.textContent = '';
    status.dataset.state = '';
    dialog.showModal();
    input.focus();
  });

  input.addEventListener('input', () => {
    submit.disabled = input.value !== 'PURGER';
    if (status.dataset.state === 'error') status.textContent = '';
  });
  cancel.addEventListener('click', () => {
    if (submit.getAttribute('aria-busy') === 'true') return;
    dialog.close();
  });
  dialog.addEventListener('cancel', event => {
    if (submit.getAttribute('aria-busy') === 'true') event.preventDefault();
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!requireAdminClient()) return;
    if (input.value !== 'PURGER') {
      status.dataset.state = 'error';
      status.textContent = 'Saisis exactement PURGER pour confirmer la suppression.';
      toast(status.textContent, 'warning');
      input.focus();
      return;
    }
    await withBusyButton('logs-purge-submit', 'Suppression…', async () => {
      status.dataset.state = 'loading';
      status.textContent = 'Purge des logs et événements dérivés en cours…';
      try {
        const r = await adminFetch('/db/purge-logs', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Purge-Confirmation': 'PURGER'
          },
          body: JSON.stringify({confirmation: 'PURGER'})
        });
        const data = await r.json();
        if (!r.ok || data.status !== 'ok') throw new Error(apiErrorMessage(data, 'Purge refusée'));
        const count = Number(data.deleted?.access_logs || 0);
        const message = `Purge terminée : ${count.toLocaleString('fr-FR')} logs supprimés. Règles et collecteur préservés.`;
        const feedback = document.getElementById('log-purge-feedback');
        if (feedback) {
          feedback.textContent = message;
          feedback.dataset.state = 'success';
        }
        dialog.close();
        toast(message, 'success', 6500);
        void loadStats(true);
        void loadPage('first');
        void loadTimeline();
        void loadHeatmap();
        if (document.body.dataset.view === 'control') void loadSecurityControl();
      } catch (error) {
        status.dataset.state = 'error';
        status.textContent = error.message || 'Purge impossible : aucun changement confirmé.';
        toast(status.textContent, 'danger', 6000);
      }
    });
  });
}

initLogPurge();

function openExport(kind) {
  if (!requireAdminClient()) return;
  const url = kind === 'nginx' ? '/blocklist/export/nginx' : '/blocklist/export/json';
  toast(`Ouverture de l'export ${kind === 'nginx' ? 'Nginx' : 'JSON'} dans un nouvel onglet…`, 'info');
  window.open(url, '_blank', 'noopener,noreferrer');
}

async function applyBlocklistExport(reload = false) {
  if (!requireAdminClient()) return;
  if (reload && !confirm('Demander un rechargement Nginx ? Le dashboard ne peut recharger NPM que si le mécanisme d’administration est explicitement activé.')) {
    toast('Rechargement annulé : aucun fichier modifié.', 'info');
    return;
  }
  const status = document.getElementById('bl-export-status');
  const buttonId = reload ? 'bl-apply-reload' : 'bl-apply-export';
  await withBusyButton(buttonId, 'Écriture…', async () => {
    if (status) {
      status.dataset.state = 'loading';
      status.textContent = 'Génération des fichiers en cours…';
    }
    try {
      const r = await adminFetch(`/blocklist/export/apply?reload=${reload ? 'true' : 'false'}`, {method:'POST'});
      const d = await r.json();
      if (!r.ok || d.error || d.status !== 'ok') throw new Error(apiErrorMessage(d, 'Erreur export'));
      const info = d.export || {};
      const reloaded = d.reload?.executed === true && d.reload?.ok !== false;
      const paths = [info.nginx_path, info.server_guard_path, info.json_path].filter(Boolean);
      const reloadMessage = reload
        ? (reloaded ? 'Rechargement confirmé' : `Aucun rechargement exécuté : ${d.reload?.message || 'mécanisme désactivé'}`)
        : 'Aucun rechargement Nginx demandé.';
      const message = `Fichiers générés : ${paths.length ? paths.join(' · ') : 'exports NPM Security'}.
${reloadMessage}`;
      if (status) {
        status.dataset.state = 'success';
        status.textContent = message;
      }
      toast(reloaded || !reload ? 'Exports Nginx et garde serveur générés' : 'Exports générés, Nginx non rechargé', reloaded || !reload ? 'success' : 'warning', 5500);
      await loadBanEvents();
    } catch (e) {
      if (status) {
        status.dataset.state = 'error';
        status.textContent = e.message || 'Erreur pendant la génération des exports.';
      }
      toast(e.message || 'Erreur pendant la génération des exports', 'danger', 5500);
    }
  });
}

async function loadTrusted() {
  try {
    const r = await adminFetch('/trusted');
    const items = await r.json();
    const cnt = document.getElementById('trusted-count');
    if (cnt) cnt.textContent = `${items.length} entrée${items.length!==1?'s':''}`;
    const el = document.getElementById('trusted-list');
    if (!el) return;
    if (!items.length) {
      el.innerHTML = '<div style="padding:12px 0;color:var(--muted);font-size:12px">Aucune entrée de confiance</div>';
      return;
    }
    el.innerHTML = items.map(item => `
      <div class="bl-item trusted-item">
        <div class="bl-item-head">
          <span class="bl-type trusted">${esc(item.type)}</span>
          <span class="bl-value">${esc(item.value)}</span>
          <button class="bl-remove" onclick="removeTrusted(${item.id})" title="Supprimer">✕</button>
        </div>
        ${item.reason?`<div class="bl-reason">${esc(item.reason)}</div>`:''}
        <div class="bl-date">${fmtDateTime(item.created_at)}</div>
      </div>`).join('');
  } catch(e) { console.error('trusted:', e); }
}

async function addTrusted() {
  if (!requireAdminClient()) return;
  if (!requiredInput('trusted-input', 'trusted-form-feedback', 'Renseigne une IP, un CIDR, un pays ou un User-Agent.')) return;
  await withBusyButton('trusted-add', 'Ajout…', async () => {
    const raw = document.getElementById('trusted-input').value.trim();
    const reason = document.getElementById('trusted-reason').value.trim();
    let type = 'ip';
    let value = raw;
    if (/^ua:/i.test(raw)) { type = 'ua'; value = raw.slice(3).trim(); }
    else if (raw.includes('/')) type = 'cidr';
    else if (/^[A-Za-z]{2}$/.test(raw)) { type = 'country'; value = raw.toUpperCase(); }
    if (!value) {
      formFeedback('trusted-form-feedback', 'Saisis une valeur après UA:.', 'error');
      toast('Saisis une valeur après UA:.', 'warning');
      document.getElementById('trusted-input')?.focus();
      return;
    }
    formFeedback('trusted-form-feedback', 'Ajout de l’exception de confiance…', 'loading');
    try {
      const r = await adminFetch('/trusted', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type,value,reason})});
      const d = await r.json();
      if (!r.ok || d.error) throw new Error(apiErrorMessage(d, 'Erreur whitelist'));
      document.getElementById('trusted-input').value = '';
      document.getElementById('trusted-reason').value = '';
      formFeedback('trusted-form-feedback', `${value} ajouté aux entrées de confiance.`, 'success');
      toast(`${value} ajouté à la liste de confiance`, 'success');
      await loadTrusted();
      loadBanEvents();
      if (document.body.dataset.view === 'lists') await loadSecurityLists();
      if (document.body.dataset.view === 'control') void loadSecurityControl();
    } catch(e) {
      formFeedback('trusted-form-feedback', e.message || 'Erreur ajout whitelist', 'error');
      toast(e.message || 'Erreur ajout whitelist', 'danger');
    }
  });
}

async function removeTrusted(id) {
  if (!requireAdminClient()) return;
  try {
    const r = await adminFetch(`/trusted/${encodeURIComponent(id)}`, {method:'DELETE'});
    const data = await r.json();
    if (!r.ok || data.error) throw new Error(apiErrorMessage(data, 'Suppression refusée'));
    toast('Exception de confiance supprimée', 'success');
    await loadTrusted();
    loadBanEvents();
    if (document.body.dataset.view === 'lists') await loadSecurityLists();
    if (document.body.dataset.view === 'control') void loadSecurityControl();
  } catch(e) {
    toast(e.message || 'Erreur de suppression', 'danger');
  }
}

// ═══════════════════════════════════════════════════════════
//  PATCH 5.1 · SECURITY LISTS DEDICATED VIEW
// ═══════════════════════════════════════════════════════════
let currentListTab = 'all';
let securityListsLoading = false;

function detectListType(raw) {
  const value = String(raw || '').trim();
  if (/^ua:/i.test(value)) return {type:'ua', value:value.slice(3).trim()};
  if (value.includes('/')) return {type:'cidr', value};
  if (/^[A-Za-z]{2}$/.test(value)) return {type:'country', value:value.toUpperCase()};
  return {type:'ip', value};
}

function emptyRow(colspan, icon, text) {
  return `<tr><td colspan="${colspan}"><div class="empty"><div class="empty-icon">${icon}</div><p>${esc(text)}</p></div></td></tr>`;
}

function applyListTab(tab) {
  currentListTab = tab || 'all';
  document.querySelectorAll('[data-list-tab]').forEach(btn => btn.classList.toggle('active', btn.dataset.listTab === currentListTab));
  document.querySelectorAll('[data-list-section]').forEach(sec => {
    const section = sec.dataset.listSection;
    sec.style.display = (currentListTab === 'all' || currentListTab === section) ? '' : 'none';
  });
}

async function fetchJsonSafe(url) {
  const r = await adminFetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function loadPolicyModes() {
  const target = document.getElementById('security-modes-list');
  const status = document.getElementById('security-modes-status');
  if (!target || !status) return;
  try {
    const data = await fetchJsonSafe('/security-control/policy/modes');
    const globalMode = data.default_mode || 'block';
    const overrides = data.overrides || [];
    const state = data.policy?.state || 'not_configured';
    status.dataset.state = state;
    status.textContent = `Mode global : ${globalMode === 'observe' ? 'Observation' : 'Blocage'} · Déploiement : ${state} · ${overrides.length} domaine(s) avec mode spécifique`;
    target.innerHTML = overrides.length ? overrides.map(item => `
      <div class="security-mode-item">
        <span><strong>${esc(item.host)}</strong> : ${item.mode === 'observe' ? 'Observation (sans 403)' : 'Blocage (403)'}</span>
        <button type="button" class="list-action-btn" data-reset-mode="${esc(item.host)}">Réinitialiser</button>
      </div>`).join('') : '<span class="security-mode-empty">Aucun mode particulier : tous les domaines héritent du mode global.</span>';
  } catch (error) {
    status.dataset.state = 'error';
    status.textContent = 'Lecture des modes impossible.';
    target.textContent = '';
  }
}

async function savePolicyMode(event) {
  event.preventDefault();
  if (!requireAdminClient()) return;
  const host = document.getElementById('security-modes-host')?.value.trim() || '';
  const mode = document.getElementById('security-modes-mode')?.value || 'block';
  if (mode === 'observe' && !confirm(
    `Passer ${host || 'TOUS les domaines par défaut'} en OBSERVATION ? Après application Nginx, les règles ne renverront plus de 403 pour cette portée.`
  )) return;

  try {
    const response = await adminFetch('/security-control/policy/modes', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({host, mode})
    });
    const result = await response.json();
    if (!response.ok || result.error) throw new Error(result.detail || result.error || 'Mode non enregistré');
    toast(`Mode ${mode} enregistré pour ${host || 'tous les domaines'}. Application Nginx en attente.`, 'success');
    document.getElementById('security-modes-host').value = '';
    await loadPolicyModes();
    void loadSecurityControlOverview();
  } catch (error) {
    toast(error.message || 'Impossible de modifier le mode', 'danger');
  }
}

async function resetPolicyMode(host) {
  if (!requireAdminClient()) return;
  if (!confirm(`Supprimer le mode spécifique de ${host} ? Ce domaine héritera du mode global à la prochaine application Nginx.`)) return;
  try {
    const response = await adminFetch(
      '/security-control/policy/modes?host=' + encodeURIComponent(host),
      {method: 'DELETE'}
    );
    const result = await response.json();
    if (!response.ok || result.error) throw new Error(result.detail || result.error || 'Réinitialisation refusée');
    toast(`Mode spécifique retiré pour ${host}. Application Nginx en attente.`, 'success');
    await loadPolicyModes();
    void loadSecurityControlOverview();
  } catch (error) {
    toast(error.message || 'Réinitialisation impossible', 'danger');
  }
}

async function simulateSavedSecurityPolicy(event) {
  event.preventDefault();
  if (!requireAdminClient()) return;
  const container = document.getElementById('security-preview-result');
  const ip = document.getElementById('security-preview-ip')?.value.trim() || '';
  const host = document.getElementById('security-preview-host')?.value.trim() || '';
  const country = document.getElementById('security-preview-country')?.value.trim() || '';
  if (!container) return;
  if (!ip || !host) {
    const missing = !ip ? 'security-preview-ip' : 'security-preview-host';
    const message = 'La simulation nécessite une adresse IP et un domaine cible.';
    container.dataset.decision = 'error';
    container.textContent = message;
    document.getElementById(missing)?.setAttribute('aria-invalid', 'true');
    document.getElementById(missing)?.focus();
    toast(message, 'warning', 5500);
    return;
  }
  document.getElementById('security-preview-ip')?.removeAttribute('aria-invalid');
  document.getElementById('security-preview-host')?.removeAttribute('aria-invalid');
  const params = new URLSearchParams({ip, host});
  if (country) params.set('country_code', country);
  container.textContent = 'Évaluation des règles enregistrées…';
  container.dataset.decision = 'loading';

  try {
    const result = await fetchJsonSafe(`/security-control/policy/preview?${params}`);
    const labels = {allow: 'Autorisation prévue', deny: 'Blocage prévu', unknown: 'Décision indéterminée'};
    const decision = result.predicted_decision || 'unknown';
    const mode = result.enforcement_mode || 'block';
    const scope = result.policy?.state || 'not_configured';
    const rules = result.matching_block_rules || [];
    const trusts = result.trusted_matches || [];
    const info = rules.map(rule =>
      `<li>${esc(rule.type)} : <strong>${esc(rule.value)}</strong> (${rule.host ? esc(rule.host) : 'Global'})</li>`
    ).join('');
    const exceptions = trusts.map(rule =>
      `<li>${esc(rule.type)} : ${esc(rule.value)}</li>`
    ).join('');

    container.dataset.decision = decision;
    container.innerHTML = `
      <div class="security-preview-decision">${esc(labels[decision] || 'Inconnu')}</div>
      <p>Mode enregistré : <strong>${mode === 'observe' ? 'Observation, sans blocage 403' : 'Blocage'}</strong>
      ${mode === 'observe' && result.would_deny ? '· Les règles auraient refusé cette requête en mode Blocage.' : ''}</p>
      <p>IP <strong>${esc(result.ip)}</strong> · Domaine <strong>${esc(result.host)}</strong>
         · Pays : ${esc(result.country_code || 'non renseigné')}</p>
      ${rules.length ? `<p>Règles correspondantes :</p><ul>${info}</ul>` : '<p>Aucune règle de refus ne correspond aux données fournies.</p>'}
      ${trusts.length ? `<p>Exceptions de confiance prioritaires :</p><ul>${exceptions}</ul>` : ''}
      ${result.requires_country ? '<p>Un pays manque pour déterminer si certaines règles géographiques s’appliquent.</p>' : ''}
      <p>État du déploiement NPM : <strong>${esc(scope)}</strong>.</p>
      <small>Simulation des règles en base. Le résultat ne vérifie pas une requête réelle auprès de Nginx.</small>
    `;
  } catch (error) {
    container.dataset.decision = 'error';
    container.textContent = error.message || 'Impossible de simuler cette politique.';
    toast(container.textContent, 'danger');
  }
}

async function loadSecurityControlOverview() {
  const root = document.getElementById('security-control-overview');
  if (!root) return;
  const put = (id, value) => {
    const target = document.getElementById(id);
    if (target) target.textContent = String(value);
  };
  const pretty = value => Number(value || 0).toLocaleString('fr-FR');
  const state = document.getElementById('control-policy-state');
  const alert = document.getElementById('control-policy-message');

  try {
    const overview = await fetchJsonSafe('/security-control/overview?hours=24');
    const policy = overview.policy || {};
    const byType = overview.rules?.by_type || {};
    const mode = overview.auto_ban_mode || 'off';
    const deploymentState = policy.state || 'not_configured';
    const labels = {
      applied: 'Dernière application confirmée',
      pending: 'Application en attente',
      not_configured: 'NPM non configuré'
    };
    if (state) {
      state.textContent = labels[deploymentState] || 'État inconnu';
      state.dataset.state = deploymentState;
    }
    if (alert) {
      alert.dataset.state = deploymentState;
      alert.textContent = deploymentState === 'applied'
        ? 'La configuration exportée correspond à la dernière validation et recharge Nginx enregistrée. Cela ne remplace pas une vérification en direct du proxy.'
        : deploymentState === 'pending'
          ? 'Les règles sont enregistrées, mais leur application dans NPM n’est pas confirmée. Vérifie nginx -t puis applique le rechargement depuis l’hôte.'
          : 'Aucun déploiement de règles confirmé. Configure les includes NPM avant de considérer ces blocages comme effectifs.';
    }

    put('control-active-rules', pretty(overview.rules?.active_total));
    put('control-rules-breakdown', `${pretty(byType.ip)} IP · ${pretty(byType.cidr)} réseaux · ${pretty(byType.country)} pays`);
    put('control-trusted-count', pretty(overview.rules?.trusted_total));
    put('control-proxy-blocked', pretty(overview.traffic?.proxy_blocked));
    put('control-threat-signals', pretty(overview.detections?.signals));
    put('control-threat-breakdown', `${pretty(overview.detections?.brute_force)} brute force · ${pretty(overview.detections?.http_scans)} scans HTTP`);
    const modes = { off: 'Désactivé', simulation: 'Simulation', active: 'Activé' };
    put('control-auto-ban-mode', `Auto-ban : ${modes[mode] || 'Inconnu'}`);
    put('control-traffic-count', `Trafic 24 h : ${pretty(overview.traffic?.requests)} requêtes · ${pretty(overview.traffic?.unique_ips)} IP`);
  } catch (err) {
    if (state) {
      state.textContent = 'Indisponible';
      state.dataset.state = 'error';
    }
    if (alert) {
      alert.textContent = 'Impossible de vérifier les règles Nginx. Aucun état « appliqué » ne peut être confirmé.';
      alert.dataset.state = 'error';
    }
  }
}

let observationIncidentsLoading = false;

async function loadObservationIncidents() {
  const body = document.getElementById('observation-incidents-body');
  if (!body || observationIncidentsLoading) return;
  observationIncidentsLoading = true;
  const note = document.getElementById('observation-telemetry-note');
  const alertsBox = document.getElementById('observation-alert-history');
  const hours = Number(document.getElementById('observation-hours')?.value || 24);
  const status = document.getElementById('observation-status')?.value || 'all';
  const pretty = value => Number(value || 0).toLocaleString('fr-FR');
  const put = (id, value) => {
    const element = document.getElementById(id);
    if (element) element.textContent = String(value);
  };
  body.innerHTML = '<tr><td colspan="6">Chargement des incidents…</td></tr>';

  try {
    const query = new URLSearchParams({hours: String(hours), limit: '50', status});
    const [result, alerts] = await Promise.all([
      fetchJsonSafe(`/security-control/observations?${query}`),
      fetchJsonSafe(`/security-control/observations/alerts?hours=${hours}&limit=10`)
    ]);
    const instrumented = result.telemetry_available;
    if (note) {
      note.dataset.state = instrumented ? 'available' : 'missing';
      note.textContent = instrumented
        ? `Télémétrie Nginx active : ${pretty(result.telemetry?.instrumented_requests)} requêtes instrumentées sur la période. Les alertes sont enregistrées en base ; Discord est facultatif.`
        : 'Aucune télémétrie Nginx instrumentée sur cette période. Ajouter npm_security_policy_mode et npm_security_would_deny au log JSON pour alimenter cette console. Aucune attaque n’est déduite des règles enregistrées.';
    }
    put('observation-would-deny', pretty(result.telemetry?.would_deny_requests));
    put('observation-alerts-count', pretty(result.alert_count));
    put('observation-incident-count', pretty(result.items?.length));

    const states = {open: 'Ouvert', acknowledged: 'Acquitté', resolved: 'Résolu'};
    const rows = result.items || [];
    body.innerHTML = rows.length ? rows.map(item => {
      const id = Number(item.id);
      const state = states[item.status] || 'Inconnu';
      const actions = item.status === 'open'
        ? `<button type="button" class="list-action-btn" data-observation-id="${id}" data-observation-status="acknowledged">Acquitter</button>
           <button type="button" class="list-action-btn" data-observation-id="${id}" data-observation-status="resolved">Résoudre</button>`
        : item.status === 'acknowledged'
          ? `<button type="button" class="list-action-btn" data-observation-id="${id}" data-observation-status="resolved">Résoudre</button>`
          : `<button type="button" class="list-action-btn" data-observation-id="${id}" data-observation-status="open">Rouvrir</button>`;
      return `<tr>
        <td class="ip-cell"><strong>${esc(item.host || '—')}</strong><small class="suspect-country">${esc(item.ip || '—')}</small></td>
        <td><strong>${pretty(item.hits)}</strong></td>
        <td class="ip-cell">${esc(item.last_uri || '—')}</td>
        <td><span class="observation-state" data-state="${esc(item.status)}">${esc(state)}</span></td>
        <td class="time-cell">${fmtDateTime(item.last_seen)}</td>
        <td class="observation-actions">${actions}</td>
      </tr>`;
    }).join('') : '<tr><td colspan="6">Aucun incident d’observation pour ce filtre.</td></tr>';

    if (alertsBox) {
      alertsBox.innerHTML = alerts.length
        ? `<strong>Dernières alertes</strong><ul>${alerts.map(a =>
            `<li>${esc(a.host)} · ${esc(a.ip)} · ${pretty(a.recent_hits)} signaux / fenêtre · ${fmtDateTime(a.created_at)}</li>`
          ).join('')}</ul>`
        : '<span>Aucune alerte enregistrée sur cette période.</span>';
    }
  } catch (error) {
    if (note) {
      note.dataset.state = 'error';
      note.textContent = 'Impossible de lire la télémétrie ou les alertes.';
    }
    body.innerHTML = '<tr><td colspan="6">Erreur de récupération des incidents.</td></tr>';
    if (alertsBox) alertsBox.textContent = '';
  } finally {
    observationIncidentsLoading = false;
  }
}

async function changeObservationStatus(event) {
  const button = event.target.closest('button[data-observation-id]');
  if (!button || !requireAdminClient()) return;
  const id = Number(button.dataset.observationId);
  const status = button.dataset.observationStatus;
  if (!Number.isSafeInteger(id) || id < 1 || !['open', 'acknowledged', 'resolved'].includes(status)) return;
  const confirmation = status === 'resolved'
    ? 'Marquer cet incident comme résolu ? Une nouvelle requête observée le rouvrira.'
    : status === 'open'
      ? 'Rouvrir cet incident ?'
      : 'Acquitter cet incident ?';
  if (!confirm(confirmation)) return;
  button.disabled = true;
  try {
    const response = await adminFetch(`/security-control/observations/${id}/status`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({status})
    });
    const result = await response.json();
    if (!response.ok || result.error) throw new Error(result.detail || result.error || 'Action refusée');
    toast('Incident mis à jour. Aucune règle Nginx modifiée.', 'success');
    await loadObservationIncidents();
  } catch (error) {
    toast(error.message || 'Mise à jour impossible', 'danger');
  } finally {
    button.disabled = false;
  }
}

let securitySuspectsLoading = false;

async function loadSecuritySuspects() {
  const body = document.getElementById('suspects-body');
  if (!body || securitySuspectsLoading) return;
  securitySuspectsLoading = true;
  const note = document.getElementById('suspects-policy-note');
  const hours = Number(document.getElementById('suspects-hours')?.value || 24);
  const minScore = Number(document.getElementById('suspects-score')?.value || 25);
  body.innerHTML = '<tr><td colspan="7">Chargement des IP suspectes…</td></tr>';

  try {
    const d = await fetchJsonSafe(
      `/security-control/suspects?hours=${hours}&min_score=${minScore}&limit=30`
    );
    const state = d.policy_state || 'not_configured';
    if (note) {
      note.dataset.state = state;
      note.textContent = state === 'applied'
        ? 'Dernier rechargement Nginx confirmé. Les événements restent des signaux à analyser, pas des verdicts.'
        : 'Les règles visibles ici sont enregistrées, mais leur application dans Nginx n’est pas confirmée.';
    }
    const items = d.items || [];
    body.innerHTML = items.length ? items.map(item => {
      const rule = item.block_rule;
      const ip = esc(item.ip);
      const label = item.trusted
        ? '🛡️ Confiance / exception'
        : rule ? `⛔ Règle ${esc(rule.type)} : ${esc(rule.value)}` : 'Aucune';
      const kinds = [
        item.brute_force ? `${Number(item.brute_force)} brute force` : '',
        item.scans ? `${Number(item.scans)} scans HTTP` : ''
      ].filter(Boolean).join(' · ') || 'Autres signaux';
      const canBlock = !item.trusted && !rule;
      const directBlock = Number(item.direct_block_id || 0);
      const action = directBlock
        ? `<button type="button" class="list-action-btn" data-suspect-action="unblock" data-ip="${ip}" data-id="${directBlock}">Débloquer</button>`
        : canBlock
          ? `<button type="button" class="list-action-btn suspect-danger" data-suspect-action="block" data-ip="${ip}">Bloquer 1 h</button>`
          : '';
      const trust = !item.trusted && !rule
        ? `<button type="button" class="list-action-btn" data-suspect-action="trust" data-ip="${ip}">Confiance</button>`
        : '';
      return `<tr>
        <td class="ip-cell">${ip}</td>
        <td><strong class="suspect-score">${Number(item.max_score || 0)}</strong>/100</td>
        <td>${Number(item.signals || 0)}</td>
        <td>${esc(kinds)}</td>
        <td>${esc(item.host || '—')}<small class="suspect-country">${esc(item.country_code || '—')}</small></td>
        <td>${label}</td>
        <td class="suspect-actions">
          <button type="button" class="list-action-btn" data-suspect-action="inspect" data-ip="${ip}">Analyser</button>
          ${action}${trust}
        </td>
      </tr>`;
    }).join('') : '<tr><td colspan="7">Aucun signal suspect dans cette période et à ce seuil.</td></tr>';
  } catch (e) {
    if (note) {
      note.dataset.state = 'error';
      note.textContent = 'Impossible de charger les IP suspectes.';
    }
    body.innerHTML = '<tr><td colspan="7">Erreur de chargement des menaces.</td></tr>';
  } finally {
    securitySuspectsLoading = false;
  }
}

async function handleSuspectAction(event) {
  const button = event.target.closest('button[data-suspect-action]');
  if (!button || !requireAdminClient()) return;
  const action = button.dataset.suspectAction;
  const ip = button.dataset.ip;
  if (!ip) return;

  if (action === 'inspect') {
    showIPProfile(ip);
    return;
  }

  const prompts = {
    block: `Bloquer ${ip} pendant 1 heure ? La règle sera enregistrée mais sa prise d'effet dépendra du rechargement NPM.`,
    trust: `Ajouter ${ip} aux IP de confiance ? Elle sera exclue du ban automatique.`,
    unblock: `Retirer le blocage direct de ${ip} ? La modification restera à appliquer dans NPM.`
  };
  if (!prompts[action] || !confirm(prompts[action])) return;
  button.disabled = true;

  try {
    let url;
    let options;
    if (action === 'block') {
      url = `/block_ip/${encodeURIComponent(ip)}?duration_minutes=60`;
      options = {method: 'POST'};
    } else if (action === 'trust') {
      url = '/trusted';
      options = {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({type: 'ip', value: ip, reason: 'Trusted via security control'})
      };
    } else {
      const id = Number(button.dataset.id);
      if (!Number.isSafeInteger(id) || id < 1) throw new Error('ID de règle incorrect');
      url = `/blocklist/${id}`;
      options = {method: 'DELETE'};
    }
    const response = await adminFetch(url, options);
    const result = await response.json();
    if (!response.ok || result.error) throw new Error(result.detail || result.error || 'Échec de l’action');
    toast(`Décision enregistrée pour ${ip}. Application Nginx à vérifier.`, 'success');
    await loadSecuritySuspects();
    loadSecurityLists();
  } catch (err) {
    toast(err.message || 'Action impossible', 'danger');
  } finally {
    button.disabled = false;
  }
}

async function loadSecurityLists() {
  if (securityListsLoading) return;
  securityListsLoading = true;
  const blockedBody = document.getElementById('lists-blocked-body');
  const trustedBody = document.getElementById('lists-trusted-body');
  const historyBody = document.getElementById('lists-history-body');
  if (!blockedBody || !trustedBody || !historyBody) { securityListsLoading = false; return; }

  blockedBody.innerHTML = emptyRow(7, '⏳', 'Chargement blocklist…');
  trustedBody.innerHTML = emptyRow(5, '⏳', 'Chargement trusted list…');
  historyBody.innerHTML = emptyRow(5, '⏳', 'Chargement historique…');

  try {
    const [blocked, trusted, history] = await Promise.all([
      fetchJsonSafe('/blocklist'),
      fetchJsonSafe('/trusted'),
      fetchJsonSafe('/ban-events?limit=100')
    ]);

    document.getElementById('lists-blocked-count').textContent = blocked.length;
    document.getElementById('lists-trusted-count').textContent = trusted.length;
    document.getElementById('lists-history-count').textContent = history.length;

    blockedBody.innerHTML = blocked.length ? blocked.map(item => `
      <tr>
        <td><span class="list-type-pill">${esc(item.type)}</span></td>
        <td class="ip-cell">${esc(item.value)}</td>
        <td>${item.host ? esc(item.host) : '<span class="list-type-pill">Global</span>'}</td>
        <td>${esc(item.reason || '—')}</td>
        <td class="time-cell">${item.expires_at ? fmtDateTime(item.expires_at) : 'Permanent'}</td>
        <td class="time-cell">${fmtDateTime(item.created_at)}</td>
        <td><button class="list-action-btn" onclick="removeBlock(${Number(item.id)})">Supprimer</button></td>
      </tr>`).join('') : emptyRow(7, '🧘', 'Aucune entrée bloquée');

    trustedBody.innerHTML = trusted.length ? trusted.map(item => `
      <tr>
        <td><span class="list-type-pill trusted">${esc(item.type)}</span></td>
        <td class="ip-cell">${esc(item.value)}</td>
        <td>${esc(item.reason || '—')}</td>
        <td class="time-cell">${fmtDateTime(item.created_at)}</td>
        <td><button class="list-action-btn" onclick="removeTrusted(${Number(item.id)})">Supprimer</button></td>
      </tr>`).join('') : emptyRow(5, '🛡️', 'Aucune entrée de confiance');

    historyBody.innerHTML = history.length ? history.map(item => `
      <tr>
        <td class="time-cell">${fmtDateTime(item.created_at)}</td>
        <td class="ip-cell">${esc(item.target || '—')}</td>
        <td>${esc(item.type || '—')}</td>
        <td><span class="list-action-pill ${esc(String(item.action || '').toLowerCase())}">${esc(item.action || '—')}</span></td>
        <td>${esc(item.reason || '—')}</td>
      </tr>`).join('') : emptyRow(5, '📭', 'Aucun événement');

    applyListTab(currentListTab);
    return true;
  } catch (e) {
    blockedBody.innerHTML = emptyRow(7, '⚠️', 'Erreur de chargement des listes');
    trustedBody.innerHTML = emptyRow(5, '⚠️', 'Erreur de chargement des listes');
    historyBody.innerHTML = emptyRow(5, '⚠️', 'Erreur de chargement de l’historique');
    toast(e.message || 'Impossible de charger les listes', 'danger');
    return false;
  } finally {
    securityListsLoading = false;
  }
}

async function addBlockFromLists() {
  if (!requireAdminClient()) return;
  if (!requiredInput('lists-block-input','lists-block-feedback','Saisis une IP, un CIDR ou un pays à bloquer.')) return;
  await withBusyButton('lists-block-add', 'Ajout…', async () => {
    const raw = document.getElementById('lists-block-input').value.trim();
    const reason = document.getElementById('lists-block-reason')?.value.trim() || 'Manual block via lists tab';
    const host = document.getElementById('lists-block-host')?.value.trim() || null;
    const durationValue = document.getElementById('lists-block-duration')?.value || '';
    const duration_minutes = durationValue ? Number(durationValue) : null;
    const {type, value} = detectListType(raw);
    formFeedback('lists-block-feedback', 'Enregistrement du blocage…', 'loading');
    try {
      const r = await adminFetch('/blocklist', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type, value, reason, duration_minutes, host})});
      const d = await r.json();
      if (!r.ok || d.error) throw new Error(apiErrorMessage(d, 'Erreur blocklist'));
      document.getElementById('lists-block-input').value = '';
      document.getElementById('lists-block-reason').value = '';
      document.getElementById('lists-block-host').value = '';
      const message = `${value} enregistré pour ${host || 'tous les domaines'}. Application Nginx en attente.`;
      formFeedback('lists-block-feedback', message, 'success');
      toast(message, 'success');
      void loadBlocklist();
      await loadSecurityLists();
    } catch(e) {
      formFeedback('lists-block-feedback', e.message || 'Erreur ajout blocklist', 'error');
      toast(e.message || 'Erreur ajout blocklist', 'danger');
    }
  });
}

async function addTrustedFromLists() {
  if (!requireAdminClient()) return;
  if (!requiredInput('lists-trusted-input','lists-trusted-feedback','Saisis une IP, un CIDR, un pays ou UA:... à autoriser.')) return;
  await withBusyButton('lists-trusted-add', 'Ajout…', async () => {
    const raw = document.getElementById('lists-trusted-input').value.trim();
    const reason = document.getElementById('lists-trusted-reason')?.value.trim() || 'Trusted via lists tab';
    const {type, value} = detectListType(raw);
    if (!value) {
      formFeedback('lists-trusted-feedback', 'Saisis une valeur après UA:.', 'error');
      toast('Saisis une valeur après UA:.', 'warning');
      return;
    }
    formFeedback('lists-trusted-feedback', 'Ajout de l’exception…', 'loading');
    try {
      const r = await adminFetch('/trusted',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type, value, reason})});
      const d = await r.json();
      if (!r.ok || d.error) throw new Error(apiErrorMessage(d, 'Erreur trusted list'));
      document.getElementById('lists-trusted-input').value = '';
      document.getElementById('lists-trusted-reason').value = '';
      formFeedback('lists-trusted-feedback', `${value} ajouté aux entrées de confiance.`, 'success');
      toast(`${value} ajouté à la liste de confiance`, 'success');
      void loadTrusted();
      await loadSecurityLists();
    } catch(e) {
      formFeedback('lists-trusted-feedback', e.message || 'Erreur ajout trusted list', 'error');
      toast(e.message || 'Erreur ajout trusted list', 'danger');
    }
  });
}

// ═══════════════════════════════════════════════════════════
//  PATCH 5.5 · MOBILE-FIRST HOME + PWA
// ═══════════════════════════════════════════════════════════
function registerPWA() {
  if (!('serviceWorker' in navigator)) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/static/sw.js')
      .catch(err => console.warn('PWA service worker disabled:', err));
  });
}

function calcSecurityScore(stats, health, threats) {
  const total = stats?.total || 0;
  const blocked = stats?.blocked || 0;
  const blockRate = total ? (blocked / total) * 100 : 0;
  const threatCount = Array.isArray(threats) ? threats.length : 0;
  const errorRate = health?.summary?.error_rate || 0;
  let score = 100;
  score -= Math.min(30, blockRate * 5);
  score -= Math.min(25, threatCount * 2);
  score -= Math.min(25, errorRate * 2);
  return Math.max(0, Math.round(score));
}

function homeThreatCard(t) {
  return `<div class="mobile-info-card danger">
    <div class="mobile-card-top"><strong>${esc(t.ip)}</strong><span class="score-pill ${threatClass(t.score)}">${esc(t.score)}</span></div>
    <div class="mobile-card-meta">${esc(t.threat_type || t.type || 'threat')} · ${esc(fmtDateTime(t.created_at || t.timestamp))}</div>
    <div class="mobile-card-uri">${esc(trunc(t.uri || '', 72))}</div>
  </div>`;
}

async function loadHomeOverview() {
  const scoreEl = document.getElementById('home-score');
  if (!scoreEl) return;
  try {
    const [stats, health, threats, detailedHealth] = await Promise.all([
      fetch('/stats').then(r => r.json()).catch(() => ({})),
      fetch('/npm-health').then(r => r.json()).catch(() => ({})),
      fetch('/threats?min_score=50&limit=6').then(r => r.json()).catch(() => []),
      fetch('/health').then(r => r.json()).catch(() => ({})),
    ]);

    const score = calcSecurityScore(stats, health, threats);
    scoreEl.textContent = `${score}/100`;
    document.getElementById('home-score-sub').textContent = score >= 80 ? 'état correct' : score >= 60 ? 'à surveiller' : 'ça sent la fumée';
    document.getElementById('home-total').textContent = num(stats.total || 0);
    document.getElementById('home-blocked').textContent = num(stats.blocked || 0);
    document.getElementById('home-block-rate').textContent = stats.total ? `${(((stats.blocked || 0) / stats.total) * 100).toFixed(1)}%` : '0%';
    document.getElementById('home-threats-24h').textContent = num(Array.isArray(threats) ? threats.length : 0);

    const topError = (health.top_errors || [])[0];
    document.getElementById('home-top-error').textContent = topError ? `HTTP ${topError.status}` : '—';
    document.getElementById('home-top-error-sub').textContent = topError ? `${num(topError.count)} événements` : 'aucune erreur';

    const list = document.getElementById('home-threat-list');
    if (list) list.innerHTML = Array.isArray(threats) && threats.length
      ? threats.slice(0, 5).map(homeThreatCard).join('')
      : '<div class="empty small">Aucune menace critique récente</div>';

    await loadSecurityActivity();

    const runtime = document.getElementById('home-runtime-list');
    if (runtime) {
      const items = [
        ['DB', detailedHealth.db_ok ? 'OK' : 'KO', detailedHealth.db_ok ? 'health-ok' : 'health-bad'],
        ['Logs', detailedHealth.log_file_exists ? 'OK' : 'KO', detailedHealth.log_file_exists ? 'health-ok' : 'health-bad'],
        ['Export', detailedHealth.export_dir_writable ? 'OK' : 'KO', detailedHealth.export_dir_writable ? 'health-ok' : 'health-bad'],
        ['Scheduler', detailedHealth.scheduler_running ? 'OK' : 'KO', detailedHealth.scheduler_running ? 'health-ok' : 'health-bad'],
      ];
      runtime.innerHTML = items.map(([k,v,c]) => `<div class="runtime-pill ${c}"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('');
    }
  } catch(e) {
    console.warn('home overview:', e);
  }
}

// Mobile cards: keep tables for desktop, offer readable cards on small screens without duplicating the backend.
function enableMobileTableCards() {
  document.querySelectorAll('.compact-table tbody, #threat-tbody').forEach(tbody => {
    const obs = new MutationObserver(() => {
      tbody.querySelectorAll('tr').forEach(tr => {
        const cells = [...tr.children].map(td => td.textContent.trim()).filter(Boolean);
        if (cells.length) tr.setAttribute('data-mobile-summary', cells.slice(0, 3).join(' · '));
      });
    });
    obs.observe(tbody, {childList:true});
  });
}

// ═══════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════
registerPWA();
initFavicon();
initTheme();
initAuth();
initMap();
initChoropleth(); // preload topo data
loadMapHistory();
loadStats(true);
loadHomeOverview();
loadPage('first');
loadTimeline();
loadHeatmap();

const threatRefreshBtn = document.getElementById('threat-refresh');
if (threatRefreshBtn) threatRefreshBtn.addEventListener('click', loadThreats);
const threatMinScore = document.getElementById('threat-min-score');
if (threatMinScore) threatMinScore.addEventListener('change', loadThreats);
const blExportJson = document.getElementById('bl-export-json');
if (blExportJson) blExportJson.addEventListener('click', () => openExport('json'));
const blExportNginx = document.getElementById('bl-export-nginx');
if (blExportNginx) blExportNginx.addEventListener('click', () => openExport('nginx'));
const blApplyExport = document.getElementById('bl-apply-export');
if (blApplyExport) blApplyExport.addEventListener('click', () => applyBlocklistExport(false));
const blApplyReload = document.getElementById('bl-apply-reload');
if (blApplyReload) blApplyReload.addEventListener('click', () => applyBlocklistExport(true));
const blHistoryBtn = document.getElementById('bl-history-btn');
if (blHistoryBtn) blHistoryBtn.addEventListener('click', loadBanEvents);
const trustedAdd = document.getElementById('trusted-add');
if (trustedAdd) trustedAdd.addEventListener('click', addTrusted);
const trustedInput = document.getElementById('trusted-input');
if (trustedInput) trustedInput.addEventListener('keydown', e => { if(e.key==='Enter') addTrusted(); });

document.querySelectorAll('[data-list-tab]').forEach(btn => btn.addEventListener('click', () => applyListTab(btn.dataset.listTab)));
const observationIncidentsBody = document.getElementById('observation-incidents-body');
if (observationIncidentsBody) observationIncidentsBody.addEventListener('click', changeObservationStatus);
for (const id of ['observation-hours', 'observation-status']) {
  const filter = document.getElementById(id);
  if (filter) filter.addEventListener('change', loadObservationIncidents);
}
const observationRefresh = document.getElementById('observation-refresh');
if (observationRefresh) observationRefresh.addEventListener('click', loadObservationIncidents);
const suspectsBody = document.getElementById('suspects-body');
if (suspectsBody) suspectsBody.addEventListener('click', handleSuspectAction);
for (const id of ['suspects-hours', 'suspects-score']) {
  const filter = document.getElementById(id);
  if (filter) filter.addEventListener('change', loadSecuritySuspects);
}
const suspectsRefresh = document.getElementById('suspects-refresh');
if (suspectsRefresh) suspectsRefresh.addEventListener('click', loadSecuritySuspects);
const policyModesForm = document.getElementById('security-modes-form');
if (policyModesForm) policyModesForm.addEventListener('submit', savePolicyMode);
const policyModesList = document.getElementById('security-modes-list');
if (policyModesList) policyModesList.addEventListener('click', event => {
  const button = event.target.closest('button[data-reset-mode]');
  if (button) void resetPolicyMode(button.dataset.resetMode);
});
const securityPreviewForm = document.getElementById('security-preview-form');
if (securityPreviewForm) securityPreviewForm.addEventListener('submit', simulateSavedSecurityPolicy);
const controlRefresh = document.getElementById('security-control-refresh');
if (controlRefresh) controlRefresh.addEventListener('click', () => {
  void withBusyButton('security-control-refresh', 'Actualisation…', async () => {
    try {
      await loadSecurityControl();
      toast('Actualisation terminée : consulte les états des différentes sections.', 'info');
    } catch (err) {
      toast(err.message || 'Actualisation impossible', 'danger');
    }
  });
});
const listsRefresh = document.getElementById('lists-refresh');
if (listsRefresh) listsRefresh.addEventListener('click', () => {
  void withBusyButton('lists-refresh', 'Actualisation…', async () => {
    const ok = await loadSecurityLists();
    if (ok) toast('Listes et historique actualisés', 'success');
  });
});
const listsBlockAdd = document.getElementById('lists-block-add');
if (listsBlockAdd) listsBlockAdd.addEventListener('click', addBlockFromLists);
const listsTrustedAdd = document.getElementById('lists-trusted-add');
if (listsTrustedAdd) listsTrustedAdd.addEventListener('click', addTrustedFromLists);
const listsBlockInput = document.getElementById('lists-block-input');
if (listsBlockInput) listsBlockInput.addEventListener('keydown', e => { if(e.key==='Enter') addBlockFromLists(); });
const listsTrustedInput = document.getElementById('lists-trusted-input');
if (listsTrustedInput) listsTrustedInput.addEventListener('keydown', e => { if(e.key==='Enter') addTrustedFromLists(); });

connectSSE();
enableMobileTableCards();
const activityRefreshBtn = document.getElementById('activity-refresh');
if (activityRefreshBtn) activityRefreshBtn.addEventListener('click', loadSecurityActivity);
const notifBtn = document.getElementById('notif-enable');
if (notifBtn) notifBtn.addEventListener('click', enableBrowserNotifications);

// Periodic refresh (stats + charts every 15s)
setInterval(()=>{ loadStats(true); loadTimeline(); loadHeatmap(); }, 15000);
// Keep Observe incident counts fresh only while the Control view is open.
setInterval(() => {
  if (document.body.dataset.view === 'control') void loadObservationIncidents();
}, 30000);

// ═══════════════════════════════════════════════════════════
//  PATCH 5.2 · NPM HEALTH + CONFIG + AUTOBAN SIMULATION
// ═══════════════════════════════════════════════════════════
function healthKV(label, value, cls='') {
  return `<div class="health-kv"><div class="health-kv-label">${esc(label)}</div><div class="health-kv-value ${cls}">${esc(value)}</div></div>`;
}
function boolStatus(v) { return v ? ['OK','health-ok'] : ['KO','health-bad']; }

async function loadIngestionDiagnostics() {
  const badge = document.getElementById('ingestion-health-status');
  const advice = document.getElementById('ingestion-health-advice');
  const metrics = document.getElementById('ingestion-health-metrics');
  const note = document.getElementById('ingestion-health-note');
  if (!badge || !advice || !metrics || !note) return;
  badge.textContent = 'Vérification…';
  badge.dataset.state = 'loading';
  advice.textContent = 'Lecture du fichier de logs et du curseur de collecte…';

  try {
    const d = await fetchJsonSafe('/health/ingestion');
    const file = d.file || {};
    const cursor = d.cursor || {};
    const runtime = d.runtime || {};
    const stored = d.stored || {};
    const counts = value => Number(value || 0).toLocaleString('fr-FR');
    const size = value => value === null || value === undefined
      ? '—' : `${counts(value)} octets`;
    const duration = value => value === null || value === undefined
      ? 'Jamais observé' : `${counts(Math.round(value))} s`;
    badge.textContent = ({
      ok: 'Collecte à jour',
      warning: 'À vérifier',
      error: 'Erreur de collecte'
    })[d.status] || 'Indéterminé';
    badge.dataset.state = d.status || 'warning';
    advice.dataset.state = d.status || 'warning';
    advice.textContent = d.advice || 'Diagnostic indisponible.';

    metrics.innerHTML = [
      healthKV('Fichier LOG_FILE', d.log_file || 'Non défini'),
      healthKV('Fichier source', file.exists ? (file.readable ? 'Présent · lisible' : 'Présent · illisible') : 'Absent',
        file.exists && file.readable ? 'health-ok' : 'health-bad'),
      healthKV('Dernière écriture Nginx', duration(file.seconds_since_write)),
      healthKV('Taille du fichier', size(file.size_bytes)),
      healthKV('Dernier cycle de collecte', duration(runtime.seconds_since_poll),
        runtime.seconds_since_poll !== null && runtime.seconds_since_poll <= 30 ? 'health-ok' : 'health-warn'),
      healthKV('Curseur SQLite', cursor.present ? size(cursor.offset_bytes) : 'Non initialisé',
        cursor.present ? 'health-ok' : 'health-warn'),
      healthKV('Octets en attente', size(cursor.backlog_bytes),
        cursor.backlog_bytes > 0 ? 'health-warn' : 'health-ok'),
      healthKV('Lignes lues depuis le démarrage', counts(runtime.lines_read)),
      healthKV('Lignes ajoutées', counts(runtime.lines_inserted), 'health-ok'),
      healthKV('Lignes JSON rejetées', counts(runtime.lines_invalid),
        runtime.lines_invalid ? 'health-warn' : 'health-ok'),
      healthKV('Relectures évitées', counts(runtime.lines_duplicate)),
      healthKV('Logs en base', counts(stored.total_logs)),
      healthKV('Dernière requête enregistrée', stored.latest_log_timestamp
        ? fmtDateTime(stored.latest_log_timestamp) : 'Aucune'),
    ].join('');

    const sampled = Number(stored.recent_sample_size || 0);
    const instrumented = Number(stored.instrumented_sample || 0);
    const modeMessage = sampled && !instrumented
      ? `Les ${sampled} dernières entrées examinées n'ont pas les variables Observe. Vérifier les champs JSON émis par Nginx.`
      : `${instrumented} requête(s) instrumentée(s) parmi ${sampled} dernières entrées.`;
    const errorMessage = runtime.last_error_type
      ? ` · Dernière erreur collecteur : ${runtime.last_error_type}.` : '';
    note.textContent = `${modeMessage} · Lignes rejetées et compteurs runtime depuis le démarrage du dashboard seulement.${errorMessage} Aucune donnée de requête brute n'est affichée ici.`;
  } catch (error) {
    badge.dataset.state = 'error';
    badge.textContent = 'Diagnostic indisponible';
    advice.dataset.state = 'error';
    advice.textContent = error.message || 'Impossible de récupérer le diagnostic de collecte.';
    metrics.textContent = '';
    note.textContent = '';
  }
}

async function loadNpmHealth() {
  void loadIngestionDiagnostics();
  const summary = document.getElementById('health-summary');
  if (!summary) return;
  try {
    const d = await fetch('/npm-health').then(r=>r.json());
    document.getElementById('health-error-rate').textContent = `${d.server_error_rate || 0}%`;
    summary.innerHTML = [
      healthKV('Total logs', num(d.total || 0)),
      healthKV('Erreurs 5xx', num(d.server_errors || 0), (d.server_errors||0) ? 'health-bad' : 'health-ok'),
      healthKV('Taux 5xx', `${d.server_error_rate || 0}%`, (d.server_error_rate||0) > 5 ? 'health-bad' : ((d.server_error_rate||0) > 1 ? 'health-warn' : 'health-ok')),
    ].join('');

    const statusBody = document.getElementById('health-status-body');
    statusBody.innerHTML = (d.top_error_statuses || []).map(x => `
      <tr><td><span class="status-badge ${statusClass(Number(x.status))}">${esc(x.status)}</span></td><td>${num(x.count)}</td></tr>
    `).join('') || '<tr><td colspan="2">Aucune erreur</td></tr>';

    const hostBody = document.getElementById('health-host-body');
    hostBody.innerHTML = (d.errors_by_host || []).map(x => `
      <tr><td class="host-cell" title="${esc(x.host)}">${esc(trunc(x.host,40))}</td><td>${num(x.server_errors)}</td><td>${num(x.http_errors)}</td><td>${esc(fmtDateTime(x.last_seen))}</td></tr>
    `).join('') || '<tr><td colspan="4">Aucun host instable</td></tr>';

    const uriBody = document.getElementById('health-uri-body');
    uriBody.innerHTML = (d.errors_by_uri || []).map(x => `
      <tr><td class="host-cell" title="${esc(x.host)}">${esc(trunc(x.host,28))}</td><td class="uri-cell" title="${esc(x.uri)}">${esc(trunc(x.uri,52))}</td><td>${esc(x.status)}</td><td>${num(x.count)}</td></tr>
    `).join('') || '<tr><td colspan="4">Aucune URI en 5xx</td></tr>';
  } catch(e) {
    summary.innerHTML = healthKV('Erreur', 'Chargement impossible', 'health-bad');
  }
}

async function loadDetailedHealth() {
  try {
    const d = await fetch('/health/details').then(r=>r.json());
    const cfg = document.getElementById('config-grid');
    if (!cfg) return;
    const [dbTxt, dbCls] = boolStatus(d.db_ok);
    const [logTxt, logCls] = boolStatus(d.log_file_exists && d.log_file_readable);
    const [expTxt, expCls] = boolStatus(d.export_dir_writable);
    const [admTxt, admCls] = boolStatus(d.admin_enabled);
    cfg.innerHTML = [
      healthKV('Statut', d.status, d.status === 'ok' ? 'health-ok' : 'health-warn'),
      healthKV('DB', dbTxt, dbCls),
      healthKV('Taille DB', `${Math.round((d.db_size_bytes || 0)/1024/1024*10)/10} MB`),
      healthKV('Log lisible', logTxt, logCls),
      healthKV('Export writable', expTxt, expCls),
      healthKV('Scheduler', d.scheduler_running ? 'running' : 'stopped', d.scheduler_running ? 'health-ok' : 'health-warn'),
      healthKV('Admin token', admTxt, admCls),
      healthKV('Discord', d.discord_configured ? 'configured' : 'disabled', d.discord_configured ? 'health-ok' : 'health-warn'),
    ].join('');
  } catch(e) {}
}

let nsdProfileState = null;

function profileFormSettings() {
  if (!nsdProfileState) throw new Error('Configuration non chargée');
  const values = {};
  for (const [key, spec] of Object.entries(nsdProfileState.schema)) {
    const node = document.getElementById('nsd-profile-field-' + key);
    if (!node) throw new Error('Champ manquant : ' + key);
    if (spec.type === 'boolean') values[key] = node.checked;
    else if (spec.type === 'integer') {
      const value = node.value.trim();
      values[key] = value && /^-?\d+$/.test(value) ? Number(value) : null;
    } else if (['countries', 'cidrs', 'tokens'].includes(spec.type)) {
      values[key] = node.value.split(',').map(part => part.trim()).filter(Boolean);
    } else values[key] = node.value;
  }
  return values;
}

function renderProfileSettings(data) {
  nsdProfileState = data;
  const root = document.getElementById('nsd-profile-fields');
  const status = document.getElementById('nsd-profile-deployment');
  if (!root || !status) return;
  document.getElementById('nsd-profile-version').textContent = 'Révision ' + data.revision;
  status.textContent = data.deployment?.message || 'Aucune politique appliquée par l’agent.';
  status.dataset.state = 'warning';
  root.innerHTML = Object.entries(data.schema).map(([key, spec]) => {
    const value = data.settings[key];
    const id = 'nsd-profile-field-' + key;
    const control = spec.type === 'boolean'
      ? '<input type="checkbox" id="' + id + '"' + (value ? ' checked' : '') + '>'
      : spec.type === 'choice'
        ? '<select class="search" id="' + id + '">' +
          spec.choices.map(choice => '<option value="' + esc(choice) + '"' +
            (choice === value ? ' selected' : '') + '>' + esc(choice) + '</option>').join('') + '</select>'
        : '<input class="search" id="' + id + '" ' +
          (spec.type === 'integer' ? 'type="number" min="' + spec.min + '" max="' + spec.max + '"' : 'type="text"') +
          ' value="' + esc(Array.isArray(value) ? value.join(', ') : value) + '">';
    return '<label class="nsd-profile-field" for="' + id + '">' +
      '<span class="nsd-profile-label">' + esc(spec.label) + '</span>' + control +
      '<small>' + esc(spec.description) + ' <em>Défaut : ' +
      esc(Array.isArray(spec.default) ? spec.default.join(', ') : String(spec.default)) +
      '</em></small></label>';
  }).join('');

  const history = document.getElementById('nsd-profile-history');
  history.innerHTML = data.history?.length ? data.history.map(row =>
    '<div class="nsd-profile-revision">' +
      '<span><strong>#' + Number(row.id) + '</strong> · ' + esc(row.created_by) +
      ' · ' + esc(row.created_at) + '<small>' + esc(row.note || 'Sans motif') + '</small></span>' +
      '<button class="page-btn" type="button" data-profile-restore="' + Number(row.id) + '"' +
        (Number(row.id) === data.revision ? ' disabled' : '') + '>Restaurer</button>' +
    '</div>'
  ).join('') : 'Aucune révision enregistrée. Les valeurs héritées servent de défaut.';
  history.querySelectorAll('[data-profile-restore]').forEach(button => {
    button.addEventListener('click', () => void restoreProfileRevision(Number(button.dataset.profileRestore)));
  });
}

async function loadSecurityProfile() {
  const feedback = document.getElementById('nsd-profile-feedback');
  try {
    const response = await fetchJsonSafe('/security-profile');
    renderProfileSettings(response);
    if (feedback) {
      feedback.textContent = 'Configuration chargée. Aucune modification Nginx effectuée.';
      feedback.dataset.state = 'info';
    }
  } catch (error) {
    if (feedback) {
      feedback.textContent = 'Impossible de charger les paramètres NSD : ' + (error.message || 'Erreur API');
      feedback.dataset.state = 'error';
    }
  }
}

async function profileApi(url, data) {
  const response = await adminFetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok || result.error) {
    const detail = result.detail || result.error || ('HTTP ' + response.status);
    throw new Error(Array.isArray(detail) ? detail.map(d => d.msg || String(d)).join('; ') : String(detail));
  }
  return result;
}

async function previewSecurityProfile() {
  if (!requireAdminClient() || !nsdProfileState) return;
  const status = document.getElementById('nsd-profile-feedback');
  await withBusyButton('nsd-profile-preview-btn', 'Validation…', async () => {
    if (status) {
      status.dataset.state = 'loading';
      status.textContent = 'Validation des champs et génération du candidat…';
    }
    try {
      const result = await profileApi('/security-profile/preview', {
        settings: profileFormSettings()
      });
      const diff = document.getElementById('nsd-profile-diff');
      if (diff) {
        diff.textContent = Object.values(result.diff || {}).join('\n') ||
          'Aucune différence avec la dernière révision enregistrée.';
        document.getElementById('nsd-profile-diff-wrap').open = true;
      }
      if (status) {
        status.dataset.state = 'success';
        status.textContent = (result.changed_files?.length || 0) +
          ' fichier(s) de profil impacté(s). Validation de schéma réussie.' +
          ' Aucun nginx -t ni reload n’a été exécuté.';
      }
      toast('Prévisualisation du candidat terminée', 'success');
    } catch (error) {
      if (status) {
        status.dataset.state = 'error';
        status.textContent = error.message || 'Candidat invalide';
      }
      toast(error.message || 'Prévisualisation impossible', 'danger');
    }
  });
}

async function saveSecurityProfile(event) {
  event.preventDefault();
  if (!requireAdminClient() || !nsdProfileState) return;
  const feedback = document.getElementById('nsd-profile-feedback');
  const note = document.getElementById('nsd-profile-note').value.trim();
  if (note.length < 5) {
    feedback.dataset.state = 'error';
    feedback.textContent = 'Indique un motif d’au moins 5 caractères pour la traçabilité.';
    document.getElementById('nsd-profile-note').focus();
    return;
  }
  await withBusyButton('nsd-profile-save-btn', 'Enregistrement…', async () => {
    try {
      const result = await profileApi('/security-profile/revisions', {
        settings: profileFormSettings(),
        expected_revision: nsdProfileState.revision,
        note
      });
      await loadSecurityProfile();
      document.getElementById('nsd-profile-note').value = '';
      feedback.dataset.state = 'success';
      feedback.textContent = 'Révision #' + result.revision +
        ' enregistrée en SQLite. Déploiement NPM en attente, aucun reload effectué.';
      toast('Révision enregistrée sans toucher à NPM', 'success', 5000);
    } catch (error) {
      feedback.dataset.state = 'error';
      feedback.textContent = error.message || 'Enregistrement impossible';
      toast(feedback.textContent, 'danger');
    }
  });
}

async function restoreProfileRevision(revision) {
  if (!requireAdminClient() || !nsdProfileState) return;
  if (!confirm('Restaurer les paramètres de la révision #' + revision +
    ' dans une NOUVELLE révision ? NPM ne sera pas rechargé.')) return;
  const feedback = document.getElementById('nsd-profile-feedback');
  try {
    const result = await profileApi('/security-profile/revisions/' + revision + '/restore', {
      expected_revision: nsdProfileState.revision
    });
    await loadSecurityProfile();
    feedback.dataset.state = 'success';
    feedback.textContent = 'Révision #' + revision + ' restaurée en nouvelle révision #' +
      result.revision + '. NPM n’a pas été modifié.';
    toast('Nouvelle révision créée, en attente de déploiement', 'success');
  } catch (error) {
    feedback.dataset.state = 'error';
    feedback.textContent = error.message || 'Restauration impossible';
    toast(feedback.textContent, 'danger');
  }
}

document.getElementById('nsd-profile-preview-btn')?.addEventListener('click', () => void previewSecurityProfile());
document.getElementById('nsd-profile-form')?.addEventListener('submit', saveSecurityProfile);

async function loadRuntimeConfig() {
  try {
    const d = await fetch('/config').then(r=>r.json());
    const version = document.getElementById('config-version');
    if (version) version.textContent = d.version || '—';
    // config-grid is filled by /health, so append runtime items after health finishes
    setTimeout(() => {
      const cfg = document.getElementById('config-grid');
      if (!cfg) return;
      cfg.insertAdjacentHTML('beforeend', [
        healthKV('Auto-ban', d.auto_ban_enabled ? 'enabled' : 'disabled', d.auto_ban_enabled ? 'health-warn' : 'health-ok'),
        healthKV('Dry-run', d.auto_ban_dry_run ? 'enabled' : 'disabled', d.auto_ban_dry_run ? 'health-ok' : 'health-warn'),
        healthKV('Score auto-ban', d.auto_ban_score),
        healthKV('Reload nginx', d.nginx_reload_enabled ? 'enabled' : 'disabled', d.nginx_reload_enabled ? 'health-warn' : 'health-ok'),
        healthKV('Export dir', d.export_dir),
      ].join(''));
    }, 80);
  } catch(e) {}
}

async function simulateAutoban() {
  const body = document.getElementById('simulate-body');
  if (!body) return;
  body.innerHTML = '<tr><td colspan="5">Simulation…</td></tr>';
  try {
    const d = await adminFetch('/threats/simulate-autoban').then(r=>r.json());
    if (d.detail) { toast(d.detail, 'danger'); body.innerHTML = `<tr><td colspan="5">${esc(d.detail)}</td></tr>`; return; }
    document.getElementById('simulate-count').textContent = d.would_block || 0;
    body.innerHTML = (d.ips || []).map(x => `
      <tr><td class="ip-cell">${esc(x.ip)}</td><td>${esc(x.max_score)}</td><td>${num(x.events)}</td><td>${esc(x.threat_type)}</td><td>${esc(trunc(x.isp,28))}</td></tr>
    `).join('') || '<tr><td colspan="5">Aucune IP à auto-bannir avec ce seuil</td></tr>';
    toast(`Simulation: ${d.would_block || 0} IP seraient bannies`, 'info');
  } catch(e) {
    body.innerHTML = '<tr><td colspan="5">Erreur simulation</td></tr>';
  }
}

const ingestionHealthRefresh = document.getElementById('ingestion-health-refresh');
if (ingestionHealthRefresh) ingestionHealthRefresh.addEventListener('click', () => {
  void withBusyButton('ingestion-health-refresh', 'Vérification…', loadIngestionDiagnostics);
});
setInterval(() => {
  if (document.body.dataset.view === 'health') void loadIngestionDiagnostics();
}, 30000);

const healthRefresh = document.getElementById('health-refresh');
if (healthRefresh) healthRefresh.addEventListener('click', loadNpmHealth);
const configRefresh = document.getElementById('config-refresh');
if (configRefresh) configRefresh.addEventListener('click', () => { loadRuntimeConfig(); loadDetailedHealth(); loadSecurityProfile(); });
const simulateBtn = document.getElementById('simulate-autoban');
if (simulateBtn) simulateBtn.addEventListener('click', simulateAutoban);


// ═══════════════════════════════════════════════════════════
//  PATCH 5.3 · METRICS + INTEL + CSV + DB MAINTENANCE
// ═══════════════════════════════════════════════════════════
async function loadPatch53Intel() {
  const asnBody = document.getElementById('asn-isp-body');
  const bfBody = document.getElementById('bruteforce-body');
  const tagsCloud = document.getElementById('threat-tags-cloud');
  try {
    const asn = await fetch('/threat-intel/asn-isp').then(r=>r.json());
    if (asnBody) asnBody.innerHTML = (asn || []).slice(0, 25).map(x => `
      <tr><td>${esc(x.asn || '—')}</td><td title="${esc(x.isp)}">${esc(trunc(x.isp,32))}</td><td>${num(x.total)}</td><td>${num(x.threat_events)}</td><td>${esc(x.max_score || 0)}</td></tr>
    `).join('') || '<tr><td colspan="5">Aucune corrélation</td></tr>';
  } catch(e) { if (asnBody) asnBody.innerHTML = '<tr><td colspan="5">Erreur chargement ASN/ISP</td></tr>'; }

  try {
    const bf = await fetch('/threat-intel/bruteforce').then(r=>r.json());
    if (bfBody) bfBody.innerHTML = (bf.items || []).map(x => `
      <tr><td title="${esc(x.host)}">${esc(trunc(x.host,28))}</td><td class="ip-cell">${esc(x.ip)}</td><td>${num(x.attempts)}</td><td>${num(x.denied)}</td><td title="${esc(x.isp)}">${esc(trunc(x.isp,24))}</td></tr>
    `).join('') || '<tr><td colspan="5">Aucun brute force détecté</td></tr>';
  } catch(e) { if (bfBody) bfBody.innerHTML = '<tr><td colspan="5">Erreur chargement brute force</td></tr>'; }

  try {
    const tags = await fetch('/threat-tags').then(r=>r.json());
    if (tagsCloud) tagsCloud.innerHTML = (tags || []).slice(0, 40).map(t => `
      <span class="threat-tag-pill" title="Dernier: ${esc(fmtDateTime(t.last_seen))}">${esc(t.tag)} <b>${num(t.count)}</b></span>
    `).join('') || '<span class="list-subtitle">Aucun tag</span>';
  } catch(e) { if (tagsCloud) tagsCloud.innerHTML = '<span class="list-subtitle">Erreur tags</span>'; }
}

function downloadAdminCsv(kind) {
  const url = `/export/csv?kind=${encodeURIComponent(kind)}&limit=20000`;
  adminFetch(url)
    .then(async r => {
      if (!r.ok) throw new Error(await r.text());
      return r.blob();
    })
    .then(blob => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `npm-security-${kind}.csv`;
      document.body.appendChild(a); a.click(); a.remove();
      toast(`Export CSV ${kind} prêt`, 'success');
    })
    .catch(() => toast('Export CSV impossible', 'danger'));
}

async function runDbBackup() {
  const grid = document.getElementById('db-maintenance-grid');
  try {
    const d = await adminFetch('/db/backup', {method:'POST'}).then(r=>r.json());
    if (grid) grid.innerHTML = healthKV('Dernier backup', d.path || 'ok', 'health-ok') + healthKV('Taille', `${Math.round((d.size_bytes || 0)/1024/1024*10)/10} MB`);
    toast('Backup SQLite créé', 'success');
  } catch(e) { toast('Backup impossible', 'danger'); }
}

async function runDbCompact() {
  const grid = document.getElementById('db-maintenance-grid');
  try {
    const d = await adminFetch('/db/compact', {method:'POST'}).then(r=>r.json());
    if (grid) grid.innerHTML = healthKV('Compactage', 'OK', 'health-ok') + healthKV('Gain', `${Math.round((d.saved_bytes || 0)/1024/1024*10)/10} MB`);
    toast('DB compactée', 'success');
  } catch(e) { toast('Compactage impossible', 'danger'); }
}


// ═══════════════════════════════════════════════════════════
//  PATCH 5.4 · USERS / WEB AUTH
// ═══════════════════════════════════════════════════════════
function userActionsHtml(u) {
  if (u.id === currentUser?.id) return '<span class="list-subtitle">session</span>';
  const toggle = u.enabled
    ? `<button class="page-btn danger" onclick="disableUser(${u.id})">désactiver</button>`
    : `<button class="page-btn" onclick="enableUser(${u.id})">activer</button>`;
  const remove = `<button class="page-btn danger" onclick="deleteUserHard(${u.id})">supprimer</button>`;
  return `<div class="user-actions">${toggle}${remove}</div>`;
}

async function loadUsers() {
  const body = document.getElementById('users-body');
  if (!body) return;
  try {
    const users = await adminFetch('/users').then(r=>r.json());
    body.innerHTML = users.map(u => `
      <tr>
        <td>${esc(u.username)}</td>
        <td><span class="user-role-badge ${u.role === 'admin' ? 'admin' : ''}">${esc(u.role)}</span></td>
        <td>${u.enabled ? 'oui' : 'non'}</td>
        <td>${esc(fmtDateTime(u.last_login))}</td>
        <td>${userActionsHtml(u)}</td>
      </tr>`).join('') || '<tr><td colspan="5">Aucun utilisateur</td></tr>';
  } catch(e) { body.innerHTML = '<tr><td colspan="5">Connexion admin requise</td></tr>'; }
}
async function createUserFromUI() {
  const username = document.getElementById('user-new-name')?.value.trim();
  const password = document.getElementById('user-new-password')?.value || '';
  const role = document.getElementById('user-new-role')?.value || 'viewer';
  if (!username || password.length < 8) { toast('Utilisateur ou mot de passe invalide', 'danger'); return; }
  try {
    const r = await adminFetch('/users', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username,password,role})});
    if (!r.ok) throw new Error(await r.text());
    document.getElementById('user-new-name').value = '';
    document.getElementById('user-new-password').value = '';
    toast('Utilisateur créé', 'success'); loadUsers();
  } catch(e) { toast('Création utilisateur impossible', 'danger'); }
}
async function disableUser(id) {
  try {
    const r = await adminFetch(`/users/${id}`, {method:'DELETE'});
    if (!r.ok) throw new Error(await r.text());
    toast('Utilisateur désactivé', 'info'); loadUsers();
  } catch(e) { toast('Désactivation utilisateur impossible', 'danger'); }
}
async function enableUser(id) {
  try {
    const r = await adminFetch(`/users/${id}/enable`, {method:'POST'});
    if (!r.ok) throw new Error(await r.text());
    toast('Utilisateur activé', 'success'); loadUsers();
  } catch(e) { toast('Activation utilisateur impossible', 'danger'); }
}
async function deleteUserHard(id) {
  if (!confirm('Supprimer définitivement cet utilisateur ?')) return;
  try {
    const r = await adminFetch(`/users/${id}/hard`, {method:'DELETE'});
    if (!r.ok) throw new Error(await r.text());
    toast('Utilisateur supprimé', 'info'); loadUsers();
  } catch(e) { toast('Suppression utilisateur impossible', 'danger'); }
}

const csvLogsBtn = document.getElementById('csv-logs');
if (csvLogsBtn) csvLogsBtn.addEventListener('click', () => downloadAdminCsv('logs'));
const csvThreatsBtn = document.getElementById('csv-threats');
if (csvThreatsBtn) csvThreatsBtn.addEventListener('click', () => downloadAdminCsv('threats'));
const dbBackupBtn = document.getElementById('db-backup');
if (dbBackupBtn) dbBackupBtn.addEventListener('click', runDbBackup);
const dbCompactBtn = document.getElementById('db-compact');
if (dbCompactBtn) dbCompactBtn.addEventListener('click', runDbCompact);
const userBtn = document.getElementById('user-btn');
if (userBtn) userBtn.addEventListener('click', () => currentUser ? logoutUser() : showLogin());
const usersRefreshBtn = document.getElementById('users-refresh');
if (usersRefreshBtn) usersRefreshBtn.addEventListener('click', loadUsers);
const userCreateBtn = document.getElementById('user-create');
if (userCreateBtn) userCreateBtn.addEventListener('click', createUserFromUI);
if (isAdminUser()) loadUsers();

