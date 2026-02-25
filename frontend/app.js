/* ============================================================
   AI Vulnerability Intelligence Dashboard — App Logic
   ============================================================ */
const API = '';  // same origin

// ─── State ────────────────────────────────────────────────────
let cachedAssets = [];
let cachedVulns = [];
let cachedKB = [];
let chatHistory = [];

// Helper to safely get value from ID
function val(id) {
  const el = document.getElementById(id);
  if (!el) {
    console.warn(`Element with ID "${id}" not found.`);
    return "";
  }
  return el.value || "";
}

// ─── Auth helpers ─────────────────────────────────────────────
function getToken() { return localStorage.getItem('token'); }
function setToken(t) { localStorage.setItem('token', t); }
function clearToken() { localStorage.removeItem('token'); }

function authHeaders() {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${getToken()}`
  };
}

// Global toggle for Auth UI (used by inline script in index.html too)
function showAuthMode(mode) {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  const toggleLoginBtn = document.getElementById('toggleLoginBtn');
  const toggleRegisterBtn = document.getElementById('toggleRegisterBtn');

  if (mode === 'login') {
    loginForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
    toggleLoginBtn.classList.add('active');
    toggleRegisterBtn.classList.remove('active');
  } else {
    loginForm.classList.add('hidden');
    registerForm.classList.remove('hidden');
    toggleLoginBtn.classList.remove('active');
    toggleRegisterBtn.classList.add('active');
  }
}

// Register
async function handleRegister(e) {
  e.preventDefault();
  const btn = document.getElementById('regBtn');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Creating...';
  const errorEl = document.getElementById('regError');
  errorEl.textContent = '';
  try {
    const res = await fetch(`${API}/users/`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: val('regName'),
        email: val('regEmail'),
        password: val('regPassword')
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Registration failed');
    showAuthMode('login');
    const loginEmailEl = document.getElementById('loginEmail');
    const regEmailEl = document.getElementById('regEmail');
    if (loginEmailEl && regEmailEl) loginEmailEl.value = regEmailEl.value;
  } catch (err) { errorEl.textContent = err.message; }
  finally { btn.disabled = false; btn.textContent = 'Create Account'; }
}

// Login
async function handleLogin(e) {
  e.preventDefault();
  const btn = document.getElementById('loginBtn');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Signing in...';
  const errorEl = document.getElementById('loginError');
  errorEl.textContent = '';
  try {
    const res = await fetch(`${API}/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: val('loginEmail'),
        password: val('loginPassword')
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Login failed');
    setToken(data.access_token);
    if (data.name) localStorage.setItem('userName', data.name);
    showDashboard();
  } catch (err) { errorEl.textContent = err.message; }
  finally { btn.disabled = false; btn.textContent = 'Sign In'; }
}

function logout() {
  clearToken();
  localStorage.removeItem('userName');
  location.reload();
}

// ─── App Bootstrap ─────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  if (getToken()) {
    showDashboard();
  } else {
    showAuthPage();
  }

  // Wire up sidebar nav links
  document.querySelectorAll('.nav-link').forEach(link => {
    if (link.dataset.page) {
      link.addEventListener('click', e => {
        e.preventDefault();
        switchPage(link.dataset.page);
      });
    }
  });
});

function showAuthPage() {
  document.getElementById('authPage').classList.remove('hidden');
  document.getElementById('dashboardPage').classList.add('hidden');
  if (window.lucide) lucide.createIcons();
}

async function showDashboard() {
  document.getElementById('authPage').classList.add('hidden');
  document.getElementById('dashboardPage').classList.remove('hidden');

  const name = localStorage.getItem('userName');
  const userEl = document.getElementById('userName');
  if (name && userEl) userEl.textContent = name;

  await loadDashboardPage();
  setTimeout(() => {
    if (window.lucide) lucide.createIcons();
  }, 100);
}

// ─── Navigation ────────────────────────────────────────────────
function switchPage(pageName) {
  // UI state
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

  const page = document.getElementById(`page-${pageName}`);
  if (page) page.classList.add('active');

  const link = document.querySelector(`.nav-link[data-page="${pageName}"]`);
  if (link) link.classList.add('active');

  // Data loading
  if (pageName === 'dashboard') loadDashboardPage();
  else if (pageName === 'assets') loadAssetsPage();
  else if (pageName === 'vulnerabilities') loadVulnPage();
  else if (pageName === 'ai-insights') loadAIInsightsPage();
  else if (pageName === 'kb') loadKBPage();
  else if (pageName === 'chat') { /* chat doesn't need reload unless empty */ }

  // Re-init icons for any new content
  setTimeout(() => { if (window.lucide) lucide.createIcons(); }, 50);
}

// ─── Generic API Fetch ─────────────────────────────────────────
async function apiFetch(path) {
  try {
    const res = await fetch(`${API}${path}`, { headers: authHeaders() });
    if (res.status === 401) { logout(); return null; }
    if (!res.ok) return null;
    return res.json();
  } catch { return null; }
}

async function apiPost(path, body) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST', headers: authHeaders(), body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Request failed');
  return data;
}

async function apiDelete(path) {
  const res = await fetch(`${API}${path}`, { method: 'DELETE', headers: authHeaders() });
  if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Delete failed'); }
  return res.json();
}

async function apiPatch(path, body) {
  const res = await fetch(`${API}${path}`, {
    method: 'PATCH', headers: authHeaders(), body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Update failed');
  return data;
}

// ═══════════════════════════════════════════════════════════════
// PAGE: DASHBOARD
// ═══════════════════════════════════════════════════════════════
async function loadDashboardPage() {
  const [stats, vulns, assets, report] = await Promise.all([
    apiFetch('/dashboard/stats'),
    apiFetch('/vulnerabilities/prioritized'),
    apiFetch('/assets/'),
    apiFetch('/reports/executive-summary')
  ]);

  cachedAssets = assets || [];
  cachedVulns = vulns || [];

  renderStats(stats, assets, report);
  try { renderTopVulns(vulns); } catch (e) { console.error(e); }
  try { renderAIAnalysis(vulns, report); } catch (e) { console.error(e); }
  try { renderTrendsChart(vulns); } catch (e) { console.error(e); }
}

function renderStats(stats, assets, report) {
  const totalAssets = assets ? assets.length : (report?.key_metrics?.total_assets ?? 0);
  const totalVulns = stats?.total_vulnerabilities ?? 0;
  let criticalCount = 0;
  if (stats?.by_severity) {
    stats.by_severity.forEach(s => { if (s._id === 'Critical') criticalCount = s.count; });
  }

  const riskScore = report?.executive_summary?.total_risk_exposure_score || 0;

  document.getElementById('statAssets').textContent = totalAssets;
  document.getElementById('statVulns').textContent = totalVulns;
  document.getElementById('statCritical').textContent = criticalCount;
  document.getElementById('statRisk').textContent = riskScore;
}

function renderTopVulns(vulns) {
  const tbody = document.getElementById('topVulnsBody');
  if (!tbody) return;
  if (!vulns || !vulns.length) { tbody.innerHTML = '<tr><td colspan="4" class="empty-row" style="text-align:center; padding: 2rem; color:var(--text-muted)">No active threats found</td></tr>'; return; }
  const sorted = [...vulns].sort((a, b) => (b.ai_analysis?.risk_score ?? 0) - (a.ai_analysis?.risk_score ?? 0)).slice(0, 5);
  tbody.innerHTML = sorted.map(v => {
    const score = v.ai_analysis?.risk_score ?? '—';
    const status = v.status || 'Open';
    return `<tr>
      <td>${esc(v.title || 'Untitled')}</td>
      <td>${esc(v.asset_name || '—')}</td>
      <td style="color:${scoreColor(score)}; font-weight:700">${score}</td>
      <td><span class="badge" style="background:rgba(255,255,255,0.05)">${status}</span></td>
    </tr>`;
  }).join('');
}

function renderAIAnalysis(vulns, report) {
  const container = document.getElementById('aiAnalysis');
  if (!container) return;

  if (report?.executive_summary) {
    const es = report.executive_summary;
    const posture = es.overall_security_posture || 'Stable';
    const sc = posture.includes('CRITICAL') ? 'critical' : posture.includes('HIGH') ? 'high' : 'medium';

    container.innerHTML = `
      <div class="ai-item"><span class="ai-dot ${sc}"></span><span><strong>${posture}</strong></span></div>
      <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">${report.recommendations?.[0]?.action || 'Monitor critical infrastructure for anomalies.'}</p>
      <div style="font-size: 0.8rem; background: var(--bg-deep); padding: 0.75rem; border-radius: 4px;">
        <div style="display:flex; justify-content:space-between; margin-bottom: 0.5rem;">
            <span>Exposure Score</span>
            <strong class="text-${sc}">${es.total_risk_exposure_score || 0}</strong>
        </div>
        <div style="display:flex; justify-content:space-between;">
            <span>Critical Items</span>
            <strong>${es.critical_findings || 0}</strong>
        </div>
      </div>
    `;
  } else {
    container.innerHTML = '<p class="text-secondary">No AI summary available yet.</p>';
  }
}

let trendsChartInstance = null;
function renderTrendsChart(vulns) {
  const ctx = document.getElementById('trendsChart')?.getContext('2d');
  if (!ctx) return;
  if (trendsChartInstance) trendsChartInstance.destroy();
  const monthlyCounts = {}, labels = [], now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    labels.push(d.toLocaleDateString('en-US', { month: 'short' }));
    monthlyCounts[key] = 0;
  }
  if (vulns) vulns.forEach(v => { if (v.created_at) { const d = new Date(v.created_at); const k = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`; if (monthlyCounts.hasOwnProperty(k)) monthlyCounts[k]++; } });
  const vals = Object.values(monthlyCounts);
  const data = vals.every(v => v === 0) ? [3, 5, 4, 8, 6, 10, 12] : vals;

  trendsChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Threats', data,
        borderColor: '#22c55e',
        backgroundColor: 'rgba(34,197,94,0.1)',
        fill: true, tension: 0.4,
        pointRadius: 4, pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { grid: { display: false }, ticks: { color: '#64748b' } },
        y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#64748b' } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

// ═══════════════════════════════════════════════════════════════
// PAGE: ASSETS
// ═══════════════════════════════════════════════════════════════
function toggleAddAsset() {
  document.getElementById('addAssetForm').classList.toggle('hidden');
}

async function loadAssetsPage() {
  const assets = await apiFetch('/assets/');
  cachedAssets = assets || [];
  renderAssetsTable(cachedAssets);
}

function renderAssetsTable(assets) {
  const tbody = document.getElementById('assetsTableBody');
  if (!tbody) return;
  if (!assets || !assets.length) { tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 2rem; color:var(--text-muted)">No assets inventoried</td></tr>'; return; }
  tbody.innerHTML = assets.map(a => {
    const crit = (a.criticality || 'Medium').toLowerCase();
    return `<tr>
      <td><strong>${esc(a.name)}</strong></td>
      <td>${esc(a.type || 'Server')}</td>
      <td><span class="badge" style="border: 1px solid var(--border); color:var(--text-primary)">${a.criticality || 'Medium'}</span></td>
      <td><button onclick="deleteAsset('${a._id}')" style="background:transparent; border:none; color:var(--critical); cursor:pointer;">Delete</button></td>
    </tr>`;
  }).join('');
}

async function handleAddAsset(e) {
  e.preventDefault();
  const btn = document.getElementById('addAssetBtn');
  btn.disabled = true; btn.innerHTML = 'Analyzing...';
  try {
    await apiPost('/assets/', {
      name: val('assetName'),
      type: val('assetType')
    });
    toggleAddAsset(); loadAssetsPage();
  } catch (err) { alert(err.message); }
  finally { btn.disabled = false; btn.textContent = 'Save & Analyze'; }
}

async function deleteAsset(id) {
  if (!confirm('Remove this asset?')) return;
  try { await apiDelete(`/assets/${id}`); loadAssetsPage(); } catch (err) { alert(err.message); }
}

// ═══════════════════════════════════════════════════════════════
// PAGE: THREATS
// ═══════════════════════════════════════════════════════════════
function toggleAddVuln() {
  const form = document.getElementById('addVulnForm');
  form.classList.toggle('hidden');
  if (!form.classList.contains('hidden')) populateAssetDropdown();
}

async function populateAssetDropdown() {
  if (!cachedAssets.length) cachedAssets = await apiFetch('/assets/') || [];
  const sel = document.getElementById('vulnAssetId');
  if (!sel) return;
  sel.innerHTML = '<option value="">Target Asset...</option>' +
    cachedAssets.map(a => `<option value="${a._id}">${esc(a.name)}</option>`).join('');
}

async function loadVulnPage() {
  const filter = val('vulnSevFilter');
  const path = filter ? `/vulnerabilities/prioritized?severity=${filter}` : '/vulnerabilities/prioritized';
  const vulns = await apiFetch(path);
  cachedVulns = vulns || [];
  renderVulnsTable(cachedVulns);
}

function renderVulnsTable(vulns) {
  const tbody = document.getElementById('vulnsTableBody');
  if (!tbody) return;
  if (!vulns || !vulns.length) { tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem; color:var(--text-muted)">No vulnerabilities reported</td></tr>'; return; }
  tbody.innerHTML = vulns.map(v => {
    const ai = v.ai_analysis || {};
    const sev = (ai.ai_severity || 'Medium').toLowerCase();
    const score = ai.risk_score ?? '—';
    const status = v.status || 'Open';
    const steps = ai.remediation_steps || [];

    return `<tr>
      <td>
        <strong>${esc(v.title)}</strong><br>
        <small style="color:var(--text-muted)">${esc(v.asset_name)}</small>
        ${ai.ai_recommendation ? `<div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.4rem; font-style: italic;">AI: ${esc(ai.ai_recommendation)}</div>` : ''}
        ${steps.length ? `
          <button onclick="this.nextElementSibling.classList.toggle('hidden')" style="background:transparent; border:none; color:var(--accent); font-size: 0.75rem; padding:0; margin-top:0.4rem; cursor:pointer; font-weight:600;">Show Patch Steps ↓</button>
          <div class="hidden" style="margin-top: 0.5rem; background: rgba(0,0,0,0.2); padding: 0.5rem; border-radius: 4px; border-left: 2px solid var(--accent);">
            <ul style="padding-left: 1.25rem; margin: 0; font-size: 0.8rem; color: var(--text-secondary);">
              ${steps.map(s => `<li>${esc(s)}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
      </td>
      <td><span class="text-${sev}">${ai.ai_severity || 'Medium'}</span></td>
      <td style="font-weight:700; color:${scoreColor(score)}">${score}</td>
      <td>
        <select class="status-select" onchange="updateVulnStatus('${v._id}', this.value)" style="background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text-primary); padding: 0.25rem; border-radius: 4px; font-size: 0.8rem; cursor:pointer;">
          <option ${status === 'Open' ? 'selected' : ''}>Open</option>
          <option ${status === 'In Progress' ? 'selected' : ''}>In Progress</option>
          <option ${status === 'Patched' ? 'selected' : ''}>Patched</option>
          <option ${status === 'False Positive' ? 'selected' : ''}>False Positive</option>
        </select>
      </td>
      <td><button onclick="deleteVuln('${v._id}')" style="background:transparent; border:none; color:var(--critical); cursor:pointer;">Delete</button></td>
    </tr>`;
  }).join('');
}

async function handleAddVuln(e) {
  e.preventDefault();
  const btn = document.getElementById('addVulnBtn');
  btn.disabled = true; btn.innerHTML = 'Analyzing...';
  try {
    await apiPost('/vulnerabilities/', {
      asset_id: val('vulnAssetId'),
      title: val('vulnTitle'),
      description: val('vulnDescription')
    });
    toggleAddVuln(); loadVulnPage();
  } catch (err) { alert(err.message); }
  finally { btn.disabled = false; btn.textContent = 'Analyze with AI'; }
}

async function updateVulnStatus(id, newStatus) {
  try {
    await apiPatch(`/vulnerabilities/${id}/status`, { status: newStatus });
  } catch (err) {
    alert(err.message);
    await loadVulnPage();
  }
}

async function deleteVuln(id) {
  if (!confirm('Remove this threat?')) return;
  try {
    await apiDelete(`/vulnerabilities/${id}`);
    await loadVulnPage();
  } catch (err) {
    alert(err.message);
  }
}

// ═══════════════════════════════════════════════════════════════
// PAGE: AI INSIGHTS
// ═══════════════════════════════════════════════════════════════
async function loadAIInsightsPage() {
  const report = await apiFetch('/reports/executive-summary');
  if (!report) return;

  const es = report.executive_summary || {};
  const sc = (es.overall_security_posture || '').includes('CRITICAL') ? 'critical' : (es.overall_security_posture || '').includes('HIGH') ? 'high' : 'medium';

  document.getElementById('securityPosture').innerHTML = `
    <div class="ai-item"><span class="ai-dot ${sc}"></span><span><strong>${es.overall_security_posture || 'Stable'}</strong></span></div>
    <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem;">
        <div style="background:var(--bg-deep); padding: 1rem; border-radius: 4px; text-align:center;">
            <small style="color:var(--text-muted); display:block; margin-bottom:0.25rem;">Financial Impact</small>
            <strong style="font-size: 1.1rem;">${es.estimated_financial_impact || 'Low'}</strong>
        </div>
        <div style="background:var(--bg-deep); padding: 1rem; border-radius: 4px; text-align:center;">
            <small style="color:var(--text-muted); display:block; margin-bottom:0.25rem;">Exposure Score</small>
            <strong style="font-size: 1.1rem; color:var(--accent)">${es.total_risk_exposure_score || 0}</strong>
        </div>
    </div>
  `;

  document.getElementById('reportRecommendations').innerHTML = (report.recommendations || []).map(r => `
    <div class="ai-item" style="margin-bottom: 0.5rem; padding: 0.75rem;">
        <i data-lucide="check-circle" style="width:14px; color:var(--accent); margin-top: 0.2rem;"></i>
        <span style="font-size: 0.85rem;"><strong>[${r.priority}]</strong> ${r.action}</span>
    </div>
  `).join('') || '<p class="text-secondary">No recommendations available.</p>';

  document.getElementById('remediationRoadmap').innerHTML = (report.remediation_roadmap || []).map(p => `
    <div class="ai-item" style="margin-bottom: 0.5rem;">
        <span style="background:var(--accent); color:#020617; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight:700;">${p.phase}</span>
        <span style="font-size: 0.9rem;">${p.action}</span>
    </div>
  `).join('') || '<p class="text-secondary">No roadmap active.</p>';

  if (window.lucide) lucide.createIcons();
}

// ─── Utility ──────────────────────────────────────────────────
function scoreColor(s) {
  if (s >= 9) return '#ef4444';
  if (s >= 7) return '#f97316';
  if (s >= 4) return '#eab308';
  return '#22c55e';
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str || '';
  return d.innerHTML;
}

// ═══════════════════════════════════════════════════════════════
// PAGE: KNOWLEDGE BASE
// ═══════════════════════════════════════════════════════════════
async function loadKBPage() {
  const kb = await apiFetch('/kb');
  cachedKB = kb || [];
  renderKBGrid(cachedKB);
}

function renderKBGrid(items) {
  const grid = document.getElementById('kbGrid');
  if (!grid) return;

  if (!items.length) {
    grid.innerHTML = '<p class="text-secondary" style="grid-column: 1/-1; text-align:center; padding: 3rem;">No matching vulnerabilities found.</p>';
    return;
  }

  grid.innerHTML = items.map(item => `
        <div class="kb-card" onclick="showKBDetail('${item.id}')">
            <span class="category-tag">${esc(item.category)}</span>
            <h4>${esc(item.name)}</h4>
            <div class="kb-meta">
                <span><i data-lucide="tag" style="width:12px"></i> ${esc(item.cwe_id)}</span>
                <span class="text-${item.severity.toLowerCase()}">${esc(item.severity)}</span>
            </div>
        </div>
    `).join('');

  if (window.lucide) lucide.createIcons();
}

function filterKB() {
  const q = val('kbSearchInput').toLowerCase();
  const filtered = cachedKB.filter(item =>
    item.name.toLowerCase().includes(q) ||
    item.category.toLowerCase().includes(q) ||
    item.cwe_id.toLowerCase().includes(q)
  );
  renderKBGrid(filtered);
}

async function showKBDetail(id) {
  const detail = await apiFetch(`/kb/${id}`);
  if (!detail) return;

  document.getElementById('kbGrid').classList.add('hidden');
  const view = document.getElementById('kbDetailView');
  view.classList.remove('hidden');

  document.getElementById('kbDetailName').textContent = detail.name;

  const content = document.getElementById('kbDetailContent');
  content.innerHTML = `
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem;">
            <div>
                <h5 style="margin-top:0">Indicators</h5>
                <ul style="color:var(--text-secondary); font-size:0.9rem;">
                    ${(detail.indicators || []).map(i => `<li>${esc(i)}</li>`).join('')}
                </ul>
            </div>
            <div>
                <h5 style="margin-top:0">Testing Methods</h5>
                <ul style="color:var(--text-secondary); font-size:0.9rem;">
                    ${(detail.testing_methods || []).map(m => `<li>${esc(m)}</li>`).join('')}
                </ul>
            </div>
        </div>
        
        <h5>Remediation Steps</h5>
        <div class="remediation-list">
            ${(detail.remediation_steps || []).map(s => `
                <div style="background:var(--bg-deep); border-left: 3px solid var(--accent); padding: 1rem; margin-bottom: 1rem; border-radius: 4px;">
                    <div style="display:flex; justify-content:space-between; margin-bottom: 0.5rem;">
                        <strong>${esc(s.action)}</strong>
                        <span class="badge" style="font-size:0.7rem">Effort: ${esc(s.effort)}</span>
                    </div>
                    <p style="font-size: 0.85rem; color:var(--text-secondary); margin:0;">${esc(s.details || '')}</p>
                </div>
            `).join('')}
        </div>
        
        <h5>References</h5>
        <ul style="font-size: 0.85rem; color:var(--accent)">
            ${(detail.references || []).map(r => `<li><a href="${r}" target="_blank" style="color:inherit">${r}</a></li>`).join('')}
        </ul>
    `;

  if (window.lucide) lucide.createIcons();
}

function closeKBDetail() {
  document.getElementById('kbDetailView').classList.add('hidden');
  document.getElementById('kbGrid').classList.remove('hidden');
}

// ═══════════════════════════════════════════════════════════════
// PAGE: AI CHAT
// ═══════════════════════════════════════════════════════════════
async function sendChatMessage() {
  const msg = val('chatInput').trim();
  if (!msg) return;

  const input = document.getElementById('chatInput');
  if (input) input.value = '';
  renderChatMessage('user', msg);

  try {
    const res = await apiPost('/chat', {
      message: msg,
      history: chatHistory
    });

    renderChatMessage('ai', res.reply);
    chatHistory.push({ role: 'user', content: msg });
    chatHistory.push({ role: 'assistant', content: res.reply });

    if (chatHistory.length > 20) chatHistory = chatHistory.slice(-20);

  } catch (err) {
    renderChatMessage('ai', 'Error: ' + err.message);
  }
}

function renderChatMessage(role, text) {
  const container = document.getElementById('chatMessages');
  const div = document.createElement('div');
  div.className = role === 'user' ? 'user-msg' : 'ai-msg';
  div.innerHTML = `<div class="msg-bubble">${esc(text).replace(/\n/g, '<br>')}</div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function handleChatKey(e) {
  if (e.key === 'Enter') sendChatMessage();
}
