/* ============================================================
   API Authorization Scanner — Dashboard JavaScript
   ============================================================ */

'use strict';

// ---- Navigation ----

const sections = document.querySelectorAll('.section');
const navItems = document.querySelectorAll('.nav-item');

function showSection(id) {
  sections.forEach(s => s.classList.toggle('active', s.id === `section-${id}`));
  navItems.forEach(n => n.classList.toggle('active', n.dataset.section === id));
}

navItems.forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    const sec = item.dataset.section;
    showSection(sec);
    if (sec === 'configuration') loadConfig();
    if (sec === 'findings')      loadFindings();
    if (sec === 'reports')       loadReports();
  });
});

// ---- Status helpers ----

function badgeClass(status) {
  switch ((status || '').toUpperCase()) {
    case 'POTENTIAL VULNERABILITY': return 'badge-vuln';
    case 'NOT DETECTED':            return 'badge-safe';
    case 'INCONCLUSIVE':            return 'badge-warn';
    case 'ERROR':                   return 'badge-vuln';
    case 'SKIPPED':                 return 'badge-grey';
    case 'COMPLETED':               return 'badge-safe';
    case 'COMPLETED_WITH_ERRORS':   return 'badge-warn';
    case 'FAILED':                  return 'badge-vuln';
    case 'RUNNING':                 return 'badge-info';
    default:                        return 'badge-grey';
  }
}

function severityClass(severity) {
  switch ((severity || '').toUpperCase()) {
    case 'HIGH':   return 'badge-vuln';
    case 'MEDIUM': return 'badge-warn';
    case 'LOW':    return 'badge-info';
    default:       return 'badge-grey';
  }
}

function cardBorderClass(status) {
  switch ((status || '').toUpperCase()) {
    case 'POTENTIAL VULNERABILITY': return 'vuln';
    case 'NOT DETECTED':            return 'safe';
    case 'INCONCLUSIVE':            return 'warn';
    default:                        return 'grey';
  }
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

// ---- API Calls ----

async function apiFetch(url, options = {}) {
  const resp = await fetch(url, options);
  const data = await resp.json().catch(() => ({}));
  return { ok: resp.ok, status: resp.status, data };
}

// ---- App Health / API Status ----

const apiStatusDot  = document.getElementById('apiStatusDot');
const apiStatusText = document.getElementById('apiStatusText');

async function checkApiStatus() {
  try {
    const { ok, data } = await apiFetch('/health');
    if (ok && data.status === 'ok') {
      apiStatusDot.className  = 'status-dot ok';
      apiStatusText.textContent = 'Dashboard online';
    } else {
      apiStatusDot.className  = 'status-dot error';
      apiStatusText.textContent = 'Dashboard error';
    }
  } catch {
    apiStatusDot.className  = 'status-dot error';
    apiStatusText.textContent = 'Offline';
  }
}

// ---- Overview: scan status polling ----

async function loadOverview() {
  try {
    const { ok, data } = await apiFetch('/api/scan/status');
    if (!ok) return;

    const summary = data.summary || {};
    const status  = data.status  || 'IDLE';

    document.getElementById('statTotal').textContent        = summary.total_tests           ?? '—';
    document.getElementById('statVuln').textContent         = summary.potential_vulnerabilities ?? '—';
    document.getElementById('statSafe').textContent         = summary.not_detected          ?? '—';
    document.getElementById('statInconclusive').textContent = summary.inconclusive          ?? '—';
    document.getElementById('statErrors').textContent       = summary.errors                ?? '—';
    document.getElementById('statSkipped').textContent      = summary.skipped               ?? '—';

    const badge = document.getElementById('scanStatusBadge');
    badge.textContent = status;
    badge.className   = `badge ${badgeClass(status)}`;

    document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();

    // Try to get target from config
    const cfgRes = await apiFetch('/api/config');
    if (cfgRes.ok && cfgRes.data.config) {
      document.getElementById('targetDisplay').textContent = cfgRes.data.config.base_url || '—';
    }
  } catch { /* silently ignore overview errors */ }
}

// ---- Configuration ----

async function loadConfig() {
  const loading = document.getElementById('configLoading');
  const error   = document.getElementById('configError');
  const content = document.getElementById('configContent');

  loading.style.display = 'block';
  error.style.display   = 'none';
  content.style.display = 'none';

  try {
    const { ok, data } = await apiFetch('/api/config');
    loading.style.display = 'none';

    if (!ok) {
      error.textContent   = data.error || 'Failed to load configuration.';
      error.style.display = 'block';
      return;
    }

    const cfg = data.config || {};
    document.getElementById('cfgBaseUrl').textContent      = cfg.base_url  || '—';
    document.getElementById('cfgTimeout').textContent      = `${cfg.timeout || '—'}s`;
    document.getElementById('cfgRetries').textContent      = cfg.retries ?? '—';
    document.getElementById('cfgAllowedHosts').textContent = (cfg.allowed_hosts || []).join(', ') || '—';

    // Identities
    const identContainer = document.getElementById('cfgIdentities');
    const identities = cfg.identities || [];
    identContainer.innerHTML = identities.map(id =>
      `<span class="identity-chip">
        ${esc(id.name)}
        <span class="role-badge ${id.role === 'admin' ? 'role-admin' : 'role-user'}">${esc(id.role)}</span>
      </span>`
    ).join('');

    // Endpoints
    const epContainer = document.getElementById('cfgEndpoints');
    const endpoints   = cfg.endpoints || [];
    document.getElementById('cfgEndpointCount').textContent = endpoints.length;
    epContainer.innerHTML = endpoints.map(ep => {
      const typeClass = (ep.vuln_type || '').toLowerCase() === 'bola' ? 'ep-bola' : 'ep-bfla';
      return `<div class="endpoint-row">
        <span class="ep-method">${esc(ep.method || 'GET')}</span>
        <span class="ep-path">${esc(ep.path || '')}</span>
        <span class="ep-type-badge ${typeClass}">${esc(ep.vuln_type || '')}</span>
        ${ep.label ? `<span style="color:var(--color-muted);font-size:.75rem;margin-left:.5rem">${esc(ep.label)}</span>` : ''}
      </div>`;
    }).join('');

    content.style.display = 'block';
  } catch (e) {
    loading.style.display = 'none';
    error.textContent   = `Network error: ${e.message}`;
    error.style.display = 'block';
  }
}

// ---- Scan ----

let scanPollInterval = null;

const btnStartScan   = document.getElementById('btnStartScan');
const dryRunToggle   = document.getElementById('dryRunToggle');
const scanProgress   = document.getElementById('scanProgress');
const progressStatus = document.getElementById('progressStatus');
const scanResult     = document.getElementById('scanResult');
const scanError      = document.getElementById('scanError');

btnStartScan.addEventListener('click', startScan);

async function startScan() {
  btnStartScan.disabled    = true;
  scanProgress.style.display = 'block';
  scanResult.style.display   = 'none';
  scanError.style.display    = 'none';
  progressStatus.textContent = 'Starting scan…';

  try {
    const { ok, data } = await apiFetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dry_run: dryRunToggle.checked }),
    });

    if (!ok) {
      showScanError(data.error || 'Failed to start scan.');
      return;
    }

    progressStatus.textContent = 'Scan running…';
    pollScanStatus();
  } catch (e) {
    showScanError(`Network error: ${e.message}`);
  }
}

function pollScanStatus() {
  if (scanPollInterval) clearInterval(scanPollInterval);
  scanPollInterval = setInterval(async () => {
    try {
      const { ok, data } = await apiFetch('/api/scan/status');
      if (!ok) return;

      const status = data.status || '';
      progressStatus.textContent = `Status: ${status}`;

      if (status === 'RUNNING') return; // keep polling

      clearInterval(scanPollInterval);
      scanPollInterval = null;
      btnStartScan.disabled      = false;
      scanProgress.style.display = 'none';

      if (status === 'FAILED') {
        showScanError(`Scan failed: ${data.error || 'Unknown error.'}`);
        return;
      }

      const summary = data.summary || {};
      const lines = [
        `✅ Scan ${status}`,
        `Total tests: ${summary.total_tests ?? 0}`,
        `Potential vulnerabilities: ${summary.potential_vulnerabilities ?? 0}`,
        `Not detected: ${summary.not_detected ?? 0}`,
        `Inconclusive: ${summary.inconclusive ?? 0}`,
        `Errors: ${summary.errors ?? 0}`,
        `Skipped: ${summary.skipped ?? 0}`,
      ];
      scanResult.innerHTML = lines.map(l => `<div>${esc(l)}</div>`).join('');
      scanResult.style.display = 'block';

      // Refresh overview counts
      loadOverview();
    } catch { /* ignore polling errors */ }
  }, 1500);
}

function showScanError(msg) {
  btnStartScan.disabled      = false;
  scanProgress.style.display = 'none';
  scanError.textContent      = msg;
  scanError.style.display    = 'block';
}

// ---- Findings ----

async function loadFindings(params = {}) {
  const loading = document.getElementById('findingsLoading');
  const empty   = document.getElementById('findingsEmpty');
  const errEl   = document.getElementById('findingsError');
  const list    = document.getElementById('findingsList');

  loading.style.display = 'block';
  empty.style.display   = 'none';
  errEl.style.display   = 'none';
  list.innerHTML        = '';

  try {
    const qs = new URLSearchParams(params).toString();
    const { ok, data } = await apiFetch(`/api/findings${qs ? '?' + qs : ''}`);
    loading.style.display = 'none';

    if (!ok) {
      errEl.textContent   = data.error || 'Failed to load findings.';
      errEl.style.display = 'block';
      return;
    }

    const findings = data.findings || [];
    if (!findings.length) {
      empty.textContent   = data.message || 'No findings match the current filters.';
      empty.style.display = 'block';
      return;
    }

    list.innerHTML = findings.map(renderFinding).join('');

    // Expand/collapse on header click
    list.querySelectorAll('.finding-header').forEach(header => {
      header.addEventListener('click', () => {
        header.closest('.finding-card').classList.toggle('expanded');
      });
    });
  } catch (e) {
    loading.style.display = 'none';
    errEl.textContent   = `Network error: ${e.message}`;
    errEl.style.display = 'block';
  }
}

function renderFinding(f) {
  const evidenceStr       = JSON.stringify(f.evidence || {}, null, 2);
  const classDetailStr    = JSON.stringify(f.classification_detail || {}, null, 2);
  const borderCls         = cardBorderClass(f.status);

  return `
  <div class="finding-card ${borderCls}">
    <div class="finding-header">
      <span class="finding-vuln-type">${esc(f.vuln_type || '')}</span>
      <span class="badge ${badgeClass(f.status)}">${esc(f.status || '')}</span>
      <span class="badge ${severityClass(f.severity)}">${esc(f.severity || '')}</span>
      <span class="finding-confidence">Confidence: ${esc(f.confidence || 'N/A')} ▼</span>
    </div>
    <div class="finding-body">
      <table class="finding-table">
        <tr><td>Finding ID</td>      <td><code>${esc(f.finding_id || '')}</code></td></tr>
        <tr><td>Endpoint</td>        <td><code>${esc(f.method || '')} ${esc(f.endpoint || '')}</code></td></tr>
        <tr><td>Test Identity</td>   <td>${esc(f.test_identity || '')} (role: ${esc(f.test_role || '')})</td></tr>
        <tr><td>Expected Policy</td> <td>${esc(f.expected_policy || '')}</td></tr>
        <tr><td>HTTP Status</td>     <td>${esc(String(f.http_status ?? 'N/A'))}</td></tr>
        <tr><td>Timestamp</td>       <td>${esc(f.timestamp || '')}</td></tr>
      </table>
      <div class="section-label">Details</div>
      <p>${esc(f.details || '')}</p>
      <div class="section-label">Evidence</div>
      <pre>${esc(evidenceStr)}</pre>
      <div class="section-label">Classification Detail</div>
      <pre>${esc(classDetailStr)}</pre>
      <div class="section-label">Remediation</div>
      <p class="remediation-text">${esc(f.remediation || '')}</p>
    </div>
  </div>`;
}

// Filters
document.getElementById('btnApplyFilters').addEventListener('click', applyFilters);
document.getElementById('btnClearFilters').addEventListener('click', () => {
  document.getElementById('searchFindings').value = '';
  document.getElementById('filterType').value     = '';
  document.getElementById('filterStatus').value   = '';
  document.getElementById('filterSeverity').value = '';
  loadFindings();
});

function applyFilters() {
  const params = {};
  const q        = document.getElementById('searchFindings').value.trim();
  const type     = document.getElementById('filterType').value;
  const status   = document.getElementById('filterStatus').value;
  const severity = document.getElementById('filterSeverity').value;
  if (q)        params.q        = q;
  if (type)     params.type     = type;
  if (status)   params.status   = status;
  if (severity) params.severity = severity;
  loadFindings(params);
}

document.getElementById('searchFindings').addEventListener('keydown', e => {
  if (e.key === 'Enter') applyFilters();
});

// ---- Reports ----

async function loadReports() {
  const loading = document.getElementById('reportsLoading');
  const empty   = document.getElementById('reportsEmpty');
  const list    = document.getElementById('reportsList');

  loading.style.display = 'block';
  empty.style.display   = 'none';
  list.innerHTML        = '';

  try {
    const { ok, data } = await apiFetch('/api/reports');
    loading.style.display = 'none';

    const reports = data.reports || [];
    if (!reports.length) {
      empty.style.display = 'block';
      return;
    }

    list.innerHTML = `<div class="reports-list">${
      reports.map(r => {
        const icon    = r.type === 'JSON' ? '📋' : '🌐';
        const typeCls = r.type === 'JSON' ? 'type-json' : 'type-html';
        const sizeKb  = (r.size_bytes / 1024).toFixed(1);
        return `<div class="report-row">
          <span class="report-icon">${icon}</span>
          <span class="report-name">${esc(r.filename)}</span>
          <span class="report-type ${typeCls}">${esc(r.type)}</span>
          <span class="report-meta">${sizeKb} KB · ${new Date(r.modified).toLocaleString()}</span>
          <a class="btn btn-ghost" href="/api/reports/${encodeURIComponent(r.filename)}" download>⬇</a>
        </div>`;
      }).join('')
    }</div>`;
  } catch (e) {
    loading.style.display = 'none';
    document.getElementById('reportsList').innerHTML =
      `<div class="alert alert-error">Failed to load reports: ${esc(e.message)}</div>`;
  }
}

document.getElementById('btnRefreshReports').addEventListener('click', loadReports);

// ---- Initialization ----

(async function init() {
  await checkApiStatus();
  await loadOverview();
  setInterval(checkApiStatus, 30000);
  setInterval(loadOverview, 10000);
})();
