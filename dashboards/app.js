const REPORT_URL = '/report.json';
const SCAN_URL = '/scan';
const REQUIRED_FIELDS = ['target', 'pri_score', 'verdict', 'findings'];
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

const PLUGIN_STORAGE_KEY = 'suscheck_dashboard_plugins_v2';
const MODULE_STORAGE_KEY = 'suscheck_dashboard_modules_v2';
const AUTO_REFRESH_STORAGE_KEY = 'suscheck_dashboard_auto_refresh_v2';
const REFRESH_INTERVAL_STORAGE_KEY = 'suscheck_dashboard_refresh_interval_v2';

const state = {
  report: null,
  sourceMode: 'server',
  sourceLabel: 'server /report.json',
  pluginVisibility: {},
  moduleVisibility: {},
  filters: {
    search: '',
    severity: 'all',
    module: 'all',
  },
  autoRefresh: false,
  refreshSeconds: 10,
  refreshTimer: null,
  scanInProgress: false,
};

const pluginRegistry = [
  { id: 'summary', title: 'Summary', render: renderSummaryPlugin },
  { id: 'moduleCoverage', title: 'Module Coverage', render: renderModuleCoveragePlugin },
  { id: 'severityMix', title: 'Severity Mix', render: renderSeverityMixPlugin },
  { id: 'coverageNotes', title: 'Coverage Notes', render: renderCoverageNotesPlugin },
  { id: 'findingExplorer', title: 'Finding Explorer', render: renderFindingExplorerPlugin },
  { id: 'tracePanels', title: 'Trace Panels', render: renderTracePanelsPlugin },
];

function byId(id) {
  return document.getElementById(id);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function pillClass(label) {
  const normalized = String(label || '').toLowerCase();
  if (['clear', 'secure', 'ok'].includes(normalized)) {
    return 'good';
  }
  if (['caution', 'warning', 'partial'].includes(normalized)) {
    return 'warn';
  }
  return 'bad';
}

function readJsonStorage(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) {
      return fallback;
    }
    return JSON.parse(raw);
  } catch (_error) {
    return fallback;
  }
}

function writeJsonStorage(key, payload) {
  localStorage.setItem(key, JSON.stringify(payload));
}

function setStatus(kind, message) {
  const statusEl = byId('report-status');
  if (!statusEl) {
    return;
  }
  statusEl.innerHTML = `<span class="pill ${pillClass(kind)}">${escapeHtml(message)}</span>`;
}

function setStdout(text) {
  const stdoutEl = byId('scan-stdout');
  if (!stdoutEl) {
    return;
  }
  stdoutEl.textContent = text || 'No scan output yet.';
}

function appendStdout(text) {
  const stdoutEl = byId('scan-stdout');
  if (!stdoutEl || !text) {
    return;
  }
  const existing = stdoutEl.textContent || '';
  stdoutEl.textContent = existing && existing !== 'No scan output yet.'
    ? `${existing}\n${text}`
    : text;
}

function validateReportPayload(report) {
  if (!report || typeof report !== 'object') {
    throw new Error('Report root must be a JSON object.');
  }

  const missing = REQUIRED_FIELDS.filter((fieldName) => !(fieldName in report));
  if (missing.length > 0) {
    throw new Error(`Report is missing required fields: ${missing.join(', ')}`);
  }

  if (!Array.isArray(report.findings)) {
    throw new Error('findings must be an array.');
  }
}

function normalizeReport(report) {
  const findings = (report.findings || []).map((finding, index) => ({
    module: finding.module || 'unknown',
    finding_id: finding.finding_id || `F-${index + 1}`,
    title: finding.title || 'Untitled finding',
    description: finding.description || '',
    severity: String(finding.severity || 'info').toLowerCase(),
    finding_type: finding.finding_type || 'unknown',
    confidence: Number(finding.confidence || 0),
    file_path: finding.file_path || null,
    line_number: finding.line_number || null,
  }));

  return {
    ...report,
    findings,
    coverage_notes: Array.isArray(report.coverage_notes) ? report.coverage_notes : [],
    modules_ran: Array.isArray(report.modules_ran) ? report.modules_ran : [],
    modules_failed: Array.isArray(report.modules_failed) ? report.modules_failed : [],
    modules_skipped: Array.isArray(report.modules_skipped) ? report.modules_skipped : [],
    policy_trace: Array.isArray(report.policy_trace) ? report.policy_trace : [],
    suppression_trace: Array.isArray(report.suppression_trace) ? report.suppression_trace : [],
    explainability_trace: Array.isArray(report.explainability_trace) ? report.explainability_trace : [],
    performance_trace: Array.isArray(report.performance_trace) ? report.performance_trace : [],
    trend_trace: Array.isArray(report.trend_trace) ? report.trend_trace : [],
    optional_scanner_trace: Array.isArray(report.optional_scanner_trace)
      ? report.optional_scanner_trace
      : [],
  };
}

function extractModules(report) {
  return [...new Set((report.findings || []).map((finding) => finding.module || 'unknown'))].sort();
}

function syncModuleVisibility(report) {
  const modules = extractModules(report);
  for (const moduleName of modules) {
    if (!(moduleName in state.moduleVisibility)) {
      state.moduleVisibility[moduleName] = true;
    }
  }
  writeJsonStorage(MODULE_STORAGE_KEY, state.moduleVisibility);
  return modules;
}

function updateModuleFilterOptions(modules) {
  const moduleFilter = byId('module-filter');
  const currentValue = state.filters.module;
  const options = modules
    .map((moduleName) => `<option value="${escapeHtml(moduleName)}">${escapeHtml(moduleName)}</option>`)
    .join('');

  moduleFilter.innerHTML = `<option value="all">All modules</option>${options}`;
  if (modules.includes(currentValue)) {
    moduleFilter.value = currentValue;
  } else {
    moduleFilter.value = 'all';
    state.filters.module = 'all';
  }
}

function renderPluginToggles() {
  const container = byId('plugin-toggle-list');
  container.innerHTML = pluginRegistry
    .map((plugin) => {
      const checked = state.pluginVisibility[plugin.id] !== false ? 'checked' : '';
      return `<label class="toggle-item"><input type="checkbox" data-plugin-id="${escapeHtml(plugin.id)}" ${checked}><span>${escapeHtml(plugin.title)}</span></label>`;
    })
    .join('');

  container.querySelectorAll('input[data-plugin-id]').forEach((checkbox) => {
    checkbox.addEventListener('change', (event) => {
      const pluginId = event.target.getAttribute('data-plugin-id');
      state.pluginVisibility[pluginId] = event.target.checked;
      writeJsonStorage(PLUGIN_STORAGE_KEY, state.pluginVisibility);
      renderDashboard();
    });
  });
}

function renderModuleToggles(modules) {
  const container = byId('module-toggle-list');
  if (!modules.length) {
    container.innerHTML = '<div class="empty-state">Load a report to toggle modules.</div>';
    return;
  }

  container.innerHTML = modules
    .map((moduleName) => {
      const checked = state.moduleVisibility[moduleName] !== false ? 'checked' : '';
      return `<label class="toggle-item"><input type="checkbox" data-module-name="${escapeHtml(moduleName)}" ${checked}><span>${escapeHtml(moduleName)}</span></label>`;
    })
    .join('');

  container.querySelectorAll('input[data-module-name]').forEach((checkbox) => {
    checkbox.addEventListener('change', (event) => {
      const moduleName = event.target.getAttribute('data-module-name');
      state.moduleVisibility[moduleName] = event.target.checked;
      writeJsonStorage(MODULE_STORAGE_KEY, state.moduleVisibility);
      renderDashboard();
    });
  });
}

function getFilteredFindings(report) {
  const findings = report.findings || [];
  const searchValue = state.filters.search.trim().toLowerCase();

  return findings.filter((finding) => {
    if (state.moduleVisibility[finding.module] === false) {
      return false;
    }
    if (state.filters.severity !== 'all' && finding.severity !== state.filters.severity) {
      return false;
    }
    if (state.filters.module !== 'all' && finding.module !== state.filters.module) {
      return false;
    }
    if (!searchValue) {
      return true;
    }

    const searchBlob = `${finding.module} ${finding.finding_id} ${finding.title} ${finding.description}`.toLowerCase();
    return searchBlob.includes(searchValue);
  });
}

function buildStatsRows(countMap) {
  const entries = Object.entries(countMap);
  if (!entries.length) {
    return '<div class="empty-state">No data available.</div>';
  }
  return entries
    .sort((a, b) => b[1] - a[1])
    .map(([label, count]) => `<div class="stat"><span>${escapeHtml(label)}</span><strong>${count}</strong></div>`)
    .join('');
}

function panelTemplate(title, bodyHtml, className = '') {
  return `<article class="panel ${className}"><h2>${escapeHtml(title)}</h2>${bodyHtml}</article>`;
}

function renderSummaryPlugin(context) {
  const report = context.report;
  const body = `
    <div class="panel-banner">PRI and target summary</div>
    <div class="stat"><span>Target</span><strong>${escapeHtml(report.target)}</strong></div>
    <div class="stat"><span>Artifact</span><strong>${escapeHtml(report.artifact_type || 'unknown')}</strong></div>
    <div class="stat"><span>PRI Score</span><strong>${Math.round(Number(report.pri_score || 0))}/100</strong></div>
    <div class="stat"><span>Verdict</span><strong><span class="pill ${pillClass(report.verdict)}">${escapeHtml(report.verdict)}</span></strong></div>
    <div class="stat"><span>Duration</span><strong>${Number(report.scan_duration || 0).toFixed(2)}s</strong></div>
    <div class="stat"><span>Findings visible</span><strong>${context.filteredFindings.length}/${report.findings.length}</strong></div>
  `;
  return panelTemplate('Summary', body);
}

function renderModuleCoveragePlugin(context) {
  const moduleCounts = {};
  for (const finding of context.filteredFindings) {
    moduleCounts[finding.module] = (moduleCounts[finding.module] || 0) + 1;
  }
  return panelTemplate('Module Coverage', `<div class="panel-banner">Module findings by current filters</div>${buildStatsRows(moduleCounts)}`);
}

function renderSeverityMixPlugin(context) {
  const severityCounts = {};
  for (const finding of context.filteredFindings) {
    severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
  }
  return panelTemplate('Severity Mix', `<div class="panel-banner">Severity counts by visible modules</div>${buildStatsRows(severityCounts)}`);
}

function renderCoverageNotesPlugin(context) {
  const report = context.report;
  const notes = report.coverage_notes.length
    ? report.coverage_notes.map((note) => `<div class="note">${escapeHtml(note)}</div>`).join('')
    : '<div class="empty-state">No coverage notes recorded.</div>';

  const body = `
    <div class="panel-banner">Pipeline coverage and module state</div>
    <div class="stat"><span>Coverage complete</span><strong>${report.coverage_complete ? 'yes' : 'no'}</strong></div>
    <div class="stat"><span>Modules ran</span><strong>${escapeHtml(report.modules_ran.join(', ') || 'none')}</strong></div>
    <div class="stat"><span>Modules failed</span><strong>${escapeHtml(report.modules_failed.join(', ') || 'none')}</strong></div>
    <div class="stat"><span>Modules skipped</span><strong>${escapeHtml(report.modules_skipped.join(', ') || 'none')}</strong></div>
    ${notes}
  `;
  return panelTemplate('Coverage Notes', body);
}

function renderFindingExplorerPlugin(context) {
  const rows = context.filteredFindings.slice(0, 200)
    .map((finding) => `<tr><td>${escapeHtml(finding.module)}</td><td>${escapeHtml(finding.finding_id)}</td><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.title)}</td></tr>`)
    .join('');

  const body = `
    <div class="panel-banner">Filtered findings (${context.filteredFindings.length})</div>
    <table class="table">
      <thead><tr><th>Module</th><th>Finding ID</th><th>Severity</th><th>Title</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="4">No findings match current filters.</td></tr>'}</tbody>
    </table>
  `;
  return panelTemplate('Finding Explorer', body, 'panel-wide');
}

function renderTracePanelsPlugin(context) {
  const report = context.report;
  const sections = [
    ['Policy trace', report.policy_trace],
    ['Suppression trace', report.suppression_trace],
    ['Explainability trace', report.explainability_trace],
    ['Performance trace', report.performance_trace],
    ['Trend trace', report.trend_trace],
    ['Optional scanner trace', report.optional_scanner_trace],
  ];

  const blocks = sections
    .map(([label, entries]) => {
      const content = entries.length
        ? entries.map((entry) => `<div class="note">${escapeHtml(entry)}</div>`).join('')
        : '<div class="empty-state">No entries.</div>';
      return `<h3>${escapeHtml(label)}</h3>${content}`;
    })
    .join('');

  return panelTemplate('Trace Panels', `<div class="panel-banner">Execution traces</div>${blocks}`, 'panel-wide');
}

function renderDashboard() {
  const report = state.report;
  const pluginGrid = byId('plugin-grid');
  byId('report-source-label').textContent = `Source: ${state.sourceLabel}`;

  if (!report) {
    byId('pri-score').textContent = '--/100';
    byId('summary-meta').innerHTML = '<div>No report loaded yet.</div>';
    pluginGrid.innerHTML = '<article class="panel panel-wide"><div class="empty-state">Run a scan or load a JSON report.</div></article>';
    renderModuleToggles([]);
    return;
  }

  const filteredFindings = getFilteredFindings(report);
  byId('pri-score').textContent = `${Math.round(Number(report.pri_score || 0))}/100`;
  byId('summary-meta').innerHTML = `
    <div><strong>Verdict:</strong> <span class="pill ${pillClass(report.verdict)}">${escapeHtml(report.verdict)}</span></div>
    <div><strong>Target:</strong> ${escapeHtml(report.target)}</div>
    <div><strong>Artifact:</strong> ${escapeHtml(report.artifact_type || 'unknown')}</div>
    <div><strong>Coverage:</strong> ${report.coverage_complete ? 'Complete' : 'Partial'}</div>
    <div><strong>Visible findings:</strong> ${filteredFindings.length}/${report.findings.length}</div>
  `;

  const context = { report, filteredFindings };
  const cards = pluginRegistry
    .filter((plugin) => state.pluginVisibility[plugin.id] !== false)
    .map((plugin) => plugin.render(context))
    .join('');

  pluginGrid.innerHTML = cards || '<article class="panel panel-wide"><div class="empty-state">All plugins are disabled.</div></article>';
}

function persistAutoRefreshState() {
  localStorage.setItem(AUTO_REFRESH_STORAGE_KEY, state.autoRefresh ? 'true' : 'false');
  localStorage.setItem(REFRESH_INTERVAL_STORAGE_KEY, String(state.refreshSeconds));
}

function applyAutoRefreshTimer() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
  if (!state.autoRefresh) {
    return;
  }

  state.refreshTimer = setInterval(() => {
    if (state.sourceMode === 'server') {
      loadServerReport(false);
    }
  }, state.refreshSeconds * 1000);
}

function mergeReportIntoState(report, sourceMode, sourceLabel) {
  const normalized = normalizeReport(report);
  state.report = normalized;
  state.sourceMode = sourceMode;
  state.sourceLabel = sourceLabel;
  const modules = syncModuleVisibility(normalized);
  updateModuleFilterOptions(modules);
  renderModuleToggles(modules);
  renderDashboard();
}

async function loadServerReport(showStatus = true) {
  try {
    const response = await fetch(REPORT_URL, { cache: 'no-store' });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.message || `Server report unavailable (${response.status})`);
    }
    validateReportPayload(payload);
    mergeReportIntoState(payload, 'server', 'server /report.json');
    if (showStatus) {
      setStatus('ok', 'Server report loaded successfully.');
    }
  } catch (error) {
    if (showStatus) {
      setStatus('abort', error.message || 'Failed to load server report.');
    }
  }
}

async function loadReportFromFile(file) {
  try {
    const text = await file.text();
    const payload = JSON.parse(text);
    validateReportPayload(payload);
    mergeReportIntoState(payload, 'file', `file ${file.name}`);
    setStatus('ok', `Loaded report file: ${file.name}`);
  } catch (error) {
    setStatus('abort', `File load failed: ${error.message || 'unknown parse error'}`);
  }
}

function setScanButtonsDisabled(disabled) {
  state.scanInProgress = disabled;
  byId('run-scan-btn').disabled = disabled;
  byId('scan-upload-btn').disabled = disabled;
}

function collectScanRequest() {
  return {
    target: byId('scan-target-input').value.trim(),
    profile: byId('scan-profile').value,
    timeout_seconds: Number(byId('scan-timeout').value || 300),
    flags: {
      ai: byId('toggle-ai').checked,
      vt: byId('toggle-vt').checked,
      upload_vt: byId('toggle-upload-vt').checked,
      mcp_dynamic: byId('toggle-mcp-dynamic').checked,
      mcp_only: byId('toggle-mcp-only').checked,
      dependency_check: byId('toggle-dependency-check').checked,
      verbose: byId('toggle-verbose').checked,
      nuclei: byId('toggle-nuclei').checked,
      trivy: byId('toggle-trivy').checked,
      grype: byId('toggle-grype').checked,
      zap: byId('toggle-zap').checked,
      openvas: byId('toggle-openvas').checked,
    },
  };
}

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || '');
      const commaIndex = result.indexOf(',');
      if (commaIndex < 0) {
        reject(new Error('Unexpected upload data format.'));
        return;
      }
      resolve(result.slice(commaIndex + 1));
    };
    reader.onerror = () => reject(new Error('Unable to read uploaded file.'));
    reader.readAsDataURL(file);
  });
}

async function runScan(payload) {
  try {
    setScanButtonsDisabled(true);
    setStatus('warning', 'Scan started. Running SusCheck...');
    setStdout('Scan in progress...');

    const response = await fetch(SCAN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.message || `Scan failed (${response.status}).`);
    }

    if (body.report) {
      validateReportPayload(body.report);
      mergeReportIntoState(body.report, 'server', body.source_label || 'server /report.json');
    }

    let successMessage = body.message || 'Scan completed.';
    if (body.report_path) {
      successMessage += ` Report: ${body.report_path}`;
    }
    if (body.log_path) {
      successMessage += ` Log: ${body.log_path}`;
    }

    setStatus('ok', successMessage);
    setStdout(body.stdout || 'Scan completed without console output.');
  } catch (error) {
    setStatus('abort', error.message || 'Scan failed.');
  } finally {
    setScanButtonsDisabled(false);
  }
}

async function onRunScanClicked() {
  const uploadInput = byId('scan-upload-input');
  const hasUpload = !!(uploadInput.files && uploadInput.files[0]);
  const payload = collectScanRequest();

  if (!payload.target && hasUpload) {
    await onUploadScanClicked();
    return;
  }

  if (!payload.target) {
    setStatus('abort', 'Enter a target path, URL, or package name before running scan.');
    const targetInput = byId('scan-target-input');
    if (targetInput) {
      targetInput.focus();
    }
    appendStdout('Hint: use Run Scan with a target, or choose a file and click Scan Uploaded Artifact.');
    return;
  }
  await runScan(payload);
}

async function onUploadScanClicked() {
  const uploadInput = byId('scan-upload-input');
  const file = uploadInput.files && uploadInput.files[0];
  if (!file) {
    setStatus('abort', 'Choose a file to upload and scan.');
    return;
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    setStatus('abort', `Upload exceeds ${Math.round(MAX_UPLOAD_BYTES / (1024 * 1024))} MB limit.`);
    return;
  }

  try {
    const base64Data = await readFileAsBase64(file);
    const payload = collectScanRequest();
    payload.upload = {
      name: file.name,
      content_b64: base64Data,
    };
    await runScan(payload);
    uploadInput.value = '';
  } catch (error) {
    setStatus('abort', error.message || 'Upload scan failed.');
  }
}

function setBooleanInput(id, value) {
  const el = byId(id);
  if (el) {
    el.checked = value;
  }
}

function initializeControls() {
  byId('run-scan-btn').addEventListener('click', onRunScanClicked);
  byId('scan-upload-btn').addEventListener('click', onUploadScanClicked);
  byId('reload-report-btn').addEventListener('click', () => loadServerReport(true));

  byId('report-file-input').addEventListener('change', (event) => {
    const file = event.target.files && event.target.files[0];
    if (file) {
      loadReportFromFile(file);
    }
    event.target.value = '';
  });

  byId('search-input').addEventListener('input', (event) => {
    state.filters.search = event.target.value;
    renderDashboard();
  });

  byId('severity-filter').addEventListener('change', (event) => {
    state.filters.severity = event.target.value;
    renderDashboard();
  });

  byId('module-filter').addEventListener('change', (event) => {
    state.filters.module = event.target.value;
    renderDashboard();
  });

  byId('auto-refresh-toggle').addEventListener('change', (event) => {
    state.autoRefresh = event.target.checked;
    persistAutoRefreshState();
    applyAutoRefreshTimer();
    setStatus('warning', state.autoRefresh ? 'Auto-refresh enabled.' : 'Auto-refresh disabled.');
  });

  byId('refresh-interval').addEventListener('change', (event) => {
    state.refreshSeconds = Number(event.target.value || 10);
    persistAutoRefreshState();
    applyAutoRefreshTimer();
  });

  byId('enable-all-adapters').addEventListener('click', () => {
    ['toggle-nuclei', 'toggle-trivy', 'toggle-grype', 'toggle-zap', 'toggle-openvas'].forEach((id) => setBooleanInput(id, true));
  });

  byId('disable-all-adapters').addEventListener('click', () => {
    ['toggle-nuclei', 'toggle-trivy', 'toggle-grype', 'toggle-zap', 'toggle-openvas'].forEach((id) => setBooleanInput(id, false));
  });

  byId('enable-all-plugins').addEventListener('click', () => {
    for (const plugin of pluginRegistry) {
      state.pluginVisibility[plugin.id] = true;
    }
    writeJsonStorage(PLUGIN_STORAGE_KEY, state.pluginVisibility);
    renderPluginToggles();
    renderDashboard();
  });

  byId('disable-all-plugins').addEventListener('click', () => {
    for (const plugin of pluginRegistry) {
      state.pluginVisibility[plugin.id] = false;
    }
    writeJsonStorage(PLUGIN_STORAGE_KEY, state.pluginVisibility);
    renderPluginToggles();
    renderDashboard();
  });

  byId('enable-all-modules').addEventListener('click', () => {
    Object.keys(state.moduleVisibility).forEach((moduleName) => {
      state.moduleVisibility[moduleName] = true;
    });
    writeJsonStorage(MODULE_STORAGE_KEY, state.moduleVisibility);
    if (state.report) {
      renderModuleToggles(extractModules(state.report));
    }
    renderDashboard();
  });

  byId('disable-all-modules').addEventListener('click', () => {
    Object.keys(state.moduleVisibility).forEach((moduleName) => {
      state.moduleVisibility[moduleName] = false;
    });
    writeJsonStorage(MODULE_STORAGE_KEY, state.moduleVisibility);
    if (state.report) {
      renderModuleToggles(extractModules(state.report));
    }
    renderDashboard();
  });

  byId('toggle-vt').addEventListener('change', (event) => {
    if (!event.target.checked) {
      setBooleanInput('toggle-upload-vt', false);
    }
  });
}

function initializeStateFromStorage() {
  state.pluginVisibility = readJsonStorage(PLUGIN_STORAGE_KEY, {});
  state.moduleVisibility = readJsonStorage(MODULE_STORAGE_KEY, {});
  state.autoRefresh = localStorage.getItem(AUTO_REFRESH_STORAGE_KEY) === 'true';
  state.refreshSeconds = Number(localStorage.getItem(REFRESH_INTERVAL_STORAGE_KEY) || 10);

  for (const plugin of pluginRegistry) {
    if (!(plugin.id in state.pluginVisibility)) {
      state.pluginVisibility[plugin.id] = true;
    }
  }
}

function init() {
  initializeStateFromStorage();
  initializeControls();
  renderPluginToggles();
  renderDashboard();
  setStdout('No scan output yet.');

  byId('auto-refresh-toggle').checked = state.autoRefresh;
  byId('refresh-interval').value = String(state.refreshSeconds);

  applyAutoRefreshTimer();
  loadServerReport(true);
}

init();
