const REPORT_URL = '/report.json';

const pillClass = (label) => {
  const normalized = String(label || '').toLowerCase();
  if (['clear', 'secure', 'ok'].includes(normalized)) {
    return 'good';
  }
  if (['caution', 'warning', 'partial'].includes(normalized)) {
    return 'warn';
  }
  return 'bad';
};

const escapeHtml = (value) =>
  String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

const renderList = (container, items) => {
  if (!items.length) {
    container.innerHTML = '<div class="note">No data available.</div>';
    return;
  }
  container.innerHTML = items
    .map(([label, count]) => `<div class="stat"><span>${escapeHtml(label)}</span><strong>${count}</strong></div>`)
    .join('');
};

const renderReport = (report) => {
  const priScore = document.getElementById('pri-score');
  const summaryMeta = document.getElementById('summary-meta');
  const moduleList = document.getElementById('module-list');
  const severityList = document.getElementById('severity-list');
  const coverageNotes = document.getElementById('coverage-notes');
  const findingsTable = document.getElementById('findings-table');

  const modules = new Map();
  const severities = new Map();
  (report.findings || []).forEach((finding) => {
    modules.set(finding.module, (modules.get(finding.module) || 0) + 1);
    severities.set(finding.severity, (severities.get(finding.severity) || 0) + 1);
  });

  priScore.textContent = `${Math.round(report.pri_score || 0)}/100`;
  summaryMeta.innerHTML = `
    <div><strong>Verdict:</strong> <span class="pill ${pillClass(report.verdict)}">${escapeHtml(report.verdict)}</span></div>
    <div><strong>Target:</strong> ${escapeHtml(report.target)}</div>
    <div><strong>Artifact:</strong> ${escapeHtml(report.artifact_type)}</div>
    <div><strong>Coverage:</strong> ${report.coverage_complete ? 'Complete' : 'Partial'}</div>
    <div><strong>Duration:</strong> ${Number(report.scan_duration || 0).toFixed(2)}s</div>
  `;

  renderList(moduleList, [...modules.entries()]);
  renderList(severityList, [...severities.entries()]);

  const notes = report.coverage_notes || [];
  coverageNotes.innerHTML = notes.length
    ? notes.map((note) => `<div class="note">${escapeHtml(note)}</div>`).join('')
    : '<div class="note">No coverage notes recorded.</div>';

  const findings = (report.findings || []).slice(0, 8);
  findingsTable.innerHTML = findings.length
    ? findings.map((finding) => `
        <tr>
          <td>${escapeHtml(finding.module)}</td>
          <td>${escapeHtml(finding.finding_id)}</td>
          <td>${escapeHtml(finding.severity)}</td>
          <td>${escapeHtml(finding.title)}</td>
        </tr>
      `).join('')
    : '<tr><td colspan="4">No findings in this report.</td></tr>';
};

const loadReport = async () => {
  const response = await fetch(REPORT_URL, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error('No report is attached to the dashboard server yet. Start it with --report <path>.');
  }
  const report = await response.json();
  renderReport(report);
};

loadReport().catch((error) => {
  const status = document.getElementById('report-status');
  if (status) {
    status.innerHTML = `<span class="pill bad">${escapeHtml(error.message)}</span>`;
  }
  document.body.insertAdjacentHTML(
    'afterbegin',
    `<div style="padding:16px;color:#ff7b7b;font-family:monospace">Dashboard load failed: ${escapeHtml(error.message)}</div>`,
  );
});
