/**
 * ShieldPM — HTML Report Generator
 * Generates beautiful, interactive HTML reports with tabbed navigation
 * covering all security modules: risk analysis, SBOM, licenses, compliance,
 * provenance, maintainer risk, remediation, posture, and monitoring.
 */

import { writeFile } from 'node:fs/promises';
import type { RiskReport } from '../analyzer/static.js';
import type { SBOMDocument } from '../sbom/generator.js';
import type { LicenseReport } from '../license/compliance.js';
import type { ComplianceReport } from '../compliance/reporter.js';
import type { ProvenanceReport } from '../provenance/verifier.js';
import type { MaintainerReport } from '../maintainer/risk.js';
import type { RemediationReport } from '../remediation/patches.js';
import type { PostureTrend } from '../posture/trending.js';
import type { MonitorStatus } from '../monitoring/watcher.js';
import type { PolicyEvaluation } from '../policy/engine.js';
import type { GateResult } from '../cicd/integration.js';

// ── Types ────────────────────────────────────────────────────────────────

export interface HTMLReportData {
  projectName: string;
  version: string;
  generatedAt: string;
  riskReports?: Map<string, RiskReport>;
  sbom?: SBOMDocument;
  licenseReport?: LicenseReport;
  complianceReports?: ComplianceReport[];
  provenanceReport?: ProvenanceReport;
  maintainerReport?: MaintainerReport;
  remediationReport?: RemediationReport;
  postureTrend?: PostureTrend;
  monitorStatus?: MonitorStatus;
  policyEvaluations?: PolicyEvaluation[];
  gateResult?: GateResult;
}

// ── Template Helpers ────────────────────────────────────────────────────

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function scoreColor(score: number): string {
  if (score >= 7) return '#ef4444';
  if (score >= 4) return '#f59e0b';
  return '#22c55e';
}

function statusBadge(status: string): string {
  const colors: Record<string, string> = {
    met: '#22c55e', partial: '#f59e0b', 'not-met': '#ef4444', 'not-applicable': '#6b7280',
    verified: '#22c55e', unverified: '#f59e0b', missing: '#ef4444', invalid: '#ef4444',
    low: '#22c55e', medium: '#f59e0b', high: '#ef4444', critical: '#dc2626',
  };
  const color = colors[status] ?? '#6b7280';
  return `<span style="background:${color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">${esc(status.toUpperCase())}</span>`;
}

// ── Tab Sections ────────────────────────────────────────────────────────

function renderOverviewTab(data: HTMLReportData): string {
  const totalPkgs = data.riskReports?.size ?? 0;
  const highRisk = data.riskReports ? [...data.riskReports.values()].filter(r => r.score >= 7).length : 0;
  const avgScore = totalPkgs > 0
    ? ([...data.riskReports!.values()].reduce((s, r) => s + r.score, 0) / totalPkgs).toFixed(1)
    : '0.0';
  const totalFindings = data.riskReports
    ? [...data.riskReports.values()].reduce((s, r) => s + r.findings.length, 0)
    : 0;

  return `
    <div class="grid">
      <div class="card metric-card">
        <div class="metric-value">${totalPkgs}</div>
        <div class="metric-label">Packages Scanned</div>
      </div>
      <div class="card metric-card">
        <div class="metric-value" style="color:${scoreColor(parseFloat(avgScore))}">${avgScore}</div>
        <div class="metric-label">Avg Risk Score</div>
      </div>
      <div class="card metric-card">
        <div class="metric-value" style="color:${highRisk > 0 ? '#ef4444' : '#22c55e'}">${highRisk}</div>
        <div class="metric-label">High Risk Packages</div>
      </div>
      <div class="card metric-card">
        <div class="metric-value">${totalFindings}</div>
        <div class="metric-label">Total Findings</div>
      </div>
      <div class="card metric-card">
        <div class="metric-value">${data.licenseReport?.violations.length ?? 0}</div>
        <div class="metric-label">License Violations</div>
      </div>
      <div class="card metric-card">
        <div class="metric-value">${data.gateResult ? (data.gateResult.passed ? 'PASS' : 'FAIL') : 'N/A'}</div>
        <div class="metric-label">Gate Status</div>
      </div>
    </div>
    ${data.gateResult ? renderGateSection(data.gateResult) : ''}
  `;
}

function renderGateSection(gate: GateResult): string {
  return `
    <div class="card" style="margin-top:20px">
      <h3>Gate Result: ${gate.passed ? '<span style="color:#22c55e">PASSED</span>' : '<span style="color:#ef4444">FAILED</span>'}</h3>
      <table><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead><tbody>
      ${gate.checks.map(c => `
        <tr>
          <td>${esc(c.name)}</td>
          <td>${c.passed ? '<span style="color:#22c55e">&#10003;</span>' : '<span style="color:#ef4444">&#10007;</span>'}</td>
          <td>${esc(c.message)}</td>
        </tr>
      `).join('')}
      </tbody></table>
    </div>`;
}

function renderRiskTab(data: HTMLReportData): string {
  if (!data.riskReports || data.riskReports.size === 0) return '<p>No risk data available.</p>';

  const sorted = [...data.riskReports.entries()].sort((a, b) => b[1].score - a[1].score);

  return `
    <table>
      <thead><tr><th>Package</th><th>Score</th><th>Findings</th><th>Categories</th></tr></thead>
      <tbody>
      ${sorted.map(([name, report]) => `
        <tr>
          <td><code>${esc(name)}</code></td>
          <td><span style="color:${scoreColor(report.score)};font-weight:700">${report.score.toFixed(1)}</span></td>
          <td>${report.findings.length}</td>
          <td>${Object.entries(report.categoryCounts).map(([cat, count]) =>
            `<span class="tag">${esc(cat)}:${count}</span>`
          ).join(' ')}</td>
        </tr>
      `).join('')}
      </tbody>
    </table>
  `;
}

function renderSBOMTab(data: HTMLReportData): string {
  if (!data.sbom) return '<p>No SBOM generated. Run: <code>shieldpm sbom</code></p>';

  return `
    <div class="grid">
      <div class="card metric-card">
        <div class="metric-value">${data.sbom.totalComponents}</div>
        <div class="metric-label">Components</div>
      </div>
      <div class="card metric-card">
        <div class="metric-value">${data.sbom.format.toUpperCase()}</div>
        <div class="metric-label">Format</div>
      </div>
      <div class="card metric-card">
        <div class="metric-value">${data.sbom.specVersion}</div>
        <div class="metric-label">Spec Version</div>
      </div>
    </div>
    <table style="margin-top:20px">
      <thead><tr><th>Component</th><th>Version</th><th>License</th><th>Scope</th></tr></thead>
      <tbody>
      ${data.sbom.components.slice(0, 100).map(c => `
        <tr>
          <td><code>${esc(c.name)}</code></td>
          <td>${esc(c.version)}</td>
          <td>${c.license ? esc(c.license) : '<em>unknown</em>'}</td>
          <td><span class="tag">${esc(c.scope)}</span></td>
        </tr>
      `).join('')}
      </tbody>
    </table>
    ${data.sbom.components.length > 100 ? `<p><em>...and ${data.sbom.components.length - 100} more</em></p>` : ''}
  `;
}

function renderLicenseTab(data: HTMLReportData): string {
  if (!data.licenseReport) return '<p>No license data. Run: <code>shieldpm license scan</code></p>';

  const r = data.licenseReport;
  return `
    <div class="grid">
      <div class="card metric-card"><div class="metric-value">${r.summary.total}</div><div class="metric-label">Total</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#22c55e">${r.summary.permissive}</div><div class="metric-label">Permissive</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#f59e0b">${r.summary.weakCopyleft}</div><div class="metric-label">Weak Copyleft</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#ef4444">${r.summary.copyleft}</div><div class="metric-label">Copyleft</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#6b7280">${r.summary.unknown}</div><div class="metric-label">Unknown</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:${r.summary.violations > 0 ? '#ef4444' : '#22c55e'}">${r.summary.violations}</div><div class="metric-label">Violations</div></div>
    </div>
    ${r.violations.length > 0 ? `
      <h3 style="margin-top:20px">Violations</h3>
      <table><thead><tr><th>Package</th><th>License</th><th>Type</th><th>Message</th></tr></thead><tbody>
      ${r.violations.map(v => `
        <tr>
          <td><code>${esc(v.packageName)}</code></td>
          <td>${esc(v.license)}</td>
          <td>${statusBadge(v.severity)}</td>
          <td>${esc(v.message)}</td>
        </tr>
      `).join('')}
      </tbody></table>
    ` : ''}
    <h3 style="margin-top:20px">All Packages</h3>
    <table><thead><tr><th>Package</th><th>License</th><th>Category</th><th>Source</th></tr></thead><tbody>
    ${r.packages.map(p => `
      <tr>
        <td><code>${esc(p.packageName)}</code></td>
        <td>${esc(p.license)}</td>
        <td>${statusBadge(p.category)}</td>
        <td>${esc(p.source)}</td>
      </tr>
    `).join('')}
    </tbody></table>
  `;
}

function renderComplianceTab(data: HTMLReportData): string {
  if (!data.complianceReports || data.complianceReports.length === 0) {
    return '<p>No compliance data. Run: <code>shieldpm compliance</code></p>';
  }

  return data.complianceReports.map(report => `
    <div class="card" style="margin-bottom:20px">
      <h3>${esc(report.frameworkName)} — ${report.summary.complianceScore}% Compliant</h3>
      <div class="progress-bar">
        <div class="progress-fill" style="width:${report.summary.complianceScore}%;background:${report.summary.complianceScore >= 80 ? '#22c55e' : report.summary.complianceScore >= 50 ? '#f59e0b' : '#ef4444'}"></div>
      </div>
      <table style="margin-top:12px"><thead><tr><th>Control</th><th>Name</th><th>Status</th><th>Gaps</th></tr></thead><tbody>
      ${report.controls.map(c => `
        <tr>
          <td><code>${esc(c.controlId)}</code></td>
          <td>${esc(c.controlName)}</td>
          <td>${statusBadge(c.status)}</td>
          <td>${c.gaps.length > 0 ? c.gaps.map(g => esc(g)).join('<br>') : '<em>None</em>'}</td>
        </tr>
      `).join('')}
      </tbody></table>
    </div>
  `).join('');
}

function renderProvenanceTab(data: HTMLReportData): string {
  if (!data.provenanceReport) return '<p>No provenance data. Run: <code>shieldpm provenance</code></p>';

  const r = data.provenanceReport;
  return `
    <div class="grid">
      <div class="card metric-card"><div class="metric-value">${r.summary.total}</div><div class="metric-label">Total</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#22c55e">${r.summary.verified}</div><div class="metric-label">Verified</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#f59e0b">${r.summary.unverified}</div><div class="metric-label">Unverified</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#ef4444">${r.summary.missing}</div><div class="metric-label">Missing</div></div>
      <div class="card metric-card"><div class="metric-value">${r.summary.provenanceCoverage}%</div><div class="metric-label">Coverage</div></div>
    </div>
    <table style="margin-top:20px"><thead><tr><th>Package</th><th>Version</th><th>Status</th><th>Source Repo</th><th>Risk Factors</th></tr></thead><tbody>
    ${r.packages.map(p => `
      <tr>
        <td><code>${esc(p.packageName)}</code></td>
        <td>${esc(p.version)}</td>
        <td>${statusBadge(p.status)}</td>
        <td>${p.sourceRepo ? `<a href="${esc(p.sourceRepo)}" target="_blank">${esc(p.sourceRepo.replace(/https?:\/\//, '').slice(0, 40))}</a>` : '<em>none</em>'}</td>
        <td>${p.riskFactors.length > 0 ? p.riskFactors.map(f => `<span class="tag tag-warn">${esc(f)}</span>`).join(' ') : '-'}</td>
      </tr>
    `).join('')}
    </tbody></table>
  `;
}

function renderMaintainerTab(data: HTMLReportData): string {
  if (!data.maintainerReport) return '<p>No maintainer data. Run: <code>shieldpm maintainer</code></p>';

  const r = data.maintainerReport;
  return `
    <div class="grid">
      <div class="card metric-card"><div class="metric-value">${r.summary.total}</div><div class="metric-label">Packages</div></div>
      <div class="card metric-card"><div class="metric-value">${r.summary.averageScore}</div><div class="metric-label">Avg Risk</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#f59e0b">${r.summary.singleMaintainerCount}</div><div class="metric-label">Single Maintainer</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#ef4444">${r.summary.critical}</div><div class="metric-label">Critical</div></div>
    </div>
    <table style="margin-top:20px"><thead><tr><th>Package</th><th>Risk</th><th>Maintainers</th><th>Factors</th><th>Actions</th></tr></thead><tbody>
    ${r.packages.slice(0, 50).map(p => `
      <tr>
        <td><code>${esc(p.packageName)}</code></td>
        <td>${statusBadge(p.riskLevel)}</td>
        <td>${p.maintainerCount}</td>
        <td>${p.riskFactors.map(f => `<span class="tag tag-warn">${esc(f.factor)}</span>`).join(' ')}</td>
        <td>${p.recommendations.map(r => esc(r)).join('<br>') || '-'}</td>
      </tr>
    `).join('')}
    </tbody></table>
  `;
}

function renderRemediationTab(data: HTMLReportData): string {
  if (!data.remediationReport) return '<p>No remediation data available.</p>';

  const r = data.remediationReport;
  return `
    <div class="grid">
      <div class="card metric-card"><div class="metric-value">${r.summary.total}</div><div class="metric-label">Suggestions</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#ef4444">${r.summary.critical}</div><div class="metric-label">Critical</div></div>
      <div class="card metric-card"><div class="metric-value" style="color:#f59e0b">${r.summary.high}</div><div class="metric-label">High</div></div>
      <div class="card metric-card"><div class="metric-value">${esc(r.summary.estimatedEffort)}</div><div class="metric-label">Est. Effort</div></div>
    </div>
    ${r.packages.map(pkg => `
      <div class="card" style="margin-top:16px">
        <h3><code>${esc(pkg.packageName)}</code> <span style="color:${scoreColor(pkg.riskScore)}">(${pkg.riskScore.toFixed(1)}/10)</span></h3>
        ${pkg.suggestions.map(s => `
          <div style="padding:8px 0;border-bottom:1px solid #333">
            ${statusBadge(s.priority)} <strong>${esc(s.title)}</strong>
            <p style="margin:4px 0;color:#999">${esc(s.description)}</p>
            <code style="font-size:12px;color:#60a5fa">${esc(s.action)}</code>
          </div>
        `).join('')}
      </div>
    `).join('')}
  `;
}

function renderPostureTab(data: HTMLReportData): string {
  if (!data.postureTrend) return '<p>No posture data. Run: <code>shieldpm posture snapshot</code></p>';

  const t = data.postureTrend;
  const trendColor = t.trend === 'improving' ? '#22c55e' : t.trend === 'declining' ? '#ef4444' : '#f59e0b';

  return `
    <div class="card">
      <h3>Trend: <span style="color:${trendColor}">${t.trend.toUpperCase()}</span> (${t.changePercent >= 0 ? '+' : ''}${t.changePercent}%)</h3>
      <p>${esc(t.summary)}</p>
    </div>
    ${t.improvements.length > 0 ? `
      <div class="card" style="margin-top:16px;border-left:3px solid #22c55e">
        <h4 style="color:#22c55e">Improvements</h4>
        <ul>${t.improvements.map(i => `<li>${esc(i)}</li>`).join('')}</ul>
      </div>
    ` : ''}
    ${t.regressions.length > 0 ? `
      <div class="card" style="margin-top:16px;border-left:3px solid #ef4444">
        <h4 style="color:#ef4444">Regressions</h4>
        <ul>${t.regressions.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
      </div>
    ` : ''}
    ${t.snapshots.length > 0 ? `
      <h3 style="margin-top:20px">Snapshot History</h3>
      <table><thead><tr><th>Date</th><th>Score</th><th>Packages</th><th>High Risk</th><th>Findings</th></tr></thead><tbody>
      ${t.snapshots.map(s => `
        <tr>
          <td>${s.timestamp.slice(0, 10)}</td>
          <td><strong>${s.metrics.overallScore}/100</strong></td>
          <td>${s.packageCount}</td>
          <td>${s.highRiskPackages.length}</td>
          <td>${s.metrics.totalFindings}</td>
        </tr>
      `).join('')}
      </tbody></table>
    ` : ''}
  `;
}

function renderMonitorTab(data: HTMLReportData): string {
  if (!data.monitorStatus) return '<p>No monitoring data. Run: <code>shieldpm monitor check</code></p>';

  const m = data.monitorStatus;
  return `
    <div class="grid">
      <div class="card metric-card"><div class="metric-value">${m.checksPerformed}</div><div class="metric-label">Checks Run</div></div>
      <div class="card metric-card"><div class="metric-value">${m.trackedPackages}</div><div class="metric-label">Tracked Packages</div></div>
      <div class="card metric-card"><div class="metric-value">${m.lastCheck?.slice(0, 10) ?? 'Never'}</div><div class="metric-label">Last Check</div></div>
    </div>
    <p style="margin-top:16px">${esc(m.summary)}</p>
    ${m.recentEvents.length > 0 ? `
      <h3 style="margin-top:20px">Recent Events</h3>
      <table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Message</th></tr></thead><tbody>
      ${m.recentEvents.map(e => `
        <tr>
          <td>${e.timestamp.slice(0, 19).replace('T', ' ')}</td>
          <td>${statusBadge(e.severity)}</td>
          <td><span class="tag">${esc(e.type)}</span></td>
          <td>${esc(e.message)}</td>
        </tr>
      `).join('')}
      </tbody></table>
    ` : '<p><em>No recent events</em></p>'}
  `;
}

// ── Main HTML Generator ─────────────────────────────────────────────────

export function generateHTMLReport(data: HTMLReportData): string {
  const tabs = [
    { id: 'overview', label: 'Overview', content: renderOverviewTab(data) },
    { id: 'risk', label: 'Risk Analysis', content: renderRiskTab(data) },
    { id: 'sbom', label: 'SBOM', content: renderSBOMTab(data) },
    { id: 'license', label: 'Licenses', content: renderLicenseTab(data) },
    { id: 'compliance', label: 'Compliance', content: renderComplianceTab(data) },
    { id: 'provenance', label: 'Provenance', content: renderProvenanceTab(data) },
    { id: 'maintainer', label: 'Maintainers', content: renderMaintainerTab(data) },
    { id: 'remediation', label: 'Remediation', content: renderRemediationTab(data) },
    { id: 'posture', label: 'Posture', content: renderPostureTab(data) },
    { id: 'monitor', label: 'Monitor', content: renderMonitorTab(data) },
  ];

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShieldPM Security Report — ${esc(data.projectName)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0a;color:#e5e5e5;line-height:1.6}
.header{background:linear-gradient(135deg,#0f172a,#1e293b);padding:32px 40px;border-bottom:1px solid #334155}
.header h1{font-size:28px;color:#38bdf8;display:flex;align-items:center;gap:12px}
.header .subtitle{color:#94a3b8;font-size:14px;margin-top:4px}
.tabs{display:flex;gap:0;background:#111;border-bottom:2px solid #222;padding:0 20px;overflow-x:auto;-webkit-overflow-scrolling:touch}
.tab{padding:12px 20px;cursor:pointer;color:#888;font-size:13px;font-weight:500;border-bottom:2px solid transparent;white-space:nowrap;transition:all .2s}
.tab:hover{color:#ccc;background:#1a1a1a}
.tab.active{color:#38bdf8;border-bottom-color:#38bdf8;background:#1a1a2e}
.content{padding:24px 40px;max-width:1400px;margin:0 auto}
.tab-panel{display:none}
.tab-panel.active{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px}
.card{background:#161616;border:1px solid #262626;border-radius:10px;padding:20px}
.metric-card{text-align:center}
.metric-value{font-size:32px;font-weight:700;color:#f0eee8}
.metric-label{font-size:12px;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
th{text-align:left;padding:10px 12px;background:#1a1a1a;color:#999;font-weight:600;border-bottom:1px solid #333;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}
td{padding:10px 12px;border-bottom:1px solid #222}
tr:hover td{background:#1a1a1a}
code{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:12px;color:#38bdf8}
a{color:#38bdf8;text-decoration:none}
a:hover{text-decoration:underline}
.tag{display:inline-block;background:#262626;color:#aaa;padding:2px 8px;border-radius:4px;font-size:11px;margin:1px}
.tag-warn{background:#422006;color:#fbbf24}
.progress-bar{height:8px;background:#262626;border-radius:4px;overflow:hidden;margin-top:8px}
.progress-fill{height:100%;border-radius:4px;transition:width .3s}
h3{font-size:16px;margin-bottom:12px;color:#e5e5e5}
h4{font-size:14px;margin-bottom:8px}
ul{padding-left:20px}
li{margin:4px 0;color:#ccc}
em{color:#666}
p{color:#999;margin:8px 0}
.footer{text-align:center;padding:24px;color:#555;font-size:12px;border-top:1px solid #222;margin-top:40px}
@media(max-width:768px){.content{padding:16px}.grid{grid-template-columns:repeat(2,1fr)}.tabs{padding:0 8px}.tab{padding:10px 14px;font-size:12px}}
</style>
</head>
<body>
<div class="header">
  <h1>&#x1f6e1; ShieldPM Security Report</h1>
  <div class="subtitle">${esc(data.projectName)} v${esc(data.version)} &mdash; Generated ${data.generatedAt.slice(0, 19).replace('T', ' ')}</div>
</div>
<div class="tabs">
  ${tabs.map((t, i) => `<div class="tab${i === 0 ? ' active' : ''}" data-tab="${t.id}">${t.label}</div>`).join('')}
</div>
<div class="content">
  ${tabs.map((t, i) => `<div class="tab-panel${i === 0 ? ' active' : ''}" id="tab-${t.id}">${t.content}</div>`).join('')}
</div>
<div class="footer">
  Generated by <strong>ShieldPM v0.3.0</strong> &mdash; Runtime-aware package firewall for Node.js<br>
  <a href="https://github.com/nrupaks/shieldpm">github.com/nrupaks/shieldpm</a>
</div>
<script>
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});
</script>
</body>
</html>`;
}

export async function writeHTMLReport(filePath: string, data: HTMLReportData): Promise<string> {
  const html = generateHTMLReport(data);
  await writeFile(filePath, html, 'utf-8');
  return filePath;
}
