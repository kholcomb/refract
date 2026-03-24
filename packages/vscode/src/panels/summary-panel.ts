import * as vscode from 'vscode'
import { Finding } from '@refract/core'

export class SummaryPanel {
  private panel: vscode.WebviewPanel | undefined
  private readonly extensionUri: vscode.Uri

  constructor(extensionUri: vscode.Uri) {
    this.extensionUri = extensionUri
  }

  isVisible(): boolean {
    return this.panel?.visible ?? false
  }

  show(findings: Finding[]): void {
    if (this.panel) {
      this.panel.reveal()
      this.update(findings)
      return
    }

    this.panel = vscode.window.createWebviewPanel(
      'antipatternSummary',
      'Anti-Pattern Findings',
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    )

    this.panel.onDidDispose(() => { this.panel = undefined })

    // Handle messages from the webview
    this.panel.webview.onDidReceiveMessage(async (msg) => {
      switch (msg.command) {
        case 'jumpToLine':
          const uri = vscode.Uri.file(msg.file)
          await vscode.window.showTextDocument(uri, {
            selection: new vscode.Range(
              new vscode.Position(Math.max(0, msg.line - 1), 0),
              new vscode.Position(Math.max(0, msg.line - 1), 9999)
            )
          })
          break
        case 'copyPrompt':
          vscode.commands.executeCommand('antipattern.copyAsAgentPrompt', msg.finding)
          break
        case 'openIssue':
          vscode.commands.executeCommand('antipattern.openGitHubIssue', msg.finding)
          break
        case 'showDiff':
          vscode.commands.executeCommand('antipattern.showDiffPreview', msg.finding)
          break
      }
    })

    this.update(findings)
  }

  update(findings: Finding[]): void {
    if (!this.panel) return
    this.panel.webview.html = buildHtml(findings)
  }
}

// -----------------------------------------------------------------------------
// HTML dashboard
// -----------------------------------------------------------------------------

function buildHtml(findings: Finding[]): string {
  const bySeverity: Record<string, number> = {}
  const byCategory: Record<string, number> = {}

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1
  }

  const severities = ['critical', 'high', 'medium', 'low', 'info']
  const severityColors: Record<string, string> = {
    critical: '#f85149', high: '#e3b341', medium: '#d29922', low: '#58a6ff', info: '#8b949e'
  }
  const effortIcons: Record<string, string> = {
    minutes: '[fast]', hours: '[hrs]', days: '[days]', weeks: '[wks]'
  }

  const findingCards = findings
    .sort((a, b) =>
      severities.indexOf(a.severity) - severities.indexOf(b.severity)
      || a.file.localeCompare(b.file)
    )
    .map(f => `
      <div class="finding-card severity-${f.severity}" data-id="${f.id}">
        <div class="finding-header">
          <span class="severity-badge severity-${f.severity}">${f.severity.toUpperCase()}</span>
          <span class="finding-name">${f.antipattern_name}</span>
          <span class="finding-effort">${effortIcons[f.effort] ?? ''} ${f.effort}</span>
        </div>
        <div class="finding-location" onclick="jumpTo('${f.file.replace(/\\/g, '\\\\')}', ${f.line_start})">
          [report] ${f.file}<span class="line-number">:${f.line_start}</span>
        </div>
        <div class="finding-message">${escHtml(f.message)}</div>
        <details>
          <summary>[fix] Remediation</summary>
          <div class="remediation">${escHtml(f.remediation)}</div>
        </details>
        <div class="finding-actions">
          <button onclick="copyPrompt(${JSON.stringify(JSON.stringify(f))})">[bot] Copy AI Prompt</button>
          <button onclick="showDiff(${JSON.stringify(JSON.stringify(f))})">Diff Preview</button>
          <button onclick="openIssue(${JSON.stringify(JSON.stringify(f))})">[issues] GitHub Issue</button>
        </div>
        <div class="finding-meta">
          <span class="tag">confidence: ${(f.confidence * 100).toFixed(0)}%</span>
          <span class="tag">${f.rule_id}</span>
          ${(f.tags ?? []).map(t => `<span class="tag">${t}</span>`).join('')}
        </div>
      </div>
    `).join('')

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anti-Pattern Findings</title>
<style>
  :root {
    --bg: var(--vscode-editor-background);
    --fg: var(--vscode-editor-foreground);
    --border: var(--vscode-panel-border);
    --input-bg: var(--vscode-input-background);
    --hover: var(--vscode-list-hoverBackground);
    --btn-bg: var(--vscode-button-background);
    --btn-fg: var(--vscode-button-foreground);
    --font: var(--vscode-font-family);
    --font-size: var(--vscode-font-size);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--fg);
    font-family: var(--font);
    font-size: var(--font-size);
    padding: 16px;
    line-height: 1.5;
  }
  h1 { font-size: 1.3em; margin-bottom: 12px; }
  h2 { font-size: 1em; margin: 16px 0 8px; color: var(--vscode-descriptionForeground); }

  /* Summary cards */
  .summary-row { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
  .summary-card {
    padding: 10px 16px;
    border-radius: 6px;
    border: 1px solid var(--border);
    min-width: 90px;
    text-align: center;
  }
  .summary-card .count { font-size: 1.8em; font-weight: bold; }
  .summary-card .label { font-size: 0.8em; opacity: 0.7; text-transform: uppercase; }

  /* Filter bar */
  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
  .filter-bar select, .filter-bar input {
    background: var(--input-bg);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 0.9em;
  }
  .filter-label { font-size: 0.85em; opacity: 0.7; }

  /* Finding cards */
  .findings-list { display: flex; flex-direction: column; gap: 10px; }
  .finding-card {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    border-left: 4px solid;
    transition: background 0.1s;
  }
  .finding-card:hover { background: var(--hover); }
  .finding-card.severity-critical { border-left-color: #f85149; }
  .finding-card.severity-high     { border-left-color: #e3b341; }
  .finding-card.severity-medium   { border-left-color: #d29922; }
  .finding-card.severity-low      { border-left-color: #58a6ff; }
  .finding-card.severity-info     { border-left-color: #8b949e; }

  .finding-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
  .finding-name { font-weight: 600; flex: 1; }
  .finding-effort { font-size: 0.8em; opacity: 0.7; }

  .severity-badge {
    font-size: 0.7em; font-weight: bold; padding: 2px 6px;
    border-radius: 3px; text-transform: uppercase;
  }
  .severity-badge.severity-critical { background: #f8514933; color: #f85149; }
  .severity-badge.severity-high     { background: #e3b34133; color: #e3b341; }
  .severity-badge.severity-medium   { background: #d2992233; color: #d29922; }
  .severity-badge.severity-low      { background: #58a6ff33; color: #58a6ff; }

  .finding-location {
    font-size: 0.85em; opacity: 0.8; cursor: pointer; margin-bottom: 6px;
    font-family: var(--vscode-editor-font-family);
  }
  .finding-location:hover { opacity: 1; text-decoration: underline; }
  .line-number { opacity: 0.6; }

  .finding-message { font-size: 0.9em; margin-bottom: 8px; }

  details summary {
    cursor: pointer; font-size: 0.85em; opacity: 0.8; margin-bottom: 4px;
    user-select: none;
  }
  .remediation {
    font-size: 0.85em; padding: 8px; background: var(--input-bg);
    border-radius: 4px; margin-bottom: 8px;
    white-space: pre-wrap;
    font-family: var(--vscode-editor-font-family);
  }

  .finding-actions { display: flex; gap: 6px; margin: 8px 0; flex-wrap: wrap; }
  .finding-actions button {
    background: var(--btn-bg); color: var(--btn-fg);
    border: none; border-radius: 4px; padding: 4px 10px;
    cursor: pointer; font-size: 0.8em;
  }
  .finding-actions button:hover { opacity: 0.85; }

  .finding-meta { display: flex; gap: 4px; flex-wrap: wrap; }
  .tag {
    font-size: 0.75em; padding: 1px 6px; border-radius: 3px;
    background: var(--input-bg); opacity: 0.8;
  }

  .empty-state {
    text-align: center; padding: 48px 24px; opacity: 0.6;
  }
  .empty-state .icon { font-size: 2em; margin-bottom: 8px; }
</style>
</head>
<body>
<h1>[scan] Anti-Pattern Findings</h1>

<div class="summary-row">
  ${severities.map(s => `
    <div class="summary-card">
      <div class="count" style="color:${severityColors[s]}">${bySeverity[s] ?? 0}</div>
      <div class="label">${s}</div>
    </div>
  `).join('')}
  <div class="summary-card">
    <div class="count">${findings.length}</div>
    <div class="label">total</div>
  </div>
</div>

<div class="filter-bar">
  <span class="filter-label">Filter:</span>
  <select id="filterSeverity" onchange="applyFilters()">
    <option value="">All severities</option>
    ${severities.map(s => `<option value="${s}">${s}</option>`).join('')}
  </select>
  <select id="filterCategory" onchange="applyFilters()">
    <option value="">All categories</option>
    ${Object.keys(byCategory).map(c => `<option value="${c}">${c.replace(/_/g, ' ')}</option>`).join('')}
  </select>
  <input id="filterText" placeholder="Search files or patterns..." oninput="applyFilters()" style="flex:1;min-width:160px">
</div>

${findings.length === 0
  ? `<div class="empty-state"><div class="icon">[ok]</div><div>No findings -- save a file to scan</div></div>`
  : `<div class="findings-list" id="findingsList">${findingCards}</div>`
}

<script>
  const vscode = acquireVsCodeApi()

  function jumpTo(file, line) {
    vscode.postMessage({ command: 'jumpToLine', file, line })
  }
  function copyPrompt(findingJson) {
    vscode.postMessage({ command: 'copyPrompt', finding: JSON.parse(findingJson) })
  }
  function showDiff(findingJson) {
    vscode.postMessage({ command: 'showDiff', finding: JSON.parse(findingJson) })
  }
  function openIssue(findingJson) {
    vscode.postMessage({ command: 'openIssue', finding: JSON.parse(findingJson) })
  }

  function applyFilters() {
    const sev = document.getElementById('filterSeverity').value
    const cat = document.getElementById('filterCategory').value
    const txt = document.getElementById('filterText').value.toLowerCase()

    document.querySelectorAll('.finding-card').forEach(card => {
      const show = (
        (!sev || card.classList.contains('severity-' + sev)) &&
        (!cat || card.querySelector('.tag')?.textContent?.includes(cat)) &&
        (!txt || card.textContent.toLowerCase().includes(txt))
      )
      card.style.display = show ? '' : 'none'
    })
  }
</script>
</body>
</html>`
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
