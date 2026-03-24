import * as vscode from 'vscode'
import * as path from 'path'
import { Finding, Severity, SEVERITY_ORDER } from '@refract/core'

const SEVERITY_ICON: Record<string, string> = {
  critical: 'error',
  high:     'warning',
  medium:   'info',
  low:      'lightbulb',
  info:     'circle-outline',
}

// --- Tree item types ---

class FileNode extends vscode.TreeItem {
  constructor(
    public readonly filePath: string,
    public readonly findings: Finding[]
  ) {
    const fileName = path.basename(filePath)
    const highestSeverity = findings.reduce((worst, f) => {
      return SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(worst)
        ? f.severity : worst
    }, 'info' as Severity)

    super(fileName, vscode.TreeItemCollapsibleState.Expanded)

    this.description = `${findings.length} finding${findings.length !== 1 ? 's' : ''}`
    this.tooltip = filePath
    this.iconPath = new vscode.ThemeIcon(
      SEVERITY_ICON[highestSeverity] ?? 'circle-outline',
      new vscode.ThemeColor(severityColor(highestSeverity))
    )
    this.resourceUri = vscode.Uri.file(filePath)
    this.contextValue = 'antipatternFile'
  }
}

class FindingNode extends vscode.TreeItem {
  constructor(public readonly finding: Finding) {
    super(finding.antipattern_name, vscode.TreeItemCollapsibleState.None)

    this.description = `line ${finding.line_start} - ${finding.effort}`
    this.tooltip = new vscode.MarkdownString(
      `**${finding.antipattern_name}** \`${finding.severity}\`\n\n` +
      `${finding.message}\n\n` +
      `**Fix:** ${finding.remediation}\n\n` +
      `*Confidence: ${(finding.confidence * 100).toFixed(0)}% - Rule: ${finding.rule_id}*`
    )
    this.tooltip.isTrusted = true

    this.iconPath = new vscode.ThemeIcon(
      SEVERITY_ICON[finding.severity] ?? 'circle-outline',
      new vscode.ThemeColor(severityColor(finding.severity))
    )

    // Click -> jump to the line in the editor
    this.command = {
      command: 'vscode.open',
      title: 'Go to finding',
      arguments: [
        vscode.Uri.file(finding.file),
        {
          selection: new vscode.Range(
            new vscode.Position(Math.max(0, finding.line_start - 1), 0),
            new vscode.Position(Math.max(0, finding.line_end - 1), 9999)
          )
        }
      ]
    }

    this.contextValue = 'antipatternFinding'
  }
}

// --- Tree data provider ---

export class FindingsTreeProvider
  implements vscode.TreeDataProvider<vscode.TreeItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined | void>()
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event

  // file path -> findings
  private findingsByFile = new Map<string, Finding[]>()

  updateFindings(filePath: string, findings: Finding[]): void {
    if (findings.length === 0) {
      this.findingsByFile.delete(filePath)
    } else {
      this.findingsByFile.set(filePath, findings)
    }
    this._onDidChangeTreeData.fire()
  }

  clear(): void {
    this.findingsByFile.clear()
    this._onDidChangeTreeData.fire()
  }

  getTotalCount(): number {
    return Array.from(this.findingsByFile.values())
      .reduce((sum, f) => sum + f.length, 0)
  }

  getAllFindings(): Finding[] {
    return Array.from(this.findingsByFile.values()).flat()
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element
  }

  getChildren(element?: vscode.TreeItem): vscode.ProviderResult<vscode.TreeItem[]> {
    // Root: list of files sorted by worst severity
    if (!element) {
      if (this.findingsByFile.size === 0) {
        const empty = new vscode.TreeItem('No findings -- looking clean [ok]')
        empty.iconPath = new vscode.ThemeIcon('pass')
        return [empty]
      }

      return Array.from(this.findingsByFile.entries())
        .sort(([, a], [, b]) => worstSeverityIndex(a) - worstSeverityIndex(b))
        .map(([filePath, findings]) => new FileNode(filePath, findings))
    }

    // File node: list its findings sorted by severity then line number
    if (element instanceof FileNode) {
      return element.findings
        .slice()
        .sort((a, b) =>
          SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
          || a.line_start - b.line_start
        )
        .map(f => new FindingNode(f))
    }

    return []
  }
}

// --- Helpers ---

function worstSeverityIndex(findings: Finding[]): number {
  return Math.min(...findings.map(f => SEVERITY_ORDER.indexOf(f.severity)))
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'errorForeground'
    case 'high':     return 'problemsWarningIconForeground'
    case 'medium':   return 'problemsWarningIconForeground'
    case 'low':      return 'problemsInfoIconForeground'
    default:         return 'foreground'
  }
}
