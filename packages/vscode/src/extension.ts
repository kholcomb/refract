/**
 * Anti-Pattern Detector -- VS Code Extension Entrypoint
 *
 * Manages the LSP client lifecycle and wires up:
 *  - LSP client <-> server connection
 *  - Commands (scan, copy prompt, show diff, open issue)
 *  - Activity bar tree view
 *  - Status bar item
 *  - Config sync to LSP server
 */

import * as vscode from 'vscode'
import * as path from 'path'
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from 'vscode-languageclient/node'
import { FindingsTreeProvider } from './panels/findings-tree'
import { SummaryPanel } from './panels/summary-panel'

let client: LanguageClient
let statusBarItem: vscode.StatusBarItem
let treeProvider: FindingsTreeProvider
let summaryPanel: SummaryPanel | undefined

// --- Activate ---

export async function activate(context: vscode.ExtensionContext) {
  const serverModule = context.asAbsolutePath(path.join('dist', 'lspServer.js'))

  // LSP server options -- runs in a Node.js child process
  const serverOptions: ServerOptions = {
    run: {
      module: serverModule,
      transport: TransportKind.stdio,
    },
    debug: {
      module: serverModule,
      transport: TransportKind.stdio,
      options: { execArgv: ['--nolazy', '--inspect=6009'] },
    },
  }

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: 'file', language: 'python' },
      { scheme: 'file', language: 'typescript' },
      { scheme: 'file', language: 'javascript' },
    ],
    synchronize: {
      configurationSection: 'antipattern',
      fileEvents: vscode.workspace.createFileSystemWatcher('**/*.py'),
    },
    initializationOptions: {
      extensionPath: context.extensionPath,
    },
  }

  client = new LanguageClient(
    'antipatternDetector',
    'Anti-Pattern Detector',
    serverOptions,
    clientOptions
  )

  // --- Status bar ---
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left, 100
  )
  statusBarItem.command = 'antipattern.showPanel'
  statusBarItem.text = '$(search) Anti-Pattern'
  statusBarItem.tooltip = 'Anti-Pattern Detector -- Click to show findings'
  statusBarItem.show()
  context.subscriptions.push(statusBarItem)

  // --- Tree view ---
  treeProvider = new FindingsTreeProvider()
  const treeView = vscode.window.createTreeView('antipattern.findingsTree', {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  })
  context.subscriptions.push(treeView)

  // --- LSP notifications from server ---
  // Registered before client.start() -- notifications are buffered until ready.

  // Receive findings updates
  client.onNotification('antipattern/findingsUpdated', (data: {
    uri: string
    file: string
    findings: any[]
    timestamp: string
  }) => {
    treeProvider.updateFindings(data.file, data.findings)
    updateStatusBar(treeProvider.getTotalCount())

    if (summaryPanel?.isVisible()) {
      summaryPanel.update(treeProvider.getAllFindings())
    }
  })

  client.onNotification('antipattern/findingsCleared', () => {
    treeProvider.clear()
    updateStatusBar(0)
    summaryPanel?.update([])
  })

  client.onNotification('antipattern/workspaceScanComplete', (data: {
    fileCount: number
    totalFindings: number
  }) => {
    vscode.window.setStatusBarMessage(
      `$(check) Anti-Pattern scan complete: ${data.totalFindings} findings in ${data.fileCount} files`,
      5000
    )
  })

  // --- Commands ---

  context.subscriptions.push(
    vscode.commands.registerCommand('antipattern.scanFile', () => {
      const uri = vscode.window.activeTextEditor?.document.uri
      if (!uri) return
      statusBarItem.text = '$(sync~spin) Scanning...'
      client.sendNotification('antipattern/scanFile', { uri: uri.toString() })
    }),

    vscode.commands.registerCommand('antipattern.scanWorkspace', () => {
      statusBarItem.text = '$(sync~spin) Scanning workspace...'
      vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Anti-Pattern: Scanning workspace...',
        cancellable: false,
      }, async () => {
        client.sendNotification('antipattern/scanWorkspace')
      })
    }),

    vscode.commands.registerCommand('antipattern.showPanel', () => {
      if (!summaryPanel) {
        summaryPanel = new SummaryPanel(context.extensionUri)
      }
      summaryPanel.show(treeProvider.getAllFindings())
    }),

    vscode.commands.registerCommand('antipattern.clearFindings', () => {
      client.sendNotification('antipattern/clearFindings')
    }),

    // Show a diff between current code and suggested fix
    vscode.commands.registerCommand('antipattern.showDiffPreview', async (finding: any) => {
      const fix = buildFixPreview(finding)
      if (!fix) {
        vscode.window.showInformationMessage(
          `No automatic fix available for ${finding.antipattern_name}. Remediation: ${finding.remediation}`
        )
        return
      }

      const original = vscode.Uri.parse(`antipattern-original:${finding.file}`)
      const fixed = vscode.Uri.parse(`antipattern-fixed:${finding.file}`)

      // Register one-time content providers for the diff
      const reg1 = vscode.workspace.registerTextDocumentContentProvider(
        'antipattern-original', {
          provideTextDocumentContent: () => fix.originalSnippet
        }
      )
      const reg2 = vscode.workspace.registerTextDocumentContentProvider(
        'antipattern-fixed', {
          provideTextDocumentContent: () => fix.fixedSnippet
        }
      )

      await vscode.commands.executeCommand(
        'vscode.diff',
        original,
        fixed,
        `Fix Preview: ${finding.antipattern_name} (${finding.file}:${finding.line_start})`
      )

      // Clean up providers after a moment
      setTimeout(() => { reg1.dispose(); reg2.dispose() }, 30_000)
    }),

    // Open GitHub issue for this finding
    vscode.commands.registerCommand('antipattern.openGitHubIssue', async (finding: any) => {
      const config = vscode.workspace.getConfiguration('antipattern')
      const token = config.get<string>('githubToken')

      if (!token) {
        const action = await vscode.window.showInformationMessage(
          'Add a GitHub token in settings to create issues directly from the IDE.',
          'Open Settings'
        )
        if (action === 'Open Settings') {
          vscode.commands.executeCommand(
            'workbench.action.openSettings', 'antipattern.githubToken'
          )
        }
        return
      }

      // Open browser to pre-filled new issue form as fallback
      const repoUrl = await getRepoUrl()
      if (repoUrl) {
        const title = encodeURIComponent(
          `[${finding.severity.toUpperCase()}] ${finding.antipattern_name} in \`${finding.file}\``
        )
        const body = encodeURIComponent(buildIssueBody(finding))
        vscode.env.openExternal(
          vscode.Uri.parse(`${repoUrl}/issues/new?title=${title}&body=${body}&labels=antipattern`)
        )
      }
    }),

    // Copy the structured AI agent prompt to clipboard
    vscode.commands.registerCommand('antipattern.copyAsAgentPrompt', async (finding: any) => {
      const prompt = await client.sendRequest('antipattern/buildAgentPrompt', finding)
      await vscode.env.clipboard.writeText(prompt as string)
      vscode.window.showInformationMessage(
        '$(clippy) AI agent prompt copied to clipboard'
      )
    })
  )

  // --- Config change listener ---
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('antipattern')) {
        syncConfigToServer()
      }
    })
  )

  // Start the LSP client (starts the server process)
  context.subscriptions.push(client)
  await client.start()

  // Sync config to server now that it's ready
  syncConfigToServer()

  vscode.window.showInformationMessage(
    '$(search) Anti-Pattern Detector active -- findings will appear on save'
  )
}

// --- Deactivate ---

export function deactivate(): Thenable<void> | undefined {
  return client?.stop()
}

// --- Helpers ---

function syncConfigToServer(): void {
  const cfg = vscode.workspace.getConfiguration('antipattern')
  client.sendNotification('antipattern/updateConfig', {
    enabled:             cfg.get('enabled', true),
    severityThreshold:   cfg.get('severityThreshold', 'medium'),
    confidenceThreshold: cfg.get('confidenceThreshold', 0.7),
    categories:          cfg.get('categories', ['code_structure', 'security', 'dependencies', 'test_quality']),
    pythonPath:          cfg.get('pythonPath', 'python3'),
    ignorePaths:         cfg.get('ignorePaths', []),
    showInlineHints:     cfg.get('showInlineHints', true),
    ciParity:            cfg.get('ciParity', true),
    scanOnOpen:          cfg.get('scanOnOpen', true),
  })
}

function updateStatusBar(count: number): void {
  if (count === 0) {
    statusBarItem.text = '$(pass) Anti-Pattern'
    statusBarItem.backgroundColor = undefined
  } else {
    statusBarItem.text = `$(warning) Anti-Pattern: ${count}`
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      'statusBarItem.warningBackground'
    )
  }
}

function buildFixPreview(finding: any): { originalSnippet: string; fixedSnippet: string } | null {
  if (!finding.code_snippet) return null

  // Pattern-specific fix previews
  switch (finding.antipattern) {
    case 'mutable_default_argument': {
      const original = finding.code_snippet
      // Simple regex-based preview -- real fix uses the interactive command
      const fixed = original.replace(
        /(\w+)\s*=\s*(\[\]|\{\}|set\(\))/g,
        '$1=None  # was: $2'
      )
      return { originalSnippet: original, fixedSnippet: fixed }
    }
    case 'wildcard_import': {
      const original = finding.code_snippet
      const fixed = original.replace(
        /from (\S+) import \*/,
        'from $1 import SpecificName  # replace with actual names'
      )
      return { originalSnippet: original, fixedSnippet: fixed }
    }
    default:
      return {
        originalSnippet: finding.code_snippet,
        fixedSnippet: `# Suggested fix:\n# ${finding.remediation}\n\n${finding.code_snippet}`,
      }
  }
}

function buildIssueBody(finding: any): string {
  return `## ${finding.antipattern_name}

**File:** \`${finding.file}:${finding.line_start}\`
**Severity:** ${finding.severity}
**Category:** ${finding.category}

### Problem
${finding.message}

### Fix
${finding.remediation}

---
> Detected by Anti-Pattern Detector - Rule: \`${finding.rule_id}\``
}

async function getRepoUrl(): Promise<string | null> {
  try {
    const gitConfig = await vscode.workspace.findFiles('.git/config', null, 1)
    if (!gitConfig.length) return null
    const content = await vscode.workspace.fs.readFile(gitConfig[0])
    const text = Buffer.from(content).toString()
    const match = text.match(/url\s*=\s*(https:\/\/github\.com\/[^\s]+)/)
    if (match) return match[1].replace(/\.git$/, '')
  } catch {}
  return null
}
