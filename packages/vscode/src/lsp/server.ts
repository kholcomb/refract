/**
 * Anti-Pattern LSP Server
 *
 * Runs as a persistent Node.js process. The VS Code extension connects to it
 * via stdio. Stays resident so the Python interpreter only cold-starts once.
 *
 * Responsibilities:
 *  - Receives textDocument/didSave notifications
 *  - Debounces rapid saves (500ms)
 *  - Spawns ast_checks.py as a child process
 *  - Maintains a per-file findings cache
 *  - Publishes LSP Diagnostics back to the extension
 *  - Serves CodeAction requests (fix, issue, prompt, diff)
 */

import {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  InitializeParams,
  InitializeResult,
  TextDocumentSyncKind,
  Diagnostic,
  DiagnosticSeverity,
  CodeAction,
  CodeActionKind,
  CodeActionParams,
  Command,
  WorkspaceEdit,
  TextEdit,
  Range,
  Position,
  PublishDiagnosticsParams,
} from 'vscode-languageserver/node'
import { TextDocument } from 'vscode-languageserver-textdocument'
import { URI } from 'vscode-uri'
import * as cp from 'child_process'
import * as path from 'path'
import * as fs from 'fs'
import * as os from 'os'
import { Finding, SEVERITY_ORDER } from '@refract/core'

interface ServerConfig {
  enabled: boolean
  severityThreshold: string
  confidenceThreshold: number
  categories: string[]
  pythonPath: string
  ignorePaths: string[]
  showInlineHints: boolean
  ciParity: boolean
  astCheckerPath: string
}

// ── Server setup ─────────────────────────────────────────────────────────────

const connection = createConnection(ProposedFeatures.all)
const documents = new TextDocuments(TextDocument)

// Per-file findings cache: filepath → Finding[]
const findingsCache = new Map<string, Finding[]>()

// Debounce timers per file
const debounceTimers = new Map<string, NodeJS.Timeout>()

const DEBOUNCE_MS = 500

let config: ServerConfig = {
  enabled: true,
  severityThreshold: 'medium',
  confidenceThreshold: 0.7,
  categories: ['code_structure', 'security', 'dependencies', 'test_quality'],
  pythonPath: 'python3',
  ignorePaths: [],
  showInlineHints: true,
  ciParity: true,
  astCheckerPath: '',
}

let workspaceRoot = ''

// ── Lifecycle ─────────────────────────────────────────────────────────────────

connection.onInitialize((params: InitializeParams): InitializeResult => {
  workspaceRoot = params.rootUri
    ? URI.parse(params.rootUri).fsPath
    : params.rootPath ?? ''

  // Locate ast_checks.py relative to this extension
  // In production this ships inside the extension's resources folder
  const extensionPath = params.initializationOptions?.extensionPath ?? ''
  config.astCheckerPath = path.join(
    extensionPath || path.join(__dirname, '..'),
    'language-packs', 'python', 'scripts', 'ast_checks.py'
  )

  connection.console.log(`Anti-Pattern LSP server started`)
  connection.console.log(`Workspace: ${workspaceRoot}`)
  connection.console.log(`AST checker: ${config.astCheckerPath}`)

  return {
    capabilities: {
      textDocumentSync: {
        openClose: true,
        save: { includeText: false },
        change: TextDocumentSyncKind.None, // We only scan on save, not on change
      },
      codeActionProvider: {
        codeActionKinds: [
          CodeActionKind.QuickFix,
          CodeActionKind.RefactorRewrite,
          'antipattern.copyAsAgentPrompt',
        ],
        resolveProvider: true,
      },
      diagnosticProvider: {
        interFileDependencies: false,
        workspaceDiagnostics: false,
      },
    },
  }
})

connection.onInitialized(() => {
  connection.console.log('LSP initialized, ready to scan')
})

// ── Config sync ───────────────────────────────────────────────────────────────

connection.onNotification('antipattern/updateConfig', (newConfig: Partial<ServerConfig>) => {
  config = { ...config, ...newConfig }
  connection.console.log(`Config updated: ${JSON.stringify(config)}`)
})

// ── Scan on save ──────────────────────────────────────────────────────────────

documents.onDidSave(event => {
  if (!config.enabled) return

  const uri = event.document.uri
  const fsPath = URI.parse(uri).fsPath
  const lang = languageFromPath(fsPath)

  if (!lang) return // unsupported language

  // Debounce: rapid saves only trigger one scan
  const existing = debounceTimers.get(uri)
  if (existing) clearTimeout(existing)

  debounceTimers.set(uri, setTimeout(() => {
    debounceTimers.delete(uri)
    scanFile(fsPath, lang, uri)
  }, DEBOUNCE_MS))
})

documents.onDidOpen(event => {
  // On open: serve cached findings if available, otherwise scan
  const uri = event.document.uri
  const fsPath = URI.parse(uri).fsPath
  const lang = languageFromPath(fsPath)
  if (!lang) return

  if (findingsCache.has(fsPath)) {
    publishDiagnostics(uri, findingsCache.get(fsPath)!)
  } else {
    scanFile(fsPath, lang, uri)
  }
})

// ── Manual scan command ───────────────────────────────────────────────────────

connection.onNotification('antipattern/scanFile', ({ uri }: { uri: string }) => {
  const fsPath = URI.parse(uri).fsPath
  const lang = languageFromPath(fsPath)
  if (lang) scanFile(fsPath, lang, uri)
})

connection.onNotification('antipattern/scanWorkspace', () => {
  connection.console.log('Workspace scan requested')
  scanWorkspace()
})

connection.onNotification('antipattern/clearFindings', () => {
  findingsCache.clear()
  // Clear all diagnostics
  documents.all().forEach(doc => {
    connection.sendDiagnostics({ uri: doc.uri, diagnostics: [] })
  })
  connection.sendNotification('antipattern/findingsCleared')
})

// ── Core scan logic ───────────────────────────────────────────────────────────

async function scanFile(fsPath: string, lang: string, uri: string): Promise<void> {
  connection.console.log(`Scanning: ${fsPath}`)

  const outputPath = path.join(os.tmpdir(), `antipattern_${hashPath(fsPath)}.json`)

  try {
    const findings = await runAnalysis(fsPath, lang, outputPath)
    findingsCache.set(fsPath, findings)
    publishDiagnostics(uri, findings)

    // Notify the extension's tree view and summary panel
    connection.sendNotification('antipattern/findingsUpdated', {
      uri,
      file: fsPath,
      findings,
      timestamp: new Date().toISOString(),
    })

    connection.console.log(`  → ${findings.length} findings in ${path.basename(fsPath)}`)
  } catch (e: any) {
    connection.console.error(`Scan failed for ${fsPath}: ${e.message}`)
  }
}

async function scanWorkspace(): Promise<void> {
  if (!workspaceRoot) return

  // Walk workspace for supported files
  const files = findSupportedFiles(workspaceRoot, config.ignorePaths)
  connection.console.log(`Workspace scan: ${files.length} files`)

  for (const { fsPath, lang, uri } of files) {
    await scanFile(fsPath, lang, uri)
    // Small yield between files to avoid starving the event loop
    await sleep(50)
  }

  connection.sendNotification('antipattern/workspaceScanComplete', {
    fileCount: files.length,
    totalFindings: Array.from(findingsCache.values()).flat().length,
  })
}

function runAnalysis(
  fsPath: string,
  lang: string,
  outputPath: string
): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    if (lang === 'python') {
      runPythonAnalysis(fsPath, outputPath, resolve, reject)
    } else {
      // Future: route to TypeScript/JS analysis
      resolve([])
    }
  })
}

function runPythonAnalysis(
  fsPath: string,
  outputPath: string,
  resolve: (f: Finding[]) => void,
  reject: (e: Error) => void
): void {
  if (!fs.existsSync(config.astCheckerPath)) {
    reject(new Error(`AST checker not found at: ${config.astCheckerPath}`))
    return
  }

  const args = [
    config.astCheckerPath,
    path.dirname(fsPath),       // scan the directory containing the file
    '--output', outputPath,
    '--single-file', fsPath,    // tell checker to only process this one file
    '--ignore', config.ignorePaths.join(','),
  ]

  const proc = cp.spawn(config.pythonPath, args, {
    cwd: workspaceRoot,
    timeout: 30_000,            // 30s hard timeout per file
  })

  let stderr = ''
  proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })

  proc.on('close', (code) => {
    if (code !== 0 && code !== null) {
      connection.console.warn(`AST checker exited ${code}: ${stderr}`)
    }

    try {
      if (!fs.existsSync(outputPath)) {
        resolve([])
        return
      }
      const raw = JSON.parse(fs.readFileSync(outputPath, 'utf-8'))
      const findings: Finding[] = (raw.findings ?? [])
        .filter((f: Finding) => meetsThreshold(f))

      resolve(findings)
    } catch (e: any) {
      reject(new Error(`Failed to parse AST output: ${e.message}`))
    }
  })

  proc.on('error', (e) => reject(e))
}

// ── LSP Diagnostics ───────────────────────────────────────────────────────────

function publishDiagnostics(uri: string, findings: Finding[]): void {
  const diagnostics: Diagnostic[] = findings.map(findingToDiagnostic)
  connection.sendDiagnostics({ uri, diagnostics })
}

function findingToDiagnostic(f: Finding): Diagnostic {
  const startLine = Math.max(0, f.line_start - 1)
  const endLine = Math.max(0, f.line_end - 1)

  return {
    range: {
      start: { line: startLine, character: f.column ?? 0 },
      end:   { line: endLine,   character: 9999 },
    },
    severity: severityToLSP(f.severity),
    code: f.rule_id,
    codeDescription: f.references?.[0]
      ? { href: f.references[0] }
      : undefined,
    source: `antipattern (${f.tool})`,
    message: `${f.antipattern_name}: ${f.message}`,
    tags: f.tags?.includes('dead_code') ? [1] : undefined, // DiagnosticTag.Unnecessary
    data: f, // carry full finding for CodeAction resolution
  }
}

function severityToLSP(s: string): DiagnosticSeverity {
  switch (s) {
    case 'critical':
    case 'high':   return DiagnosticSeverity.Error
    case 'medium': return DiagnosticSeverity.Warning
    case 'low':    return DiagnosticSeverity.Information
    default:       return DiagnosticSeverity.Hint
  }
}

// ── Code Actions ──────────────────────────────────────────────────────────────

connection.onCodeAction((params: CodeActionParams): CodeAction[] => {
  const actions: CodeAction[] = []
  const uri = params.textDocument.uri
  const fsPath = URI.parse(uri).fsPath

  for (const diagnostic of params.context.diagnostics) {
    const finding = diagnostic.data as Finding
    if (!finding?.antipattern) continue

    // 1. One-click fix (if we have an auto-fix for this pattern)
    const fix = buildAutoFix(finding, uri, diagnostic.range)
    if (fix) actions.push(fix)

    // 2. Diff preview of suggested fix
    actions.push({
      title: `$(diff) Preview fix: ${finding.antipattern_name}`,
      kind: CodeActionKind.RefactorRewrite,
      diagnostics: [diagnostic],
      command: {
        command: 'antipattern.showDiffPreview',
        title: 'Preview Fix',
        arguments: [finding],
      },
    })

    // 3. Open related GitHub Issue
    actions.push({
      title: `$(github) Open GitHub Issue for this finding`,
      kind: CodeActionKind.Empty,
      diagnostics: [diagnostic],
      command: {
        command: 'antipattern.openGitHubIssue',
        title: 'Open GitHub Issue',
        arguments: [finding],
      },
    })

    // 4. Copy as AI agent prompt
    actions.push({
      title: `$(clippy) Copy as AI agent prompt`,
      kind: 'antipattern.copyAsAgentPrompt' as CodeActionKind,
      diagnostics: [diagnostic],
      command: {
        command: 'antipattern.copyAsAgentPrompt',
        title: 'Copy AI Prompt',
        arguments: [finding],
      },
    })
  }

  return actions
})

/**
 * Build a WorkspaceEdit auto-fix for patterns where we can do so safely.
 * Only deterministic, low-risk rewrites are auto-fixed.
 */
function buildAutoFix(
  finding: Finding,
  uri: string,
  range: Range
): CodeAction | null {
  switch (finding.antipattern) {
    case 'mutable_default_argument': {
      // We can suggest the fix but not safely rewrite without full AST context
      // So we provide a command-based fix that opens an interactive rename
      return {
        title: `$(wand) Fix: Replace mutable default with None`,
        kind: CodeActionKind.QuickFix,
        isPreferred: true,
        command: {
          command: 'antipattern.applyInteractiveFix',
          title: 'Fix Mutable Default',
          arguments: [finding, uri],
        },
      }
    }

    case 'wildcard_import': {
      return {
        title: `$(wand) Fix: Remove wildcard import`,
        kind: CodeActionKind.QuickFix,
        isPreferred: true,
        command: {
          command: 'antipattern.applyInteractiveFix',
          title: 'Fix Wildcard Import',
          arguments: [finding, uri],
        },
      }
    }

    default:
      return null
  }
}

// ── Agent prompt builder ──────────────────────────────────────────────────────

/**
 * Builds a structured prompt optimized for AI coding agents.
 * This is the primary monetizable output format for agent workflows.
 */
function buildAgentPrompt(finding: Finding): string {
  return `## Anti-Pattern Remediation Task

**Anti-Pattern:** ${finding.antipattern_name}
**Category:** ${finding.category}
**Severity:** ${finding.severity}
**Confidence:** ${(finding.confidence * 100).toFixed(0)}%
**Estimated Effort:** ${finding.effort}

### Location
- File: \`${finding.file}\`
- Lines: ${finding.line_start}–${finding.line_end}
- Language: ${finding.language}

### Problem
${finding.message}

### Current Code
\`\`\`${finding.language}
${finding.code_snippet ?? '(code snippet not available)'}
\`\`\`

### Required Fix
${finding.remediation}

### Constraints
- Do not change the function's public API or return type
- Preserve existing tests
- Add a brief inline comment explaining the fix if non-obvious
- Rule: \`${finding.rule_id}\`

${finding.references?.length ? `### References\n${finding.references.map(r => `- ${r}`).join('\n')}` : ''}
`.trim()
}

// Expose prompt builder to the extension via notification
connection.onRequest('antipattern/buildAgentPrompt', (finding: Finding) => {
  return buildAgentPrompt(finding)
})

// ── Helpers ───────────────────────────────────────────────────────────────────

function meetsThreshold(f: Finding): boolean {
  const threshIdx = SEVERITY_ORDER.indexOf(config.severityThreshold as any)
  const findingIdx = SEVERITY_ORDER.indexOf(f.severity as any)
  return findingIdx <= threshIdx && f.confidence >= config.confidenceThreshold
}

function languageFromPath(fsPath: string): string | null {
  const ext = path.extname(fsPath).toLowerCase()
  if (['.py', '.pyw', '.pyi'].includes(ext)) return 'python'
  if (['.ts', '.tsx'].includes(ext)) return 'typescript'
  if (['.js', '.jsx', '.mjs'].includes(ext)) return 'javascript'
  return null
}

function* walkDir(dir: string, ignorePatterns: string[]): Generator<string> {
  const skipDirs = new Set([
    'node_modules', '__pycache__', '.git', 'venv', '.venv',
    'dist', 'build', '.tox', '.mypy_cache'
  ])
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  for (const entry of entries) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (!skipDirs.has(entry.name)) yield* walkDir(full, ignorePatterns)
    } else {
      yield full
    }
  }
}

function findSupportedFiles(
  root: string,
  ignorePaths: string[]
): Array<{ fsPath: string; lang: string; uri: string }> {
  const results = []
  try {
    for (const fsPath of walkDir(root, ignorePaths)) {
      const lang = languageFromPath(fsPath)
      if (lang) {
        results.push({ fsPath, lang, uri: URI.file(fsPath).toString() })
      }
    }
  } catch (e) {
    connection.console.error(`walkDir failed: ${e}`)
  }
  return results
}

function hashPath(p: string): string {
  let h = 0
  for (let i = 0; i < p.length; i++) {
    h = (Math.imul(31, h) + p.charCodeAt(i)) | 0
  }
  return Math.abs(h).toString(36)
}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms))
}

// ── Start ─────────────────────────────────────────────────────────────────────
documents.listen(connection)
connection.listen()
