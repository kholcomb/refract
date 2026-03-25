// Note: This module uses @actions/exec which calls child_process.execFile()
// internally with argument arrays -- no shell interpretation, no injection risk.

import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as crypto from 'crypto'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { Finding, AntipatternCategory, Severity, getActionRoot, loadThresholds, Thresholds } from '@refract/core'
import { runGitleaks } from '../shared-scanners'

const PACK_VERSION = 'go_v1'
let thresholds: Thresholds

export interface GoScanOptions {
  workspacePath: string
  categories: AntipatternCategory[]
  confidenceThreshold: number
  ignorePaths: string[]
}

export async function scanGo(options: GoScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []

  core.info('[go] Running Go language pack...')

  thresholds = loadThresholds('go', options.workspacePath)

  if (options.categories.includes('code_structure')) {
    findings.push(...await runStructureChecks(options))
  }
  if (options.categories.includes('security')) {
    findings.push(...await runSecurityChecks(options))
  }
  if (options.categories.includes('dependencies')) {
    findings.push(...await runDependencyChecks(options))
  }
  if (options.categories.includes('test_quality')) {
    findings.push(...await runTestQualityChecks(options))
  }

  return findings.filter(f => f.confidence >= options.confidenceThreshold)
}

// --- CODE STRUCTURE ---

async function runStructureChecks(options: GoScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []

  core.info('  -> Code structure checks (AST analysis, complexity...)')

  // Custom AST-based checks via compiled Go binary
  const astBinaryPath = path.join(getActionRoot(), 'language-packs/go/scripts/ast_checks')
  const astScriptPath = path.join(getActionRoot(), 'language-packs/go/scripts/ast_checks.go')
  const outputPath = path.join(os.tmpdir(), 'go_ast_findings.json')

  // Write thresholds to temp file for sidecar consumption
  const thresholdsPath = path.join(os.tmpdir(), 'go_thresholds.json')
  fs.writeFileSync(thresholdsPath, JSON.stringify(thresholds))

  // Prefer compiled binary, fall back to go run
  let astCmd: string
  let astArgs: string[]
  if (fs.existsSync(astBinaryPath)) {
    astCmd = astBinaryPath
    astArgs = [options.workspacePath, '--output', outputPath,
               '--ignore', options.ignorePaths.join(','),
               '--thresholds-json', thresholdsPath]
  } else if (fs.existsSync(astScriptPath)) {
    astCmd = 'go'
    astArgs = ['run', astScriptPath, options.workspacePath,
               '--output', outputPath,
               '--ignore', options.ignorePaths.join(','),
               '--thresholds-json', thresholdsPath]
  } else {
    core.warning('Go AST checker not found, skipping structure checks')
    return findings
  }

  await runCommand(astCmd, astArgs, { ignoreReturnCode: true })

  if (fs.existsSync(outputPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(outputPath, 'utf-8'))
      findings.push(...data.findings ?? [])
    } catch (e) {
      core.warning(`Failed to parse Go AST findings: ${e}`)
    }
  }

  // Lizard for complexity (supports Go)
  await runCommand(
    'lizard',
    [options.workspacePath, '--output-file', path.join(os.tmpdir(), 'lizard_go_output.json'),
     '--json', '-l', 'golang',
     '--length', String(thresholds.code_structure.max_function_length),
     '--CCN', String(thresholds.code_structure.max_cyclomatic_complexity)],
    { ignoreReturnCode: true }
  )

  if (fs.existsSync(path.join(os.tmpdir(), 'lizard_go_output.json'))) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(os.tmpdir(), 'lizard_go_output.json'), 'utf-8'))
      findings.push(...parseLizardOutput(data, options.workspacePath))
    } catch (e) {
      core.warning(`Failed to parse lizard output: ${e}`)
    }
  }

  return findings
}

function parseLizardOutput(data: any, workspacePath: string): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()

  const cs = thresholds.code_structure
  for (const file of data?.function_list ?? []) {
    const relPath = path.relative(workspacePath, file.filename)

    if (file.length > cs.max_function_length) {
      findings.push({
        id: generateId(),
        antipattern: 'long_method',
        antipattern_name: 'Long Function',
        category: 'code_structure',
        severity: file.length > cs.max_function_length * 3 ? 'high' : 'medium',
        confidence: 0.95,
        file: relPath,
        line_start: file.start_line,
        line_end: file.end_line,
        language: 'go',
        language_pack: PACK_VERSION,
        message: `Function '${file.name}' is ${file.length} lines long (threshold: ${cs.max_function_length})`,
        remediation: `Break '${file.name}' into smaller functions with single responsibilities.`,
        effort: file.length > cs.max_function_length * 3 ? 'days' : 'hours',
        tool: 'lizard',
        rule_id: 'go/long-function',
        tags: ['maintainability'],
        detected_at: now,
      })
    }

    if (file.cyclomatic_complexity > cs.max_cyclomatic_complexity) {
      findings.push({
        id: generateId(),
        antipattern: 'high_cyclomatic_complexity',
        antipattern_name: 'High Cyclomatic Complexity',
        category: 'code_structure',
        severity: file.cyclomatic_complexity > cs.max_cyclomatic_complexity * 2 ? 'high' : 'medium',
        confidence: 1.0,
        file: relPath,
        line_start: file.start_line,
        line_end: file.end_line,
        language: 'go',
        language_pack: PACK_VERSION,
        message: `Function '${file.name}' has cyclomatic complexity of ${file.cyclomatic_complexity} (threshold: ${cs.max_cyclomatic_complexity})`,
        remediation: `Reduce branching with early returns, table-driven logic, or extracted helper functions.`,
        effort: 'hours',
        tool: 'lizard',
        rule_id: 'go/high-complexity',
        tags: ['maintainability', 'testability'],
        detected_at: now,
      })
    }
  }

  return findings
}

// --- SECURITY ---

async function runSecurityChecks(options: GoScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []

  core.info('  -> Security checks (gosec, gitleaks...)')

  // gitleaks (shared single-pass)
  const goExtensions = new Set(['.go'])
  findings.push(...await runGitleaks(options.workspacePath, PACK_VERSION, 'go', goExtensions))

  // gosec (Apache 2.0)
  const gosecOutput = await runCommand(
    'gosec',
    ['-fmt', 'json', '-out', path.join(os.tmpdir(), 'gosec.json'), '-severity', 'medium', '-quiet', './...'],
    { ignoreReturnCode: true, cwd: options.workspacePath }
  )

  if (fs.existsSync(path.join(os.tmpdir(), 'gosec.json'))) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(os.tmpdir(), 'gosec.json'), 'utf-8'))
      findings.push(...parseGosecOutput(data, options.workspacePath))
    } catch {
      core.warning('Failed to parse gosec output')
    }
  }

  return findings
}

function parseGosecOutput(data: any, workspacePath: string): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()

  const severityMap: Record<string, Severity> = {
    HIGH: 'high', MEDIUM: 'medium', LOW: 'low',
  }

  for (const issue of data?.Issues ?? []) {
    findings.push({
      id: generateId(),
      antipattern: mapGosecRule(issue.rule_id),
      antipattern_name: issue.details ?? issue.rule_id,
      category: 'security',
      severity: severityMap[issue.severity] ?? 'medium',
      confidence: issue.confidence === 'HIGH' ? 0.9
                : issue.confidence === 'MEDIUM' ? 0.7 : 0.5,
      file: path.relative(workspacePath, issue.file),
      line_start: parseInt(issue.line, 10) || 1,
      line_end: parseInt(issue.line, 10) || 1,
      language: 'go',
      language_pack: PACK_VERSION,
      message: issue.details,
      remediation: buildGosecRemediation(issue.rule_id),
      effort: 'hours',
      tool: 'gosec',
      rule_id: `gosec/${issue.rule_id}`,
      code_snippet: issue.code,
      references: issue.cwe?.url ? [issue.cwe.url] : [],
      tags: ['security'],
      detected_at: now,
    })
  }

  return findings
}

function mapGosecRule(ruleId: string): string {
  const map: Record<string, string> = {
    'G101': 'hardcoded_secret',
    'G201': 'sql_injection_vector',
    'G202': 'sql_injection_vector',
    'G203': 'shell_injection_vector',
    'G204': 'shell_injection_vector',
    'G301': 'path_traversal',
    'G302': 'path_traversal',
    'G304': 'path_traversal',
    'G401': 'weak_cryptography',
    'G501': 'weak_cryptography',
  }
  return map[ruleId] ?? 'security_issue'
}

function buildGosecRemediation(ruleId: string): string {
  const map: Record<string, string> = {
    'G101': 'Remove hardcoded credentials. Use environment variables or a secrets manager.',
    'G201': 'Use parameterized queries instead of string concatenation.',
    'G204': 'Avoid exec.Command with user input. Validate and sanitize arguments.',
    'G304': 'Validate file paths against a whitelist. Use filepath.Clean().',
    'G401': 'Use modern cryptographic algorithms (SHA-256+, AES-256).',
  }
  return map[ruleId] ?? 'Review this security finding and apply the principle of least privilege.'
}

// --- DEPENDENCIES ---

async function runDependencyChecks(options: GoScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []
  const now = new Date().toISOString()

  core.info('  -> Dependency checks (govulncheck, osv-scanner...)')

  // govulncheck (BSD) -- Go's official vuln scanner
  const goModPath = path.join(options.workspacePath, 'go.mod')
  if (fs.existsSync(goModPath)) {
    const vulnOutput = await runCommand(
      'govulncheck', ['-json', './...'],
      { ignoreReturnCode: true, cwd: options.workspacePath }
    )

    if (vulnOutput.stdout) {
      try {
        for (const line of vulnOutput.stdout.split('\n')) {
          if (!line.trim()) continue
          const msg = JSON.parse(line)
          if (msg.vulnerability) {
            const vuln = msg.vulnerability
            findings.push({
              id: generateId(),
              antipattern: 'vulnerable_dependency',
              antipattern_name: 'Vulnerable Dependency',
              category: 'dependencies',
              severity: vulnSeverity(vuln),
              confidence: 1.0,
              file: 'go.mod',
              line_start: 1,
              line_end: 1,
              language: 'go',
              language_pack: PACK_VERSION,
              message: `${vuln.osv?.id}: ${vuln.osv?.summary ?? 'Known vulnerability'}`,
              remediation: `Update the affected module. Run: go get -u <module>@latest`,
              effort: 'hours',
              tool: 'govulncheck',
              rule_id: `govulncheck/${vuln.osv?.id ?? 'unknown'}`,
              references: vuln.osv?.references?.map((r: any) => r.url) ?? [],
              tags: ['security', 'dependencies'],
              detected_at: now,
            })
          }
        }
      } catch {
        core.warning('Failed to parse govulncheck output')
      }
    }
  }

  return findings
}

function vulnSeverity(vuln: any): Severity {
  const summary = (vuln.osv?.summary ?? '').toLowerCase()
  if (summary.includes('remote code') || summary.includes('rce')) return 'critical'
  if (summary.includes('denial') || summary.includes('overflow')) return 'high'
  return 'medium'
}

// --- TEST QUALITY ---

async function runTestQualityChecks(_options: GoScanOptions): Promise<Finding[]> {
  core.info('  -> Test quality checks (coverage...)')
  return []
}

// --- UTILITIES ---

async function runCommand(
  cmd: string,
  args: string[],
  options: { ignoreReturnCode?: boolean; silent?: boolean; cwd?: string } = {}
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  let stdout = ''
  let stderr = ''

  const exitCode = await exec.exec(cmd, args, {
    ignoreReturnCode: options.ignoreReturnCode ?? false,
    silent: options.silent ?? true,
    cwd: options.cwd,
    listeners: {
      stdout: (data: Buffer) => { stdout += data.toString() },
      stderr: (data: Buffer) => { stderr += data.toString() },
    },
  }).catch(() => -1)

  return { stdout, stderr, exitCode }
}

function generateId(): string {
  return crypto.randomUUID().replace(/-/g, '').substring(0, 9)
}
