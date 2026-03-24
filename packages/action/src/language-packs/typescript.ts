import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as fs from 'fs'
import * as path from 'path'
import { Finding, AntipatternCategory, Severity, getActionRoot } from '@refract/core'
import { runGitleaks } from '../shared-scanners'

const PACK_VERSION = 'typescript_v1'

export interface TypeScriptScanOptions {
  workspacePath: string
  categories: AntipatternCategory[]
  confidenceThreshold: number
  ignorePaths: string[]
}

export async function scanTypeScript(options: TypeScriptScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []

  core.info('[ts] Running TypeScript/JavaScript language pack...')

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

// -----------------------------------------------------------------------------
// CODE STRUCTURE
// -----------------------------------------------------------------------------

async function runStructureChecks(options: TypeScriptScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []

  core.info('  -> Code structure checks (complexity, nesting, magic numbers...)')

  // Lizard supports JS/TS
  const lizardInstalled = await runCommand(
    'pip', ['install', '--quiet', 'lizard'],
    { ignoreReturnCode: true }
  )

  if (lizardInstalled.exitCode === 0) {
    await runCommand(
      'lizard',
      [options.workspacePath, '--output-file', '/tmp/lizard_ts_output.json',
       '--json', '-l', 'javascript', '--length', '50', '--CCN', '10'],
      { ignoreReturnCode: true }
    )

    if (fs.existsSync('/tmp/lizard_ts_output.json')) {
      const data = JSON.parse(fs.readFileSync('/tmp/lizard_ts_output.json', 'utf-8'))
      findings.push(...parseLizardOutput(data, options.workspacePath))
    }
  }

  // Custom AST-based checks via the sidecar script
  const astScriptPath = path.join(getActionRoot(), 'language-packs/typescript/scripts/ast_checks.js')
  if (fs.existsSync(astScriptPath)) {
    await runCommand(
      'node',
      [astScriptPath, options.workspacePath,
       '--output', '/tmp/ts_ast_findings.json',
       '--ignore', options.ignorePaths.join(',')],
      { ignoreReturnCode: true }
    )
    if (fs.existsSync('/tmp/ts_ast_findings.json')) {
      const data = JSON.parse(fs.readFileSync('/tmp/ts_ast_findings.json', 'utf-8'))
      findings.push(...data.findings ?? [])
    }
  }

  return findings
}

function parseLizardOutput(data: any, workspacePath: string): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()

  for (const file of data?.function_list ?? []) {
    const relPath = path.relative(workspacePath, file.filename)
    const lang = inferLang(relPath)

    if (file.length > 50) {
      findings.push({
        id: generateId(),
        antipattern: 'long_method',
        antipattern_name: 'Long Method',
        category: 'code_structure',
        severity: file.length > 150 ? 'high' : 'medium',
        confidence: 0.95,
        file: relPath,
        line_start: file.start_line,
        line_end: file.end_line,
        language: lang,
        language_pack: PACK_VERSION,
        message: `Function '${file.name}' is ${file.length} lines long (threshold: 50)`,
        remediation: `Break '${file.name}' into smaller, single-responsibility functions. Consider extracting logical blocks into helper methods.`,
        effort: file.length > 150 ? 'days' : 'hours',
        tool: 'lizard',
        rule_id: 'ts/long-method',
        tags: ['maintainability'],
        detected_at: now,
      })
    }

    if (file.cyclomatic_complexity > 10) {
      findings.push({
        id: generateId(),
        antipattern: 'high_cyclomatic_complexity',
        antipattern_name: 'High Cyclomatic Complexity',
        category: 'code_structure',
        severity: file.cyclomatic_complexity > 20 ? 'high' : 'medium',
        confidence: 1.0,
        file: relPath,
        line_start: file.start_line,
        line_end: file.end_line,
        language: lang,
        language_pack: PACK_VERSION,
        message: `Function '${file.name}' has cyclomatic complexity of ${file.cyclomatic_complexity} (threshold: 10)`,
        remediation: `Reduce branching in '${file.name}' by extracting conditions into named predicates, using early returns, or applying the Strategy pattern.`,
        effort: 'hours',
        tool: 'lizard',
        rule_id: 'ts/high-complexity',
        references: ['https://en.wikipedia.org/wiki/Cyclomatic_complexity'],
        tags: ['maintainability', 'testability'],
        detected_at: now,
      })
    }
  }

  // God class detection
  const fileGroups: Record<string, any[]> = {}
  for (const fn of data?.function_list ?? []) {
    fileGroups[fn.filename] = fileGroups[fn.filename] ?? []
    fileGroups[fn.filename].push(fn)
  }

  for (const [filename, fns] of Object.entries(fileGroups)) {
    const relPath = path.relative(workspacePath, filename)
    const lang = inferLang(relPath)
    const methodCount = fns.length
    const totalLines = fns.reduce((acc: number, f: any) => acc + f.length, 0)

    if (methodCount > 20 || totalLines > 500) {
      findings.push({
        id: generateId(),
        antipattern: 'god_class',
        antipattern_name: 'God Class',
        category: 'code_structure',
        severity: methodCount > 40 ? 'high' : 'medium',
        confidence: 0.82,
        file: relPath,
        line_start: 1,
        line_end: totalLines,
        language: lang,
        language_pack: PACK_VERSION,
        message: `Module/class in '${relPath}' has ${methodCount} functions and ~${totalLines} lines of logic`,
        remediation: `Decompose into focused modules grouped by responsibility. Apply the Single Responsibility Principle.`,
        effort: 'days',
        tool: 'lizard',
        rule_id: 'ts/god-class',
        references: ['https://refactoring.guru/smells/large-class'],
        tags: ['maintainability', 'srp'],
        detected_at: now,
      })
    }
  }

  return findings
}

// -----------------------------------------------------------------------------
// SECURITY
// -----------------------------------------------------------------------------

async function runSecurityChecks(options: TypeScriptScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []

  core.info('  -> Security checks (secrets via gitleaks...)')

  // gitleaks (MIT) -- shared single-pass scanner, filtered to JS/TS files
  const jstsExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'])
  findings.push(...await runGitleaks(options.workspacePath, PACK_VERSION, 'typescript', jstsExtensions))

  return findings
}

// -----------------------------------------------------------------------------
// DEPENDENCIES
// -----------------------------------------------------------------------------

async function runDependencyChecks(options: TypeScriptScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []
  const now = new Date().toISOString()

  core.info('  -> Dependency checks (npm audit, osv-scanner...)')

  // npm audit (built-in, MIT-compatible output)
  const packageJsonPath = path.join(options.workspacePath, 'package.json')
  if (fs.existsSync(packageJsonPath)) {
    const auditOutput = await runCommand(
      'npm', ['audit', '--json'],
      { ignoreReturnCode: true, cwd: options.workspacePath }
    )

    if (auditOutput.stdout) {
      try {
        const data = JSON.parse(auditOutput.stdout)
        for (const [name, advisory] of Object.entries(data?.vulnerabilities ?? {})) {
          const adv = advisory as any
          const severity = mapNpmSeverity(adv.severity)
          findings.push({
            id: generateId(),
            antipattern: 'vulnerable_dependency',
            antipattern_name: 'Vulnerable Dependency',
            category: 'dependencies',
            severity,
            confidence: 1.0,
            file: 'package.json',
            line_start: 1,
            line_end: 1,
            language: 'typescript',
            language_pack: PACK_VERSION,
            message: `${name} has known vulnerability: ${adv.title ?? adv.via?.[0]?.title ?? 'see npm audit'}`,
            remediation: adv.fixAvailable
              ? `Run \`npm audit fix\` or manually upgrade ${name}.`
              : `No automated fix available for ${name}. Review and consider alternatives.`,
            effort: 'hours',
            tool: 'npm-audit',
            rule_id: `npm-audit/${name}`,
            references: adv.via?.filter((v: any) => v.url).map((v: any) => v.url) ?? [],
            tags: ['security', 'dependencies'],
            detected_at: now,
          })
        }
      } catch (e) {
        core.warning(`Failed to parse npm audit output: ${e}`)
      }
    }
  }

  // osv-scanner for CVEs (Apache 2.0)
  const osvOutput = await runCommand(
    'osv-scanner',
    ['--format', 'json', '--recursive', options.workspacePath],
    { ignoreReturnCode: true }
  )

  if (osvOutput.stdout) {
    try {
      const data = JSON.parse(osvOutput.stdout)
      for (const result of data?.results ?? []) {
        for (const pkg of result?.packages ?? []) {
          const ecosystem = pkg?.package?.ecosystem ?? ''
          if (!['npm', 'node', ''].includes(ecosystem.toLowerCase())) continue

          for (const vuln of pkg?.vulnerabilities ?? []) {
            findings.push({
              id: generateId(),
              antipattern: 'vulnerable_dependency',
              antipattern_name: 'Vulnerable Dependency',
              category: 'dependencies',
              severity: osvSeverity(vuln),
              confidence: 1.0,
              file: path.relative(options.workspacePath, result.source?.path ?? 'package-lock.json'),
              line_start: 1,
              line_end: 1,
              language: 'typescript',
              language_pack: PACK_VERSION,
              message: `${pkg.package?.name}@${pkg.package?.version} has known vulnerability: ${vuln.id}`,
              remediation: `Upgrade ${pkg.package?.name} to a patched version. Check ${vuln.id} for affected/fixed versions.`,
              effort: 'hours',
              tool: 'osv-scanner',
              rule_id: `osv/${vuln.id}`,
              references: vuln.references?.map((r: any) => r.url) ?? [],
              tags: ['security', 'dependencies', vuln.id],
              detected_at: now,
            })
          }
        }
      }
    } catch (e) {
      core.warning(`Failed to parse osv-scanner output: ${e}`)
    }
  }

  return findings
}

function mapNpmSeverity(npmSev: string): Severity {
  switch (npmSev) {
    case 'critical': return 'critical'
    case 'high': return 'high'
    case 'moderate': return 'medium'
    case 'low': return 'low'
    default: return 'medium'
  }
}

function osvSeverity(vuln: any): Severity {
  const score = vuln?.database_specific?.severity ?? vuln?.severity?.[0]?.score
  if (!score) return 'medium'
  if (score >= 9.0) return 'critical'
  if (score >= 7.0) return 'high'
  if (score >= 4.0) return 'medium'
  return 'low'
}

// -----------------------------------------------------------------------------
// TEST QUALITY
// -----------------------------------------------------------------------------

async function runTestQualityChecks(options: TypeScriptScanOptions): Promise<Finding[]> {
  core.info('  -> Test quality checks (assertion roulette, excessive mocking...)')
  // Test quality checks are handled by the AST sidecar script
  // (assertion roulette, excessive mocking detection)
  return []
}

// -----------------------------------------------------------------------------
// UTILITIES
// -----------------------------------------------------------------------------

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
  return Math.random().toString(36).substring(2, 11)
}

function inferLang(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase()
  if (ext === '.ts' || ext === '.tsx') return 'typescript'
  return 'javascript'
}
