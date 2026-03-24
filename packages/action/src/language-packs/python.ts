import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as fs from 'fs'
import * as path from 'path'
import { Finding, AntipatternCategory, Severity, getActionRoot } from '@refract/core'
import { runGitleaks } from '../shared-scanners'

const PACK_VERSION = 'python_v1'

export interface PythonScanOptions {
  workspacePath: string
  categories: AntipatternCategory[]
  confidenceThreshold: number
  ignorePaths: string[]
}

export async function scanPython(options: PythonScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []

  core.info('🐍 Running Python language pack...')

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

// ─────────────────────────────────────────────────────────────────────────────
// CODE STRUCTURE
// ─────────────────────────────────────────────────────────────────────────────

async function runStructureChecks(options: PythonScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []

  core.info('  → Code structure checks (complexity, god classes, nesting...)')

  // Install lizard for complexity analysis
  await exec.exec('pip', ['install', '--quiet', 'lizard'], { silent: true })
    .catch(() => core.warning('lizard install failed, skipping complexity checks'))

  const lizardOutput = await runCommand(
    'lizard',
    [options.workspacePath, '--output-file', '/tmp/lizard_output.json',
     '--json', '-l', 'python', '--length', '50', '--CCN', '10'],
    { ignoreReturnCode: true }
  )

  if (fs.existsSync('/tmp/lizard_output.json')) {
    const data = JSON.parse(fs.readFileSync('/tmp/lizard_output.json', 'utf-8'))
    findings.push(...parseLizardOutput(data, options.workspacePath))
  }

  // Custom AST-based checks using Python script
  const customScriptPath = path.join(getActionRoot(), 'language-packs/python/scripts/ast_checks.py')
  if (fs.existsSync(customScriptPath)) {
    const astOutput = await runCommand(
      'python3',
      [customScriptPath, options.workspacePath, '--output', '/tmp/ast_findings.json',
       '--ignore', options.ignorePaths.join(',')],
      { ignoreReturnCode: true }
    )
    if (fs.existsSync('/tmp/ast_findings.json')) {
      const data = JSON.parse(fs.readFileSync('/tmp/ast_findings.json', 'utf-8'))
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

    // Long method
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
        language: 'python',
        language_pack: PACK_VERSION,
        message: `Function '${file.name}' is ${file.length} lines long (threshold: 50)`,
        remediation: `Break '${file.name}' into smaller, single-responsibility functions. Consider extracting logical blocks into helper methods.`,
        effort: file.length > 150 ? 'days' : 'hours',
        tool: 'lizard',
        rule_id: 'python/long-method',
        tags: ['maintainability'],
        detected_at: now,
      })
    }

    // High cyclomatic complexity
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
        language: 'python',
        language_pack: PACK_VERSION,
        message: `Function '${file.name}' has cyclomatic complexity of ${file.cyclomatic_complexity} (threshold: 10)`,
        remediation: `Reduce branching in '${file.name}' by extracting conditions into named predicates, using early returns, or applying the Strategy pattern.`,
        effort: 'hours',
        tool: 'lizard',
        rule_id: 'python/high-complexity',
        references: ['https://en.wikipedia.org/wiki/Cyclomatic_complexity'],
        tags: ['maintainability', 'testability'],
        detected_at: now,
      })
    }
  }

  // God class detection: files with too many functions/methods
  const fileGroups: Record<string, any[]> = {}
  for (const fn of data?.function_list ?? []) {
    fileGroups[fn.filename] = fileGroups[fn.filename] ?? []
    fileGroups[fn.filename].push(fn)
  }

  for (const [filename, fns] of Object.entries(fileGroups)) {
    const relPath = path.relative(workspacePath, filename)
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
        language: 'python',
        language_pack: PACK_VERSION,
        message: `Module/class in '${relPath}' has ${methodCount} functions and ~${totalLines} lines of logic`,
        remediation: `Decompose into focused classes or modules grouped by responsibility. Apply the Single Responsibility Principle.`,
        effort: 'days',
        tool: 'lizard',
        rule_id: 'python/god-class',
        references: ['https://refactoring.guru/smells/large-class'],
        tags: ['maintainability', 'srp'],
        detected_at: now,
      })
    }
  }

  return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY
// ─────────────────────────────────────────────────────────────────────────────

async function runSecurityChecks(options: PythonScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []

  core.info('  → Security checks (secrets, injection, weak crypto...)')

  // gitleaks for secrets (MIT licensed) — shared single-pass scanner
  const pyExtensions = new Set(['.py', '.pyw'])
  findings.push(...await runGitleaks(options.workspacePath, PACK_VERSION, 'python', pyExtensions))

  // Bandit for Python-specific security issues (Apache 2.0)
  await exec.exec('pip', ['install', '--quiet', 'bandit'], { silent: true })
    .catch(() => core.warning('bandit install failed'))

  await runCommand(
    'bandit',
    ['-r', options.workspacePath, '-f', 'json', '-o', '/tmp/bandit.json',
     '--severity-level', 'medium', '-q'],
    { ignoreReturnCode: true }
  )

  if (fs.existsSync('/tmp/bandit.json')) {
    const banditData = JSON.parse(fs.readFileSync('/tmp/bandit.json', 'utf-8'))
    findings.push(...parseBanditOutput(banditData, options.workspacePath))
  }

  return findings
}

function parseBanditOutput(data: any, workspacePath: string): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()

  const severityMap: Record<string, Severity> = {
    HIGH: 'high', MEDIUM: 'medium', LOW: 'low'
  }

  const antipatternMap: Record<string, string> = {
    'B105': 'hardcoded_secret',
    'B106': 'hardcoded_secret',
    'B107': 'hardcoded_secret',
    'B201': 'shell_injection_vector',
    'B202': 'shell_injection_vector',
    'B301': 'insecure_deserialization',
    'B302': 'insecure_deserialization',
    'B303': 'weak_cryptography',
    'B304': 'weak_cryptography',
    'B305': 'weak_cryptography',
    'B306': 'weak_cryptography',
    'B307': 'shell_injection_vector',
    'B311': 'weak_cryptography',
    'B320': 'sql_injection_vector',
    'B324': 'weak_cryptography',
    'B601': 'shell_injection_vector',
    'B602': 'shell_injection_vector',
    'B608': 'sql_injection_vector',
  }

  for (const issue of data?.results ?? []) {
    const antipattern = antipatternMap[issue.test_id] ?? 'security_issue'
    findings.push({
      id: generateId(),
      antipattern,
      antipattern_name: issue.test_name ?? antipattern,
      category: 'security',
      severity: severityMap[issue.issue_severity] ?? 'medium',
      confidence: issue.issue_confidence === 'HIGH' ? 0.9
                : issue.issue_confidence === 'MEDIUM' ? 0.7 : 0.5,
      file: path.relative(workspacePath, issue.filename),
      line_start: issue.line_number,
      line_end: issue.line_range?.[issue.line_range.length - 1] ?? issue.line_number,
      language: 'python',
      language_pack: PACK_VERSION,
      message: issue.issue_text,
      remediation: buildSecurityRemediation(issue.test_id),
      effort: 'hours',
      tool: 'bandit',
      rule_id: `bandit/${issue.test_id}`,
      code_snippet: issue.code,
      references: issue.more_info ? [issue.more_info] : [],
      tags: ['security'],
      detected_at: now,
    })
  }

  return findings
}

function buildSecurityRemediation(testId: string): string {
  const remediations: Record<string, string> = {
    'B105': 'Replace hardcoded password with an environment variable: os.environ["PASSWORD"]',
    'B106': 'Remove hardcoded credentials from function arguments. Use environment variables.',
    'B301': 'Replace pickle with a safer serialization format like json or msgpack.',
    'B303': 'Replace MD5/SHA1 with SHA-256 or stronger: hashlib.sha256()',
    'B307': 'Avoid eval(). Use ast.literal_eval() for safe expression evaluation.',
    'B601': 'Parameterize shell commands or use subprocess with a list instead of shell=True.',
    'B608': 'Use parameterized queries or an ORM instead of string-formatted SQL.',
  }
  return remediations[testId] ?? 'Review this security issue and apply the principle of least privilege.'
}

// ─────────────────────────────────────────────────────────────────────────────
// DEPENDENCIES
// ─────────────────────────────────────────────────────────────────────────────

async function runDependencyChecks(options: PythonScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []
  const now = new Date().toISOString()

  core.info('  → Dependency checks (CVEs, outdated, unused...)')

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
          for (const vuln of pkg?.vulnerabilities ?? []) {
            findings.push({
              id: generateId(),
              antipattern: 'vulnerable_dependency',
              antipattern_name: 'Vulnerable Dependency',
              category: 'dependencies',
              severity: osvSeverity(vuln),
              confidence: 1.0,
              file: path.relative(options.workspacePath, result.source?.path ?? ''),
              line_start: 1,
              line_end: 1,
              language: 'python',
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

  // pip-audit for Python-specific vuln scanning
  await exec.exec('pip', ['install', '--quiet', 'pip-audit'], { silent: true })
    .catch(() => {})

  await runCommand(
    'pip-audit',
    ['--format', 'json', '--output', '/tmp/pip_audit.json', '-r',
     path.join(options.workspacePath, 'requirements.txt')],
    { ignoreReturnCode: true }
  )

  if (fs.existsSync('/tmp/pip_audit.json')) {
    const data = JSON.parse(fs.readFileSync('/tmp/pip_audit.json', 'utf-8'))
    for (const dep of data?.dependencies ?? []) {
      for (const vuln of dep?.vulns ?? []) {
        findings.push({
          id: generateId(),
          antipattern: 'vulnerable_dependency',
          antipattern_name: 'Vulnerable Dependency',
          category: 'dependencies',
          severity: 'high',
          confidence: 1.0,
          file: 'requirements.txt',
          line_start: 1,
          line_end: 1,
          language: 'python',
          language_pack: PACK_VERSION,
          message: `${dep.name}==${dep.version} is vulnerable: ${vuln.id} - ${vuln.description}`,
          remediation: `Upgrade ${dep.name} to version ${vuln.fix_versions?.join(' or ')} or later.`,
          effort: 'hours',
          tool: 'pip-audit',
          rule_id: `pip-audit/${vuln.id}`,
          references: [vuln.link],
          tags: ['security', 'dependencies'],
          detected_at: now,
        })
      }
    }
  }

  return findings
}

function osvSeverity(vuln: any): Severity {
  const score = vuln?.database_specific?.severity
    ?? vuln?.severity?.[0]?.score
  if (!score) return 'medium'
  if (score >= 9.0) return 'critical'
  if (score >= 7.0) return 'high'
  if (score >= 4.0) return 'medium'
  return 'low'
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST QUALITY
// ─────────────────────────────────────────────────────────────────────────────

async function runTestQualityChecks(options: PythonScanOptions): Promise<Finding[]> {
  const findings: Finding[] = []
  const now = new Date().toISOString()

  core.info('  → Test quality checks (coverage, bare asserts, missing tests...)')

  // pytest-cov for coverage
  await exec.exec('pip', ['install', '--quiet', 'pytest', 'pytest-cov'], { silent: true })
    .catch(() => {})

  await runCommand(
    'python3',
    ['-m', 'pytest', '--cov', options.workspacePath,
     '--cov-report', 'json:/tmp/coverage.json', '-q', '--no-header'],
    { ignoreReturnCode: true, cwd: options.workspacePath }
  )

  if (fs.existsSync('/tmp/coverage.json')) {
    const data = JSON.parse(fs.readFileSync('/tmp/coverage.json', 'utf-8'))
    for (const [file, fileData] of Object.entries(data?.files ?? {})) {
      const cov = fileData as any
      const pct = cov.summary?.percent_covered ?? 100

      // Skip test files themselves
      if (file.includes('test_') || file.includes('_test.py')) continue

      if (pct < 50) {
        findings.push({
          id: generateId(),
          antipattern: 'missing_test_coverage',
          antipattern_name: 'Missing Test Coverage',
          category: 'test_quality',
          severity: pct < 20 ? 'high' : 'medium',
          confidence: 1.0,
          file: path.relative(options.workspacePath, file),
          line_start: 1,
          line_end: 1,
          language: 'python',
          language_pack: PACK_VERSION,
          message: `File has only ${pct.toFixed(1)}% test coverage (threshold: 50%). Uncovered lines: ${cov.missing_lines?.join(', ')}`,
          remediation: `Add unit tests covering the uncovered lines, especially for business logic and error paths. Focus on lines: ${(cov.missing_lines ?? []).slice(0, 10).join(', ')}`,
          effort: 'days',
          tool: 'pytest-cov',
          rule_id: 'python/low-coverage',
          tags: ['test_quality', 'coverage'],
          detected_at: now,
        })
      }
    }
  }

  return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

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
