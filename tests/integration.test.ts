/**
 * Integration tests for the full scan pipeline.
 * Mocks @actions/core and @actions/exec, then runs the language pack
 * scanners against the fixture directories to verify end-to-end
 * Finding schema compliance.
 */

import { execFileSync } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import { Finding } from '../src/types'

// ── Mock @actions/core and @actions/exec ─────────────────────────────────────
// These must be set up before importing language packs, because the modules
// capture references at import time.

const mockExecResults: Record<string, { exitCode: number; stdout: string }> = {}

jest.mock('@actions/core', () => ({
  info: jest.fn(),
  warning: jest.fn(),
  debug: jest.fn(),
  error: jest.fn(),
  startGroup: jest.fn(),
  endGroup: jest.fn(),
  setOutput: jest.fn(),
  setFailed: jest.fn(),
  getInput: jest.fn(() => ''),
  summary: { addRaw: jest.fn().mockReturnThis(), write: jest.fn() },
}))

jest.mock('@actions/exec', () => ({
  exec: jest.fn(async (cmd: string, args: string[], options: any) => {
    const key = `${cmd} ${(args ?? []).join(' ')}`

    // For the TS AST sidecar and Python AST sidecar, actually run them
    if (cmd === 'node' || cmd === 'python3') {
      const { execFileSync } = require('child_process')
      try {
        const result = execFileSync(cmd, args, {
          timeout: 30000,
          encoding: 'utf-8',
          cwd: options?.cwd,
        })
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from(result))
        }
        return 0
      } catch (e: any) {
        if (options?.ignoreReturnCode) return e.status ?? 1
        throw e
      }
    }

    // For tool installs (pip, npm) — skip silently
    if (cmd === 'pip' || cmd === 'npm') return 0

    // For external tools (lizard, gitleaks, osv-scanner, bandit, pip-audit) — skip
    if (options?.ignoreReturnCode) return 1
    return 0
  }),
}))

jest.mock('@actions/github', () => ({
  context: {
    repo: { owner: 'test', repo: 'test' },
    sha: 'abc1234',
    ref: 'refs/heads/main',
    runId: 1,
    runNumber: 1,
    actor: 'test',
    eventName: 'push',
  },
  getOctokit: jest.fn(),
}))

// ── Required Finding fields ─────────────────────────────────────────────────

const REQUIRED_FINDING_FIELDS: (keyof Finding)[] = [
  'id', 'antipattern', 'antipattern_name', 'category', 'severity',
  'confidence', 'file', 'line_start', 'line_end', 'language',
  'language_pack', 'message', 'remediation', 'effort', 'tool',
  'rule_id', 'detected_at',
]

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const VALID_CATEGORIES = ['code_structure', 'security', 'dependencies', 'test_quality', 'concurrency', 'api_design', 'documentation']
const VALID_EFFORTS = ['minutes', 'hours', 'days', 'weeks']

function assertFindingSchema(finding: any, context: string): void {
  for (const field of REQUIRED_FINDING_FIELDS) {
    expect(finding).toHaveProperty(field)
    expect(finding[field]).not.toBeUndefined()
    expect(finding[field]).not.toBeNull()
  }

  expect(VALID_SEVERITIES).toContain(finding.severity)
  expect(VALID_CATEGORIES).toContain(finding.category)
  expect(VALID_EFFORTS).toContain(finding.effort)
  expect(finding.confidence).toBeGreaterThanOrEqual(0)
  expect(finding.confidence).toBeLessThanOrEqual(1)
  expect(finding.line_start).toBeGreaterThan(0)
  expect(finding.line_end).toBeGreaterThanOrEqual(finding.line_start)
  expect(typeof finding.id).toBe('string')
  expect(finding.id.length).toBeGreaterThan(0)
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe('Integration: Python AST sidecar', () => {
  const fixtureDir = path.join(__dirname, 'fixtures/python')
  const outputPath = '/tmp/integration_py_ast.json'

  it('should produce valid findings from Python fixtures', () => {
    execFileSync('python3', [
      path.join(__dirname, '../language-packs/python/scripts/ast_checks.py'),
      fixtureDir,
      '--output', outputPath,
    ])

    const result = JSON.parse(fs.readFileSync(outputPath, 'utf-8'))
    expect(result.count).toBeGreaterThan(0)

    for (const finding of result.findings) {
      assertFindingSchema(finding, 'Python AST')
      expect(finding.language).toBe('python')
      expect(finding.language_pack).toBe('python_v1')
      expect(finding.tool).toBe('ast-checker')
    }
  })

  it('should detect known fixture anti-patterns', () => {
    const result = JSON.parse(fs.readFileSync(outputPath, 'utf-8'))
    const patterns = result.findings.map((f: any) => f.antipattern)

    expect(patterns).toContain('mutable_default_argument')
    expect(patterns).toContain('bare_except')
    expect(patterns).toContain('exception_sink')
    expect(patterns).toContain('wildcard_import')
    expect(patterns).toContain('deep_nesting')
    expect(patterns).toContain('n_plus_one_query')
    expect(patterns).toContain('magic_number')
  })
})

describe('Integration: TypeScript AST sidecar', () => {
  const fixtureDir = path.join(__dirname, 'fixtures/typescript')
  const outputPath = '/tmp/integration_ts_ast.json'

  it('should produce valid findings from TypeScript fixtures', () => {
    execFileSync('node', [
      path.join(__dirname, '../language-packs/typescript/scripts/ast_checks.js'),
      fixtureDir,
      '--output', outputPath,
    ])

    const result = JSON.parse(fs.readFileSync(outputPath, 'utf-8'))
    expect(result.count).toBeGreaterThan(0)

    for (const finding of result.findings) {
      assertFindingSchema(finding, 'TypeScript AST')
      expect(['typescript', 'javascript']).toContain(finding.language)
      expect(finding.language_pack).toBe('typescript_v1')
      expect(finding.tool).toBe('ast-checker')
    }
  })

  it('should detect known fixture anti-patterns', () => {
    const result = JSON.parse(fs.readFileSync(outputPath, 'utf-8'))
    const patterns = result.findings.map((f: any) => f.antipattern)

    expect(patterns).toContain('deep_nesting')
    expect(patterns).toContain('magic_number')
    expect(patterns).toContain('god_class')
    expect(patterns).toContain('assertion_roulette')
    expect(patterns).toContain('excessive_mocking')
    expect(patterns).toContain('any_type_abuse')
    expect(patterns).toContain('ts_ignore_proliferation')
    expect(patterns).toContain('callback_hell')
  })
})

describe('Integration: buildSummary round-trip', () => {
  // Import after mocks are set up
  const { buildSummary } = require('../src/index')

  it('should produce valid summary from mixed findings', () => {
    // Combine Python + TS AST findings
    const pyResult = JSON.parse(fs.readFileSync('/tmp/integration_py_ast.json', 'utf-8'))
    const tsResult = JSON.parse(fs.readFileSync('/tmp/integration_ts_ast.json', 'utf-8'))
    const allFindings = [...pyResult.findings, ...tsResult.findings]

    const summary = buildSummary(allFindings)

    expect(summary.total).toBe(allFindings.length)
    expect(summary.files_affected).toBeGreaterThan(0)
    expect(summary.by_severity).toBeDefined()
    expect(summary.by_category).toBeDefined()
    expect(summary.by_language).toBeDefined()

    // Both languages should be represented
    expect(summary.by_language.python).toBeGreaterThan(0)
    expect(summary.by_language.typescript).toBeGreaterThan(0)

    // Severity counts should sum to total
    const sevTotal = Object.values(summary.by_severity as Record<string, number>)
      .reduce((a, b) => a + b, 0)
    expect(sevTotal).toBe(summary.total)
  })
})

describe('Integration: Finding → Issue body round-trip', () => {
  const { buildIssueBody } = require('../src/outputter')

  it('should produce valid markdown from real findings', () => {
    const pyResult = JSON.parse(fs.readFileSync('/tmp/integration_py_ast.json', 'utf-8'))
    const finding = pyResult.findings[0]

    const body = buildIssueBody([finding], finding)

    expect(typeof body).toBe('string')
    expect(body.length).toBeGreaterThan(100)
    expect(body).toContain(finding.antipattern_name)
    expect(body).toContain(finding.file)
    expect(body).toContain('Remediation')
    expect(body).toContain(finding.rule_id)
  })
})
