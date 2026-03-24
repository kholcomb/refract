import { buildSummary, SEVERITY_ORDER } from '../src/index'
import { Finding, Severity } from '../src/types'

// Prevent the action's run() from executing on import
jest.mock('@actions/core', () => ({
  getInput: jest.fn(),
  info: jest.fn(),
  warning: jest.fn(),
  debug: jest.fn(),
  setOutput: jest.fn(),
  setFailed: jest.fn(),
  startGroup: jest.fn(),
  endGroup: jest.fn(),
  summary: { addRaw: jest.fn().mockReturnThis(), write: jest.fn() },
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

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'test-1',
    antipattern: 'mutable_default_argument',
    antipattern_name: 'Mutable Default Argument',
    category: 'code_structure',
    severity: 'high',
    confidence: 1.0,
    file: 'src/app.py',
    line_start: 10,
    line_end: 10,
    language: 'python',
    language_pack: 'python_v1',
    message: 'Test message',
    remediation: 'Fix it',
    effort: 'minutes',
    tool: 'ast-checker',
    rule_id: 'python/mutable-default',
    detected_at: '2024-01-01T00:00:00Z',
    ...overrides,
  }
}

describe('SEVERITY_ORDER', () => {
  it('should order critical first, info last', () => {
    expect(SEVERITY_ORDER).toEqual(['critical', 'high', 'medium', 'low', 'info'])
  })
})

describe('buildSummary', () => {
  it('should return zero counts for empty findings', () => {
    const summary = buildSummary([])
    expect(summary.total).toBe(0)
    expect(summary.files_affected).toBe(0)
    expect(summary.by_severity.critical).toBe(0)
    expect(summary.by_severity.high).toBe(0)
  })

  it('should count findings by severity', () => {
    const findings = [
      makeFinding({ severity: 'critical' }),
      makeFinding({ severity: 'critical', id: '2' }),
      makeFinding({ severity: 'high', id: '3' }),
      makeFinding({ severity: 'low', id: '4' }),
    ]
    const summary = buildSummary(findings)
    expect(summary.total).toBe(4)
    expect(summary.by_severity.critical).toBe(2)
    expect(summary.by_severity.high).toBe(1)
    expect(summary.by_severity.low).toBe(1)
    expect(summary.by_severity.medium).toBe(0)
  })

  it('should count findings by category', () => {
    const findings = [
      makeFinding({ category: 'security' }),
      makeFinding({ category: 'security', id: '2' }),
      makeFinding({ category: 'code_structure', id: '3' }),
    ]
    const summary = buildSummary(findings)
    expect(summary.by_category.security).toBe(2)
    expect(summary.by_category.code_structure).toBe(1)
  })

  it('should count findings by language', () => {
    const findings = [
      makeFinding({ language: 'python' }),
      makeFinding({ language: 'typescript', id: '2' }),
      makeFinding({ language: 'typescript', id: '3' }),
    ]
    const summary = buildSummary(findings)
    expect(summary.by_language.python).toBe(1)
    expect(summary.by_language.typescript).toBe(2)
  })

  it('should count unique files affected', () => {
    const findings = [
      makeFinding({ file: 'a.py' }),
      makeFinding({ file: 'a.py', id: '2', line_start: 20 }),
      makeFinding({ file: 'b.py', id: '3' }),
    ]
    const summary = buildSummary(findings)
    expect(summary.files_affected).toBe(2)
  })

  it('should handle severity filtering correctly', () => {
    const findings = [
      makeFinding({ severity: 'critical' }),
      makeFinding({ severity: 'info', id: '2' }),
    ]
    const thresholdIndex = SEVERITY_ORDER.indexOf('high')
    const filtered = findings.filter(
      f => SEVERITY_ORDER.indexOf(f.severity) <= thresholdIndex
    )
    expect(filtered).toHaveLength(1)
    expect(filtered[0].severity).toBe('critical')
  })
})
