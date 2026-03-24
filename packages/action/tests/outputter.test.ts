import {
  buildIssueBody,
  buildPRCommentBody,
  groupBy,
  formatCategory,
  truncate,
} from '../src/outputter'
import { Finding } from '@refract/core'

// Mock GitHub dependencies -- not needed for template/util tests, but required at import time
jest.mock('@actions/core', () => ({
  info: jest.fn(),
  warning: jest.fn(),
  debug: jest.fn(),
  summary: { addRaw: jest.fn().mockReturnThis(), write: jest.fn() },
}))
jest.mock('@actions/github', () => ({
  context: {
    repo: { owner: 'test', repo: 'test' },
    eventName: 'push',
    payload: {},
  },
  getOctokit: jest.fn(),
}))

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'test-1',
    antipattern: 'bare_except',
    antipattern_name: 'Bare Except',
    category: 'code_structure',
    severity: 'high',
    confidence: 0.95,
    file: 'src/handler.py',
    line_start: 42,
    line_end: 45,
    language: 'python',
    language_pack: 'python_v1',
    message: 'Bare except catches all exceptions',
    remediation: 'Catch specific exceptions instead',
    effort: 'minutes',
    tool: 'ast-checker',
    rule_id: 'python/bare-except',
    detected_at: '2024-01-01T00:00:00Z',
    ...overrides,
  }
}

describe('buildIssueBody', () => {
  it('should include severity, category, and language', () => {
    const finding = makeFinding()
    const body = buildIssueBody([finding], finding)
    expect(body).toContain('code_structure')
    expect(body).toContain('python')
    expect(body).toContain('high')
  })

  it('should include affected locations with file links', () => {
    const f1 = makeFinding({ file: 'a.py', line_start: 10 })
    const f2 = makeFinding({ file: 'a.py', line_start: 20, id: '2' })
    const body = buildIssueBody([f1, f2], f1)
    expect(body).toContain('a.py:10')
    expect(body).toContain('a.py:20')
    expect(body).toContain('blob/HEAD/a.py#L10')
  })

  it('should include remediation section', () => {
    const finding = makeFinding({ remediation: 'Use except ValueError' })
    const body = buildIssueBody([finding], finding)
    expect(body).toContain('### Remediation')
    expect(body).toContain('Use except ValueError')
  })

  it('should include code snippet when present', () => {
    const finding = makeFinding({ code_snippet: 'except:\n    pass' })
    const body = buildIssueBody([finding], finding)
    expect(body).toContain('### Offending Code')
    expect(body).toContain('except:\n    pass')
  })

  it('should skip code snippet section when absent', () => {
    const finding = makeFinding()
    const body = buildIssueBody([finding], finding)
    expect(body).not.toContain('### Offending Code')
  })

  it('should include references when present', () => {
    const finding = makeFinding({ references: ['https://example.com/doc'] })
    const body = buildIssueBody([finding], finding)
    expect(body).toContain('### References')
    expect(body).toContain('https://example.com/doc')
  })

  it('should include auto-generated footer with rule_id', () => {
    const finding = makeFinding({ rule_id: 'python/bare-except', language_pack: 'python_v1' })
    const body = buildIssueBody([finding], finding)
    expect(body).toContain('python/bare-except')
    expect(body).toContain('python_v1')
  })
})

describe('buildPRCommentBody', () => {
  it('should include severity emoji and antipattern name', () => {
    const body = buildPRCommentBody(makeFinding({ severity: 'critical' }))
    expect(body).toContain('Bare Except')
  })

  it('should include remediation as a fix hint', () => {
    const body = buildPRCommentBody(makeFinding({ remediation: 'Do X instead' }))
    expect(body).toContain('Do X instead')
  })

  it('should include confidence percentage', () => {
    const body = buildPRCommentBody(makeFinding({ confidence: 0.85 }))
    expect(body).toContain('85%')
  })

  it('should include effort estimate', () => {
    const body = buildPRCommentBody(makeFinding({ effort: 'hours' }))
    expect(body).toContain('hours to fix')
  })
})

describe('groupBy', () => {
  it('should group items by key function', () => {
    const items = [
      { name: 'a', type: 'x' },
      { name: 'b', type: 'y' },
      { name: 'c', type: 'x' },
    ]
    const result = groupBy(items, i => i.type)
    expect(result['x']).toHaveLength(2)
    expect(result['y']).toHaveLength(1)
  })

  it('should return empty object for empty array', () => {
    expect(groupBy([], () => 'key')).toEqual({})
  })
})

describe('formatCategory', () => {
  it('should replace underscores and capitalize words', () => {
    expect(formatCategory('code_structure')).toBe('Code Structure')
    expect(formatCategory('test_quality')).toBe('Test Quality')
  })

  it('should handle single word', () => {
    expect(formatCategory('security')).toBe('Security')
  })
})

describe('truncate', () => {
  it('should return string unchanged if within limit', () => {
    expect(truncate('short', 10)).toBe('short')
  })

  it('should truncate with leading ellipsis', () => {
    const result = truncate('a/very/long/path/to/file.py', 15)
    expect(result.length).toBe(15)
    expect(result).toMatch(/^\.\.\./)
  })

  it('should preserve the end of the string', () => {
    const result = truncate('a/very/long/path/to/file.py', 15)
    expect(result).toContain('file.py')
  })
})

describe('deduplication key', () => {
  it('should group findings by antipattern::file', () => {
    const findings = [
      makeFinding({ antipattern: 'bare_except', file: 'a.py' }),
      makeFinding({ antipattern: 'bare_except', file: 'a.py', id: '2', line_start: 50 }),
      makeFinding({ antipattern: 'bare_except', file: 'b.py', id: '3' }),
      makeFinding({ antipattern: 'magic_number', file: 'a.py', id: '4' }),
    ]
    const groups = groupBy(findings, f => `${f.antipattern}::${f.file}`)
    expect(Object.keys(groups)).toHaveLength(3)
    expect(groups['bare_except::a.py']).toHaveLength(2)
    expect(groups['bare_except::b.py']).toHaveLength(1)
    expect(groups['magic_number::a.py']).toHaveLength(1)
  })
})
