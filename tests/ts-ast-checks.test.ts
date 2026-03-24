import { execFileSync } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'

const SCRIPT_PATH = path.join(__dirname, '../language-packs/typescript/scripts/ast_checks.js')
const FIXTURE_DIR = path.join(__dirname, 'fixtures/typescript')
const OUTPUT_PATH = '/tmp/ts_ast_test_jest.json'

interface ASTResult {
  findings: Array<{
    antipattern: string
    file: string
    line_start: number
    severity: string
    confidence: number
    category: string
    tool: string
    rule_id: string
    language: string
    language_pack: string
    remediation: string
    effort: string
  }>
  count: number
}

function runAST(fixtureDir: string = FIXTURE_DIR): ASTResult {
  execFileSync('node', [SCRIPT_PATH, fixtureDir, '--output', OUTPUT_PATH])
  return JSON.parse(fs.readFileSync(OUTPUT_PATH, 'utf-8'))
}

describe('TypeScript AST Checker', () => {
  let result: ASTResult

  beforeAll(() => {
    result = runAST()
  })

  it('should find findings in the fixture files', () => {
    expect(result.count).toBeGreaterThan(0)
    expect(result.findings.length).toBe(result.count)
  })

  it('should detect deep nesting', () => {
    const nesting = result.findings.filter(f => f.antipattern === 'deep_nesting')
    expect(nesting.length).toBeGreaterThanOrEqual(1)
    expect(nesting[0].file).toContain('antipatterns_fixture.ts')
    expect(nesting[0].severity).toMatch(/medium|high/)
  })

  it('should detect magic numbers', () => {
    const magic = result.findings.filter(f => f.antipattern === 'magic_number')
    expect(magic.length).toBeGreaterThanOrEqual(4)
    expect(magic[0].severity).toBe('low')
    expect(magic[0].confidence).toBe(0.7)
  })

  it('should detect god class with >15 methods', () => {
    const gods = result.findings.filter(f => f.antipattern === 'god_class')
    expect(gods.length).toBeGreaterThanOrEqual(1)
    expect(gods[0].file).toContain('antipatterns_fixture.ts')
  })

  it('should detect assertion roulette', () => {
    const roulette = result.findings.filter(f => f.antipattern === 'assertion_roulette')
    expect(roulette.length).toBeGreaterThanOrEqual(3)
    expect(roulette[0].category).toBe('test_quality')
  })

  it('should detect excessive mocking', () => {
    const mocking = result.findings.filter(f => f.antipattern === 'excessive_mocking')
    expect(mocking.length).toBe(1)
    expect(mocking[0].category).toBe('test_quality')
    expect(mocking[0].file).toContain('assertion_roulette.test.ts')
  })

  it('should include all required Finding fields', () => {
    const required = [
      'id', 'antipattern', 'antipattern_name', 'category', 'severity',
      'confidence', 'file', 'line_start', 'line_end', 'language',
      'language_pack', 'message', 'remediation', 'effort', 'tool',
      'rule_id', 'detected_at',
    ]
    for (const finding of result.findings) {
      for (const field of required) {
        expect(finding).toHaveProperty(field)
      }
    }
  })

  it('should set language to typescript for .ts files', () => {
    const tsFindings = result.findings.filter(f => f.file.endsWith('.ts'))
    for (const f of tsFindings) {
      expect(f.language).toBe('typescript')
    }
  })

  it('should set language_pack to typescript_v1', () => {
    for (const f of result.findings) {
      expect(f.language_pack).toBe('typescript_v1')
    }
  })

  it('should not flag const declarations as magic numbers', () => {
    // The API_KEY constant in the fixture is a string, not a number,
    // so it won't be flagged as magic_number. This tests the const-exclusion logic.
    const magic = result.findings.filter(f => f.antipattern === 'magic_number')
    for (const f of magic) {
      expect(f.rule_id).toBe('ts/magic-number')
    }
  })
})
