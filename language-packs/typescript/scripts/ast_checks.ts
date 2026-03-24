#!/usr/bin/env node
/**
 * TypeScript/JavaScript AST Anti-Pattern Checker
 *
 * Detects TS/JS-specific anti-patterns via AST walking:
 *   - Deep nesting (>4 levels of control flow)
 *   - Magic numbers (unexplained numeric literals)
 *   - Assertion roulette (expect(true).toBe(true), expect(1).toBe(1))
 *   - Excessive mocking (>5 jest.mock() calls in a single test file)
 *   - God class (class with >15 methods)
 *
 * Uses @typescript-eslint/typescript-estree (BSD-2-Clause — safe to monetize)
 */

import { parse, AST_NODE_TYPES, TSESTree } from '@typescript-eslint/typescript-estree'
import * as fs from 'fs'
import * as path from 'path'

const PACK_VERSION = 'typescript_v1'

interface Finding {
  id: string
  antipattern: string
  antipattern_name: string
  category: string
  severity: string
  confidence: number
  file: string
  line_start: number
  line_end: number
  language: string
  language_pack: string
  message: string
  remediation: string
  effort: string
  tool: string
  rule_id: string
  code_snippet?: string
  references?: string[]
  tags?: string[]
  detected_at: string
}

function makeId(): string {
  return Math.random().toString(36).substring(2, 11)
}

function inferLang(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase()
  return (ext === '.ts' || ext === '.tsx') ? 'typescript' : 'javascript'
}

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next',
  '.cache', '__pycache__', '.venv', 'vendor',
])

const JS_TS_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'])

// ─────────────────────────────────────────────────────────────────────────────
// AST Checkers
// ─────────────────────────────────────────────────────────────────────────────

function checkDeepNesting(
  ast: TSESTree.Program,
  filePath: string,
  sourceLines: string[]
): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()
  const lang = inferLang(filePath)

  const NESTING_NODES = new Set([
    AST_NODE_TYPES.IfStatement,
    AST_NODE_TYPES.ForStatement,
    AST_NODE_TYPES.ForInStatement,
    AST_NODE_TYPES.ForOfStatement,
    AST_NODE_TYPES.WhileStatement,
    AST_NODE_TYPES.DoWhileStatement,
    AST_NODE_TYPES.SwitchStatement,
    AST_NODE_TYPES.TryStatement,
    AST_NODE_TYPES.WithStatement,
  ])

  function walkFunction(node: TSESTree.Node, body: TSESTree.Node): void {
    let maxDepth = 0

    function countNesting(n: TSESTree.Node, depth: number): void {
      if (NESTING_NODES.has(n.type as AST_NODE_TYPES)) {
        depth++
        maxDepth = Math.max(maxDepth, depth)
      }
      for (const key of Object.keys(n)) {
        if (key === 'parent') continue
        const val = (n as any)[key]
        if (val && typeof val === 'object') {
          if (Array.isArray(val)) {
            for (const child of val) {
              if (child && typeof child.type === 'string') countNesting(child, depth)
            }
          } else if (val.type) {
            countNesting(val, depth)
          }
        }
      }
    }

    countNesting(body, 0)

    if (maxDepth >= 4) {
      const funcName = getFunctionName(node)
      const startLine = node.loc.start.line
      const endLine = node.loc.end.line
      const snippet = sourceLines.slice(startLine - 1, Math.min(startLine + 4, sourceLines.length)).join('\n')

      findings.push({
        id: makeId(),
        antipattern: 'deep_nesting',
        antipattern_name: 'Deep Nesting',
        category: 'code_structure',
        severity: maxDepth >= 6 ? 'high' : 'medium',
        confidence: 0.9,
        file: filePath,
        line_start: startLine,
        line_end: endLine,
        language: lang,
        language_pack: PACK_VERSION,
        message: `Function '${funcName}' has nesting depth of ${maxDepth} (threshold: 4). Deep nesting makes code hard to read and test.`,
        remediation: 'Reduce nesting by: (1) returning early on guard conditions, (2) extracting nested blocks into helper functions, (3) using array methods instead of nested loops.',
        effort: 'hours',
        tool: 'ast-checker',
        rule_id: 'ts/deep-nesting',
        code_snippet: snippet,
        tags: ['maintainability', 'readability'],
        detected_at: now,
      })
    }
  }

  walkAST(ast, (node) => {
    if (
      node.type === AST_NODE_TYPES.FunctionDeclaration ||
      node.type === AST_NODE_TYPES.FunctionExpression ||
      node.type === AST_NODE_TYPES.ArrowFunctionExpression
    ) {
      walkFunction(node, node.body)
    } else if (node.type === AST_NODE_TYPES.MethodDefinition) {
      if (node.value && node.value.body) {
        walkFunction(node, node.value.body)
      }
    }
  })

  return findings
}

function checkMagicNumbers(
  ast: TSESTree.Program,
  filePath: string,
  sourceLines: string[]
): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()
  const lang = inferLang(filePath)
  const ALLOWED = new Set([0, 1, -1, 2, 100])

  walkAST(ast, (node, ancestors) => {
    if (node.type !== AST_NODE_TYPES.Literal) return
    if (typeof node.value !== 'number') return
    if (ALLOWED.has(node.value)) return

    // Skip: array indices, enum values, type annotations, default parameter values in simple cases
    const parent = ancestors[ancestors.length - 1]
    if (!parent) return
    if (parent.type === AST_NODE_TYPES.TSEnumMember) return
    if (parent.type === AST_NODE_TYPES.TSTypeAliasDeclaration) return
    if (parent.type === AST_NODE_TYPES.TSLiteralType) return

    // Skip constants: const X = 42
    if (
      parent.type === AST_NODE_TYPES.VariableDeclarator &&
      ancestors.length >= 2
    ) {
      const grandparent = ancestors[ancestors.length - 2]
      if (
        grandparent?.type === AST_NODE_TYPES.VariableDeclaration &&
        (grandparent as TSESTree.VariableDeclaration).kind === 'const'
      ) return
    }

    findings.push({
      id: makeId(),
      antipattern: 'magic_number',
      antipattern_name: 'Magic Number',
      category: 'code_structure',
      severity: 'low',
      confidence: 0.7,
      file: filePath,
      line_start: node.loc.start.line,
      line_end: node.loc.start.line,
      language: lang,
      language_pack: PACK_VERSION,
      message: `Magic number \`${node.value}\` — unexplained numeric literal makes intent unclear.`,
      remediation: `Extract to a named constant: \`const THRESHOLD = ${node.value}\` and reference it by name.`,
      effort: 'minutes',
      tool: 'ast-checker',
      rule_id: 'ts/magic-number',
      tags: ['readability', 'maintainability'],
      detected_at: now,
    })
  })

  return findings
}

function checkAssertionRoulette(
  ast: TSESTree.Program,
  filePath: string,
  sourceLines: string[]
): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()
  const lang = inferLang(filePath)

  // Patterns: expect(true).toBe(true), expect(1).toBe(1), expect(false).toBe(false)
  walkAST(ast, (node) => {
    if (node.type !== AST_NODE_TYPES.CallExpression) return
    if (node.callee.type !== AST_NODE_TYPES.MemberExpression) return

    const method = node.callee.property
    if (method.type !== AST_NODE_TYPES.Identifier) return
    if (!['toBe', 'toEqual', 'toStrictEqual'].includes(method.name)) return

    // Check if the argument to toBe is a trivial literal
    if (node.arguments.length === 0) return
    const arg = node.arguments[0]
    if (arg.type !== AST_NODE_TYPES.Literal) return

    // Check if expect() was called with the same trivial literal
    const expectCall = node.callee.object
    if (expectCall.type !== AST_NODE_TYPES.CallExpression) return
    if (expectCall.callee.type !== AST_NODE_TYPES.Identifier) return
    if (expectCall.callee.name !== 'expect') return
    if (expectCall.arguments.length === 0) return

    const expectArg = expectCall.arguments[0]
    if (expectArg.type !== AST_NODE_TYPES.Literal) return

    // Same trivial value on both sides
    if (expectArg.value === arg.value && (arg.value === true || arg.value === false || arg.value === 1 || arg.value === 0)) {
      findings.push({
        id: makeId(),
        antipattern: 'assertion_roulette',
        antipattern_name: 'Assertion Roulette',
        category: 'test_quality',
        severity: 'medium',
        confidence: 0.95,
        file: filePath,
        line_start: node.loc.start.line,
        line_end: node.loc.end.line,
        language: lang,
        language_pack: PACK_VERSION,
        message: `Trivial assertion \`expect(${expectArg.raw}).${method.name}(${arg.raw})\` always passes — this tests nothing.`,
        remediation: 'Replace with a meaningful assertion that tests actual behavior: `expect(result).toBe(expectedValue)`.',
        effort: 'minutes',
        tool: 'ast-checker',
        rule_id: 'ts/assertion-roulette',
        references: ['https://testsmells.org/pages/testsmellexamples.html#AssertionRoulette'],
        tags: ['test_quality', 'test-smell'],
        detected_at: now,
      })
    }
  })

  return findings
}

function checkExcessiveMocking(
  ast: TSESTree.Program,
  filePath: string,
  sourceLines: string[]
): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()
  const lang = inferLang(filePath)

  // Only check test files
  const basename = path.basename(filePath)
  if (!basename.includes('.test.') && !basename.includes('.spec.') && !basename.includes('__tests__')) {
    return findings
  }

  let mockCount = 0
  const mockLocations: number[] = []

  walkAST(ast, (node) => {
    if (node.type !== AST_NODE_TYPES.CallExpression) return
    const callee = node.callee

    // jest.mock('...')
    if (
      callee.type === AST_NODE_TYPES.MemberExpression &&
      callee.object.type === AST_NODE_TYPES.Identifier &&
      callee.object.name === 'jest' &&
      callee.property.type === AST_NODE_TYPES.Identifier &&
      callee.property.name === 'mock'
    ) {
      mockCount++
      mockLocations.push(node.loc.start.line)
    }
  })

  if (mockCount > 5) {
    findings.push({
      id: makeId(),
      antipattern: 'excessive_mocking',
      antipattern_name: 'Excessive Mocking',
      category: 'test_quality',
      severity: 'medium',
      confidence: 0.85,
      file: filePath,
      line_start: mockLocations[0] ?? 1,
      line_end: mockLocations[mockLocations.length - 1] ?? 1,
      language: lang,
      language_pack: PACK_VERSION,
      message: `Test file has ${mockCount} jest.mock() calls. Excessive mocking makes tests brittle and tightly coupled to implementation details.`,
      remediation: 'Reduce mocking by: (1) testing through public APIs, (2) using dependency injection, (3) splitting the module under test into smaller units.',
      effort: 'hours',
      tool: 'ast-checker',
      rule_id: 'ts/excessive-mocking',
      references: ['https://kentcdodds.com/blog/testing-implementation-details'],
      tags: ['test_quality', 'test-smell'],
      detected_at: now,
    })
  }

  return findings
}

function checkGodClass(
  ast: TSESTree.Program,
  filePath: string,
  sourceLines: string[]
): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()
  const lang = inferLang(filePath)

  walkAST(ast, (node) => {
    if (node.type !== AST_NODE_TYPES.ClassDeclaration && node.type !== AST_NODE_TYPES.ClassExpression) return

    const classNode = node as TSESTree.ClassDeclaration | TSESTree.ClassExpression
    const methods = classNode.body.body.filter(
      m => m.type === AST_NODE_TYPES.MethodDefinition || m.type === AST_NODE_TYPES.PropertyDefinition
    )
    const methodCount = methods.filter(m => m.type === AST_NODE_TYPES.MethodDefinition).length

    if (methodCount > 15) {
      const className = classNode.id?.name ?? '<anonymous>'
      findings.push({
        id: makeId(),
        antipattern: 'god_class',
        antipattern_name: 'God Class',
        category: 'code_structure',
        severity: methodCount > 30 ? 'high' : 'medium',
        confidence: 0.85,
        file: filePath,
        line_start: node.loc.start.line,
        line_end: node.loc.end.line,
        language: lang,
        language_pack: PACK_VERSION,
        message: `Class '${className}' has ${methodCount} methods. Large classes are hard to understand and test.`,
        remediation: `Decompose '${className}' into smaller classes with single responsibilities. Consider extracting groups of related methods into separate classes.`,
        effort: 'days',
        tool: 'ast-checker',
        rule_id: 'ts/god-class',
        references: ['https://refactoring.guru/smells/large-class'],
        tags: ['maintainability', 'srp'],
        detected_at: now,
      })
    }
  })

  return findings
}

function checkAnyTypeAbuse(
  ast: TSESTree.Program,
  filePath: string,
  sourceLines: string[]
): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()
  const lang = inferLang(filePath)

  // Skip .js files — they don't have type annotations
  if (lang === 'javascript') return findings

  let anyCount = 0
  const anyLocations: number[] = []

  walkAST(ast, (node) => {
    // Explicit `: any` type annotation
    if (node.type === AST_NODE_TYPES.TSAnyKeyword) {
      anyCount++
      anyLocations.push(node.loc.start.line)
    }
  })

  if (anyCount > 5) {
    findings.push({
      id: makeId(),
      antipattern: 'any_type_abuse',
      antipattern_name: 'Excessive `any` Type Usage',
      category: 'code_structure',
      severity: anyCount > 15 ? 'high' : 'medium',
      confidence: 0.9,
      file: filePath,
      line_start: anyLocations[0] ?? 1,
      line_end: anyLocations[anyLocations.length - 1] ?? 1,
      language: lang,
      language_pack: PACK_VERSION,
      message: `File has ${anyCount} explicit \`any\` type annotations. This defeats TypeScript's type safety and hides bugs.`,
      remediation: 'Replace `any` with specific types, `unknown` (for truly unknown types), or generic type parameters. Use `any` only at FFI boundaries with untyped libraries.',
      effort: anyCount > 15 ? 'days' : 'hours',
      tool: 'ast-checker',
      rule_id: 'ts/any-type-abuse',
      references: ['https://www.typescriptlang.org/docs/handbook/2/types-from-types.html'],
      tags: ['type-safety', 'maintainability'],
      detected_at: now,
    })
  }

  return findings
}

function checkTsIgnoreProliferation(
  ast: TSESTree.Program,
  filePath: string,
  sourceLines: string[]
): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()
  const lang = inferLang(filePath)

  // Scan source lines for @ts-ignore and @ts-expect-error comments
  let ignoreCount = 0
  const ignoreLocations: number[] = []

  for (let i = 0; i < sourceLines.length; i++) {
    const line = sourceLines[i]
    if (line.includes('@ts-ignore') || line.includes('@ts-expect-error')) {
      ignoreCount++
      ignoreLocations.push(i + 1) // 1-indexed
    }
  }

  if (ignoreCount > 3) {
    findings.push({
      id: makeId(),
      antipattern: 'ts_ignore_proliferation',
      antipattern_name: '@ts-ignore Proliferation',
      category: 'code_structure',
      severity: ignoreCount > 10 ? 'high' : 'medium',
      confidence: 0.95,
      file: filePath,
      line_start: ignoreLocations[0] ?? 1,
      line_end: ignoreLocations[ignoreLocations.length - 1] ?? 1,
      language: lang,
      language_pack: PACK_VERSION,
      message: `File has ${ignoreCount} @ts-ignore/@ts-expect-error directives. Each one silences a type error that may indicate a real bug.`,
      remediation: 'Fix the underlying type errors instead of suppressing them. If suppression is truly needed, prefer @ts-expect-error (which fails when the error is fixed) over @ts-ignore.',
      effort: 'hours',
      tool: 'ast-checker',
      rule_id: 'ts/ts-ignore-proliferation',
      tags: ['type-safety', 'maintainability'],
      detected_at: now,
    })
  }

  return findings
}

function checkCallbackHell(
  ast: TSESTree.Program,
  filePath: string,
  sourceLines: string[]
): Finding[] {
  const findings: Finding[] = []
  const now = new Date().toISOString()
  const lang = inferLang(filePath)

  // Detect deeply nested callbacks: function expressions or arrow functions
  // passed as arguments to calls, nested >3 levels deep.
  const CALLBACK_TYPES = new Set([
    AST_NODE_TYPES.FunctionExpression,
    AST_NODE_TYPES.ArrowFunctionExpression,
  ])

  walkAST(ast, (node, ancestors) => {
    if (!CALLBACK_TYPES.has(node.type as AST_NODE_TYPES)) return

    // Count how many ancestor callbacks this is nested within
    let callbackDepth = 0
    for (const ancestor of ancestors) {
      if (CALLBACK_TYPES.has(ancestor.type as AST_NODE_TYPES)) {
        // Only count if the ancestor was passed as a call argument
        const parent = ancestors[ancestors.indexOf(ancestor) - 1]
        if (parent?.type === AST_NODE_TYPES.CallExpression) {
          callbackDepth++
        }
      }
    }

    if (callbackDepth >= 3) {
      findings.push({
        id: makeId(),
        antipattern: 'callback_hell',
        antipattern_name: 'Callback Hell',
        category: 'code_structure',
        severity: callbackDepth >= 5 ? 'high' : 'medium',
        confidence: 0.85,
        file: filePath,
        line_start: node.loc.start.line,
        line_end: node.loc.end.line,
        language: lang,
        language_pack: PACK_VERSION,
        message: `Callback nested ${callbackDepth} levels deep. Deeply nested callbacks make code hard to read, debug, and test.`,
        remediation: 'Refactor using async/await, Promise chains, or extract named functions to flatten the nesting.',
        effort: 'hours',
        tool: 'ast-checker',
        rule_id: 'ts/callback-hell',
        references: ['http://callbackhell.com/'],
        tags: ['readability', 'maintainability', 'async'],
        detected_at: now,
      })
    }
  })

  return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// AST Walking Utility
// ─────────────────────────────────────────────────────────────────────────────

function walkAST(
  node: TSESTree.Node,
  visitor: (node: TSESTree.Node, ancestors: TSESTree.Node[]) => void,
  ancestors: TSESTree.Node[] = []
): void {
  visitor(node, ancestors)
  const nextAncestors = [...ancestors, node]

  for (const key of Object.keys(node)) {
    if (key === 'parent') continue
    const val = (node as any)[key]
    if (val && typeof val === 'object') {
      if (Array.isArray(val)) {
        for (const child of val) {
          if (child && typeof child.type === 'string') {
            walkAST(child, visitor, nextAncestors)
          }
        }
      } else if (val.type) {
        walkAST(val, visitor, nextAncestors)
      }
    }
  }
}

function getFunctionName(node: TSESTree.Node): string {
  if ('id' in node && (node as any).id?.name) return (node as any).id.name
  if ('key' in node && (node as any).key?.name) return (node as any).key.name
  return '<anonymous>'
}

// ─────────────────────────────────────────────────────────────────────────────
// File Scanner
// ─────────────────────────────────────────────────────────────────────────────

function scanFile(filePath: string, repoRoot: string): Finding[] {
  let source: string
  try {
    source = fs.readFileSync(filePath, 'utf-8')
  } catch {
    return []
  }

  const relPath = path.relative(repoRoot, filePath)
  const sourceLines = source.split('\n')

  let ast: TSESTree.Program
  try {
    ast = parse(source, {
      loc: true,
      range: true,
      jsx: true,
      comment: false,
    })
  } catch {
    return []
  }

  return [
    ...checkDeepNesting(ast, relPath, sourceLines),
    ...checkMagicNumbers(ast, relPath, sourceLines),
    ...checkAssertionRoulette(ast, relPath, sourceLines),
    ...checkExcessiveMocking(ast, relPath, sourceLines),
    ...checkGodClass(ast, relPath, sourceLines),
    ...checkAnyTypeAbuse(ast, relPath, sourceLines),
    ...checkTsIgnoreProliferation(ast, relPath, sourceLines),
    ...checkCallbackHell(ast, relPath, sourceLines),
  ]
}

function scanDirectory(root: string, ignorePrefixes: string[]): Finding[] {
  const findings: Finding[] = []

  function walk(dir: string): void {
    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue
        const rel = path.relative(root, path.join(dir, entry.name))
        if (ignorePrefixes.some(p => rel.startsWith(p))) continue
        walk(path.join(dir, entry.name))
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase()
        if (!JS_TS_EXTENSIONS.has(ext)) continue
        findings.push(...scanFile(path.join(dir, entry.name), root))
      }
    }
  }

  walk(root)
  return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI Entrypoint
// ─────────────────────────────────────────────────────────────────────────────

function main(): void {
  const args = process.argv.slice(2)
  const rootPath = args[0]
  if (!rootPath) {
    console.error('Usage: ast_checks <path> [--output <file>] [--ignore <prefixes>]')
    process.exit(1)
  }

  let outputPath = '/tmp/ts_ast_findings.json'
  let ignorePrefixes: string[] = []

  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--output' && args[i + 1]) {
      outputPath = args[++i]
    } else if (args[i] === '--ignore' && args[i + 1]) {
      ignorePrefixes = args[++i].split(',').filter(Boolean)
    }
  }

  const findings = scanDirectory(rootPath, ignorePrefixes)

  const result = { findings, count: findings.length }
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2))
  console.log(`TS/JS AST checker found ${findings.length} findings → ${outputPath}`)
}

main()
