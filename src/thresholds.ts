import * as fs from 'fs'
import * as path from 'path'
import { getActionRoot } from './action-root'

export interface CodeStructureThresholds {
  max_cyclomatic_complexity: number
  max_function_length: number
  max_nesting_depth: number
  god_class_method_count: number
  god_class_total_lines: number
  god_class_lizard_method_count?: number
  god_class_lizard_total_lines?: number
  magic_number_allowed: number[]
}

export interface TestQualityThresholds {
  min_coverage_percent?: number
  max_mock_calls?: number
}

export interface SecurityThresholds {
  bandit_severity_level?: string
}

export interface Thresholds {
  code_structure: CodeStructureThresholds
  test_quality: TestQualityThresholds
  security: SecurityThresholds
}

const DEFAULT_THRESHOLDS: Thresholds = {
  code_structure: {
    max_cyclomatic_complexity: 10,
    max_function_length: 50,
    max_nesting_depth: 4,
    god_class_method_count: 20,
    god_class_total_lines: 500,
    magic_number_allowed: [0, 1, -1, 2, 100],
  },
  test_quality: {
    min_coverage_percent: 50,
    max_mock_calls: 5,
  },
  security: {
    bandit_severity_level: 'medium',
  },
}

/**
 * Load thresholds for a language pack, merging:
 * 1. Built-in defaults
 * 2. Language pack config (language-packs/<lang>/config/thresholds.yml)
 * 3. Repo-level overrides (.antipattern-thresholds.yml in workspace root)
 *
 * Uses a simple YAML subset parser (key: value) to avoid adding a yaml dependency.
 */
export function loadThresholds(language: string, workspacePath?: string): Thresholds {
  const result = structuredClone(DEFAULT_THRESHOLDS)

  // Load language pack defaults
  const packConfigPath = path.join(
    getActionRoot(),
    'language-packs', language, 'config', 'thresholds.yml'
  )
  mergeFromYaml(result, packConfigPath)

  // Load repo-level overrides
  if (workspacePath) {
    const repoConfigPath = path.join(workspacePath, '.antipattern-thresholds.yml')
    mergeFromYaml(result, repoConfigPath)
  }

  return result
}

function mergeFromYaml(target: Thresholds, filePath: string): void {
  if (!fs.existsSync(filePath)) return

  const content = fs.readFileSync(filePath, 'utf-8')
  const parsed = parseSimpleYaml(content)

  for (const [section, values] of Object.entries(parsed)) {
    if (section in target) {
      Object.assign((target as any)[section], values)
    }
  }
}

/**
 * Minimal YAML parser for flat key-value sections.
 * Handles: section headers, numeric values, string values, arrays on single line.
 * Does NOT handle nested objects, multi-line strings, or anchors.
 */
function parseSimpleYaml(content: string): Record<string, Record<string, any>> {
  const result: Record<string, Record<string, any>> = {}
  let currentSection = ''

  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue

    // Section header (no leading whitespace, ends with colon)
    if (!line.startsWith(' ') && !line.startsWith('\t') && trimmed.endsWith(':')) {
      currentSection = trimmed.slice(0, -1)
      result[currentSection] = result[currentSection] ?? {}
      continue
    }

    // Key-value pair (indented)
    const match = trimmed.match(/^(\w+):\s*(.+)$/)
    if (match && currentSection) {
      const [, key, rawValue] = match
      result[currentSection][key] = parseYamlValue(rawValue)
    }
  }

  return result
}

function parseYamlValue(raw: string): any {
  const trimmed = raw.trim()

  // Array: [1, 2, 3]
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return trimmed.slice(1, -1).split(',').map(s => parseYamlValue(s.trim()))
  }

  // Number
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
    return Number(trimmed)
  }

  // Boolean
  if (trimmed === 'true') return true
  if (trimmed === 'false') return false

  // String
  return trimmed
}
