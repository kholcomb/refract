import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as fs from 'fs'
import * as path from 'path'
import { Finding } from './types'

/**
 * Note: This module uses @actions/exec which calls child_process.execFile()
 * internally with argument arrays — no shell interpretation, no injection risk.
 */

const GITLEAKS_REPORT = '/tmp/gitleaks_global.json'

let gitleaksCache: Finding[] | null = null

/**
 * Run gitleaks once globally, cache results, and return findings
 * filtered to the requested file extensions.
 */
export async function runGitleaks(
  workspacePath: string,
  languagePack: string,
  languageLabel: string,
  fileExtensions: Set<string>,
): Promise<Finding[]> {
  if (gitleaksCache === null) {
    gitleaksCache = await runGitleaksGlobal(workspacePath)
  }

  return gitleaksCache
    .filter(f => fileExtensions.has(path.extname(f.file).toLowerCase()))
    .map(f => ({
      ...f,
      language: languageLabel,
      language_pack: languagePack,
    }))
}

async function runGitleaksGlobal(workspacePath: string): Promise<Finding[]> {
  core.info('  → Running gitleaks (global, single pass)...')

  let stdout = ''
  let stderr = ''

  const exitCode = await exec.exec(
    'gitleaks',
    ['detect', '--source', workspacePath,
     '--report-format', 'json', '--report-path', GITLEAKS_REPORT,
     '--no-git', '--exit-code', '0'],
    {
      ignoreReturnCode: true,
      silent: true,
      listeners: {
        stdout: (data: Buffer) => { stdout += data.toString() },
        stderr: (data: Buffer) => { stderr += data.toString() },
      },
    }
  ).catch(() => -1)

  if (!fs.existsSync(GITLEAKS_REPORT)) return []

  const leaks = JSON.parse(fs.readFileSync(GITLEAKS_REPORT, 'utf-8') || '[]')
  const now = new Date().toISOString()
  const findings: Finding[] = []

  for (const leak of leaks ?? []) {
    const relFile = path.relative(workspacePath, leak.File ?? '')
    findings.push({
      id: generateId(),
      antipattern: 'hardcoded_secret',
      antipattern_name: 'Hardcoded Secret',
      category: 'security',
      severity: 'critical',
      confidence: leak.RuleID?.includes('generic') ? 0.75 : 0.95,
      file: relFile,
      line_start: leak.StartLine ?? 1,
      line_end: leak.EndLine ?? leak.StartLine ?? 1,
      language: '',
      language_pack: '',
      message: `Potential secret detected: ${leak.Description} (rule: ${leak.RuleID})`,
      remediation: 'Remove this secret from source code immediately. Use environment variables or a secrets manager. Rotate the secret if it was ever committed.',
      effort: 'hours',
      tool: 'gitleaks',
      rule_id: leak.RuleID ?? 'gitleaks/secret',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
      tags: ['security', 'owasp-a02', 'secrets'],
      detected_at: now,
    })
  }

  core.info(`  → gitleaks found ${findings.length} secrets globally`)
  return findings
}

/**
 * Reset the gitleaks cache between scan runs or for testing.
 */
export function resetGitleaksCache(): void {
  gitleaksCache = null
}

function generateId(): string {
  return Math.random().toString(36).substring(2, 11)
}
