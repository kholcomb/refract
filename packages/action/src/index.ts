import * as core from '@actions/core'
import * as github from '@actions/github'
import * as fs from 'fs'
import * as path from 'path'
import { detectLanguages } from './language-detector'
import { scanPython } from './language-packs/python'
import { scanTypeScript } from './language-packs/typescript'
import { GitHubOutputter } from './outputter'
import {
  Finding, ScanResult, ScanSummary, ScanMeta,
  Severity, AntipatternCategory, SEVERITY_ORDER
} from '@refract/core'

export { SEVERITY_ORDER }

async function run(): Promise<void> {
  const startTime = Date.now()

  try {
    // --- Read inputs ---
    const token           = core.getInput('github_token', { required: true })
    const languagesInput  = core.getInput('languages')
    const categoriesInput = core.getInput('categories')
    const severityThresh  = core.getInput('severity_threshold') as Severity
    const failOnSeverity  = core.getInput('fail_on_severity') as Severity | 'none'
    const createIssues    = core.getInput('create_issues') === 'true'
    const prComments      = core.getInput('pr_comments') === 'true'
    const stepSummary     = core.getInput('step_summary') === 'true'
    const slackWebhook    = core.getInput('slack_webhook_url')
    const issueLabel      = core.getInput('issue_label')
    const confidenceStr   = parseFloat(core.getInput('confidence_threshold'))
    const pathsIgnore     = core.getInput('paths_ignore')
      .split(',').map(s => s.trim()).filter(Boolean)

    const categories = categoriesInput
      .split(',')
      .map(s => s.trim()) as AntipatternCategory[]

    const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd()

    core.info(`[scan] Anti-pattern detector starting...`)
    core.info(`   Workspace: ${workspace}`)
    core.info(`   Categories: ${categories.join(', ')}`)

    // --- Detect languages ---
    let languagesToScan: string[]

    if (languagesInput === 'auto') {
      core.info('[detect] Auto-detecting languages...')
      const detected = await detectLanguages(workspace, pathsIgnore)
      languagesToScan = detected.map(d => d.language)
      core.info(`   Detected: ${detected.map(d => `${d.language} (${d.fileCount} files)`).join(', ')}`)

      const withoutPacks = detected.filter(d => !d.packAvailable)
      if (withoutPacks.length > 0) {
        core.warning(
          `No language pack available for: ${withoutPacks.map(d => d.language).join(', ')}. ` +
          `These languages will be skipped.`
        )
      }
    } else {
      languagesToScan = languagesInput.split(',').map(s => s.trim())
    }

    // --- Run language packs ---
    const allFindings: Finding[] = []
    const packsUsed: string[] = []

    for (const lang of languagesToScan) {
      core.startGroup(`[pack] Language pack: ${lang}`)

      const scanOptions = {
        workspacePath: workspace,
        categories,
        confidenceThreshold: confidenceStr,
        ignorePaths: pathsIgnore,
      }

      try {
        switch (lang) {
          case 'python':
            allFindings.push(...await scanPython(scanOptions))
            packsUsed.push('python_v1')
            break

          case 'typescript':
          case 'javascript':
            allFindings.push(...await scanTypeScript(scanOptions))
            packsUsed.push('typescript_v1')
            break

          default:
            core.info(`  [i]  No pack available for '${lang}', skipping`)
        }
      } catch (e: any) {
        core.warning(`Language pack '${lang}' failed: ${e.message}`)
      }

      core.endGroup()
    }

    // --- Filter by severity threshold ---
    const thresholdIndex = SEVERITY_ORDER.indexOf(severityThresh)
    const filteredFindings = allFindings.filter(
      f => SEVERITY_ORDER.indexOf(f.severity) <= thresholdIndex
    )

    core.info(`[stats] Total findings: ${allFindings.length} (${filteredFindings.length} above threshold)`)

    // --- Build result ---
    const scanDuration = Date.now() - startTime
    const ctx = github.context

    const meta: ScanMeta = {
      repo: `${ctx.repo.owner}/${ctx.repo.repo}`,
      sha: ctx.sha,
      ref: ctx.ref,
      run_id: String(ctx.runId),
      run_number: String(ctx.runNumber),
      actor: ctx.actor,
      event: ctx.eventName,
      languages_detected: languagesToScan,
      language_packs_used: packsUsed,
      categories_scanned: categories,
      scan_duration_ms: scanDuration,
      scanned_at: new Date().toISOString(),
    }

    const summary = buildSummary(filteredFindings)
    const result: ScanResult = { meta, findings: filteredFindings, summary }

    // --- Write JSON report ---
    const reportPath = '/tmp/antipattern-report.json'
    fs.writeFileSync(reportPath, JSON.stringify(result, null, 2))
    core.info(`[report] Report written to ${reportPath}`)

    // --- Outputs ---
    const outputter = new GitHubOutputter(token)

    if (stepSummary) {
      await outputter.writeStepSummary(result)
    }

    if (createIssues && filteredFindings.length > 0) {
      core.startGroup('[issues] Creating GitHub Issues')
      const existingTitles = await outputter.getExistingIssueTitles(issueLabel)
      await outputter.createIssues(filteredFindings, issueLabel, existingTitles)
      core.endGroup()
    }

    if (prComments && filteredFindings.length > 0) {
      core.startGroup('[comments] Posting PR comments')
      await outputter.postPRComments(filteredFindings)
      core.endGroup()
    }

    if (slackWebhook) {
      await outputter.notifySlack(slackWebhook, result)
    }

    // --- Set action outputs ---
    core.setOutput('findings_count', filteredFindings.length)
    core.setOutput('critical_count', summary.by_severity.critical ?? 0)
    core.setOutput('high_count', summary.by_severity.high ?? 0)
    core.setOutput('report_path', reportPath)

    // --- Fail check ---
    if (failOnSeverity !== 'none') {
      const failThresholdIndex = SEVERITY_ORDER.indexOf(failOnSeverity as Severity)
      const blockingFindings = filteredFindings.filter(
        f => SEVERITY_ORDER.indexOf(f.severity) <= failThresholdIndex
      )

      if (blockingFindings.length > 0) {
        core.setFailed(
          `[fail] ${blockingFindings.length} finding(s) at or above '${failOnSeverity}' severity. ` +
          `See step summary or GitHub Issues for details.`
        )
        return
      }
    }

    core.info(`[ok] Scan complete. ${filteredFindings.length} findings reported.`)

  } catch (error: any) {
    core.setFailed(`Action failed: ${error.message}`)
    core.debug(error.stack)
  }
}

export function buildSummary(findings: Finding[]): ScanSummary {
  const bySev = Object.fromEntries(
    SEVERITY_ORDER.map((s: Severity) => [s, findings.filter((f: Finding) => f.severity === s).length])
  ) as Record<Severity, number>

  const byCat: Record<string, number> = {}
  const byLang: Record<string, number> = {}
  const files = new Set<string>()

  for (const f of findings) {
    byCat[f.category] = (byCat[f.category] ?? 0) + 1
    byLang[f.language] = (byLang[f.language] ?? 0) + 1
    files.add(f.file)
  }

  return {
    total: findings.length,
    by_severity: bySev,
    by_category: byCat as any,
    by_language: byLang,
    files_affected: files.size,
  }
}

run()
