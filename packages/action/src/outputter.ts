import * as core from '@actions/core'
import * as github from '@actions/github'
import { Finding, ScanResult, Severity, bySeverity } from '@refract/core'

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high:     '🟠',
  medium:   '🟡',
  low:      '🔵',
  info:     '⚪',
}

const SEVERITY_LABEL_COLOR: Record<Severity, string> = {
  critical: 'B60205',
  high:     'E4E669',
  medium:   'FBCA04',
  low:      '0075CA',
  info:     'EDEDED',
}

const EFFORT_EMOJI: Record<string, string> = {
  minutes: '⚡',
  hours:   '🕐',
  days:    '📅',
  weeks:   '🗓️',
}

export class GitHubOutputter {
  private octokit: ReturnType<typeof github.getOctokit>
  private context = github.context
  private token: string

  constructor(token: string) {
    this.token = token
    this.octokit = github.getOctokit(token)
  }

  // ── Step Summary ───────────────────────────────────────────────────────────

  async writeStepSummary(result: ScanResult): Promise<void> {
    const { findings, summary, meta } = result

    const lines: string[] = [
      `# 🔍 Anti-Pattern Scan Results`,
      ``,
      `**Repo:** \`${meta.repo}\` | **Commit:** \`${meta.sha.substring(0, 7)}\` | **Duration:** ${(meta.scan_duration_ms / 1000).toFixed(1)}s`,
      ``,
      `## Summary`,
      ``,
      `| Severity | Count |`,
      `|----------|-------|`,
      ...(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(s =>
        `| ${SEVERITY_EMOJI[s]} ${s.charAt(0).toUpperCase() + s.slice(1)} | **${summary.by_severity[s] ?? 0}** |`
      ),
      `| **Total** | **${summary.total}** |`,
      ``,
      `**Files affected:** ${summary.files_affected} | **Languages scanned:** ${meta.languages_detected.join(', ')}`,
      ``,
    ]

    if (findings.length === 0) {
      lines.push(`## ✅ No anti-patterns found above threshold!`)
    } else {
      lines.push(`## Findings by Category`)
      lines.push(``)

      const byCategory = groupBy(findings, f => f.category)
      for (const [category, catFindings] of Object.entries(byCategory)) {
        lines.push(`### ${formatCategory(category)} (${catFindings.length})`)
        lines.push(``)
        lines.push(`| Severity | Anti-Pattern | File | Line | Effort |`)
        lines.push(`|----------|-------------|------|------|--------|`)

        for (const f of catFindings.sort(bySeverity)) {
          lines.push(
            `| ${SEVERITY_EMOJI[f.severity]} ${f.severity} | ${f.antipattern_name} | ` +
            `\`${truncate(f.file, 40)}\` | ${f.line_start} | ${EFFORT_EMOJI[f.effort]} ${f.effort} |`
          )
        }
        lines.push(``)
      }

      lines.push(`## Top Findings`)
      lines.push(``)
      const topFindings = findings
        .filter(f => f.severity === 'critical' || f.severity === 'high')
        .slice(0, 10)

      for (const f of topFindings) {
        lines.push(`<details>`)
        lines.push(`<summary>${SEVERITY_EMOJI[f.severity]} <strong>${f.antipattern_name}</strong> — \`${f.file}:${f.line_start}\`</summary>`)
        lines.push(``)
        lines.push(`**Message:** ${f.message}`)
        lines.push(``)
        lines.push(`**Remediation:** ${f.remediation}`)
        lines.push(``)
        if (f.code_snippet) {
          lines.push(`\`\`\`python`)
          lines.push(f.code_snippet)
          lines.push(`\`\`\``)
        }
        lines.push(`**Confidence:** ${(f.confidence * 100).toFixed(0)}% | **Effort:** ${EFFORT_EMOJI[f.effort]} ${f.effort}`)
        lines.push(`</details>`)
        lines.push(``)
      }
    }

    await core.summary.addRaw(lines.join('\n')).write()
    core.info('✅ Step summary written')
  }

  // ── GitHub Issues ──────────────────────────────────────────────────────────

  async createIssues(
    findings: Finding[],
    label: string,
    existingIssues?: Set<string>
  ): Promise<number> {
    const { owner, repo } = this.context.repo
    let created = 0

    // Ensure the label exists
    await this.ensureLabel(label, 'D93F0B', 'Anti-pattern detected by automated scan')

    // Group findings into single issues per antipattern+file to avoid noise
    const groups = groupBy(findings, f => `${f.antipattern}::${f.file}`)

    for (const [key, group] of Object.entries(groups)) {
      const representative = group[0]
      const title = `[${representative.severity.toUpperCase()}] ${representative.antipattern_name} in \`${representative.file}\``

      // Deduplicate: skip if open issue with same title already exists
      if (existingIssues?.has(title)) {
        core.info(`  ↩ Skipping duplicate issue: ${title}`)
        continue
      }

      const body = buildIssueBody(group, representative)

      try {
        await this.octokit.rest.issues.create({
          owner,
          repo,
          title,
          body,
          labels: [label, representative.category, `severity:${representative.severity}`],
        })
        created++
        core.info(`  ✅ Created issue: ${title}`)

        // Rate limit: GH allows ~30 issues/min via REST
        await sleep(2000)
      } catch (e: any) {
        core.warning(`Failed to create issue "${title}": ${e.message}`)
      }
    }

    core.info(`📋 Created ${created} GitHub Issues`)
    return created
  }

  async getExistingIssueTitles(label: string): Promise<Set<string>> {
    const { owner, repo } = this.context.repo
    const titles = new Set<string>()

    try {
      const issues = await this.octokit.paginate(
        this.octokit.rest.issues.listForRepo,
        { owner, repo, state: 'open', labels: label, per_page: 100 }
      )
      for (const issue of issues) titles.add(issue.title)
    } catch (e) {
      core.warning(`Could not fetch existing issues: ${e}`)
    }

    return titles
  }

  // ── PR Inline Comments ─────────────────────────────────────────────────────

  async postPRComments(findings: Finding[]): Promise<void> {
    if (this.context.eventName !== 'pull_request') {
      core.info('Not a PR event, skipping inline comments')
      return
    }

    const { owner, repo } = this.context.repo
    const prNumber = this.context.payload.pull_request?.number
    if (!prNumber) return

    // Get files changed in this PR to only comment on relevant lines
    const { data: changedFiles } = await this.octokit.rest.pulls.listFiles({
      owner, repo, pull_number: prNumber, per_page: 100
    })

    const changedFilePaths = new Set(changedFiles.map(f => f.filename))
    const prFindings = findings.filter(f => changedFilePaths.has(f.file))

    if (prFindings.length === 0) {
      core.info('No findings in changed PR files')
      return
    }

    // Get the latest commit SHA for this PR
    const commitId = this.context.payload.pull_request?.head?.sha

    for (const finding of prFindings.filter(
      f => f.severity === 'critical' || f.severity === 'high'
    )) {
      try {
        await this.octokit.rest.pulls.createReviewComment({
          owner,
          repo,
          pull_number: prNumber,
          commit_id: commitId,
          path: finding.file,
          line: finding.line_start,
          side: 'RIGHT',
          body: buildPRCommentBody(finding),
        })
        await sleep(500)
      } catch (e: any) {
        // Line may not be in diff — that's okay
        core.debug(`Skipped PR comment on ${finding.file}:${finding.line_start}: ${e.message}`)
      }
    }

    core.info(`💬 Posted PR inline comments for ${prFindings.length} findings`)
  }

  // ── Slack Notification ─────────────────────────────────────────────────────

  async notifySlack(webhookUrl: string, result: ScanResult): Promise<void> {
    const { summary, meta } = result
    const critical = summary.by_severity.critical ?? 0
    const high = summary.by_severity.high ?? 0
    const repoUrl = `https://github.com/${meta.repo}`
    const runUrl = `${repoUrl}/actions/runs/${meta.run_id}`

    const payload = {
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: `🔍 Anti-Pattern Scan: ${meta.repo}` }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Total Findings:*\n${summary.total}` },
            { type: 'mrkdwn', text: `*Critical/High:*\n${critical + high}` },
            { type: 'mrkdwn', text: `*Branch:*\n\`${meta.ref}\`` },
            { type: 'mrkdwn', text: `*Languages:*\n${meta.languages_detected.join(', ')}` },
          ]
        },
        ...(critical > 0 ? [{
          type: 'section',
          text: { type: 'mrkdwn', text: `🔴 *${critical} critical findings* require immediate attention.` }
        }] : []),
        {
          type: 'actions',
          elements: [{
            type: 'button',
            text: { type: 'plain_text', text: 'View Full Report' },
            url: runUrl,
            style: critical > 0 ? 'danger' : 'primary',
          }]
        }
      ]
    }

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })

    if (!response.ok) {
      core.warning(`Slack notification failed: ${response.status}`)
    } else {
      core.info('📣 Slack notification sent')
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private async ensureLabel(name: string, color: string, description: string): Promise<void> {
    const { owner, repo } = this.context.repo
    try {
      await this.octokit.rest.issues.createLabel({ owner, repo, name, color, description })
    } catch {
      // Label already exists — that's fine
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Template builders
// ─────────────────────────────────────────────────────────────────────────────

export function buildIssueBody(findings: Finding[], rep: Finding): string {
  const lines = [
    `## ${SEVERITY_EMOJI[rep.severity]} ${rep.antipattern_name}`,
    ``,
    `**Category:** \`${rep.category}\` | **Language:** \`${rep.language}\` | **Severity:** \`${rep.severity}\``,
    `**Confidence:** ${(rep.confidence * 100).toFixed(0)}% | **Estimated Effort:** ${EFFORT_EMOJI[rep.effort]} ${rep.effort}`,
    ``,
    `---`,
    ``,
    `### Affected Locations`,
    ``,
  ]

  for (const f of findings) {
    lines.push(`- [ ] [\`${f.file}:${f.line_start}\`](../../blob/HEAD/${f.file}#L${f.line_start}) — ${f.message}`)
  }

  lines.push(``, `### What is this anti-pattern?`, ``)
  lines.push(rep.message)
  lines.push(``, `### Remediation`, ``)
  lines.push(rep.remediation)

  if (rep.code_snippet) {
    lines.push(``, `### Offending Code`, ``)
    lines.push(`\`\`\`${rep.language}`)
    lines.push(rep.code_snippet)
    lines.push(`\`\`\``)
  }

  if (rep.references?.length) {
    lines.push(``, `### References`, ``)
    for (const ref of rep.references) lines.push(`- ${ref}`)
  }

  lines.push(``, `---`)
  lines.push(`> 🤖 Auto-generated by [antipattern-detector](https://github.com/kholcomb/refract) · Rule: \`${rep.rule_id}\` · Pack: \`${rep.language_pack}\``)

  return lines.join('\n')
}

export function buildPRCommentBody(f: Finding): string {
  return [
    `### ${SEVERITY_EMOJI[f.severity]} ${f.antipattern_name}`,
    ``,
    `${f.message}`,
    ``,
    `**💡 Fix:** ${f.remediation}`,
    ``,
    `\`${f.rule_id}\` · Confidence: ${(f.confidence * 100).toFixed(0)}% · ${EFFORT_EMOJI[f.effort]} ${f.effort} to fix`,
  ].join('\n')
}

// ─────────────────────────────────────────────────────────────────────────────
// Utils
// ─────────────────────────────────────────────────────────────────────────────

export function groupBy<T>(arr: T[], key: (t: T) => string): Record<string, T[]> {
  return arr.reduce((acc, item) => {
    const k = key(item)
    acc[k] = acc[k] ?? []
    acc[k].push(item)
    return acc
  }, {} as Record<string, T[]>)
}

export function formatCategory(cat: string): string {
  return cat.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

export function truncate(s: string, len: number): string {
  return s.length > len ? '...' + s.slice(-(len - 3)) : s
}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms))
}
