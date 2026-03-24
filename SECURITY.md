# Security Policy

## Reporting vulnerabilities

If you discover a security vulnerability in Refract, please report it responsibly:

1. **Do not** open a public GitHub Issue.
2. Email **security@kholcomb.com** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Suggested fix (if any)
3. You will receive an acknowledgment within 48 hours and a detailed response within 7 days.

## Scope

This policy covers:

- The `@refract/core`, `@refract/action`, and `@refract/vscode` packages
- The `language-packs/` sidecar scripts (`ast_checks.py`, `ast_checks.ts`)
- The Dockerfile and GitHub Action definition

## Security design

### No secrets in transit

Refract runs entirely within your CI runner or local machine. No code, findings, or telemetry are sent to external servers. The only outbound calls are:

- **GitHub API** -- to create issues and PR comments (using the token you provide)
- **Slack webhook** -- only if you configure `slack_webhook_url`

### Tool execution model

The action orchestrates third-party tools via `@actions/exec`, which uses `execFile()` with argument arrays internally. No shell interpretation occurs, eliminating command injection vectors.

| Tool | License | Purpose |
| ---- | ------- | ------- |
| lizard | MIT | Cyclomatic complexity |
| gitleaks | MIT | Secret detection |
| bandit | Apache 2.0 | Python security |
| osv-scanner | Apache 2.0 | CVE scanning |
| pip-audit | Apache 2.0 | Python dependency vulns |
| npm audit | MIT (npm CLI) | Node dependency vulns |
| typescript-estree | BSD-2-Clause | TypeScript AST parsing |

### Excluded tools

- **Semgrep rules** -- LGPL-licensed engine is acceptable, but the rule registry has a restricted license. We do not ship or depend on Semgrep rules.

### Confidence-based filtering

Findings below the configured `confidence_threshold` (default: 0.7) are discarded before any output is produced. This prevents low-confidence heuristic matches from creating noise in issues or PR comments.

### Issue deduplication

Issues are deduplicated by title (`[SEVERITY] Antipattern Name in file`). Before creating an issue, the action queries all open issues with the configured label and skips any with a matching title.

### PR comment scoping

PR inline comments are only posted on lines that appear in the current diff, and only for critical/high severity findings.

### Containerized mode

For environments requiring full isolation, the Dockerfile at `packages/action/Dockerfile` provides a self-contained image with all tools pre-installed. No network calls are made during analysis.

## Dependencies

Run `npm audit` to check for known vulnerabilities in Node.js dependencies.

## Supported versions

| Version | Supported |
| ------- | --------- |
| v1.x | Current |
