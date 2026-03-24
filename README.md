# Refract -- Anti-Pattern Detector

A GitHub Action + VS Code extension that scans codebases for anti-patterns and produces structured findings for AI agent consumption.

## What it does

Refract detects **46 anti-patterns** across Python, TypeScript/JavaScript, and Go, then outputs findings as:

- **GitHub Issues** (deduplicated by `antipattern::file`)
- **PR inline comments** (critical/high only, on changed lines)
- **Step summary** (markdown table in Actions UI)
- **Slack notifications** (Block Kit)
- **JSON report** (primary AI agent input)
- **VS Code diagnostics** (squiggles, hover cards, code actions)

## Detection matrix

### Python (14 AST rules + external tools)

| Anti-Pattern | Category | Severity | Confidence |
|---|---|---|---|
| Mutable default argument | code_structure | high | 1.0 |
| Bare except / exception sink | code_structure | high | 1.0 |
| Wildcard import | code_structure | medium | 1.0 |
| Deep nesting (>5 levels) | code_structure | medium/high | 0.85 |
| Cognitive complexity (>20) | code_structure | medium/high | 0.9 |
| N+1 query pattern (ORM) | code_structure | high | 0.8 |
| Magic numbers (contextual) | code_structure | low | 0.7 |
| isinstance chain (>4 branches) | code_structure | medium | 0.8 |
| Naive datetime.now() | code_structure | medium | 0.9 |
| Dangerous eval usage | security | critical | 1.0 |
| String-formatted SQL | security | high | 0.85 |
| yaml.load() without SafeLoader | security | high | 0.95 |
| open() without `with` statement | code_structure | medium | 0.8 |
| Test function with no assertion | test_quality | medium | 0.85 |
| Long method (>50 lines) | code_structure | medium/high | 0.95 |
| High cyclomatic complexity (>10) | code_structure | medium/high | 1.0 |
| God class | code_structure | medium/high | 0.82 |
| Hardcoded secrets | security | critical | 0.75-0.95 |
| Shell/SQL injection, weak crypto | security | varies | 0.5-0.9 |
| Vulnerable dependencies | dependencies | varies | 1.0 |
| Missing test coverage (<50%) | test_quality | medium/high | 1.0 |

### TypeScript / JavaScript (14 AST rules + external tools)

| Anti-Pattern | Category | Severity | Confidence |
|---|---|---|---|
| Deep nesting (>4 levels) | code_structure | medium/high | 0.9 |
| Magic numbers (contextual) | code_structure | low | 0.7 |
| God class (>15 methods) | code_structure | medium/high | 0.85 |
| Assertion roulette | test_quality | medium | 0.95 |
| Excessive mocking (>5 mocks) | test_quality | medium | 0.85 |
| `any` type abuse (>5) | code_structure | medium/high | 0.9 |
| `@ts-ignore` proliferation (>3) | code_structure | medium/high | 0.95 |
| Callback hell (>3 nested) | code_structure | medium | 0.85 |
| Dangerous eval / dynamic code | security | critical | 1.0 |
| innerHTML/outerHTML assignment | security | high | 0.9 |
| Unhandled promise (.then no .catch) | code_structure | medium | 0.75 |
| Console logging left in code (>3) | code_structure | low | 0.8 |
| Non-null assertion abuse (>5) | code_structure | medium/high | 0.85 |
| Test with no assertion | test_quality | medium | 0.85 |
| Long method / high complexity | code_structure | medium/high | 0.95-1.0 |
| Hardcoded secrets | security | critical | 0.75-0.95 |
| Vulnerable dependencies | dependencies | varies | 1.0 |

### Go (12 AST rules + external tools)

| Anti-Pattern | Category | Severity | Confidence |
|---|---|---|---|
| Unchecked error (`_ = f()`) | code_structure | high | 0.85 |
| Bare goroutine (no recover) | concurrency | medium | 0.8 |
| Deep nesting (>5 levels) | code_structure | medium/high | 0.85 |
| God struct (>15 methods) | code_structure | medium/high | 0.85 |
| Magic numbers (contextual) | code_structure | low | 0.7 |
| Empty interface abuse (>3 any params) | code_structure | medium | 0.8 |
| Context not first parameter | code_structure | medium | 0.95 |
| Large interface (>5 methods) | code_structure | medium/high | 0.85 |
| Complex init() function | code_structure | medium | 0.75 |
| Defer in loop (resource leak) | code_structure | high | 0.95 |
| Verbose error construction | code_structure | low | 1.0 |
| Loop variable captured by goroutine | concurrency | high | 0.9 |
| TLS InsecureSkipVerify: true | security | critical | 1.0 |
| SQL string concatenation in Query | security | high | 0.85 |
| Weak math/rand for security | security | high | 0.75 |
| Long function / high complexity | code_structure | medium/high | 0.95-1.0 |
| Hardcoded secrets | security | critical | 0.75-0.95 |
| Vulnerable dependencies | dependencies | varies | 1.0 |

## Quick start -- GitHub Action

```yaml
- name: Detect Anti-Patterns
  uses: kholcomb/refract@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    languages: auto
    severity_threshold: medium
    fail_on_severity: high
    create_issues: true
    pr_comments: true
```

### Action inputs

| Input | Default | Description |
|---|---|---|
| `github_token` | `${{ github.token }}` | Token for issues/PR comments |
| `languages` | `auto` | Comma-separated or `auto` for detection |
| `categories` | `code_structure,security,dependencies,test_quality` | Which categories to scan |
| `severity_threshold` | `medium` | Minimum severity to report |
| `fail_on_severity` | `high` | Fail build at this severity (`none` to disable) |
| `create_issues` | `true` | Create deduplicated GitHub Issues |
| `pr_comments` | `true` | Inline PR comments on changed lines |
| `step_summary` | `true` | Write Actions step summary |
| `slack_webhook_url` | *(empty)* | Slack webhook for notifications |
| `confidence_threshold` | `0.7` | Minimum confidence score (0.0-1.0) |
| `paths_ignore` | *(empty)* | Comma-separated glob prefixes to skip |

### Action outputs

| Output | Description |
|---|---|
| `findings_count` | Total findings above threshold |
| `critical_count` | Critical severity count |
| `high_count` | High severity count |
| `report_path` | Path to JSON report (for AI agents) |

## Quick start -- VS Code extension

The extension provides real-time anti-pattern detection for Python, TypeScript/JavaScript, and Go:

1. Install from the VS Code Marketplace (or build locally -- see below)
2. Open a project -- workspace scan runs automatically on activation
3. Save a file -- findings appear as diagnostics (squiggles + hover cards)

### Commands

| Command | Description |
|---|---|
| `Anti-Pattern: Scan Current File` | Scan the active file |
| `Anti-Pattern: Scan Entire Workspace` | Full workspace scan |
| `Anti-Pattern: Show Findings Panel` | Open the summary webview |
| `Anti-Pattern: Copy as AI Agent Prompt` | Copy structured prompt to clipboard |
| `Anti-Pattern: Clear All Findings` | Reset all diagnostics |

### Extension settings

| Setting | Default | Description |
|---|---|---|
| `antipattern.enabled` | `true` | Enable scan-on-save |
| `antipattern.severityThreshold` | `medium` | Minimum severity for diagnostics |
| `antipattern.confidenceThreshold` | `0.7` | Minimum confidence score |
| `antipattern.pythonPath` | `python3` | Python interpreter path |
| `antipattern.scanOnOpen` | `true` | Auto-scan workspace on activation |
| `antipattern.ciParity` | `true` | Match CI thresholds exactly |

## Customizing thresholds

Place a `.antipattern-thresholds.yml` in your repo root to override defaults:

```yaml
code_structure:
  max_cyclomatic_complexity: 15
  max_function_length: 80
  max_nesting_depth: 5
  god_class_method_count: 25

test_quality:
  min_coverage_percent: 60
  max_mock_calls: 8
```

See `language-packs/*/config/thresholds.yml` for all available options.

## JSON report format

The report at `report_path` is the primary AI agent contract:

```json
{
  "meta": { "repo": "owner/repo", "sha": "abc1234", ... },
  "findings": [
    {
      "id": "k8f2m9x3a",
      "antipattern": "mutable_default_argument",
      "antipattern_name": "Mutable Default Argument",
      "category": "code_structure",
      "severity": "high",
      "confidence": 1.0,
      "file": "src/handler.py",
      "line_start": 42,
      "line_end": 42,
      "language": "python",
      "message": "Function 'process' uses a mutable list as a default argument...",
      "remediation": "Replace with None and initialize inside the function...",
      "effort": "minutes",
      "tool": "ast-checker",
      "rule_id": "python/mutable-default-argument"
    }
  ],
  "summary": { "total": 7, "by_severity": { "critical": 0, "high": 3, ... } }
}
```

## Development

```bash
# Install all workspace dependencies
npm install

# Build everything
npm run build

# Run action tests (53 tests)
npm test --workspace=packages/action

# Typecheck all packages
npm run typecheck
```

### Monorepo structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full package layout and data flow.
