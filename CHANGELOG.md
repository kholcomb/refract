# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Go Language Pack (`go_v1`)

- New language pack with 12 AST rules using pure go/ast stdlib (zero dependencies)
- Unchecked errors, bare goroutines, deep nesting, god struct, magic numbers,
  empty interface abuse, context-not-first-param, large interface, complex init(),
  defer in loop, verbose error construction, goroutine closure capture
- Security: TLS InsecureSkipVerify, SQL string concatenation, weak math/rand
- Orchestrator with gosec (Apache 2.0), govulncheck (BSD), lizard, gitleaks

#### Expanded Python Rules

- datetime_now_naive: datetime.now() without timezone
- string_format_sql: f-strings in SQL calls
- isinstance_chain: 4+ elif isinstance() branches
- eval_usage: dangerous dynamic code evaluation
- yaml_unsafe_load: yaml.load() without SafeLoader
- file_not_closed: open() outside with statement
- test_no_assertion: test functions with no assert

#### Expanded TypeScript/JS Rules

- eval_usage: dangerous dynamic code evaluation
- innerhtml_assignment: DOM XSS via innerHTML/outerHTML
- promise_no_catch: .then() without .catch()
- console_log_left: console logging left in production code
- non_null_assertion: excessive ! operator usage
- test_no_assertion: test callbacks with no expect()

### Improved

- Magic number detection uses contextual filtering instead of value whitelist
  (skips const blocks, test files, hex/octal, kwargs, comparisons, arithmetic)
- N+1 query detector distinguishes dict.get() from ORM .get() via arg analysis
- Deep nesting excludes try/with blocks, elif chains, early exits, recursive functions
- Cognitive complexity metric (SonarQube-inspired) suppresses nesting when both fire
- LSP server: fixed IPC/stdio transport mismatch, wired Go and TS scanning,
  fixed category filter, ignorePaths, clearFindings for unopened files
- Summary panel buttons no longer render raw JSON
- 53 tests with full fixture coverage for all 46 rules

## [1.0.0] - 2026-03-24

### Added

#### GitHub Action (`@refract/action`)

- Node20 GitHub Action with `@vercel/ncc` single-file bundle
- Language auto-detection by file extension
- Python language pack: AST checker (mutable defaults, bare excepts, exception sinks, wildcard imports, deep nesting, N+1 queries, magic numbers), lizard complexity, gitleaks secrets, bandit security, osv-scanner + pip-audit dependency scanning, pytest-cov coverage
- TypeScript/JavaScript language pack: AST checker (deep nesting, magic numbers, god class, assertion roulette, excessive mocking, `any` type abuse, `@ts-ignore` proliferation, callback hell), lizard complexity, gitleaks secrets, npm audit + osv-scanner dependency scanning
- Shared single-pass gitleaks scanner with per-language filtering
- Output targets: GitHub Issues (deduplicated by `antipattern::file`), PR inline comments (critical/high on changed lines only), step summary, Slack Block Kit notifications, JSON report
- Configurable severity threshold, confidence threshold, fail-on-severity, paths-ignore
- Containerized mode via Dockerfile (Node 20 + Python 3 + gitleaks + osv-scanner + bandit + lizard)

#### VS Code Extension (`@refract/vscode`)

- LSP server with persistent Node.js process and 500ms debounce on save
- Per-file findings cache for instant tree view queries
- Python file scanning via `ast_checks.py --single-file` sidecar
- LSP diagnostics mapped from Finding schema (severity to DiagnosticSeverity)
- Code actions: quick fix, diff preview, GitHub issue creation, AI agent prompt copy
- Activity bar tree view with findings grouped by file, sorted by severity
- Summary webview panel with severity/category breakdown, filtering, and action buttons
- `ciParity` setting to match CI thresholds in the IDE

#### Shared (`@refract/core`)

- Unified `Finding` schema as the contract between all consumers
- `Severity`, `AntipatternCategory`, `AntipatternId`, `EffortEstimate` types
- `SEVERITY_ORDER` and `bySeverity` sort utilities
- Threshold loader with three-layer merge (defaults, language pack config, repo overrides)
- Simple YAML parser (no dependency required)
- `getActionRoot()` for correct sidecar path resolution after ncc bundling

#### Infrastructure

- npm workspaces monorepo (`packages/core`, `packages/action`, `packages/vscode`)
- Externalized threshold configs in `language-packs/*/config/thresholds.yml`
- Repo-level threshold overrides via `.antipattern-thresholds.yml`
- 52 unit + integration tests (Jest + ts-jest)
- MIT license

[1.0.0]: https://github.com/kholcomb/refract/releases/tag/v1.0.0
