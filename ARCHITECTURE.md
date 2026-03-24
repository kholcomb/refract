# Architecture

## Monorepo layout

```
refract/
├── package.json                          # npm workspaces root
├── tsconfig.base.json                    # shared TypeScript compiler options
├── language-packs/                       # shared analysis sidecars
│   ├── python/
│   │   ├── config/thresholds.yml         # default thresholds (overridable)
│   │   └── scripts/ast_checks.py         # pure-stdlib AST walker
│   ├── typescript/
│   │   ├── config/thresholds.yml
│   │   └── scripts/ast_checks.{ts,js}    # typescript-estree AST walker
│   └── go/
│       ├── config/thresholds.yml
│       └── scripts/ast_checks{,.go}       # go/ast stdlib walker (compiled binary)
├── packages/
│   ├── core/                             # @refract/core
│   │   └── src/
│   │       ├── types.ts                  # Finding schema (the contract)
│   │       ├── severity.ts               # SEVERITY_ORDER, bySeverity
│   │       ├── thresholds.ts             # threshold loader + YAML parser
│   │       └── action-root.ts            # GITHUB_ACTION_PATH resolver
│   ├── action/                           # @refract/action
│   │   ├── action.yml                    # GitHub Action definition
│   │   ├── Dockerfile                    # containerized mode
│   │   └── src/
│   │       ├── index.ts                  # entrypoint: detect → scan → output
│   │       ├── language-detector.ts      # file-extension language detection
│   │       ├── language-packs/
│   │       │   ├── python.ts             # orchestrates lizard, gitleaks, bandit, etc.
│   │       │   ├── typescript.ts         # orchestrates lizard, gitleaks, npm audit, etc.
│   │       │   └── go.ts                 # orchestrates gosec, gitleaks, govulncheck, etc.
│   │       ├── shared-scanners.ts        # gitleaks single-pass with cache
│   │       └── outputter.ts              # issues, PR comments, step summary, Slack
│   └── vscode/                           # @refract/vscode
│       └── src/
│           ├── extension.ts              # VS Code extension client
│           ├── lsp/server.ts             # LSP server (persistent Node process)
│           └── panels/
│               ├── findings-tree.ts      # activity bar tree view
│               └── summary-panel.ts      # webview dashboard
```

## Package dependency graph

```
@refract/core          ← no dependencies (pure types + utils)
    ↑
    ├── @refract/action    ← @actions/core, @actions/exec, @actions/github
    └── @refract/vscode    ← vscode-languageserver, vscode-languageclient
```

Both `action` and `vscode` import the Finding schema, severity utilities, and threshold loader from `core`. Neither depends on the other.

## Data flow — GitHub Action

```
action.yml inputs
    │
    ▼
src/index.ts (entrypoint)
    │
    ├── language-detector.ts          walks workspace, counts extensions
    │       │
    │       ▼
    ├── language-packs/python.ts      orchestrates Python tools
    │       ├── lizard                → complexity findings
    │       ├── ast_checks.py         → AST pattern findings
    │       ├── gitleaks (shared)     → secret findings
    │       ├── bandit                → security findings
    │       ├── osv-scanner           → CVE findings
    │       ├── pip-audit             → dependency findings
    │       └── pytest-cov            → coverage findings
    │
    ├── language-packs/typescript.ts  orchestrates TS/JS tools
    │       ├── lizard                → complexity findings
    │       ├── ast_checks.js         → AST pattern findings
    │       ├── gitleaks (shared)     → secret findings
    │       ├── npm audit             → dependency findings
    │       └── osv-scanner           → CVE findings
    │
    ▼
Finding[]  (normalized to @refract/core schema)
    │
    ├── filter by severity_threshold + confidence_threshold
    │
    ├── JSON report  → /tmp/antipattern-report.json (AI agent input)
    ├── Step summary → GitHub Actions UI
    ├── Issues       → GitHub API (deduplicated by title)
    ├── PR comments  → GitHub API (only on changed lines, critical/high)
    └── Slack        → webhook (Block Kit payload)
```

## Data flow — VS Code extension

```
TextDocument.onDidSave
    │
    ├── debounce (500ms)
    │
    ▼
LSP server (server.ts, persistent Node process)
    │
    ├── languageFromPath()           → route to correct analyzer
    │
    ├── Python files:
    │   └── spawn python3 ast_checks.py --single-file <path>
    │
    ├── TS/JS files:
    │   └── (planned: in-process typescript-estree analysis)
    │
    ▼
Finding[]  (same schema as CI)
    │
    ├── findingsCache.set(file, findings)    per-file cache
    │
    ├── publishDiagnostics()                 → squiggles in editor
    ├── findingsUpdated notification         → tree view + summary panel
    └── CodeAction provider                  → quick fix, diff preview,
                                               GitHub issue, AI prompt
```

## The Finding schema

Every finding — regardless of tool, language, or delivery mechanism — normalizes to this shape before output:

```typescript
interface Finding {
  id: string                    // unique instance ID
  antipattern: AntipatternId    // e.g. 'mutable_default_argument'
  antipattern_name: string      // e.g. 'Mutable Default Argument'
  category: AntipatternCategory // code_structure | security | dependencies | test_quality
  severity: Severity            // critical | high | medium | low | info
  confidence: number            // 0.0–1.0
  file: string                  // relative path from repo root
  line_start: number            // 1-indexed
  line_end: number
  language: string
  language_pack: string         // e.g. 'python_v1'
  message: string               // what's wrong
  remediation: string           // how to fix it (AI agents act on this)
  effort: EffortEstimate        // minutes | hours | days | weeks
  tool: string                  // which tool produced this
  rule_id: string               // tool-specific rule ID
  detected_at: string           // ISO timestamp
}
```

This schema is defined once in `packages/core/src/types.ts` and consumed by all packages. It is the contract between the scanner pipeline and all downstream consumers (issues, PR comments, diagnostics, AI agents).

## Shared gitleaks scanner

Both Python and TypeScript language packs need secret scanning, but gitleaks scans the entire workspace. To avoid running it twice, `shared-scanners.ts` runs gitleaks once globally, caches the results, and partitions findings by file extension when each language pack requests them.

## Threshold system

Thresholds are loaded in three layers (later overrides earlier):

1. **Built-in defaults** — hardcoded in `packages/core/src/thresholds.ts`
2. **Language pack config** — `language-packs/<lang>/config/thresholds.yml`
3. **Repo overrides** — `.antipattern-thresholds.yml` in the workspace root

The VS Code extension's `ciParity` setting reads the same threshold files so IDE diagnostics match what CI will catch.

## Language pack system

Each language is a self-contained folder under `language-packs/` with:

- `config/thresholds.yml` — default thresholds
- `scripts/` — sidecar analysis scripts (run as child processes)

A TypeScript orchestrator in `packages/action/src/language-packs/<lang>.ts` coordinates tool execution, collects raw output, and normalizes everything to `Finding[]`.

To add a new language:

1. Create `language-packs/<lang>/` with config and scripts
2. Create `packages/action/src/language-packs/<lang>.ts` orchestrator
3. Add `case '<lang>':` in `packages/action/src/index.ts`
4. Update `AVAILABLE_PACKS` in `packages/action/src/language-detector.ts`

## Build pipeline

| Package | Build tool | Output |
| ------- | ---------- | ------ |
| `@refract/core` | `tsc` | `packages/core/dist/` (declarations + JS) |
| `@refract/action` | `@vercel/ncc` | `packages/action/dist/index.js` (single bundle) |
| `@refract/vscode` | `esbuild` | `packages/vscode/dist/{extension,lspServer}.js` |
| TS AST sidecar | `tsc` | `language-packs/typescript/scripts/ast_checks.js` |

The sidecar `.js` is committed to the repo because it runs as a separate process (not bundled by ncc or esbuild). The `build:sidecars` script at the workspace root keeps it in sync with the `.ts` source.

## Licensing constraints

All tools in the pipeline are MIT, Apache 2.0, BSD-2-Clause, or LGPL licensed. The Opengrep engine (LGPL) is acceptable if needed in the future. Semgrep rule files are explicitly excluded due to their restricted license. The `AntipatternId` type is `| string` extensible so new packs can add custom rule IDs without modifying core.
