# Anti-Pattern Detector

Real-time anti-pattern detection for Python and TypeScript/JavaScript. Scans on save, surfaces findings as diagnostics, and generates AI-agent-ready remediation prompts.

## Features

- **Scan on save** -- findings appear as squiggly underlines with hover details
- **Workspace scan** -- full project scan on activation, no need to open every file
- **Findings tree** -- activity bar panel showing all findings grouped by file
- **Summary dashboard** -- webview with severity breakdown, filtering, and action buttons
- **Code actions** -- quick fix, diff preview, GitHub Issue creation, AI prompt copy
- **CI parity** -- uses the same thresholds as the Refract GitHub Action

## What it detects

### Python

| Anti-Pattern | Confidence |
|---|---|
| Mutable default argument | 1.0 |
| Bare except / exception sink | 1.0 |
| Wildcard import | 1.0 |
| Deep nesting (>5 levels) | 0.85 |
| N+1 query pattern (ORM) | 0.8 |
| Magic numbers | 0.7 |
| High cognitive complexity (>20) | 0.9 |

### TypeScript / JavaScript

| Anti-Pattern | Confidence |
|---|---|
| Deep nesting (>4 levels) | 0.9 |
| Magic numbers | 0.7 |
| God class (>15 methods) | 0.85 |
| Assertion roulette | 0.95 |
| Excessive mocking (>5 mocks) | 0.85 |
| `any` type abuse (>5) | 0.9 |
| `@ts-ignore` proliferation (>3) | 0.95 |
| Callback hell (>3 nested) | 0.85 |

## Commands

| Command | Description |
|---|---|
| `Anti-Pattern: Scan Current File` | Scan the active file |
| `Anti-Pattern: Scan Entire Workspace` | Full workspace scan |
| `Anti-Pattern: Show Findings Panel` | Open the summary dashboard |
| `Anti-Pattern: Copy as AI Agent Prompt` | Copy structured prompt to clipboard |
| `Anti-Pattern: Clear All Findings` | Reset all diagnostics |

## Settings

| Setting | Default | Description |
|---|---|---|
| `antipattern.enabled` | `true` | Enable scan-on-save |
| `antipattern.severityThreshold` | `medium` | Minimum severity for diagnostics |
| `antipattern.confidenceThreshold` | `0.7` | Minimum confidence score |
| `antipattern.pythonPath` | `python3` | Python interpreter path |
| `antipattern.scanOnOpen` | `true` | Auto-scan workspace on activation |
| `antipattern.ciParity` | `true` | Match GitHub Action thresholds |

## Requirements

- Python 3.8+ (for Python file scanning)
- Node.js 18+ (bundled with VS Code)

## Links

- [GitHub](https://github.com/kholcomb/refract)
- [GitHub Action](https://github.com/kholcomb/refract) -- same detectors, runs in CI
- [Issue Tracker](https://github.com/kholcomb/refract/issues)

## License

MIT
