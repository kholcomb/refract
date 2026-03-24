# Anti-Pattern Detector

Real-time anti-pattern detection for Python, TypeScript/JavaScript, and Go. Scans on save and on workspace open, surfaces findings as diagnostics, and generates AI-agent-ready remediation prompts.

## Features

- **Workspace scan** -- full project scan on activation, no need to open every file
- **Scan on save** -- findings appear as squiggly underlines with hover details
- **Findings tree** -- activity bar panel showing all findings grouped by file
- **Summary dashboard** -- webview with severity breakdown, filtering, and action buttons
- **Code actions** -- quick fix, diff preview, GitHub Issue creation, AI prompt copy
- **CI parity** -- uses the same thresholds as the Refract GitHub Action

## What it detects

### Python (14 rules)

| Anti-Pattern | Confidence |
|---|---|
| Mutable default argument | 1.0 |
| Bare except / exception sink | 1.0 |
| Wildcard import | 1.0 |
| Deep nesting (>5 levels) | 0.85 |
| Cognitive complexity (>20) | 0.9 |
| N+1 query pattern (ORM) | 0.8 |
| Magic numbers (contextual) | 0.7 |
| isinstance chain (>4 branches) | 0.8 |
| Naive datetime.now() | 0.9 |
| Dangerous eval usage | 1.0 |
| String-formatted SQL | 0.85 |
| yaml.load() without SafeLoader | 0.95 |
| open() without `with` | 0.8 |
| Test with no assertion | 0.85 |

### TypeScript / JavaScript (14 rules)

| Anti-Pattern | Confidence |
|---|---|
| Deep nesting (>4 levels) | 0.9 |
| Magic numbers (contextual) | 0.7 |
| God class (>15 methods) | 0.85 |
| Assertion roulette | 0.95 |
| Excessive mocking (>5 mocks) | 0.85 |
| `any` type abuse (>5) | 0.9 |
| `@ts-ignore` proliferation (>3) | 0.95 |
| Callback hell (>3 nested) | 0.85 |
| Dangerous eval / dynamic code | 1.0 |
| innerHTML/outerHTML assignment | 0.9 |
| Unhandled promise | 0.75 |
| Console logging left in code | 0.8 |
| Non-null assertion abuse (>5) | 0.85 |
| Test with no assertion | 0.85 |

### Go (12 rules)

| Anti-Pattern | Confidence |
|---|---|
| Unchecked error | 0.85 |
| Bare goroutine (no recover) | 0.8 |
| Deep nesting (>5 levels) | 0.85 |
| God struct (>15 methods) | 0.85 |
| Magic numbers (contextual) | 0.7 |
| Empty interface abuse | 0.8 |
| Context not first parameter | 0.95 |
| Large interface (>5 methods) | 0.85 |
| Complex init() function | 0.75 |
| Defer in loop | 0.95 |
| Verbose error construction | 1.0 |
| Loop variable captured by goroutine | 0.9 |
| TLS InsecureSkipVerify | 1.0 |
| SQL string concatenation | 0.85 |
| Weak random for security | 0.75 |

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
- Go AST checker binary is pre-compiled (no Go toolchain needed)

## Links

- [GitHub](https://github.com/kholcomb/refract)
- [GitHub Action](https://github.com/kholcomb/refract) -- same detectors, runs in CI
- [Issue Tracker](https://github.com/kholcomb/refract/issues)

## License

MIT
