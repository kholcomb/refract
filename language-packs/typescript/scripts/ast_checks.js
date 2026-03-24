#!/usr/bin/env node
"use strict";
/**
 * TypeScript/JavaScript AST Anti-Pattern Checker
 *
 * Detects TS/JS-specific anti-patterns via AST walking:
 *   - Deep nesting (>4 levels of control flow)
 *   - Magic numbers (unexplained numeric literals)
 *   - Assertion roulette (expect(true).toBe(true), expect(1).toBe(1))
 *   - Excessive mocking (>5 jest.mock() calls in a single test file)
 *   - God class (class with >15 methods)
 *
 * Uses @typescript-eslint/typescript-estree (BSD-2-Clause -- safe to monetize)
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const typescript_estree_1 = require("@typescript-eslint/typescript-estree");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const PACK_VERSION = 'typescript_v1';
function makeId() {
    return Math.random().toString(36).substring(2, 11);
}
function inferLang(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return (ext === '.ts' || ext === '.tsx') ? 'typescript' : 'javascript';
}
const SKIP_DIRS = new Set([
    'node_modules', '.git', 'dist', 'build', 'coverage', '.next',
    '.cache', '__pycache__', '.venv', 'vendor',
]);
const JS_TS_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);
// -----------------------------------------------------------------------------
// AST Checkers
// -----------------------------------------------------------------------------
function checkDeepNesting(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    const NESTING_NODES = new Set([
        typescript_estree_1.AST_NODE_TYPES.IfStatement,
        typescript_estree_1.AST_NODE_TYPES.ForStatement,
        typescript_estree_1.AST_NODE_TYPES.ForInStatement,
        typescript_estree_1.AST_NODE_TYPES.ForOfStatement,
        typescript_estree_1.AST_NODE_TYPES.WhileStatement,
        typescript_estree_1.AST_NODE_TYPES.DoWhileStatement,
        typescript_estree_1.AST_NODE_TYPES.SwitchStatement,
        typescript_estree_1.AST_NODE_TYPES.TryStatement,
        typescript_estree_1.AST_NODE_TYPES.WithStatement,
    ]);
    function walkFunction(node, body) {
        let maxDepth = 0;
        function countNesting(n, depth) {
            if (NESTING_NODES.has(n.type)) {
                depth++;
                maxDepth = Math.max(maxDepth, depth);
            }
            for (const key of Object.keys(n)) {
                if (key === 'parent')
                    continue;
                const val = n[key];
                if (val && typeof val === 'object') {
                    if (Array.isArray(val)) {
                        for (const child of val) {
                            if (child && typeof child.type === 'string')
                                countNesting(child, depth);
                        }
                    }
                    else if (val.type) {
                        countNesting(val, depth);
                    }
                }
            }
        }
        countNesting(body, 0);
        if (maxDepth >= 4) {
            const funcName = getFunctionName(node);
            const startLine = node.loc.start.line;
            const endLine = node.loc.end.line;
            const snippet = sourceLines.slice(startLine - 1, Math.min(startLine + 4, sourceLines.length)).join('\n');
            findings.push({
                id: makeId(),
                antipattern: 'deep_nesting',
                antipattern_name: 'Deep Nesting',
                category: 'code_structure',
                severity: maxDepth >= 6 ? 'high' : 'medium',
                confidence: 0.9,
                file: filePath,
                line_start: startLine,
                line_end: endLine,
                language: lang,
                language_pack: PACK_VERSION,
                message: `Function '${funcName}' has nesting depth of ${maxDepth} (threshold: 4). Deep nesting makes code hard to read and test.`,
                remediation: 'Reduce nesting by: (1) returning early on guard conditions, (2) extracting nested blocks into helper functions, (3) using array methods instead of nested loops.',
                effort: 'hours',
                tool: 'ast-checker',
                rule_id: 'ts/deep-nesting',
                code_snippet: snippet,
                tags: ['maintainability', 'readability'],
                detected_at: now,
            });
        }
    }
    walkAST(ast, (node) => {
        if (node.type === typescript_estree_1.AST_NODE_TYPES.FunctionDeclaration ||
            node.type === typescript_estree_1.AST_NODE_TYPES.FunctionExpression ||
            node.type === typescript_estree_1.AST_NODE_TYPES.ArrowFunctionExpression) {
            walkFunction(node, node.body);
        }
        else if (node.type === typescript_estree_1.AST_NODE_TYPES.MethodDefinition) {
            if (node.value && node.value.body) {
                walkFunction(node, node.value.body);
            }
        }
    });
    return findings;
}
function checkMagicNumbers(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    const TRIVIAL = new Set([0, 1, -1]);
    const isTestFile = filePath.includes('.test.') || filePath.includes('.spec.') || filePath.includes('__tests__');
    walkAST(ast, (node, ancestors) => {
        if (node.type !== typescript_estree_1.AST_NODE_TYPES.Literal)
            return;
        if (typeof node.value !== 'number')
            return;
        if (TRIVIAL.has(node.value))
            return;
        const parent = ancestors[ancestors.length - 1];
        const grandparent = ancestors[ancestors.length - 2];
        if (!parent)
            return;
        // Context: skip test files (assertions use literal values)
        if (isTestFile)
            return;
        // Context: skip enum members, type annotations, type literals
        if (parent.type === typescript_estree_1.AST_NODE_TYPES.TSEnumMember)
            return;
        if (parent.type === typescript_estree_1.AST_NODE_TYPES.TSTypeAliasDeclaration)
            return;
        if (parent.type === typescript_estree_1.AST_NODE_TYPES.TSLiteralType)
            return;
        // Context: skip const declarations (const X = 42)
        if (parent.type === typescript_estree_1.AST_NODE_TYPES.VariableDeclarator && grandparent) {
            if (grandparent.type === typescript_estree_1.AST_NODE_TYPES.VariableDeclaration &&
                grandparent.kind === 'const')
                return;
        }
        // Context: skip default parameter values
        if (parent.type === typescript_estree_1.AST_NODE_TYPES.AssignmentPattern)
            return;
        // Context: skip array/object literal values (data, not logic)
        if (parent.type === typescript_estree_1.AST_NODE_TYPES.ArrayExpression)
            return;
        if (parent.type === typescript_estree_1.AST_NODE_TYPES.Property && grandparent?.type === typescript_estree_1.AST_NODE_TYPES.ObjectExpression)
            return;
        // Context: skip computed property access (arr[0], obj[2])
        if (parent.type === typescript_estree_1.AST_NODE_TYPES.MemberExpression && parent.computed)
            return;
        // Context: skip bitwise operations (bitmasks are self-documenting)
        if (parent.type === typescript_estree_1.AST_NODE_TYPES.BinaryExpression) {
            const op = parent.operator;
            if (op === '&' || op === '|' || op === '^' || op === '<<' || op === '>>' || op === '>>>')
                return;
        }
        // Context: skip hex/octal in source (check raw representation)
        const raw = node.raw;
        if (raw && (raw.startsWith('0x') || raw.startsWith('0X') || raw.startsWith('0o') || raw.startsWith('0O')))
            return;
        findings.push({
            id: makeId(),
            antipattern: 'magic_number',
            antipattern_name: 'Magic Number',
            category: 'code_structure',
            severity: 'low',
            confidence: 0.7,
            file: filePath,
            line_start: node.loc.start.line,
            line_end: node.loc.start.line,
            language: lang,
            language_pack: PACK_VERSION,
            message: `Magic number \`${node.value}\` -- unexplained numeric literal makes intent unclear.`,
            remediation: `Extract to a named constant: \`const THRESHOLD = ${node.value}\` and reference it by name.`,
            effort: 'minutes',
            tool: 'ast-checker',
            rule_id: 'ts/magic-number',
            tags: ['readability', 'maintainability'],
            detected_at: now,
        });
    });
    return findings;
}
function checkAssertionRoulette(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    // Patterns: expect(true).toBe(true), expect(1).toBe(1), expect(false).toBe(false)
    walkAST(ast, (node) => {
        if (node.type !== typescript_estree_1.AST_NODE_TYPES.CallExpression)
            return;
        if (node.callee.type !== typescript_estree_1.AST_NODE_TYPES.MemberExpression)
            return;
        const method = node.callee.property;
        if (method.type !== typescript_estree_1.AST_NODE_TYPES.Identifier)
            return;
        if (!['toBe', 'toEqual', 'toStrictEqual'].includes(method.name))
            return;
        // Check if the argument to toBe is a trivial literal
        if (node.arguments.length === 0)
            return;
        const arg = node.arguments[0];
        if (arg.type !== typescript_estree_1.AST_NODE_TYPES.Literal)
            return;
        // Check if expect() was called with the same trivial literal
        const expectCall = node.callee.object;
        if (expectCall.type !== typescript_estree_1.AST_NODE_TYPES.CallExpression)
            return;
        if (expectCall.callee.type !== typescript_estree_1.AST_NODE_TYPES.Identifier)
            return;
        if (expectCall.callee.name !== 'expect')
            return;
        if (expectCall.arguments.length === 0)
            return;
        const expectArg = expectCall.arguments[0];
        if (expectArg.type !== typescript_estree_1.AST_NODE_TYPES.Literal)
            return;
        // Same trivial value on both sides
        if (expectArg.value === arg.value && (arg.value === true || arg.value === false || arg.value === 1 || arg.value === 0)) {
            findings.push({
                id: makeId(),
                antipattern: 'assertion_roulette',
                antipattern_name: 'Assertion Roulette',
                category: 'test_quality',
                severity: 'medium',
                confidence: 0.95,
                file: filePath,
                line_start: node.loc.start.line,
                line_end: node.loc.end.line,
                language: lang,
                language_pack: PACK_VERSION,
                message: `Trivial assertion \`expect(${expectArg.raw}).${method.name}(${arg.raw})\` always passes -- this tests nothing.`,
                remediation: 'Replace with a meaningful assertion that tests actual behavior: `expect(result).toBe(expectedValue)`.',
                effort: 'minutes',
                tool: 'ast-checker',
                rule_id: 'ts/assertion-roulette',
                references: ['https://testsmells.org/pages/testsmellexamples.html#AssertionRoulette'],
                tags: ['test_quality', 'test-smell'],
                detected_at: now,
            });
        }
    });
    return findings;
}
function checkExcessiveMocking(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    // Only check test files
    const basename = path.basename(filePath);
    if (!basename.includes('.test.') && !basename.includes('.spec.') && !basename.includes('__tests__')) {
        return findings;
    }
    let mockCount = 0;
    const mockLocations = [];
    walkAST(ast, (node) => {
        if (node.type !== typescript_estree_1.AST_NODE_TYPES.CallExpression)
            return;
        const callee = node.callee;
        // jest.mock('...')
        if (callee.type === typescript_estree_1.AST_NODE_TYPES.MemberExpression &&
            callee.object.type === typescript_estree_1.AST_NODE_TYPES.Identifier &&
            callee.object.name === 'jest' &&
            callee.property.type === typescript_estree_1.AST_NODE_TYPES.Identifier &&
            callee.property.name === 'mock') {
            mockCount++;
            mockLocations.push(node.loc.start.line);
        }
    });
    if (mockCount > 5) {
        findings.push({
            id: makeId(),
            antipattern: 'excessive_mocking',
            antipattern_name: 'Excessive Mocking',
            category: 'test_quality',
            severity: 'medium',
            confidence: 0.85,
            file: filePath,
            line_start: mockLocations[0] ?? 1,
            line_end: mockLocations[mockLocations.length - 1] ?? 1,
            language: lang,
            language_pack: PACK_VERSION,
            message: `Test file has ${mockCount} jest.mock() calls. Excessive mocking makes tests brittle and tightly coupled to implementation details.`,
            remediation: 'Reduce mocking by: (1) testing through public APIs, (2) using dependency injection, (3) splitting the module under test into smaller units.',
            effort: 'hours',
            tool: 'ast-checker',
            rule_id: 'ts/excessive-mocking',
            references: ['https://kentcdodds.com/blog/testing-implementation-details'],
            tags: ['test_quality', 'test-smell'],
            detected_at: now,
        });
    }
    return findings;
}
function checkGodClass(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    walkAST(ast, (node) => {
        if (node.type !== typescript_estree_1.AST_NODE_TYPES.ClassDeclaration && node.type !== typescript_estree_1.AST_NODE_TYPES.ClassExpression)
            return;
        const classNode = node;
        const methods = classNode.body.body.filter(m => m.type === typescript_estree_1.AST_NODE_TYPES.MethodDefinition || m.type === typescript_estree_1.AST_NODE_TYPES.PropertyDefinition);
        const methodCount = methods.filter(m => m.type === typescript_estree_1.AST_NODE_TYPES.MethodDefinition).length;
        if (methodCount > 15) {
            const className = classNode.id?.name ?? '<anonymous>';
            findings.push({
                id: makeId(),
                antipattern: 'god_class',
                antipattern_name: 'God Class',
                category: 'code_structure',
                severity: methodCount > 30 ? 'high' : 'medium',
                confidence: 0.85,
                file: filePath,
                line_start: node.loc.start.line,
                line_end: node.loc.end.line,
                language: lang,
                language_pack: PACK_VERSION,
                message: `Class '${className}' has ${methodCount} methods. Large classes are hard to understand and test.`,
                remediation: `Decompose '${className}' into smaller classes with single responsibilities. Consider extracting groups of related methods into separate classes.`,
                effort: 'days',
                tool: 'ast-checker',
                rule_id: 'ts/god-class',
                references: ['https://refactoring.guru/smells/large-class'],
                tags: ['maintainability', 'srp'],
                detected_at: now,
            });
        }
    });
    return findings;
}
function checkAnyTypeAbuse(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    // Skip .js files -- they don't have type annotations
    if (lang === 'javascript')
        return findings;
    let anyCount = 0;
    const anyLocations = [];
    walkAST(ast, (node) => {
        // Explicit `: any` type annotation
        if (node.type === typescript_estree_1.AST_NODE_TYPES.TSAnyKeyword) {
            anyCount++;
            anyLocations.push(node.loc.start.line);
        }
    });
    if (anyCount > 5) {
        findings.push({
            id: makeId(),
            antipattern: 'any_type_abuse',
            antipattern_name: 'Excessive `any` Type Usage',
            category: 'code_structure',
            severity: anyCount > 15 ? 'high' : 'medium',
            confidence: 0.9,
            file: filePath,
            line_start: anyLocations[0] ?? 1,
            line_end: anyLocations[anyLocations.length - 1] ?? 1,
            language: lang,
            language_pack: PACK_VERSION,
            message: `File has ${anyCount} explicit \`any\` type annotations. This defeats TypeScript's type safety and hides bugs.`,
            remediation: 'Replace `any` with specific types, `unknown` (for truly unknown types), or generic type parameters. Use `any` only at FFI boundaries with untyped libraries.',
            effort: anyCount > 15 ? 'days' : 'hours',
            tool: 'ast-checker',
            rule_id: 'ts/any-type-abuse',
            references: ['https://www.typescriptlang.org/docs/handbook/2/types-from-types.html'],
            tags: ['type-safety', 'maintainability'],
            detected_at: now,
        });
    }
    return findings;
}
function checkTsIgnoreProliferation(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    // Scan source lines for @ts-ignore and @ts-expect-error comments
    let ignoreCount = 0;
    const ignoreLocations = [];
    for (let i = 0; i < sourceLines.length; i++) {
        const line = sourceLines[i];
        if (line.includes('@ts-ignore') || line.includes('@ts-expect-error')) {
            ignoreCount++;
            ignoreLocations.push(i + 1); // 1-indexed
        }
    }
    if (ignoreCount > 3) {
        findings.push({
            id: makeId(),
            antipattern: 'ts_ignore_proliferation',
            antipattern_name: '@ts-ignore Proliferation',
            category: 'code_structure',
            severity: ignoreCount > 10 ? 'high' : 'medium',
            confidence: 0.95,
            file: filePath,
            line_start: ignoreLocations[0] ?? 1,
            line_end: ignoreLocations[ignoreLocations.length - 1] ?? 1,
            language: lang,
            language_pack: PACK_VERSION,
            message: `File has ${ignoreCount} @ts-ignore/@ts-expect-error directives. Each one silences a type error that may indicate a real bug.`,
            remediation: 'Fix the underlying type errors instead of suppressing them. If suppression is truly needed, prefer @ts-expect-error (which fails when the error is fixed) over @ts-ignore.',
            effort: 'hours',
            tool: 'ast-checker',
            rule_id: 'ts/ts-ignore-proliferation',
            tags: ['type-safety', 'maintainability'],
            detected_at: now,
        });
    }
    return findings;
}
function checkCallbackHell(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    // Detect deeply nested callbacks: function expressions or arrow functions
    // passed as arguments to calls, nested >3 levels deep.
    const CALLBACK_TYPES = new Set([
        typescript_estree_1.AST_NODE_TYPES.FunctionExpression,
        typescript_estree_1.AST_NODE_TYPES.ArrowFunctionExpression,
    ]);
    walkAST(ast, (node, ancestors) => {
        if (!CALLBACK_TYPES.has(node.type))
            return;
        // Count how many ancestor callbacks this is nested within
        let callbackDepth = 0;
        for (const ancestor of ancestors) {
            if (CALLBACK_TYPES.has(ancestor.type)) {
                // Only count if the ancestor was passed as a call argument
                const parent = ancestors[ancestors.indexOf(ancestor) - 1];
                if (parent?.type === typescript_estree_1.AST_NODE_TYPES.CallExpression) {
                    callbackDepth++;
                }
            }
        }
        if (callbackDepth >= 3) {
            findings.push({
                id: makeId(),
                antipattern: 'callback_hell',
                antipattern_name: 'Callback Hell',
                category: 'code_structure',
                severity: callbackDepth >= 5 ? 'high' : 'medium',
                confidence: 0.85,
                file: filePath,
                line_start: node.loc.start.line,
                line_end: node.loc.end.line,
                language: lang,
                language_pack: PACK_VERSION,
                message: `Callback nested ${callbackDepth} levels deep. Deeply nested callbacks make code hard to read, debug, and test.`,
                remediation: 'Refactor using async/await, Promise chains, or extract named functions to flatten the nesting.',
                effort: 'hours',
                tool: 'ast-checker',
                rule_id: 'ts/callback-hell',
                references: ['http://callbackhell.com/'],
                tags: ['readability', 'maintainability', 'async'],
                detected_at: now,
            });
        }
    });
    return findings;
}
function checkPromiseNoCatch(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    const isTestFile = filePath.includes('.test.') || filePath.includes('.spec.');
    if (isTestFile)
        return findings;
    walkAST(ast, (node) => {
        // .then() without .catch() in the same chain
        if (node.type !== typescript_estree_1.AST_NODE_TYPES.CallExpression)
            return;
        if (node.callee.type !== typescript_estree_1.AST_NODE_TYPES.MemberExpression)
            return;
        const method = node.callee.property;
        if (method.type !== typescript_estree_1.AST_NODE_TYPES.Identifier || method.name !== 'then')
            return;
        // Walk up to see if .catch() follows in the chain
        // Check: is the result of .then() immediately followed by .catch()?
        // We can't easily check the full chain from inside, so we check if
        // .then() is the terminal call (not chained further with .catch)
        // Heuristic: if .then() is a standalone expression statement, it's unguarded
        // We flag it with moderate confidence since the catch might be elsewhere
        findings.push({
            id: makeId(),
            antipattern: 'promise_no_catch',
            antipattern_name: 'Unhandled Promise',
            category: 'code_structure',
            severity: 'medium',
            confidence: 0.75,
            file: filePath,
            line_start: node.loc.start.line,
            line_end: node.loc.end.line,
            language: lang,
            language_pack: PACK_VERSION,
            message: '.then() without .catch() -- unhandled promise rejections crash Node.js processes.',
            remediation: 'Add .catch(err => ...) to the promise chain, or use async/await with try/catch.',
            effort: 'minutes',
            tool: 'ast-checker',
            rule_id: 'ts/promise-no-catch',
            references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/catch'],
            tags: ['async', 'reliability'],
            detected_at: now,
        });
    });
    return findings;
}
function checkConsoleLogLeft(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    // Skip test files and config files
    const basename = path.basename(filePath);
    if (basename.includes('.test.') || basename.includes('.spec.') ||
        basename.includes('config') || basename.includes('.config.')) {
        return findings;
    }
    let consoleCount = 0;
    const consoleLocations = [];
    walkAST(ast, (node) => {
        if (node.type !== typescript_estree_1.AST_NODE_TYPES.CallExpression)
            return;
        if (node.callee.type !== typescript_estree_1.AST_NODE_TYPES.MemberExpression)
            return;
        const obj = node.callee.object;
        const prop = node.callee.property;
        if (obj.type !== typescript_estree_1.AST_NODE_TYPES.Identifier || obj.name !== 'console')
            return;
        if (prop.type !== typescript_estree_1.AST_NODE_TYPES.Identifier)
            return;
        if (['log', 'debug', 'info', 'warn', 'error', 'trace'].includes(prop.name)) {
            consoleCount++;
            consoleLocations.push(node.loc.start.line);
        }
    });
    if (consoleCount > 3) {
        findings.push({
            id: makeId(),
            antipattern: 'console_log_left',
            antipattern_name: 'Console Logging Left in Code',
            category: 'code_structure',
            severity: 'low',
            confidence: 0.8,
            file: filePath,
            line_start: consoleLocations[0] ?? 1,
            line_end: consoleLocations[consoleLocations.length - 1] ?? 1,
            language: lang,
            language_pack: PACK_VERSION,
            message: `File has ${consoleCount} console.log/debug/warn calls. Console output in production code leaks internal state and impacts performance.`,
            remediation: 'Remove console calls or replace with a proper logging library that supports log levels and structured output.',
            effort: 'minutes',
            tool: 'ast-checker',
            rule_id: 'ts/console-log-left',
            tags: ['cleanup', 'production'],
            detected_at: now,
        });
    }
    return findings;
}
function checkNonNullAssertion(ast, filePath, sourceLines) {
    const findings = [];
    const now = new Date().toISOString();
    const lang = inferLang(filePath);
    if (lang === 'javascript')
        return findings; // JS doesn't have !
    let assertionCount = 0;
    const locations = [];
    walkAST(ast, (node) => {
        if (node.type === typescript_estree_1.AST_NODE_TYPES.TSNonNullExpression) {
            assertionCount++;
            locations.push(node.loc.start.line);
        }
    });
    if (assertionCount > 5) {
        findings.push({
            id: makeId(),
            antipattern: 'non_null_assertion',
            antipattern_name: 'Excessive Non-Null Assertions',
            category: 'code_structure',
            severity: assertionCount > 10 ? 'high' : 'medium',
            confidence: 0.85,
            file: filePath,
            line_start: locations[0] ?? 1,
            line_end: locations[locations.length - 1] ?? 1,
            language: lang,
            language_pack: PACK_VERSION,
            message: `File has ${assertionCount} non-null assertion operators (!). Each one silences a potential null/undefined error that TypeScript would otherwise catch.`,
            remediation: 'Replace ! with proper null checks: optional chaining (?.), nullish coalescing (??), or type narrowing with if guards.',
            effort: 'hours',
            tool: 'ast-checker',
            rule_id: 'ts/non-null-assertion',
            references: ['https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#non-null-assertion-operator-postfix-'],
            tags: ['type-safety', 'maintainability'],
            detected_at: now,
        });
    }
    return findings;
}
// -----------------------------------------------------------------------------
// AST Walking Utility
// -----------------------------------------------------------------------------
function walkAST(node, visitor, ancestors = []) {
    visitor(node, ancestors);
    const nextAncestors = [...ancestors, node];
    for (const key of Object.keys(node)) {
        if (key === 'parent')
            continue;
        const val = node[key];
        if (val && typeof val === 'object') {
            if (Array.isArray(val)) {
                for (const child of val) {
                    if (child && typeof child.type === 'string') {
                        walkAST(child, visitor, nextAncestors);
                    }
                }
            }
            else if (val.type) {
                walkAST(val, visitor, nextAncestors);
            }
        }
    }
}
function getFunctionName(node) {
    if ('id' in node && node.id?.name)
        return node.id.name;
    if ('key' in node && node.key?.name)
        return node.key.name;
    return '<anonymous>';
}
// -----------------------------------------------------------------------------
// File Scanner
// -----------------------------------------------------------------------------
function scanFile(filePath, repoRoot) {
    let source;
    try {
        source = fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return [];
    }
    const relPath = path.relative(repoRoot, filePath);
    const sourceLines = source.split('\n');
    let ast;
    try {
        ast = (0, typescript_estree_1.parse)(source, {
            loc: true,
            range: true,
            jsx: true,
            comment: false,
        });
    }
    catch {
        return [];
    }
    return [
        ...checkDeepNesting(ast, relPath, sourceLines),
        ...checkMagicNumbers(ast, relPath, sourceLines),
        ...checkAssertionRoulette(ast, relPath, sourceLines),
        ...checkExcessiveMocking(ast, relPath, sourceLines),
        ...checkGodClass(ast, relPath, sourceLines),
        ...checkAnyTypeAbuse(ast, relPath, sourceLines),
        ...checkTsIgnoreProliferation(ast, relPath, sourceLines),
        ...checkCallbackHell(ast, relPath, sourceLines),
        ...checkPromiseNoCatch(ast, relPath, sourceLines),
        ...checkConsoleLogLeft(ast, relPath, sourceLines),
        ...checkNonNullAssertion(ast, relPath, sourceLines),
    ];
}
function scanDirectory(root, ignorePrefixes) {
    const findings = [];
    function walk(dir) {
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        }
        catch {
            return;
        }
        for (const entry of entries) {
            if (entry.isDirectory()) {
                if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.'))
                    continue;
                const rel = path.relative(root, path.join(dir, entry.name));
                if (ignorePrefixes.some(p => rel.startsWith(p)))
                    continue;
                walk(path.join(dir, entry.name));
            }
            else if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                if (!JS_TS_EXTENSIONS.has(ext))
                    continue;
                findings.push(...scanFile(path.join(dir, entry.name), root));
            }
        }
    }
    walk(root);
    return findings;
}
// -----------------------------------------------------------------------------
// CLI Entrypoint
// -----------------------------------------------------------------------------
function main() {
    const args = process.argv.slice(2);
    const rootPath = args[0];
    if (!rootPath) {
        console.error('Usage: ast_checks <path> [--output <file>] [--ignore <prefixes>]');
        process.exit(1);
    }
    let outputPath = '/tmp/ts_ast_findings.json';
    let ignorePrefixes = [];
    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--output' && args[i + 1]) {
            outputPath = args[++i];
        }
        else if (args[i] === '--ignore' && args[i + 1]) {
            ignorePrefixes = args[++i].split(',').filter(Boolean);
        }
    }
    const findings = scanDirectory(rootPath, ignorePrefixes);
    const result = { findings, count: findings.length };
    fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
    console.log(`TS/JS AST checker found ${findings.length} findings -> ${outputPath}`);
}
main();
