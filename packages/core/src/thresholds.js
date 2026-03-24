"use strict";
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
exports.loadThresholds = loadThresholds;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const action_root_1 = require("./action-root");
const DEFAULT_THRESHOLDS = {
    code_structure: {
        max_cyclomatic_complexity: 10,
        max_function_length: 50,
        max_nesting_depth: 4,
        god_class_method_count: 20,
        god_class_total_lines: 500,
        magic_number_allowed: [0, 1, -1, 2, 100],
    },
    test_quality: {
        min_coverage_percent: 50,
        max_mock_calls: 5,
    },
    security: {
        bandit_severity_level: 'medium',
    },
};
/**
 * Load thresholds for a language pack, merging:
 * 1. Built-in defaults
 * 2. Language pack config (language-packs/<lang>/config/thresholds.yml)
 * 3. Repo-level overrides (.antipattern-thresholds.yml in workspace root)
 *
 * Uses a simple YAML subset parser (key: value) to avoid adding a yaml dependency.
 */
function loadThresholds(language, workspacePath) {
    const result = structuredClone(DEFAULT_THRESHOLDS);
    // Load language pack defaults
    const packConfigPath = path.join((0, action_root_1.getActionRoot)(), 'language-packs', language, 'config', 'thresholds.yml');
    mergeFromYaml(result, packConfigPath);
    // Load repo-level overrides
    if (workspacePath) {
        const repoConfigPath = path.join(workspacePath, '.antipattern-thresholds.yml');
        mergeFromYaml(result, repoConfigPath);
    }
    return result;
}
function mergeFromYaml(target, filePath) {
    if (!fs.existsSync(filePath))
        return;
    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed = parseSimpleYaml(content);
    for (const [section, values] of Object.entries(parsed)) {
        if (section in target) {
            Object.assign(target[section], values);
        }
    }
}
/**
 * Minimal YAML parser for flat key-value sections.
 * Handles: section headers, numeric values, string values, arrays on single line.
 * Does NOT handle nested objects, multi-line strings, or anchors.
 */
function parseSimpleYaml(content) {
    const result = {};
    let currentSection = '';
    for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#'))
            continue;
        // Section header (no leading whitespace, ends with colon)
        if (!line.startsWith(' ') && !line.startsWith('\t') && trimmed.endsWith(':')) {
            currentSection = trimmed.slice(0, -1);
            result[currentSection] = result[currentSection] ?? {};
            continue;
        }
        // Key-value pair (indented)
        const match = trimmed.match(/^(\w+):\s*(.+)$/);
        if (match && currentSection) {
            const [, key, rawValue] = match;
            result[currentSection][key] = parseYamlValue(rawValue);
        }
    }
    return result;
}
function parseYamlValue(raw) {
    const trimmed = raw.trim();
    // Array: [1, 2, 3]
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        return trimmed.slice(1, -1).split(',').map(s => parseYamlValue(s.trim()));
    }
    // Number
    if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
        return Number(trimmed);
    }
    // Boolean
    if (trimmed === 'true')
        return true;
    if (trimmed === 'false')
        return false;
    // String
    return trimmed;
}
//# sourceMappingURL=thresholds.js.map