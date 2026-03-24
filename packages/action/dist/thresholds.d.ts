export interface CodeStructureThresholds {
    max_cyclomatic_complexity: number;
    max_function_length: number;
    max_nesting_depth: number;
    god_class_method_count: number;
    god_class_total_lines: number;
    god_class_lizard_method_count?: number;
    god_class_lizard_total_lines?: number;
    magic_number_allowed: number[];
}
export interface TestQualityThresholds {
    min_coverage_percent?: number;
    max_mock_calls?: number;
}
export interface SecurityThresholds {
    bandit_severity_level?: string;
}
export interface Thresholds {
    code_structure: CodeStructureThresholds;
    test_quality: TestQualityThresholds;
    security: SecurityThresholds;
}
/**
 * Load thresholds for a language pack, merging:
 * 1. Built-in defaults
 * 2. Language pack config (language-packs/<lang>/config/thresholds.yml)
 * 3. Repo-level overrides (.antipattern-thresholds.yml in workspace root)
 *
 * Uses a simple YAML subset parser (key: value) to avoid adding a yaml dependency.
 */
export declare function loadThresholds(language: string, workspacePath?: string): Thresholds;
