/**
 * Unified Finding Schema
 *
 * Every finding — regardless of source tool, language, or category —
 * is normalized into this shape before any output is produced.
 * This is the contract that downstream AI agents and issue trackers consume.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type EffortEstimate = 'minutes' | 'hours' | 'days' | 'weeks';
export type AntipatternCategory = 'code_structure' | 'security' | 'dependencies' | 'test_quality' | 'concurrency' | 'api_design' | 'documentation';
export type AntipatternId = 'god_class' | 'long_method' | 'high_cyclomatic_complexity' | 'duplicate_code' | 'dead_code' | 'feature_envy' | 'data_clump' | 'primitive_obsession' | 'deep_nesting' | 'magic_number' | 'magic_string' | 'hardcoded_secret' | 'sql_injection_vector' | 'shell_injection_vector' | 'insecure_deserialization' | 'weak_cryptography' | 'error_info_exposure' | 'path_traversal' | 'open_redirect' | 'vulnerable_dependency' | 'outdated_dependency' | 'unused_dependency' | 'dependency_bloat' | 'missing_test_coverage' | 'test_interdependence' | 'excessive_mocking' | 'assertion_roulette' | 'mystery_guest' | 'mutable_default_argument' | 'bare_except' | 'exception_sink' | 'implicit_string_concat' | 'wildcard_import' | 'circular_import' | 'n_plus_one_query' | 'any_type_abuse' | 'ts_ignore_proliferation' | 'callback_hell' | string;
export interface Finding {
    /** Unique identifier for this specific finding instance */
    id: string;
    /** Which anti-pattern this is */
    antipattern: AntipatternId;
    /** Human-readable name */
    antipattern_name: string;
    /** Broad category for grouping and filtering */
    category: AntipatternCategory;
    /** How bad is this */
    severity: Severity;
    /**
     * Confidence score 0.0–1.0.
     * 1.0 = deterministic (e.g. exact regex match on a secret)
     * 0.5 = heuristic (e.g. class is probably a god class)
     */
    confidence: number;
    /** Relative path from repo root */
    file: string;
    /** 1-indexed start line */
    line_start: number;
    /** 1-indexed end line (same as line_start for single-line findings) */
    line_end: number;
    /** Optional column for precise positioning */
    column?: number;
    /** The language this finding applies to */
    language: string;
    /** Which language pack version detected this */
    language_pack: string;
    /** Short description of the problem */
    message: string;
    /** Actionable remediation hint — this is what AI agents will act on */
    remediation: string;
    /**
     * Rough effort to fix.
     * Used to prioritize issue backlogs.
     */
    effort: EffortEstimate;
    /** The underlying tool that produced this finding */
    tool: string;
    /** The specific rule ID within the tool */
    rule_id: string;
    /**
     * Optional: the offending code snippet (max 10 lines).
     * Populated when available to give context in issue bodies.
     */
    code_snippet?: string;
    /**
     * Optional: links to docs, CWE entries, etc.
     */
    references?: string[];
    /**
     * Tags for filtering, e.g. ['owasp-a03', 'pci-dss']
     */
    tags?: string[];
    /** ISO timestamp of when this finding was detected */
    detected_at: string;
}
export interface ScanResult {
    /** Repo and run metadata */
    meta: ScanMeta;
    /** All normalized findings */
    findings: Finding[];
    /** Aggregated counts by severity */
    summary: ScanSummary;
}
export interface ScanMeta {
    repo: string;
    sha: string;
    ref: string;
    run_id: string;
    run_number: string;
    actor: string;
    event: string;
    languages_detected: string[];
    language_packs_used: string[];
    categories_scanned: AntipatternCategory[];
    scan_duration_ms: number;
    scanned_at: string;
}
export interface ScanSummary {
    total: number;
    by_severity: Record<Severity, number>;
    by_category: Record<AntipatternCategory, number>;
    by_language: Record<string, number>;
    files_affected: number;
}
//# sourceMappingURL=types.d.ts.map