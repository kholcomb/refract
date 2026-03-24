import { Finding, Severity } from './types';
export declare const SEVERITY_ORDER: Severity[];
export declare function bySeverity(a: Finding, b: Finding): number;
export declare function severityAtOrAbove(severity: Severity, threshold: Severity): boolean;
//# sourceMappingURL=severity.d.ts.map