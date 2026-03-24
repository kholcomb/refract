import { Finding, AntipatternCategory } from '@refract/core';
export interface PythonScanOptions {
    workspacePath: string;
    categories: AntipatternCategory[];
    confidenceThreshold: number;
    ignorePaths: string[];
}
export declare function scanPython(options: PythonScanOptions): Promise<Finding[]>;
//# sourceMappingURL=python.d.ts.map