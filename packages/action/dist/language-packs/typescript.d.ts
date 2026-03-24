import { Finding, AntipatternCategory } from '@refract/core';
export interface TypeScriptScanOptions {
    workspacePath: string;
    categories: AntipatternCategory[];
    confidenceThreshold: number;
    ignorePaths: string[];
}
export declare function scanTypeScript(options: TypeScriptScanOptions): Promise<Finding[]>;
//# sourceMappingURL=typescript.d.ts.map