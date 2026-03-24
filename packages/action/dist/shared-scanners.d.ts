import { Finding } from '@refract/core';
/**
 * Run gitleaks once globally, cache results, and return findings
 * filtered to the requested file extensions.
 */
export declare function runGitleaks(workspacePath: string, languagePack: string, languageLabel: string, fileExtensions: Set<string>): Promise<Finding[]>;
/**
 * Reset the gitleaks cache between scan runs or for testing.
 */
export declare function resetGitleaksCache(): void;
