import { Finding, ScanResult } from '@refract/core';
export declare class GitHubOutputter {
    private octokit;
    private context;
    private token;
    constructor(token: string);
    writeStepSummary(result: ScanResult): Promise<void>;
    createIssues(findings: Finding[], label: string, existingIssues?: Set<string>): Promise<number>;
    getExistingIssueTitles(label: string): Promise<Set<string>>;
    postPRComments(findings: Finding[]): Promise<void>;
    notifySlack(webhookUrl: string, result: ScanResult): Promise<void>;
    private ensureLabel;
}
export declare function buildIssueBody(findings: Finding[], rep: Finding): string;
export declare function buildPRCommentBody(f: Finding): string;
export declare function groupBy<T>(arr: T[], key: (t: T) => string): Record<string, T[]>;
export declare function formatCategory(cat: string): string;
export declare function truncate(s: string, len: number): string;
