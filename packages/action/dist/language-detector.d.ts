export interface DetectedLanguage {
    language: string;
    fileCount: number;
    packAvailable: boolean;
}
export declare function detectLanguages(rootPath: string, ignorePaths: string[]): Promise<DetectedLanguage[]>;
