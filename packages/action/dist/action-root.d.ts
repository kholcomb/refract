/**
 * Returns the root directory of the action.
 *
 * In a GitHub Actions runner, GITHUB_ACTION_PATH points to the action root.
 * Locally or in tests, fall back to __dirname-based resolution (assumes
 * we're running from src/ or dist/ one level below root).
 */
export declare function getActionRoot(): string;
