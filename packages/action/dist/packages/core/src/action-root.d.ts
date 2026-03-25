/**
 * Returns the root directory of the action (where language-packs/ lives).
 *
 * Resolution order:
 * 1. GITHUB_ACTION_PATH (set by the runner for the action's checkout)
 * 2. GITHUB_WORKSPACE (the repo checkout root — works with `uses: ./`)
 * 3. __dirname-based fallback (local dev / tests)
 */
export declare function getActionRoot(): string;
//# sourceMappingURL=action-root.d.ts.map