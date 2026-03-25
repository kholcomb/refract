import * as path from 'path'
import * as fs from 'fs'

/**
 * Returns the root directory of the action (where language-packs/ lives).
 *
 * Resolution order:
 * 1. GITHUB_ACTION_PATH (set by the runner for the action's checkout)
 * 2. GITHUB_WORKSPACE (the repo checkout root — works with `uses: ./`)
 * 3. __dirname-based fallback (local dev / tests)
 */
export function getActionRoot(): string {
  // GITHUB_ACTION_PATH is the canonical location
  const actionPath = process.env.GITHUB_ACTION_PATH
  if (actionPath && fs.existsSync(path.join(actionPath, 'language-packs'))) {
    return actionPath
  }

  // For `uses: ./`, language-packs may be in the workspace root instead
  const workspace = process.env.GITHUB_WORKSPACE
  if (workspace && fs.existsSync(path.join(workspace, 'language-packs'))) {
    return workspace
  }

  // Local dev: __dirname is src/ or dist/ one level below packages/action/
  return actionPath ?? path.join(__dirname, '..')
}
