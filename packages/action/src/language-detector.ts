import * as fs from 'fs'
import * as path from 'path'

export interface DetectedLanguage {
  language: string
  fileCount: number
  packAvailable: boolean
}

const EXTENSION_MAP: Record<string, string> = {
  '.py': 'python',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.go': 'go',
  '.rs': 'rust',
  '.java': 'java',
  '.rb': 'ruby',
  '.php': 'php',
  '.cs': 'csharp',
  '.swift': 'swift',
  '.kt': 'kotlin',
}

const AVAILABLE_PACKS = new Set(['python', 'typescript', 'javascript'])

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.venv', 'venv', 'env', '__pycache__',
  'dist', 'build', '.tox', '.mypy_cache', '.next', 'coverage',
  'vendor', '.cache', '.terraform',
])

export async function detectLanguages(
  rootPath: string,
  ignorePaths: string[]
): Promise<DetectedLanguage[]> {
  const counts: Record<string, number> = {}

  function walk(dir: string): void {
    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue
        const rel = path.relative(rootPath, path.join(dir, entry.name))
        if (ignorePaths.some(p => rel.startsWith(p))) continue
        walk(path.join(dir, entry.name))
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase()
        const lang = EXTENSION_MAP[ext]
        if (lang) {
          counts[lang] = (counts[lang] ?? 0) + 1
        }
      }
    }
  }

  walk(rootPath)

  return Object.entries(counts)
    .filter(([, count]) => count >= 1)
    .sort(([, a], [, b]) => b - a)
    .map(([language, fileCount]) => ({
      language,
      fileCount,
      packAvailable: AVAILABLE_PACKS.has(language),
    }))
}
