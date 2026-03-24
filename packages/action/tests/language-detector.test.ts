import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { detectLanguages } from '../src/language-detector'

describe('detectLanguages', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lang-detect-'))
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  function touch(relPath: string): void {
    const full = path.join(tmpDir, relPath)
    fs.mkdirSync(path.dirname(full), { recursive: true })
    fs.writeFileSync(full, '')
  }

  it('should detect Python files', async () => {
    touch('src/app.py')
    touch('src/utils.py')
    const result = await detectLanguages(tmpDir, [])
    expect(result).toEqual([
      { language: 'python', fileCount: 2, packAvailable: true },
    ])
  })

  it('should detect multiple languages sorted by count', async () => {
    touch('a.py')
    touch('b.py')
    touch('c.py')
    touch('d.ts')
    const result = await detectLanguages(tmpDir, [])
    expect(result[0].language).toBe('python')
    expect(result[0].fileCount).toBe(3)
    expect(result[1].language).toBe('typescript')
    expect(result[1].fileCount).toBe(1)
  })

  it('should skip node_modules', async () => {
    touch('node_modules/pkg/index.js')
    touch('src/app.ts')
    const result = await detectLanguages(tmpDir, [])
    expect(result).toEqual([
      { language: 'typescript', fileCount: 1, packAvailable: true },
    ])
  })

  it('should skip ignored paths', async () => {
    touch('vendor/lib.py')
    touch('src/app.py')
    const result = await detectLanguages(tmpDir, ['vendor'])
    expect(result).toHaveLength(1)
    expect(result[0].fileCount).toBe(1)
  })

  it('should mark languages without packs as unavailable', async () => {
    touch('main.go')
    const result = await detectLanguages(tmpDir, [])
    expect(result[0].packAvailable).toBe(false)
  })

  it('should return empty array for empty directory', async () => {
    const result = await detectLanguages(tmpDir, [])
    expect(result).toEqual([])
  })

  it('should detect TypeScript and JavaScript as having packs', async () => {
    touch('app.ts')
    touch('util.js')
    const result = await detectLanguages(tmpDir, [])
    expect(result.every(r => r.packAvailable)).toBe(true)
  })
})
