import { spawnSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { devNull, tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  captureDiffEvidence,
  changedFiles,
  emptyTree,
  GIT_NULL_DEVICE,
  head,
  parseNameStatusZ,
  parseNumstatZ,
  parseStatusZ,
} from '../src/git.js'
import { materializeIndexSnapshot, materializeTreeSnapshot, materializeWorkingTreeSnapshot } from '../src/git-snapshot.js'

const cleanup: string[] = []

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'codetruss-git-test-'))
  cleanup.push(root)
  git(root, 'init', '--quiet')
  git(root, 'config', 'user.name', 'CodeTruss Test')
  git(root, 'config', 'user.email', 'test@codetruss.invalid')
  return root
}

function git(root: string, ...args: string[]): string {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' })
  if (result.status !== 0) throw new Error(`${args.join(' ')} failed: ${result.stderr}`)
  return result.stdout
}

const classify = () => 'allowed' as const
const noSensitive = () => undefined
const dependency = (path: string) => path.endsWith('package-lock.json')

describe('Git evidence parsing', () => {
  it('preserves tabs/newlines and rename paths in NUL-delimited output', () => {
    expect(parseStatusZ(Buffer.from('R  new\nname.ts\0old\tname.ts\0?? loose\tfile.ts\0'))).toEqual([
      { indexStatus: 'R', worktreeStatus: ' ', path: 'new\nname.ts', oldPath: 'old\tname.ts', untracked: false },
      { indexStatus: '?', worktreeStatus: '?', path: 'loose\tfile.ts', untracked: true },
    ])
    expect(parseNameStatusZ(Buffer.from('R100\0old\tname.ts\0new\nname.ts\0'))).toEqual([
      { status: 'R100', oldPath: 'old\tname.ts', path: 'new\nname.ts' },
    ])
    expect(parseNumstatZ(Buffer.from('2\t1\tfile\tname.ts\0-\t-\tbinary.bin\0'))).toEqual(new Map([
      ['file\tname.ts', { additions: 2, deletions: 1, binary: false }],
      ['binary.bin', { additions: 0, deletions: 0, binary: true }],
    ]))
  })

  it('parses rename numstat destination records', () => {
    expect(parseNumstatZ(Buffer.from('0\t0\t\0old/name.ts\0new/name.ts\0'))).toEqual(new Map([
      ['new/name.ts', { additions: 0, deletions: 0, binary: false }],
    ]))
  })
})

describe('repository evidence', () => {
  it('uses Node\'s platform-specific null device for untracked no-index diffs', () => {
    expect(GIT_NULL_DEVICE).toBe(devNull)
  })

  it('uses an explicit empty tree for unborn and first-commit sessions', async () => {
    const root = await repository()
    expect(head(root)).toBe('')
    const base = emptyTree(root)
    expect(base).toMatch(/^[0-9a-f]{40,64}$/)
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'first.ts'), 'export const first = true\n')
    git(root, 'add', '.')

    const staged = await changedFiles(root, 'HEAD', true, classify, noSensitive, dependency)
    expect(staged).toMatchObject([{ path: 'src/first.ts', change: 'added', additions: 1 }])

    git(root, 'commit', '--quiet', '-m', 'first')
    const committed = await changedFiles(root, base, false, classify, noSensitive, dependency)
    expect(committed).toMatchObject([{ path: 'src/first.ts', change: 'added', additions: 1 }])
  })

  it.runIf(process.platform !== 'win32')('keeps unusual paths and rename stats exact', async () => {
    const root = await repository()
    const oldPath = 'old\tname.ts'
    const newPath = 'new\nname.ts'
    await writeFile(join(root, oldPath), 'line one\nline two\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, oldPath), 'line one\nline two\nline three\n')
    await (await import('node:fs/promises')).rename(join(root, oldPath), join(root, newPath))
    git(root, 'add', '-A')

    const files = await changedFiles(root, 'HEAD', true, classify, noSensitive, dependency)
    expect(files).toHaveLength(1)
    expect(files[0]).toMatchObject({
      path: newPath,
      oldPath,
      change: 'renamed',
      additions: 1,
      deletions: 0,
    })
  })

  it('streams and reports a bounded diff instead of silently truncating it', async () => {
    const root = await repository()
    await writeFile(join(root, 'large.txt'), '')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'large.txt'), 'A'.repeat(256 * 1024))
    const files = await changedFiles(root, 'HEAD', false, classify, noSensitive, dependency)
    const evidence = await captureDiffEvidence(root, 'HEAD', false, files, { maxCapturedBytes: 8 * 1024 })
    expect(evidence.patch).toHaveLength(8 * 1024)
    expect(evidence.capturedBytes).toBe(8 * 1024)
    expect(evidence.totalBytes).toBeGreaterThan(evidence.capturedBytes)
    expect(evidence.truncated).toBe(true)
  })

  it('captures untracked text and empty files as explicit patch evidence', async () => {
    const root = await repository()
    await writeFile(join(root, 'README.md'), 'baseline\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'untracked.txt'), 'new line\n')
    await writeFile(join(root, 'empty.txt'), '')
    const files = await changedFiles(root, 'HEAD', false, classify, noSensitive, dependency)
    const evidence = await captureDiffEvidence(root, 'HEAD', false, files)
    const patch = evidence.patch.toString('utf8')
    expect(patch).toContain('untracked.txt')
    expect(patch).toContain('+new line')
    expect(patch).toContain('empty.txt')
    expect(evidence.truncated).toBe(false)
    expect(evidence.totalBytes).toBe(evidence.capturedBytes)
  })

  it('surfaces an invalid diff base instead of treating it as an empty diff', async () => {
    const root = await repository()
    await writeFile(join(root, 'README.md'), 'baseline\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await expect(changedFiles(root, 'definitely-not-a-revision', false, classify, noSensitive, dependency)).rejects.toThrow('failed')
  })
})

describe('materialized snapshots', () => {
  it('materializes the exact index while leaving unstaged content out', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'a.ts'), 'export const value = "baseline"\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'src', 'a.ts'), 'export const value = "staged"\n')
    git(root, 'add', 'src/a.ts')
    await writeFile(join(root, 'src', 'a.ts'), 'export const value = "working"\n')

    const snapshot = await materializeIndexSnapshot(root)
    try {
      expect(await readFile(join(snapshot.root, 'src', 'a.ts'), 'utf8')).toBe('export const value = "staged"\n')
      expect(await readFile(join(root, 'src', 'a.ts'), 'utf8')).toBe('export const value = "working"\n')
    } finally {
      await snapshot.cleanup()
    }
  })

  it('materializes the empty tree for an unborn HEAD', async () => {
    const root = await repository()
    await writeFile(join(root, 'untracked.txt'), 'not in HEAD\n')
    const snapshot = await materializeTreeSnapshot(root, 'HEAD')
    try {
      await expect(readFile(join(snapshot.root, 'untracked.txt'))).rejects.toMatchObject({ code: 'ENOENT' })
      expect(snapshot.tree).toBe(emptyTree(root))
    } finally {
      await snapshot.cleanup()
    }
  })

  it('materializes the exact Git-visible working state and excludes local evidence', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, '.gitignore'), 'ignored.txt\n')
    await writeFile(join(root, 'src', 'mixed.ts'), 'baseline\n')
    await writeFile(join(root, 'src', 'deleted.ts'), 'delete me\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')

    await writeFile(join(root, 'src', 'mixed.ts'), 'staged\n')
    git(root, 'add', 'src/mixed.ts')
    await writeFile(join(root, 'src', 'mixed.ts'), 'working\n')
    await rm(join(root, 'src', 'deleted.ts'))
    await writeFile(join(root, 'untracked.txt'), 'untracked\n')
    await writeFile(join(root, 'ignored.txt'), 'ignored\n')
    await mkdir(join(root, '.codetruss'), { recursive: true })
    await writeFile(join(root, '.codetruss', 'receipt.json'), '{"verdict":"PASS"}\n')

    const snapshot = await materializeWorkingTreeSnapshot(root)
    try {
      expect(snapshot.source).toBe('working')
      expect(snapshot.tree).toBeNull()
      expect(await readFile(join(snapshot.root, 'src', 'mixed.ts'), 'utf8')).toBe('working\n')
      expect(await readFile(join(snapshot.root, 'untracked.txt'), 'utf8')).toBe('untracked\n')
      await expect(readFile(join(snapshot.root, 'src', 'deleted.ts'))).rejects.toMatchObject({ code: 'ENOENT' })
      await expect(readFile(join(snapshot.root, 'ignored.txt'))).rejects.toMatchObject({ code: 'ENOENT' })
      await expect(readFile(join(snapshot.root, '.codetruss', 'receipt.json'))).rejects.toMatchObject({ code: 'ENOENT' })
    } finally {
      await snapshot.cleanup()
    }
  })
})
