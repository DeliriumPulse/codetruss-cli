import { spawnSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  ensureLocalEvidenceProtected,
  LOCAL_EVIDENCE_EXCLUDE_PATTERN,
} from '../src/local-evidence.js'

const cleanup: string[] = []

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function git(root: string, ...args: string[]): string {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' })
  if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(' ')} failed`)
  return result.stdout.trim()
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'codetruss-local-evidence-'))
  cleanup.push(root)
  git(root, 'init', '--quiet')
  git(root, 'config', 'user.name', 'CodeTruss Test')
  git(root, 'config', 'user.email', 'test@codetruss.invalid')
  await writeFile(join(root, 'README.md'), 'baseline\n')
  git(root, 'add', 'README.md')
  git(root, 'commit', '--quiet', '-m', 'baseline')
  return root
}

function excludePath(root: string): string {
  const raw = git(root, 'rev-parse', '--git-path', 'info/exclude')
  return resolve(isAbsolute(raw) ? raw : join(root, raw))
}

describe('local evidence Git protection', () => {
  it('adds one local exclude rule idempotently and keeps private evidence out of git add', async () => {
    const root = await repository()
    const first = await ensureLocalEvidenceProtected(root)
    const second = await ensureLocalEvidenceProtected(root)

    expect(first.changed).toBe(true)
    expect(second).toEqual({ excludePath: first.excludePath, changed: false })
    const exclude = await readFile(first.excludePath, 'utf8')
    expect(exclude.match(new RegExp(LOCAL_EVIDENCE_EXCLUDE_PATTERN.replaceAll('/', '\\/'), 'g'))).toHaveLength(1)

    await mkdir(join(root, '.codetruss', 'receipts'), { recursive: true })
    await writeFile(join(root, '.codetruss', 'receipts', 'private.patch'), 'private source diff\n')
    await writeFile(join(root, '.codetruss', 'receipts', 'private.json'), '{"task":"private"}\n')
    git(root, 'add', '.')

    expect(git(root, 'status', '--porcelain=v1')).toBe('')
    expect(git(root, 'check-ignore', '--no-index', '.codetruss/receipts/private.patch')).toBe(
      '.codetruss/receipts/private.patch',
    )
  })

  it('adds defense-in-depth local protection even when the repository already ignores evidence', async () => {
    const root = await repository()
    await writeFile(join(root, '.gitignore'), '/.codetruss/\n')
    git(root, 'add', '.gitignore')
    git(root, 'commit', '--quiet', '-m', 'ignore local evidence')
    const path = excludePath(root)
    const protection = await ensureLocalEvidenceProtected(root)

    expect(protection).toEqual({ excludePath: path, changed: true })
    expect(await readFile(path, 'utf8')).toContain(LOCAL_EVIDENCE_EXCLUDE_PATTERN)
  })

  it('fails closed when a higher-priority repository rule re-includes receipts', async () => {
    const root = await repository()
    await writeFile(join(root, '.gitignore'), [
      '!/.codetruss/',
      '!/.codetruss/receipts/',
      '!/.codetruss/receipts/**',
      '',
    ].join('\n'))

    await expect(ensureLocalEvidenceProtected(root)).rejects.toThrow(
      'is not excluded from Git; add /.codetruss/ after any .codetruss negations',
    )
  })

  it('fails closed when known receipt extensions are ignored but temporary receipt files are re-included', async () => {
    const root = await repository()
    await writeFile(join(root, '.gitignore'), [
      '!/.codetruss/',
      '/.codetruss/receipts/*.json',
      '/.codetruss/receipts/*.md',
      '/.codetruss/receipts/*.patch',
      '/.codetruss/receipts/*.sig',
      '/.codetruss/hooks/agent.cjs',
      '/.codetruss/snapshots/**',
      '!/.codetruss/receipts/*.tmp',
      '',
    ].join('\n'))

    await expect(ensureLocalEvidenceProtected(root)).rejects.toThrow('is not excluded from Git')
  })

  it('refuses to claim protection when .codetruss already contains tracked files', async () => {
    const root = await repository()
    await mkdir(join(root, '.codetruss', 'receipts'), { recursive: true })
    await writeFile(join(root, '.codetruss', 'receipts', 'exposed.patch'), 'already tracked\n')
    git(root, 'add', '-f', '.codetruss/receipts/exposed.patch')
    git(root, 'commit', '--quiet', '-m', 'tracked private evidence')

    await expect(ensureLocalEvidenceProtected(root)).rejects.toThrow(
      '.codetruss/ already contains 1 Git-tracked file',
    )
  })

  it('protects evidence created in a linked worktree', async () => {
    const root = await repository()
    const linked = `${root}-linked`
    cleanup.push(linked)
    git(root, 'worktree', 'add', '--quiet', '-b', 'linked-evidence-test', linked)

    await ensureLocalEvidenceProtected(linked)
    await mkdir(join(linked, '.codetruss', 'receipts'), { recursive: true })
    await writeFile(join(linked, '.codetruss', 'receipts', 'linked.patch'), 'linked private diff\n')
    git(linked, 'add', '.')

    expect(git(linked, 'status', '--porcelain=v1')).toBe('')
    expect(git(linked, 'check-ignore', '--no-index', '.codetruss/receipts/linked.patch')).toBe(
      '.codetruss/receipts/linked.patch',
    )
  })

  it.runIf(process.platform !== 'win32')('refuses a symlinked Git exclude file', async () => {
    const root = await repository()
    const path = excludePath(root)
    const outside = `${root}-outside-exclude`
    cleanup.push(outside)
    await writeFile(outside, '# outside\n')
    await rm(path, { force: true })
    await mkdir(dirname(path), { recursive: true })
    await symlink(outside, path)

    await expect(ensureLocalEvidenceProtected(root)).rejects.toThrow('non-regular Git exclude file')
    expect(await readFile(outside, 'utf8')).toBe('# outside\n')
  })

  it.runIf(process.platform !== 'win32')('refuses a symlinked private evidence subdirectory', async () => {
    const root = await repository()
    await ensureLocalEvidenceProtected(root)
    const outside = `${root}-outside-snapshots`
    cleanup.push(outside)
    await mkdir(outside)
    await rm(join(root, '.codetruss', 'snapshots'), { recursive: true, force: true })
    await symlink(outside, join(root, '.codetruss', 'snapshots'), 'dir')

    await expect(ensureLocalEvidenceProtected(root)).rejects.toThrow('refusing non-directory local evidence path')
  })

  it.runIf(process.platform !== 'win32')('refuses a Git exclude directory that resolves outside the common directory', async () => {
    const root = await repository()
    const path = excludePath(root)
    const info = dirname(path)
    const outside = `${root}-outside-info`
    cleanup.push(outside)
    await mkdir(outside)
    await writeFile(join(outside, 'exclude'), '# outside\n')
    await rm(info, { recursive: true, force: true })
    await symlink(outside, info, 'dir')

    await expect(ensureLocalEvidenceProtected(root)).rejects.toThrow(
      'refusing Git exclude directory outside the repository common directory',
    )
    expect(await readFile(join(outside, 'exclude'), 'utf8')).toBe('# outside\n')
  })

  it('preserves non-UTF-8 Git exclude bytes exactly when appending protection', async () => {
    const root = await repository()
    const path = excludePath(root)
    const original = Buffer.from([0xff, 0xfe, 0x0a])
    await writeFile(path, original)

    await ensureLocalEvidenceProtected(root)

    const protectedContents = await readFile(path)
    expect(protectedContents.subarray(0, original.length)).toEqual(original)
    expect(protectedContents.subarray(original.length).toString('ascii')).toBe(
      '# CodeTruss local evidence; never add receipts or patches to Git\n/.codetruss/\n',
    )
  })
})
