import { createHash, randomUUID } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readFile, readdir, readlink, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import { DEFAULT_CONFIG } from '../src/config.js'
import { captureDiffEvidence, changedFiles } from '../src/git.js'
import { createExactHookBaseline } from '../src/hook-baseline.js'
import {
  CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV,
  CODETRUSS_HOOK_CONTEXT_PATH_ENV,
  CODETRUSS_HOOK_CONTEXT_SHA256_ENV,
  handleAgentHook,
  hookReviewEnvironment,
  readHookTurnContext,
  type HookReviewRequest,
} from '../src/hook-runtime.js'
import { materializeTreeSnapshot, materializeWorkingTreeSnapshot } from '../src/git-snapshot.js'
import { doctorHooks, hookStatus, installHooks, uninstallHooks } from '../src/hooks.js'
import { classifyPath, isDependencyFile, sensitiveCategory } from '../src/policy.js'
import {
  CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV,
  initializePrivateGitObjectStore,
  privateGitReadEnvironment,
  withoutPrivateGitEvidenceEnvironment,
  type PrivateGitObjectStore,
} from '../src/private-git-object-store.js'
import type { CliConfig } from '../src/types.js'

const CLI_ENTRY = fileURLToPath(new URL('../src/cli.ts', import.meta.url))
const TSX_BIN = fileURLToPath(import.meta.resolve('tsx/cli'))

function git(root: string, ...args: string[]): string {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' })
  if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(' ')} failed`)
  return result.stdout.trim()
}

function gitWithEnvironment(root: string, environment: NodeJS.ProcessEnv, ...args: string[]): string {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', env: environment })
  if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(' ')} failed`)
  return result.stdout.trim()
}

async function repo(prefix = 'codetruss-hook-'): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix))
  git(root, 'init', '--quiet')
  git(root, 'config', 'user.name', 'Hook Test')
  git(root, 'config', 'user.email', 'hook@example.com')
  await writeFile(join(root, 'README.md'), 'baseline\n')
  git(root, 'add', 'README.md')
  git(root, 'commit', '--quiet', '-m', 'baseline')
  return root
}

async function writeConfig(root: string, allow = ['src/**']): Promise<void> {
  const allowYaml = allow.length ? `allow:\n${allow.map((glob) => `  - ${glob}`).join('\n')}` : 'allow: []'
  await writeFile(join(root, '.codetruss.yml'), `version: 1\n${allowYaml}\ndeny:\n  - vendor/**\nverify: []\n`)
}

function config(allow = ['src/**']): CliConfig {
  return { ...structuredClone(DEFAULT_CONFIG), allow, deny: ['vendor/**'] }
}

function stateDir(root: string, surface: 'claude' | 'codex', session: string): string {
  const common = git(root, 'rev-parse', '--git-common-dir')
  const commonDir = common.startsWith('/') ? common : join(root, common)
  const digest = (value: string) => createHash('sha256').update(value).digest('hex')
  return join(commonDir, 'codetruss', 'hooks', 'v1', digest(root), surface, digest(session))
}

async function privateStore(root: string): Promise<PrivateGitObjectStore> {
  const common = git(root, 'rev-parse', '--git-common-dir')
  const commonDir = common.startsWith('/') ? common : join(root, common)
  return initializePrivateGitObjectStore(
    root,
    join(commonDir, 'codetruss', 'test-object-stores', randomUUID(), 'object-store'),
  )
}

describe('hook installation', () => {
  it('preserves user hooks and installs one idempotent handler for every tier', async () => {
    const root = await repo()
    await writeConfig(root)
    const path = join(root, '.claude', 'settings.json')
    await mkdir(join(root, '.claude'), { recursive: true })
    await writeFile(path, JSON.stringify({ custom: true, hooks: { PostToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'npm test' }] }] } }))

    await installHooks(root, 'claude')
    await installHooks(root, 'claude')

    const document = JSON.parse(await readFile(path, 'utf8')) as { custom: boolean; hooks: Record<string, Array<{ matcher?: string; hooks: Array<{ command?: string; args?: string[]; commandWindows?: string }> }>> }
    expect(document.custom).toBe(true)
    expect(document.hooks.PostToolUse.some((group) => group.hooks.some((hook) => hook.command === 'npm test'))).toBe(true)
    for (const event of ['UserPromptSubmit', 'PostToolUse', 'Stop']) {
      const installed = document.hooks[event].flatMap((group) => group.hooks).filter((hook) => [hook.command, ...(hook.args ?? [])].some((value) => value?.includes('.codetruss/hooks/agent.cjs')))
      expect(installed).toHaveLength(1)
    }
    expect(document.hooks.PostToolUse.find((group) => group.hooks.some((hook) => [hook.command, ...(hook.args ?? [])].some((value) => value?.includes('agent.cjs'))))?.matcher).toBe('Edit|Write')
    for (const event of ['UserPromptSubmit', 'PostToolUse', 'Stop']) {
      const handler = document.hooks[event].flatMap((group) => group.hooks).find((hook) => hook.args?.includes('claude'))
      expect(handler).toMatchObject({
        command: 'node',
        args: ['${CLAUDE_PROJECT_DIR}/.codetruss/hooks/agent.cjs', 'claude'],
      })
      expect(handler).not.toHaveProperty('commandWindows')
    }
    const runner = await readFile(join(root, '.codetruss', 'hooks', 'agent.cjs'), 'utf8')
    expect(runner).toContain("['hooks', 'dispatch', surface]")
    expect(runner).toContain("return { decision: 'block', reason: text }")
    expect(runner).not.toContain('continue: false')
    expect(runner).not.toContain("['review'")
  })

  it('refuses agent hooks until an allow surface is configured', async () => {
    const root = await repo()
    await writeConfig(root, [])
    await expect(installHooks(root, 'codex')).rejects.toThrow('require at least one allow glob')
    await expect(readFile(join(root, '.codex', 'hooks.json'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('preserves invalid user-owned JSON instead of replacing it', async () => {
    const root = await repo()
    await writeConfig(root)
    const path = join(root, '.claude', 'settings.json')
    await mkdir(join(root, '.claude'), { recursive: true })
    await writeFile(path, '{ invalid')
    await expect(installHooks(root, 'claude')).rejects.toThrow('refusing to overwrite invalid JSON')
    await expect(readFile(path, 'utf8')).resolves.toBe('{ invalid')
  })

  it('plans all targets before writing so an invalid later target cannot leave a partial installation', async () => {
    const root = await repo()
    await writeConfig(root)
    const invalidPath = join(root, '.codex', 'hooks.json')
    await mkdir(dirname(invalidPath), { recursive: true })
    await writeFile(invalidPath, '{ keep this invalid file')

    await expect(installHooks(root, 'all')).rejects.toThrow('refusing to overwrite invalid JSON')

    await expect(readFile(invalidPath, 'utf8')).resolves.toBe('{ keep this invalid file')
    await expect(readFile(join(root, '.claude', 'settings.json'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(readFile(join(root, '.codetruss', 'hooks', 'agent.cjs'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(readFile(join(root, '.git', 'hooks', 'pre-commit'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('uses the effective core.hooksPath and preserves exact staged review semantics', async () => {
    const root = await repo()
    git(root, 'config', 'core.hooksPath', '.githooks')
    await installHooks(root, 'pre-commit')
    const path = join(root, '.githooks', 'pre-commit')
    const hook = await readFile(path, 'utf8')
    expect(hook).toContain('review --staged --task "pre-commit"')
    expect(hook).not.toContain('--no-verify')
    await installHooks(root, 'pre-commit')
    expect((await readFile(path, 'utf8')).match(/codetruss-agent-guard:begin/g)).toHaveLength(1)
  })

  it.runIf(process.platform !== 'win32')('allows REVIEW_REQUIRED but blocks FAILED and operational errors at pre-commit', async () => {
    const root = await repo()
    const bin = join(root, 'node_modules', '.bin', 'codetruss')
    await mkdir(dirname(bin), { recursive: true })
    await writeFile(bin, '#!/bin/sh\nexit "${CODETRUSS_FAKE_STATUS:-0}"\n')
    await chmod(bin, 0o755)
    await installHooks(root, 'pre-commit')
    const path = join(root, '.git', 'hooks', 'pre-commit')
    const execute = (status: number) => spawnSync(path, [], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, CODETRUSS_FAKE_STATUS: String(status) },
    })

    expect(execute(0).status).toBe(0)
    const review = execute(1)
    expect(review.status).toBe(0)
    expect(review.stderr).toContain('CodeTruss REVIEW_REQUIRED')
    const failed = execute(2)
    expect(failed.status).toBe(2)
    expect(failed.stderr).toContain('CodeTruss FAILED')
    const error = execute(3)
    expect(error.status).toBe(3)
    expect(error.stderr).toContain('could not produce a trustworthy receipt')
  })

  it('refuses to append shell syntax to a non-shell pre-commit hook', async () => {
    const root = await repo()
    const path = join(root, '.git', 'hooks', 'pre-commit')
    const original = '#!/usr/bin/env python3\nprint("existing")\n'
    await mkdir(join(root, '.git', 'hooks'), { recursive: true })
    await writeFile(path, original)
    await expect(installHooks(root, 'pre-commit')).rejects.toThrow('is not a POSIX shell hook')
    await expect(readFile(path, 'utf8')).resolves.toBe(original)
  })

  it('uninstalls only CodeTruss handlers and reports status without clobbering user JSON', async () => {
    const root = await repo()
    await writeConfig(root)
    const path = join(root, '.codex', 'hooks.json')
    await installHooks(root, 'codex')
    const installedOutput = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    await hookStatus(root, 'codex')
    expect(installedOutput.mock.calls.flat().join('')).toContain('installed\tcodex')
    installedOutput.mockRestore()
    const document = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>
    document.userSetting = 'keep'
    await writeFile(path, `${JSON.stringify(document)}\n`)
    await uninstallHooks(root, 'codex')
    const final = JSON.parse(await readFile(path, 'utf8')) as { userSetting: string; hooks: Record<string, unknown> }
    expect(final.userSetting).toBe('keep')
    expect(final.hooks.UserPromptSubmit).toBeUndefined()
    expect(final.hooks.PostToolUse).toBeUndefined()
    expect(final.hooks.Stop).toBeUndefined()
  })

  it.runIf(process.platform !== 'win32')('diagnoses an exact healthy installation and fails when executable hook code drifts', async () => {
    const root = await repo()
    await writeConfig(root)
    const bin = join(root, 'node_modules', '.bin', 'codetruss')
    await mkdir(dirname(bin), { recursive: true })
    await writeFile(bin, '#!/bin/sh\nexit 0\n')
    await chmod(bin, 0o755)
    await installHooks(root, 'all')
    const output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    try {
      const healthy = await doctorHooks(root, 'all')
      expect(healthy.ok).toBe(true)
      expect(healthy.checks).toEqual(expect.arrayContaining([
        expect.objectContaining({ level: 'ok', target: 'pre-commit', message: 'staged-review block is current' }),
        expect.objectContaining({ level: 'ok', target: 'claude', message: 'Stop handler is current' }),
        expect.objectContaining({ level: 'ok', target: 'codex', message: 'Stop handler is current' }),
        expect.objectContaining({ level: 'warning', target: 'codex', message: expect.stringContaining('open /hooks') }),
      ]))
      expect(output.mock.calls.flat().join('')).toContain('doctor\thealthy\t0 error(s), 1 warning(s)')

      await writeFile(join(root, '.codetruss', 'hooks', 'agent.cjs'), 'module.exports = "changed"\n')
      const unhealthy = await doctorHooks(root, 'codex')
      expect(unhealthy.ok).toBe(false)
      expect(unhealthy.checks).toContainEqual(expect.objectContaining({
        level: 'error', target: 'runtime', message: expect.stringContaining('differs from this CLI version'),
      }))
    } finally {
      output.mockRestore()
    }
  })

  it.runIf(process.platform !== 'win32')('routes hook JSON from a subdirectory through the local CLI dispatcher', async () => {
    const root = await repo()
    await writeConfig(root)
    await installHooks(root, 'codex')
    const nested = join(root, 'src', 'nested')
    const bin = join(root, 'node_modules', '.bin', 'codetruss')
    const argsLog = join(root, 'hook-args.txt')
    const inputLog = join(root, 'hook-input.json')
    await mkdir(nested, { recursive: true })
    await mkdir(join(root, 'node_modules', '.bin'), { recursive: true })
    await writeFile(bin, `#!/bin/sh\nprintf '%s\\n' "$@" > "${argsLog}"\ncat > "${inputLog}"\nprintf '%s\\n' '{"systemMessage":"routed"}'\n`)
    await chmod(bin, 0o755)
    const input = JSON.stringify({ session_id: 'runner', turn_id: 'turn', hook_event_name: 'PostToolUse', tool_input: { path: 'src/a.ts' } })
    const result = spawnSync(process.execPath, [join(root, '.codetruss', 'hooks', 'agent.cjs'), 'codex'], { cwd: nested, input, encoding: 'utf8' })
    expect(result.status, result.stderr).toBe(0)
    expect(result.stdout.trim()).toBe('{"systemMessage":"routed"}')
    expect(await readFile(argsLog, 'utf8')).toBe('hooks\ndispatch\ncodex\n')
    expect(await readFile(inputLog, 'utf8')).toBe(input)
  })
})

describe('exact immutable hook snapshots', () => {
  it('refuses unowned or out-of-state object-store cleanup targets', async () => {
    const root = await repo()
    const common = git(root, 'rev-parse', '--git-common-dir')
    const commonDir = common.startsWith('/') ? common : join(root, common)
    const unowned = join(commonDir, 'codetruss', 'unowned-test', 'object-store')
    await mkdir(unowned, { recursive: true })
    const sentinel = join(unowned, 'sentinel.txt')
    await writeFile(sentinel, 'keep\n')
    await expect(initializePrivateGitObjectStore(root, unowned)).rejects.toThrow('ownership manifest')
    await expect(readFile(sentinel, 'utf8')).resolves.toBe('keep\n')
    const outside = join(await mkdtemp(join(tmpdir(), 'codetruss-outside-store-')), 'object-store')
    await expect(initializePrivateGitObjectStore(root, outside)).rejects.toThrow('stay under')
    const store = await privateStore(root)
    try {
      expect(store.objectFormat).toBe('sha1')
      expect(() => store.assertObjectId('a'.repeat(41))).toThrow('not a valid sha1')
      expect(() => store.assertObjectId('a'.repeat(64))).toThrow('not a valid sha1')
      expect(() => store.assertObjectId(git(root, 'rev-parse', 'HEAD'))).not.toThrow()
    } finally {
      await store.cleanup()
    }
    expect(withoutPrivateGitEvidenceEnvironment({
      SAFE_VALUE: 'keep',
      CODETRUSS_INTERNAL_HOOK: '1',
      CODETRUSS_HOOK_CONTEXT_PATH: '/private/context',
      CODETRUSS_EVIDENCE_OBJECT_DIRECTORY: '/private/objects',
      GIT_OBJECT_DIRECTORY: '/private/objects',
      GIT_ALTERNATE_OBJECT_DIRECTORIES: '/real/objects',
      GIT_DIR: '/real/git-dir',
      GIT_INDEX_FILE: '.git/index',
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'safe.directory',
      GIT_CONFIG_VALUE_0: '*',
    } as unknown as NodeJS.ProcessEnv)).toEqual({ SAFE_VALUE: 'keep' })
  })

  it('keeps a baseline-untracked file as modified with its exact final patch', async () => {
    const root = await repo()
    await mkdir(join(root, 'src'), { recursive: true })
    await writeFile(join(root, 'src', 'draft.ts'), 'export const value = "before"\n')
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-hook-snapshots-'))
    const store = await privateStore(root)
    try {
      const baseline = await createExactHookBaseline(root, parent, store)
      await writeFile(join(root, 'src', 'draft.ts'), 'export const value = "after"\n')
      const final = await createExactHookBaseline(root, parent, store)
      const environment = store.writeEnvironment()
      const files = await changedFiles(root, baseline.commit, false, (path, oldPath) => classifyPath(path, oldPath, ['src/**'], []), sensitiveCategory, isDependencyFile, final.commit, { env: environment })
      expect(files).toEqual([expect.objectContaining({ path: 'src/draft.ts', change: 'modified', additions: 1, deletions: 1 })])
      const diff = await captureDiffEvidence(root, baseline.commit, false, files, { targetTreeish: final.commit, env: environment })
      expect(diff.truncated).toBe(false)
      expect(diff.patch.toString('utf8')).toContain('-export const value = "before"')
      expect(diff.patch.toString('utf8')).toContain('+export const value = "after"')
      expect(diff.patch.toString('utf8')).not.toContain('deleted file mode')
    } finally {
      await store.cleanup()
    }
  })

  it('classifies an agent-created untracked file as added', async () => {
    const root = await repo()
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-hook-snapshots-'))
    const store = await privateStore(root)
    try {
      const baseline = await createExactHookBaseline(root, parent, store)
      await mkdir(join(root, 'src'), { recursive: true })
      await writeFile(join(root, 'src', 'created.ts'), 'export const created = true\n')
      const final = await createExactHookBaseline(root, parent, store)
      const environment = store.writeEnvironment()
      const files = await changedFiles(root, baseline.commit, false, (path, oldPath) => classifyPath(path, oldPath, ['src/**'], []), sensitiveCategory, isDependencyFile, final.commit, { env: environment })
      expect(files).toEqual([expect.objectContaining({ path: 'src/created.ts', change: 'added', additions: 1, deletions: 0 })])
      const diff = await captureDiffEvidence(root, baseline.commit, false, files, { targetTreeish: final.commit, env: environment })
      expect(diff.patch.toString('utf8')).toContain('new file mode 100644')
      expect(diff.patch.toString('utf8')).toContain('+export const created = true')
    } finally {
      await store.cleanup()
    }
  })

  it.runIf(process.platform !== 'win32')('preserves filter-free bytes, symlinks, executables, deletions, and Git tree prefix ordering', async () => {
    const root = await repo()
    git(root, 'config', 'filter.rewrite.clean', 'sed s/raw/clean/')
    git(root, 'config', 'filter.rewrite.smudge', 'sed s/raw/smudged/')
    await writeFile(join(root, '.gitattributes'), '*.txt filter=rewrite\n')
    await writeFile(join(root, 'foo.txt'), 'raw\n')
    await mkdir(join(root, 'foo'), { recursive: true })
    await writeFile(join(root, 'foo', 'bar.ts'), 'export {}\n')
    await writeFile(join(root, 'run.sh'), '#!/bin/sh\nexit 0\n')
    await chmod(join(root, 'run.sh'), 0o755)
    await symlink('foo.txt', join(root, 'link'))
    const beforeIndex = git(root, 'write-tree')
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-hook-snapshots-'))
    const store = await privateStore(root)
    try {
      const baseline = await createExactHookBaseline(root, parent, store)
      const environment = store.writeEnvironment()
      expect(git(root, 'write-tree')).toBe(beforeIndex)
      expect(gitWithEnvironment(root, environment, 'show', `${baseline.commit}:foo.txt`)).toBe('raw')
      expect(gitWithEnvironment(root, environment, 'ls-tree', baseline.commit, 'run.sh')).toMatch(/^100755 blob /)
      expect(gitWithEnvironment(root, environment, 'ls-tree', baseline.commit, 'link')).toMatch(/^120000 blob /)
      expect(gitWithEnvironment(root, environment, 'show', `${baseline.commit}:link`)).toBe('foo.txt')
      expect(await readlink(join(root, 'link'))).toBe('foo.txt')
      expect(gitWithEnvironment(root, environment, 'ls-tree', baseline.commit, 'foo.txt')).toContain(' blob ')
      const materialized = await materializeTreeSnapshot(root, baseline.commit, { parentDir: parent, gitEnvironment: environment })
      try {
        expect(await readFile(join(materialized.root, 'foo.txt'), 'utf8')).toBe('raw\n')
        expect((await stat(join(materialized.root, 'run.sh'))).mode & 0o777).toBe(0o755)
        expect(await readlink(join(materialized.root, 'link'))).toBe('foo.txt')
      } finally {
        await materialized.cleanup()
      }

      await writeFile(join(root, 'foo.txt'), 'raw changed\n')
      await rm(join(root, 'foo', 'bar.ts'))
      const final = await createExactHookBaseline(root, parent, store)
      const files = await changedFiles(root, baseline.commit, false, () => 'allowed', sensitiveCategory, isDependencyFile, final.commit, { env: environment })
      expect(files.map((file) => file.path)).toContain('foo.txt')
      expect(files).toContainEqual(expect.objectContaining({ path: 'foo/bar.ts', change: 'deleted' }))
    } finally {
      await store.cleanup()
    }
  })

  it.runIf(process.platform !== 'win32')('round-trips arbitrary symlink target bytes without UTF-8 replacement', async () => {
    const root = await repo()
    const target = Buffer.from([0x66, 0x6f, 0x80])
    await symlink(target, join(root, 'byte-link'))
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-hook-snapshots-'))
    const store = await privateStore(root)
    const baseline = await createExactHookBaseline(root, parent, store)
    const environment = store.writeEnvironment()
    const treeEntry = gitWithEnvironment(root, environment, 'ls-tree', baseline.commit, 'byte-link')
    const oid = treeEntry.split(/\s+/)[2]
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', baseline.commit]).status).not.toBe(0)
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', oid]).status).not.toBe(0)
    const blob = spawnSync('git', ['-C', root, 'cat-file', 'blob', oid], { encoding: null, env: environment })
    expect(blob.status, blob.stderr?.toString('utf8')).toBe(0)
    expect(blob.stdout).toEqual(target)
    expect((await stat(store.directory)).mode & 0o777).toBe(0o700)
    expect(git(root, 'for-each-ref', '--format=%(refname)', 'refs/codetruss/hooks')).toBe('')
    expect(spawnSync('git', ['-C', root, 'fsck', '--no-dangling']).status).toBe(0)
    const snapshot = await materializeTreeSnapshot(root, baseline.commit, { parentDir: parent, gitEnvironment: environment })
    try {
      expect(await readlink(join(snapshot.root, 'byte-link'), { encoding: 'buffer' })).toEqual(target)
    } finally {
      await snapshot.cleanup()
    }
    await store.cleanup()
    await expect(stat(store.directory)).rejects.toMatchObject({ code: 'ENOENT' })
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', baseline.commit], { env: environment }).status).not.toBe(0)
  })

  it('detects drift after an otherwise stable working-tree snapshot', async () => {
    const root = await repo()
    const path = join(root, 'README.md')
    const snapshot = await materializeWorkingTreeSnapshot(root)
    try {
      await snapshot.verifyStillCurrent?.()
      await writeFile(path, 'drifted!\n')
      await expect(snapshot.verifyStillCurrent?.()).rejects.toThrow('working tree changed while snapshotting')
    } finally {
      await snapshot.cleanup()
    }
  })

  it('supports SHA-256 repositories when the installed Git does', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-hook-sha256-'))
    const initialized = spawnSync('git', ['init', '--quiet', '--object-format=sha256', root], { encoding: 'utf8' })
    if (initialized.status !== 0) return
    git(root, 'config', 'user.name', 'Hook Test')
    git(root, 'config', 'user.email', 'hook@example.com')
    await writeFile(join(root, 'README.md'), 'sha256\n')
    const store = await privateStore(root)
    try {
      const baseline = await createExactHookBaseline(root, await mkdtemp(join(tmpdir(), 'codetruss-hook-snapshots-')), store)
      expect(store.objectFormat).toBe('sha256')
      expect(baseline.commit).toMatch(/^[0-9a-f]{64}$/)
      expect(baseline.tree).toMatch(/^[0-9a-f]{64}$/)
      expect(spawnSync('git', ['-C', root, 'cat-file', '-e', baseline.commit]).status).not.toBe(0)
      expect(gitWithEnvironment(root, store.writeEnvironment(), 'cat-file', '-t', baseline.commit)).toBe('commit')
    } finally {
      await store.cleanup()
    }
  })

  it('isolates linked-worktree captures inside the shared common Git state', async () => {
    const root = await repo()
    const linked = await mkdtemp(join(tmpdir(), 'codetruss-linked-worktree-'))
    await rm(linked, { recursive: true, force: true })
    git(root, 'worktree', 'add', '--quiet', '--detach', linked)
    await writeFile(join(root, 'main-only.txt'), `main-${randomUUID()}\n`)
    await writeFile(join(linked, 'linked-only.txt'), `linked-${randomUUID()}\n`)
    const mainStore = await privateStore(root)
    const linkedStore = await privateStore(linked)
    try {
      const [mainCapture, linkedCapture] = await Promise.all([
        createExactHookBaseline(root, await mkdtemp(join(tmpdir(), 'codetruss-main-snapshot-')), mainStore),
        createExactHookBaseline(linked, await mkdtemp(join(tmpdir(), 'codetruss-linked-snapshot-')), linkedStore),
      ])
      expect(mainStore.directory).not.toBe(linkedStore.directory)
      expect(gitWithEnvironment(root, mainStore.writeEnvironment(), 'show', `${mainCapture.commit}:main-only.txt`)).toContain('main-')
      expect(gitWithEnvironment(linked, linkedStore.writeEnvironment(), 'show', `${linkedCapture.commit}:linked-only.txt`)).toContain('linked-')
      expect(spawnSync('git', ['-C', root, 'cat-file', '-e', mainCapture.commit]).status).not.toBe(0)
      expect(spawnSync('git', ['-C', linked, 'cat-file', '-e', linkedCapture.commit]).status).not.toBe(0)
      await mainStore.cleanup()
      expect(gitWithEnvironment(linked, linkedStore.writeEnvironment(), 'cat-file', '-t', linkedCapture.commit)).toBe('commit')
    } finally {
      await mainStore.cleanup().catch(() => undefined)
      await linkedStore.cleanup().catch(() => undefined)
    }
  })

  it('reads repository-level alternates without writing snapshot objects into them', async () => {
    const source = await repo('codetruss-alternate-source-')
    const root = await mkdtemp(join(tmpdir(), 'codetruss-shared-clone-'))
    await rm(root, { recursive: true, force: true })
    const cloned = spawnSync('git', ['clone', '--quiet', '--shared', source, root], { encoding: 'utf8' })
    expect(cloned.status, cloned.stderr).toBe(0)
    const alternates = join(root, '.git', 'objects', 'info', 'alternates')
    expect((await readFile(alternates, 'utf8')).trim()).not.toBe('')
    await writeFile(join(root, 'README.md'), `private-${randomUUID()}\n`)
    const store = await privateStore(root)
    try {
      const capture = await createExactHookBaseline(root, await mkdtemp(join(tmpdir(), 'codetruss-alternate-snapshot-')), store)
      expect(gitWithEnvironment(root, store.writeEnvironment(), 'cat-file', '-t', capture.commit)).toBe('commit')
      expect(gitWithEnvironment(root, store.writeEnvironment(), 'show', `${capture.commit}:README.md`)).toContain('private-')
      expect(spawnSync('git', ['-C', root, 'cat-file', '-e', capture.commit]).status).not.toBe(0)
    } finally {
      await store.cleanup()
    }
  })

  it('preserves an uninitialized nested gitlink without inventing working-tree bytes', async () => {
    const root = await repo()
    const target = git(root, 'rev-parse', 'HEAD')
    git(root, 'update-index', '--add', '--cacheinfo', `160000,${target},vendor/submodule`)
    git(root, 'commit', '--quiet', '-m', 'add gitlink')
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-hook-snapshots-'))
    const store = await privateStore(root)
    try {
      const baseline = await createExactHookBaseline(root, parent, store)
      const environment = store.writeEnvironment()
      expect(gitWithEnvironment(root, environment, 'ls-tree', baseline.commit, 'vendor/submodule')).toMatch(new RegExp(`^160000 commit ${target}`))
      const snapshot = await materializeTreeSnapshot(root, baseline.commit, { parentDir: parent, gitEnvironment: environment })
      try {
        expect((await stat(join(snapshot.root, 'vendor', 'submodule'))).isDirectory()).toBe(true)
      } finally {
        await snapshot.cleanup()
      }
    } finally {
      await store.cleanup()
    }
  })

  it('drives the real receipt pipeline entirely from private immutable baseline and final commits', async () => {
    const root = await repo()
    await mkdir(join(root, 'src'), { recursive: true })
    await writeFile(join(root, 'src', 'draft.ts'), 'export const value = "before"\n')
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-hook-snapshots-'))
    const store = await privateStore(root)
    const baseline = await createExactHookBaseline(root, parent, store)
    await writeFile(join(root, 'src', 'draft.ts'), 'export const value = "after"\n')
    const final = await createExactHookBaseline(root, parent, store)
    const contextPath = join(dirname(store.directory), 'turn-context.json')
    const contextText = `${JSON.stringify({ version: 1, task: 'Update the draft value', config: config(), baselineDirtyFiles: baseline.dirtyFiles })}\n`
    await writeFile(contextPath, contextText, { mode: 0o600 })
    const contextSha256 = createHash('sha256').update(contextText).digest('hex')
    const reviewEnvironment = {
      ...process.env,
      HOME: `${root}-home`,
      CODETRUSS_SIGNING_KEY: join(root, '.codetruss', 'hook-signing.pem'),
      CODETRUSS_INTERNAL_HOOK: '1',
      CODETRUSS_HOOK_START_COMMIT: git(root, 'rev-parse', 'HEAD'),
      CODETRUSS_HOOK_END_COMMIT: git(root, 'rev-parse', 'HEAD'),
      CODETRUSS_HOOK_STARTED_AT: '2026-07-14T10:00:00.000Z',
      [CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV]: store.objectDirectory,
      [CODETRUSS_HOOK_CONTEXT_PATH_ENV]: contextPath,
      [CODETRUSS_HOOK_CONTEXT_SHA256_ENV]: contextSha256,
      [CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV]: createHash('sha256').update(JSON.stringify(baseline.dirtyFiles)).digest('hex'),
    }
    const mismatchedTask = spawnSync(TSX_BIN, [
      CLI_ENTRY, 'review', '--task', 'Substituted task',
      '--base', baseline.commit, '--final', final.commit,
    ], { cwd: root, encoding: 'utf8', env: reviewEnvironment, maxBuffer: 8 * 1024 * 1024 })
    expect(mismatchedTask.status).toBe(3)
    expect(mismatchedTask.stderr).toContain('does not match the authenticated prompt-time task')
    const result = spawnSync(TSX_BIN, [
      CLI_ENTRY, 'review', '--task', 'Update the draft value',
      '--base', baseline.commit, '--final', final.commit,
    ], {
      cwd: root,
      encoding: 'utf8',
      env: reviewEnvironment,
      maxBuffer: 8 * 1024 * 1024,
    })
    expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0)
    const receiptDir = join(root, '.codetruss', 'receipts')
    const receiptName = (await readdir(receiptDir)).filter((name) => name.endsWith('.json')).sort().at(-1)!
    const receipt = JSON.parse(await readFile(join(receiptDir, receiptName), 'utf8')) as {
      files: Array<{ path: string; change: string }>
      evidence: { patchFile: string }
      coverageNotes: string[]
    }
    expect(receipt.files).toEqual([expect.objectContaining({ path: 'src/draft.ts', change: 'modified' })])
    expect(await readFile(join(receiptDir, receipt.evidence.patchFile), 'utf8')).toContain('-export const value = "before"')
    expect(await readFile(join(receiptDir, receipt.evidence.patchFile), 'utf8')).toContain('+export const value = "after"')
    expect(receipt.coverageNotes[0]).toContain('prompt-time and Stop-time immutable private Git trees')
    await store.cleanup()
  }, 30_000)
})

describe('agent hook runtime', () => {
  it.each(['claude', 'codex'] as const)('blocks invalid UserPromptSubmit input with the %s decision contract', async (surface) => {
    const root = await repo()
    const output = await handleAgentHook(root, surface, {
      session_id: `${surface}-invalid-prompt`,
      hook_event_name: 'UserPromptSubmit',
      cwd: root,
    }, config())
    expect(output).toEqual({
      decision: 'block',
      reason: expect.stringContaining('missing the submitted prompt'),
    })
    expect(output).not.toHaveProperty('continue')
    expect(output).not.toHaveProperty('stopReason')
  })

  it('runs only a cheap path/scope check after a tool edit', async () => {
    const root = await repo()
    const runReview = vi.fn()
    const output = await handleAgentHook(root, 'codex', {
      session_id: 'session-fast',
      hook_event_name: 'PostToolUse',
      cwd: root,
      tool_name: 'apply_patch',
      tool_input: { patch: '*** Begin Patch\n*** Add File: .github/workflows/ci.yml\n+name: ci\n*** End Patch' },
    }, config(), { runReview })
    expect(output).toMatchObject({
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        additionalContext: expect.stringContaining('outside the allowed task scope'),
      },
    })
    expect(JSON.stringify(output)).toContain('sensitive ci surface')
    expect(runReview).not.toHaveBeenCalled()
    await expect(readFile(join(root, '.codetruss', 'receipts', 'latest'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('normalizes outside paths and tolerates unknown tool schemas', async () => {
    const root = await repo()
    const outside = await handleAgentHook(root, 'claude', {
      session_id: 'session-outside', hook_event_name: 'PostToolUse', cwd: root,
      tool_input: { file_path: join(root, '..', 'outside.ts') },
    }, config())
    expect(JSON.stringify(outside)).toContain('resolves outside the repository')
    expect(outside).toHaveProperty('hookSpecificOutput.hookEventName', 'PostToolUse')
    await expect(handleAgentHook(root, 'codex', {
      session_id: 'session-unknown', hook_event_name: 'PostToolUse', tool_input: { arbitrary: { nested: true } },
    }, config())).resolves.toBeUndefined()
  })

  it('captures once, waits for background tasks, reviews immutable final evidence once, and lets PASS stop quietly', async () => {
    const root = await repo()
    await writeConfig(root)
    const receipt = join(root, '.codetruss', 'receipts', 'hook.md')
    await mkdir(join(root, '.codetruss', 'receipts'), { recursive: true })
    await writeFile(receipt, '# receipt\n')
    const requests: HookReviewRequest[] = []
    const startedAt = new Date('2026-07-14T10:00:00.000Z')
    const runReview = vi.fn((request: HookReviewRequest) => {
      requests.push(request)
      const environment = privateGitReadEnvironment(request.objectDirectory)
      expect(gitWithEnvironment(root, environment, 'show', `${request.baselineRef}:src/value.ts`)).toBe('export const value = "before"')
      expect(gitWithEnvironment(root, environment, 'show', `${request.finalRef}:src/value.ts`)).toBe('export const value = "after"')
      return { status: 0, stdout: `PASS hook-session\n${receipt}\n`, stderr: '' }
    })
    await mkdir(join(root, 'src'), { recursive: true })
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "before"\n')
    const prompt = { session_id: 'session-stop', turn_id: 'turn-1', hook_event_name: 'UserPromptSubmit', prompt: 'Change the value', cwd: root }
    const dependencies = { runReview, now: () => startedAt }
    const promptConfig = config(['src/**'])
    await expect(handleAgentHook(root, 'codex', prompt, promptConfig, dependencies)).resolves.toBeUndefined()
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "after"\n')

    const waiting = await handleAgentHook(root, 'codex', { ...prompt, hook_event_name: 'Stop', background_tasks: [{ id: 'build', status: 'running' }] }, config(), dependencies)
    expect(waiting).toBeUndefined()
    expect(runReview).not.toHaveBeenCalled()
    const output = await handleAgentHook(root, 'codex', { ...prompt, hook_event_name: 'Stop', background_tasks: [] }, config(['changed-live-policy/**']), dependencies)
    expect(output).toBeUndefined()
    await expect(handleAgentHook(root, 'codex', { ...prompt, hook_event_name: 'Stop', stop_hook_active: true }, config(), dependencies)).resolves.toBeUndefined()
    expect(runReview).toHaveBeenCalledTimes(1)
    expect(requests[0]).toMatchObject({
      startCommit: git(root, 'rev-parse', 'HEAD'),
      finalHead: git(root, 'rev-parse', 'HEAD'),
      startedAt: startedAt.toISOString(),
      context: { task: 'Change the value', config: { allow: ['src/**'] } },
    })
    expect(requests[0].baselineDirtyFiles).toContain('src/value.ts')
    await expect(readHookTurnContext(requests[0].contextPath, requests[0].contextSha256)).rejects.toMatchObject({ code: 'ENOENT' })
    expect(hookReviewEnvironment(requests[0], {} as NodeJS.ProcessEnv)).toEqual({
      CODETRUSS_INTERNAL_HOOK: '1',
      CODETRUSS_HOOK_START_COMMIT: git(root, 'rev-parse', 'HEAD'),
      CODETRUSS_HOOK_END_COMMIT: git(root, 'rev-parse', 'HEAD'),
      CODETRUSS_HOOK_STARTED_AT: startedAt.toISOString(),
      [CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV]: requests[0].objectDirectory,
      [CODETRUSS_HOOK_CONTEXT_PATH_ENV]: requests[0].contextPath,
      [CODETRUSS_HOOK_CONTEXT_SHA256_ENV]: requests[0].contextSha256,
      [CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV]: createHash('sha256').update(JSON.stringify(requests[0].baselineDirtyFiles)).digest('hex'),
    })
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', requests[0].baselineRef]).status).not.toBe(0)
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', requests[0].baselineRef], { env: privateGitReadEnvironment(requests[0].objectDirectory) }).status).not.toBe(0)
  })

  it.each(['claude', 'codex'] as const)('uses protocol-correct Stop verdict output on %s', async (surface) => {
    const root = await repo()
    await mkdir(join(root, 'src'), { recursive: true })
    await mkdir(join(root, '.codetruss', 'receipts'), { recursive: true })
    await writeFile(join(root, 'src', 'value.ts'), 'initial\n')

    async function review(
      verdict: 'PASS' | 'REVIEW_REQUIRED' | 'FAILED',
      status: 0 | 1 | 2,
      stopHookActive = false,
    ): Promise<Record<string, unknown> | undefined> {
      const suffix = `${verdict.toLowerCase()}-${stopHookActive ? 'active' : 'first'}`
      const receipt = join(root, '.codetruss', 'receipts', `${surface}-${suffix}.md`)
      await writeFile(receipt, `# ${verdict}\n`)
      const prompt = {
        session_id: `${surface}-${suffix}`,
        turn_id: `${surface}-${suffix}-turn`,
        hook_event_name: 'UserPromptSubmit',
        prompt: `Exercise ${verdict} on ${surface}`,
        cwd: root,
      }
      await expect(handleAgentHook(root, surface, prompt, config())).resolves.toBeUndefined()
      await writeFile(join(root, 'src', 'value.ts'), `${suffix}\n`)
      return handleAgentHook(root, surface, {
        ...prompt,
        hook_event_name: 'Stop',
        stop_hook_active: stopHookActive,
        background_tasks: [],
      }, config(), {
        runReview: () => ({
          status,
          stdout: `${verdict} ${suffix}\n${receipt}\n- protocol reason\n`,
          stderr: '',
        }),
      })
    }

    await expect(review('PASS', 0)).resolves.toBeUndefined()

    const reviewRequired = await review('REVIEW_REQUIRED', 1)
    expect(reviewRequired).toEqual({ systemMessage: expect.stringContaining('CodeTruss REVIEW_REQUIRED') })
    expect(reviewRequired).not.toHaveProperty('decision')
    expect(reviewRequired).not.toHaveProperty('continue')
    expect(reviewRequired).not.toHaveProperty('hookSpecificOutput')

    const failed = await review('FAILED', 2)
    expect(failed).toEqual({ decision: 'block', reason: expect.stringContaining('CodeTruss FAILED') })
    expect(failed).not.toHaveProperty('continue')
    expect(failed).not.toHaveProperty('systemMessage')

    const failedDuringContinuation = await review('FAILED', 2, true)
    expect(failedDuringContinuation).toEqual({ systemMessage: expect.stringContaining('CodeTruss FAILED') })
    expect(failedDuringContinuation).not.toHaveProperty('decision')
    expect(failedDuringContinuation).not.toHaveProperty('continue')
  }, 30_000)

  it('serializes duplicate prompt capture so an active private store cannot be reset', async () => {
    const root = await repo()
    await mkdir(join(root, 'src'), { recursive: true })
    await writeFile(join(root, 'src', 'value.ts'), 'before\n')
    let announceCapture!: () => void
    let releaseCapture!: () => void
    const captureStarted = new Promise<void>((resolveStarted) => { announceCapture = resolveStarted })
    const release = new Promise<void>((resolveRelease) => { releaseCapture = resolveRelease })
    const captureBaseline = vi.fn(async (captureRoot: string, parent: string, store: PrivateGitObjectStore) => {
      announceCapture()
      await release
      return createExactHookBaseline(captureRoot, parent, store)
    })
    const prompt = {
      session_id: 'duplicate-capture-session', turn_id: 'same-turn', hook_event_name: 'UserPromptSubmit',
      prompt: 'Change value', cwd: root,
    }
    const first = handleAgentHook(root, 'codex', prompt, config(), { captureBaseline })
    await captureStarted
    const duplicate = await handleAgentHook(root, 'codex', prompt, config(), { captureBaseline })
    expect(duplicate).toMatchObject({ decision: 'block', reason: expect.stringContaining('already running') })
    expect(duplicate).not.toHaveProperty('continue')
    expect(captureBaseline).toHaveBeenCalledTimes(1)
    releaseCapture()
    await expect(first).resolves.toBeUndefined()
    expect(captureBaseline).toHaveBeenCalledTimes(1)
    const current = JSON.parse(await readFile(join(stateDir(root, 'codex', 'duplicate-capture-session'), 'current.json'), 'utf8')) as { turnKey: string }
    await expect(stat(join(stateDir(root, 'codex', 'duplicate-capture-session'), current.turnKey, 'object-store', 'objects'))).resolves.toBeDefined()
  })

  it('does not prune a live capture lease when many turns share one session', async () => {
    const root = await repo()
    let releaseFirst!: () => void
    let announceFirst!: () => void
    const firstStarted = new Promise<void>((resolveStarted) => { announceFirst = resolveStarted })
    const firstRelease = new Promise<void>((resolveRelease) => { releaseFirst = resolveRelease })
    let calls = 0
    const captureBaseline = vi.fn(async () => {
      calls++
      if (calls === 1) {
        announceFirst()
        await firstRelease
      }
      return {
        commit: git(root, 'rev-parse', 'HEAD'),
        tree: git(root, 'write-tree'),
        head: git(root, 'rev-parse', 'HEAD'),
        dirtyFiles: [],
      }
    })
    const firstPrompt = {
      session_id: 'prune-live-session', turn_id: 'live-turn', hook_event_name: 'UserPromptSubmit', prompt: 'Live capture', cwd: root,
    }
    const first = handleAgentHook(root, 'codex', firstPrompt, config(), { captureBaseline })
    await firstStarted
    for (let index = 0; index < 22; index++) {
      await handleAgentHook(root, 'codex', {
        ...firstPrompt,
        turn_id: `later-${index}`,
        prompt: `Later capture ${index}`,
      }, config(), { captureBaseline })
    }
    const liveTurnKey = createHash('sha256').update('id:live-turn').digest('hex')
    const liveTurnDir = join(stateDir(root, 'codex', 'prune-live-session'), liveTurnKey)
    await expect(stat(join(liveTurnDir, 'capture.lock'))).resolves.toBeDefined()
    await expect(stat(join(liveTurnDir, 'object-store'))).resolves.toBeDefined()
    releaseFirst()
    await expect(first).resolves.toBeUndefined()
    await expect(stat(join(liveTurnDir, 'state.json'))).resolves.toBeDefined()
  }, 30_000)

  it('keeps private prompt state under Git metadata and blocks prompt processing if exact capture fails', async () => {
    const root = await repo()
    const prompt = { session_id: 'private-session', prompt_id: 'prompt-1', hook_event_name: 'UserPromptSubmit', prompt: 'private task text', cwd: root }
    await expect(handleAgentHook(root, 'claude', prompt, config())).resolves.toBeUndefined()
    const current = JSON.parse(await readFile(join(stateDir(root, 'claude', 'private-session'), 'current.json'), 'utf8')) as { turnKey: string }
    const turnDir = join(stateDir(root, 'claude', 'private-session'), current.turnKey)
    const statePath = join(turnDir, 'state.json')
    expect((await stat(statePath)).mode & 0o777).toBe(0o600)
    expect((await stat(join(turnDir, 'object-store'))).mode & 0o777).toBe(0o700)
    expect((await stat(join(turnDir, 'turn-context.json'))).mode & 0o777).toBe(0o600)
    expect(git(root, 'status', '--porcelain')).not.toContain('codetruss/hooks')
    const failed = await handleAgentHook(root, 'claude', { ...prompt, session_id: 'failed-session', prompt_id: 'prompt-fail' }, config(), {
      captureBaseline: async () => { throw new Error('unstable working tree') },
    })
    expect(failed).toEqual({ decision: 'block', reason: expect.stringContaining('unstable working tree') })
  })

  it('fails closed when frozen prompt-time policy evidence is changed before Stop', async () => {
    const root = await repo()
    const prompt = {
      session_id: 'tampered-context-session', turn_id: 'tampered-turn', hook_event_name: 'UserPromptSubmit',
      prompt: 'Respect prompt policy', cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config(['src/**']))
    const session = stateDir(root, 'codex', 'tampered-context-session')
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    const turnDir = join(session, current.turnKey)
    await writeFile(join(turnDir, 'turn-context.json'), '{"version":1}\n', { mode: 0o600 })
    const runReview = vi.fn()
    const output = await handleAgentHook(root, 'codex', { ...prompt, hook_event_name: 'Stop' }, config(['live-policy/**']), { runReview })
    expect(output).toEqual({ systemMessage: expect.stringContaining('context changed after prompt-time capture') })
    expect(runReview).not.toHaveBeenCalled()
    await expect(stat(join(turnDir, 'object-store'))).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('fails closed when the review task disagrees with the authenticated prompt-time context', async () => {
    const root = await repo()
    const prompt = {
      session_id: 'tampered-task-session', turn_id: 'tampered-task-turn', hook_event_name: 'UserPromptSubmit',
      prompt: 'Keep this exact task', cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config(['src/**']))
    const session = stateDir(root, 'codex', 'tampered-task-session')
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    const turnDir = join(session, current.turnKey)
    const statePath = join(turnDir, 'state.json')
    const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>
    state.task = 'Substitute a different task'
    await writeFile(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    const runReview = vi.fn()

    const output = await handleAgentHook(root, 'codex', { ...prompt, hook_event_name: 'Stop' }, config(), { runReview })

    expect(output).toEqual({ systemMessage: expect.stringContaining('task evidence does not match prompt-time context') })
    expect(runReview).not.toHaveBeenCalled()
    await expect(stat(join(turnDir, 'object-store'))).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('reports missing baseline evidence without claiming success or creating a Stop loop', async () => {
    const root = await repo()
    const output = await handleAgentHook(root, 'claude', {
      session_id: 'no-baseline', hook_event_name: 'Stop', stop_hook_active: false, background_tasks: [],
    }, config())
    expect(output).toEqual({ systemMessage: expect.stringContaining('no exact baseline') })
    expect(JSON.stringify(output)).not.toContain('PASS')
    expect(output).not.toHaveProperty('decision')
    expect(output).not.toHaveProperty('continue')
  })

  it('recovers a stale Stop lock and cleans private objects and locks after a review crash', async () => {
    const root = await repo()
    await writeConfig(root)
    const receipt = join(root, '.codetruss', 'receipts', 'recovered.md')
    await mkdir(join(root, '.codetruss', 'receipts'), { recursive: true })
    await writeFile(receipt, '# recovered\n')
    const prompt = { session_id: 'stale-lock-session', turn_id: 'stale-turn', hook_event_name: 'UserPromptSubmit', prompt: 'Recover review', cwd: root }
    await handleAgentHook(root, 'codex', prompt, config())
    const sessionDir = stateDir(root, 'codex', 'stale-lock-session')
    const current = JSON.parse(await readFile(join(sessionDir, 'current.json'), 'utf8')) as { turnKey: string }
    const turnDir = join(sessionDir, current.turnKey)
    await writeFile(join(turnDir, 'stop.lock'), `${JSON.stringify({ pid: 2_147_483_647, createdAt: '2000-01-01T00:00:00.000Z' })}\n`, { mode: 0o600 })
    const recovered = await handleAgentHook(root, 'codex', { ...prompt, hook_event_name: 'Stop', background_tasks: [] }, config(), {
      runReview: () => ({ status: 0, stdout: `PASS recovered\n${receipt}\n`, stderr: '' }),
    })
    expect(recovered).toBeUndefined()
    await expect(stat(join(turnDir, 'stop.lock'))).rejects.toMatchObject({ code: 'ENOENT' })

    const secondPrompt = { ...prompt, session_id: 'crash-session', turn_id: 'crash-turn', prompt: 'Crash safely' }
    await handleAgentHook(root, 'codex', secondPrompt, config())
    const secondSession = stateDir(root, 'codex', 'crash-session')
    const secondCurrent = JSON.parse(await readFile(join(secondSession, 'current.json'), 'utf8')) as { turnKey: string }
    const secondTurn = join(secondSession, secondCurrent.turnKey)
    const before = JSON.parse(await readFile(join(secondTurn, 'state.json'), 'utf8')) as { baselineCommit: string }
    const failed = await handleAgentHook(root, 'codex', { ...secondPrompt, hook_event_name: 'Stop', background_tasks: [] }, config(), {
      runReview: () => { throw new Error('review process crashed') },
    })
    expect(failed).toEqual({ systemMessage: expect.stringContaining('review process crashed') })
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', before.baselineCommit]).status).not.toBe(0)
    await expect(stat(join(secondTurn, 'object-store'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(join(secondTurn, 'stop.lock'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(handleAgentHook(root, 'codex', { ...secondPrompt, hook_event_name: 'Stop' }, config(), {
      runReview: () => { throw new Error('must not run twice') },
    })).resolves.toBeUndefined()
  }, 30_000)
})
