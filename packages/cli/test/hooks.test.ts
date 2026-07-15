import { createHash, randomUUID } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readFile, readdir, readlink, realpath, rename, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, delimiter, dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { DEFAULT_CONFIG } from '../src/config.js'
import { captureDiffEvidence, changedFiles } from '../src/git.js'
import { createExactHookBaseline } from '../src/hook-baseline.js'
import {
  CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV,
  CODETRUSS_HOOK_CONTEXT_PATH_ENV,
  CODETRUSS_HOOK_CONTEXT_SHA256_ENV,
  CODETRUSS_HOOK_SURFACE_ENV,
  handleAgentHook,
  hookReviewEnvironment,
  readHookTurnContext,
  type HookReviewRequest,
} from '../src/hook-runtime.js'
import { CODETRUSS_HOOK_RESULT_PATH_ENV, CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV } from '../src/hook-result.js'
import { materializeTreeSnapshot, materializeWorkingTreeSnapshot } from '../src/git-snapshot.js'
import { doctorHooks, hookStatus, inspectLocalHookHealth, installHooks, uninstallHooks } from '../src/hooks.js'
import { classifyPath, isDependencyFile, sensitiveCategory } from '../src/policy.js'
import { hookSessionId } from '../src/receipt.js'
import {
  CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV,
  initializePrivateGitObjectStore,
  openPrivateGitObjectStore,
  privateGitReadEnvironment,
  withoutPrivateGitEvidenceEnvironment,
  type PrivateGitObjectStore,
} from '../src/private-git-object-store.js'
import type { CliConfig } from '../src/types.js'

const CLI_ENTRY = fileURLToPath(new URL('../src/cli.ts', import.meta.url))
const TSX_BIN = fileURLToPath(import.meta.resolve('tsx/cli'))
const originalPath = process.env.PATH
let cliShimDirectory = ''

beforeAll(async () => {
  cliShimDirectory = await mkdtemp(join(tmpdir(), 'codetruss-cli-path-shim-'))
  const executable = join(cliShimDirectory, process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
  await writeFile(executable, process.platform === 'win32' ? '@exit /b 0\r\n' : '#!/bin/sh\nexit 0\n')
  await chmod(executable, 0o755)
  process.env.PATH = `${cliShimDirectory}${delimiter}${originalPath ?? ''}`
})

afterAll(async () => {
  if (originalPath === undefined) delete process.env.PATH
  else process.env.PATH = originalPath
  if (cliShimDirectory) await rm(cliShimDirectory, { recursive: true, force: true })
})

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

async function writeHookReviewResult(
  request: HookReviewRequest,
  verdict: 'PASS' | 'REVIEW_REQUIRED' | 'FAILED',
  receiptPath: string,
  reasons: string[] = [],
): Promise<void> {
  await writeFile(request.resultPath, `${JSON.stringify({
    version: 1,
    attemptId: request.attemptId,
    verdict,
    receiptPath,
    reasons,
  })}\n`, { mode: 0o600, flag: 'wx' })
}

async function hookReviewResponse(
  request: HookReviewRequest,
  verdict: 'PASS' | 'REVIEW_REQUIRED' | 'FAILED',
  status: 0 | 1 | 2,
  receiptPath: string,
  reasons: string[] = [],
  stdout = 'verification log noise\n',
  stderr = '',
): Promise<{ status: 0 | 1 | 2; stdout: string; stderr: string }> {
  await writeHookReviewResult(request, verdict, receiptPath, reasons)
  return { status, stdout, stderr }
}

function hookStateRoot(root: string, version: 'v1' | 'v2', repositoryKey: 'short' | 'full'): string {
  const common = git(root, 'rev-parse', '--git-common-dir')
  const commonDir = isAbsolute(common) ? resolve(common) : resolve(root, common)
  const digest = (value: string) => createHash('sha256').update(value).digest('hex')
  const repositoryHash = digest(resolve(root))
  return join(commonDir, 'codetruss', 'hooks', version, repositoryKey === 'short' ? repositoryHash.slice(0, 24) : repositoryHash)
}

function hookStateRootForPath(
  currentRoot: string,
  repositoryPath: string,
  version: 'v1' | 'v2',
  repositoryKey: 'short' | 'full',
): string {
  const common = git(currentRoot, 'rev-parse', '--git-common-dir')
  const commonDir = isAbsolute(common) ? resolve(common) : resolve(currentRoot, common)
  const repositoryHash = createHash('sha256').update(resolve(repositoryPath)).digest('hex')
  return join(commonDir, 'codetruss', 'hooks', version, repositoryKey === 'short' ? repositoryHash.slice(0, 24) : repositoryHash)
}

function stateDir(root: string, surface: 'claude' | 'codex', session: string): string {
  const digest = (value: string) => createHash('sha256').update(value).digest('hex')
  return join(hookStateRoot(root, 'v2', 'short'), surface, digest(session).slice(0, 24))
}

function legacyStateDir(root: string, surface: 'claude' | 'codex', session: string, repositoryKey: 'short' | 'full'): string {
  const digest = (value: string) => createHash('sha256').update(value).digest('hex')
  const sessionHash = digest(session)
  return join(hookStateRoot(root, 'v1', repositoryKey), surface, repositoryKey === 'short' ? sessionHash.slice(0, 24) : sessionHash)
}

async function moveCurrentStateToLegacy(
  root: string,
  surface: 'claude' | 'codex',
  session: string,
  repositoryKey: 'short' | 'full',
): Promise<{ sessionDir: string; turnDir: string; statePath: string; contextPath: string; objectStorePath: string }> {
  const currentSession = stateDir(root, surface, session)
  const current = JSON.parse(await readFile(join(currentSession, 'current.json'), 'utf8')) as { version: 1; turnKey: string; turnId?: string }
  const sourceTurn = join(currentSession, current.turnKey)
  const legacySession = legacyStateDir(root, surface, session, repositoryKey)
  const legacyTurnKey = repositoryKey === 'full' && current.turnId
    ? createHash('sha256').update(`id:${current.turnId}`).digest('hex')
    : current.turnKey
  const legacyTurn = join(legacySession, legacyTurnKey)
  await mkdir(legacySession, { recursive: true, mode: 0o700 })
  await rename(sourceTurn, legacyTurn)
  const statePath = join(legacyTurn, 'state.json')
  const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>
  state.turnKey = legacyTurnKey
  await writeFile(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
  await writeFile(join(legacySession, 'current.json'), `${JSON.stringify({ ...current, turnKey: legacyTurnKey })}\n`, { mode: 0o600 })
  await rm(currentSession, { recursive: true, force: true })
  try {
    await rename(join(legacyTurn, 's'), join(legacyTurn, 'snapshots'))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  return {
    sessionDir: legacySession,
    turnDir: legacyTurn,
    statePath,
    contextPath: join(legacyTurn, 'turn-context.json'),
    objectStorePath: join(legacyTurn, 'object-store'),
  }
}

type MigrationCrashBoundary = 'target-created' | 'selector-temp' | 'selector-written' | 'turn-moved' | 'state-normalized'

async function stageMigrationCrash(
  root: string,
  surface: 'claude' | 'codex',
  session: string,
  boundary: MigrationCrashBoundary,
): Promise<{ legacySession: string; targetSession: string; targetTurn: string }> {
  const legacy = await moveCurrentStateToLegacy(root, surface, session, 'full')
  const current = JSON.parse(await readFile(join(legacy.sessionDir, 'current.json'), 'utf8')) as { version: 1; turnKey: string; turnId?: string }
  const targetSession = stateDir(root, surface, session)
  const targetTurnKey = current.turnKey.slice(0, 24)
  const targetTurn = join(targetSession, targetTurnKey)
  await mkdir(targetSession, { recursive: true, mode: 0o700 })
  if (boundary === 'target-created') return { legacySession: legacy.sessionDir, targetSession, targetTurn }
  if (boundary === 'selector-temp') {
    await writeFile(join(targetSession, `current.json.${process.pid}.123456789abc.tmp`), '{"version":', { mode: 0o600 })
    return { legacySession: legacy.sessionDir, targetSession, targetTurn }
  }
  await writeFile(join(targetSession, 'current.json'), `${JSON.stringify({ ...current, turnKey: targetTurnKey })}\n`, { mode: 0o600 })
  if (boundary === 'selector-written') return { legacySession: legacy.sessionDir, targetSession, targetTurn }
  await rename(legacy.turnDir, targetTurn)
  if (boundary === 'turn-moved') return { legacySession: legacy.sessionDir, targetSession, targetTurn }
  const statePath = join(targetTurn, 'state.json')
  const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>
  state.turnKey = targetTurnKey
  delete state.baselineRef
  await writeFile(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
  return { legacySession: legacy.sessionDir, targetSession, targetTurn }
}

async function privateStore(root: string): Promise<PrivateGitObjectStore> {
  const common = git(root, 'rev-parse', '--git-common-dir')
  const commonDir = isAbsolute(common) ? resolve(common) : resolve(root, common)
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
    expect(runner).toContain("['-c', 'core.longpaths=true', 'rev-parse', '--show-toplevel']")
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

  it('refuses every automatic hook until repository verification commands are trusted', async () => {
    const root = await repo()
    await writeFile(join(root, '.codetruss.yml'), [
      'version: 1',
      'allow:',
      '  - src/**',
      'verify:',
      '  - node -e "process.exit(0)"',
      '',
    ].join('\n'))

    await expect(installHooks(root, 'pre-commit')).rejects.toThrow('hooks require trusted repository verification commands')
    await expect(readFile(join(root, '.git', 'hooks', 'pre-commit'))).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('does not mutate hook files when no persistent CodeTruss CLI is available', async () => {
    const root = await repo()
    await writeConfig(root)
    const savedPath = process.env.PATH
    process.env.PATH = ''
    try {
      await expect(installHooks(root, 'all')).rejects.toThrow('require a persistent CodeTruss CLI')
    } finally {
      process.env.PATH = savedPath
    }
    await expect(readFile(join(root, '.git', 'hooks', 'pre-commit'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(readFile(join(root, '.claude', 'settings.json'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(readFile(join(root, '.codex', 'hooks.json'))).rejects.toMatchObject({ code: 'ENOENT' })
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
    expect(hook).toContain('git -c core.longpaths=true rev-parse --show-toplevel')
    expect(hook).toContain('review --staged --task "pre-commit"')
    expect(hook).toContain('CODETRUSS_INTERNAL_PRE_COMMIT=1')
    expect(hook).not.toContain('--no-verify')
    await installHooks(root, 'pre-commit')
    const reinstalled = await readFile(path, 'utf8')
    expect(reinstalled).toBe(hook)
    expect(reinstalled.match(/codetruss-agent-guard:begin/g)).toHaveLength(1)
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
    const installedDocument = JSON.parse(await readFile(path, 'utf8')) as {
      hooks: Record<string, Array<{ hooks: Array<{ command?: string; commandWindows?: string }> }>>
    }
    for (const event of ['UserPromptSubmit', 'PostToolUse', 'Stop']) {
      const handler = installedDocument.hooks[event].flatMap((group) => group.hooks)
        .find((candidate) => candidate.command?.includes('.codetruss/hooks/agent.cjs'))
      expect(handler?.command).toContain('git -c core.longpaths=true rev-parse --show-toplevel')
      expect(handler?.commandWindows).toContain('git -c core.longpaths=true rev-parse --show-toplevel')
    }
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

  it('diagnoses an exact healthy installation and fails when executable hook code drifts', async () => {
    const root = await repo()
    await writeConfig(root)
    const bin = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
    await mkdir(dirname(bin), { recursive: true })
    await writeFile(bin, process.platform === 'win32' ? '@exit /b 0\r\n' : '#!/bin/sh\nexit 0\n')
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
      await expect(inspectLocalHookHealth(root)).resolves.toEqual({
        preCommit: 'healthy',
        claude: 'healthy',
        codex: 'warning',
      })

      await writeFile(join(root, '.codetruss', 'hooks', 'agent.cjs'), 'module.exports = "changed"\n')
      const unhealthy = await doctorHooks(root, 'codex')
      expect(unhealthy.ok).toBe(false)
      expect(unhealthy.checks).toContainEqual(expect.objectContaining({
        level: 'error', target: 'agent-runtime', message: expect.stringContaining('differs from this CLI version'),
      }))
      await expect(inspectLocalHookHealth(root)).resolves.toEqual({
        preCommit: 'healthy',
        claude: 'unhealthy',
        codex: 'unhealthy',
      })
    } finally {
      output.mockRestore()
    }
  })

  it('keeps pre-commit-only health independent from agent scope while reporting verification trust', async () => {
    const root = await repo()
    const bin = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
    await mkdir(dirname(bin), { recursive: true })
    await writeFile(bin, process.platform === 'win32' ? '@exit /b 0\r\n' : '#!/bin/sh\nexit 0\n')
    await chmod(bin, 0o755)
    await installHooks(root, 'pre-commit')

    await expect(inspectLocalHookHealth(root)).resolves.toEqual({
      preCommit: 'healthy',
      claude: 'not_installed',
      codex: 'not_installed',
    })

    await writeFile(join(root, '.codetruss.yml'), 'version: 1\nallow: []\ndeny: []\nverify:\n  - node --version\n')
    await expect(inspectLocalHookHealth(root)).resolves.toEqual({
      preCommit: 'unhealthy',
      claude: 'not_installed',
      codex: 'not_installed',
    })
  })

  it('reports partial and malformed agent hook definitions as unhealthy', async () => {
    const root = await repo()
    await writeConfig(root)
    const bin = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
    await mkdir(dirname(bin), { recursive: true })
    await writeFile(bin, process.platform === 'win32' ? '@exit /b 0\r\n' : '#!/bin/sh\nexit 0\n')
    await chmod(bin, 0o755)
    await installHooks(root, 'all')
    const path = join(root, '.codex', 'hooks.json')
    const partial = JSON.parse(await readFile(path, 'utf8')) as { hooks: Record<string, unknown> }
    delete partial.hooks.Stop
    await writeFile(path, `${JSON.stringify(partial)}\n`)
    await expect(inspectLocalHookHealth(root)).resolves.toMatchObject({ codex: 'unhealthy' })

    await writeFile(path, '{"marker":".codetruss/hooks/agent.cjs"')
    await expect(inspectLocalHookHealth(root)).resolves.toMatchObject({ codex: 'unhealthy' })
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

  it.runIf(process.platform !== 'win32')('blocks once when the installed Stop runner cannot dispatch', async () => {
    const root = await repo('codetruss-installed-stop-failure-')
    await writeConfig(root)
    await installHooks(root, 'codex')
    const bin = join(root, 'node_modules', '.bin', 'codetruss')
    await mkdir(dirname(bin), { recursive: true })
    await writeFile(bin, '#!/bin/sh\ncat >/dev/null\necho simulated-dispatch-failure >&2\nexit 3\n')
    await chmod(bin, 0o755)
    const runner = join(root, '.codetruss', 'hooks', 'agent.cjs')
    const invoke = (stopHookActive: boolean) => spawnSync(process.execPath, [runner, 'codex'], {
      cwd: root,
      input: JSON.stringify({
        session_id: 'installed-runner-failure',
        turn_id: 'installed-runner-failure-turn',
        hook_event_name: 'Stop',
        stop_hook_active: stopHookActive,
      }),
      encoding: 'utf8',
    })

    const first = invoke(false)
    expect(first.status, first.stderr).toBe(0)
    expect(JSON.parse(first.stdout)).toEqual({
      decision: 'block',
      reason: expect.stringContaining('simulated-dispatch-failure'),
    })
    const continuation = invoke(true)
    expect(continuation.status, continuation.stderr).toBe(0)
    expect(JSON.parse(continuation.stdout)).toEqual({
      systemMessage: expect.stringContaining('simulated-dispatch-failure'),
    })
  })
})

describe('exact immutable hook snapshots', () => {
  it.runIf(process.platform !== 'win32')('canonicalizes an equivalent repository path alias before enforcing private-store containment', async () => {
    const root = await repo('codetruss-object-alias-source-')
    const alias = join(tmpdir(), `codetruss-object-alias-${randomUUID()}`)
    await symlink(root, alias, 'dir')
    const aliasedStore = join(alias, '.git', 'codetruss', 'alias-test', randomUUID(), 'object-store')
    const store = await initializePrivateGitObjectStore(root, aliasedStore)
    try {
      expect(store.directory).toBe(await realpath(aliasedStore))
      await expect(stat(join(store.objectDirectory, 'info'))).resolves.toBeDefined()
    } finally {
      await store.cleanup()
      await rm(alias, { force: true })
    }
  })

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
      CODETRUSS_INTERNAL_PRE_COMMIT: '1',
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
      [CODETRUSS_HOOK_SURFACE_ENV]: 'codex',
      CODETRUSS_HOOK_START_COMMIT: git(root, 'rev-parse', 'HEAD'),
      CODETRUSS_HOOK_END_COMMIT: git(root, 'rev-parse', 'HEAD'),
      CODETRUSS_HOOK_STARTED_AT: '2026-07-14T10:00:00.000Z',
      [CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV]: store.objectDirectory,
      [CODETRUSS_HOOK_CONTEXT_PATH_ENV]: contextPath,
      [CODETRUSS_HOOK_CONTEXT_SHA256_ENV]: contextSha256,
      [CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV]: createHash('sha256').update(JSON.stringify(baseline.dirtyFiles)).digest('hex'),
    }
    const mismatchedTask = spawnSync(process.execPath, [
      TSX_BIN, CLI_ENTRY, 'review', '--task', 'Substituted task',
      '--base', baseline.commit, '--final', final.commit,
    ], { cwd: root, encoding: 'utf8', env: reviewEnvironment, maxBuffer: 8 * 1024 * 1024 })
    expect(mismatchedTask.status).toBe(3)
    expect(mismatchedTask.stderr).toContain('does not match the authenticated prompt-time task')
    const result = spawnSync(process.execPath, [
      TSX_BIN, CLI_ENTRY, 'review', '--task', 'Update the draft value',
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
  it('authenticates pending legacy hook context with deprecated codex provider data', async () => {
    const root = await repo('codetruss-hook-legacy-codex-context-')
    const path = join(root, '.git', 'legacy-hook-context.json')
    const legacyConfig = structuredClone(config()) as unknown as { llm: { provider?: string } }
    legacyConfig.llm.provider = 'codex'
    const text = `${JSON.stringify({
      version: 1,
      task: 'Load a pending legacy Codex provider context',
      config: legacyConfig,
      baselineDirtyFiles: [],
    })}\n`
    await writeFile(path, text, { mode: 0o600 })
    const sha256 = createHash('sha256').update(text).digest('hex')

    await expect(readHookTurnContext(path, sha256)).resolves.toMatchObject({
      task: 'Load a pending legacy Codex provider context',
      config: { llm: { provider: 'codex' } },
    })
  })

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

  it('fails closed on a cross-session current selector and leaves the targeted session untouched', async () => {
    const root = await repo('codetruss-hook-cross-session-selector-')
    const sessionA = 'selector-session-a'
    const sessionB = 'selector-session-b'
    const promptA = {
      session_id: sessionA,
      turn_id: 'selector-turn-a',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Capture A',
      cwd: root,
    }
    const promptB = {
      ...promptA,
      session_id: sessionB,
      turn_id: 'selector-turn-b',
      prompt: 'Capture B',
    }
    await handleAgentHook(root, 'codex', promptA, config())
    await handleAgentHook(root, 'codex', promptB, config())
    const aDir = stateDir(root, 'codex', sessionA)
    const bDir = stateDir(root, 'codex', sessionB)
    const bCurrent = JSON.parse(await readFile(join(bDir, 'current.json'), 'utf8')) as { turnKey: string }
    const bTurn = join(bDir, bCurrent.turnKey)
    const bStateBefore = await readFile(join(bTurn, 'state.json'), 'utf8')
    const bContextBefore = await readFile(join(bTurn, 'turn-context.json'), 'utf8')
    await writeFile(join(aDir, 'current.json'), `${JSON.stringify({
      version: 1,
      turnKey: `../${basename(bDir)}/${bCurrent.turnKey}`,
      turnId: promptA.turn_id,
    })}\n`, { mode: 0o600 })
    const runReview = vi.fn()

    const output = await handleAgentHook(root, 'codex', { ...promptA, hook_event_name: 'Stop' }, config(), { runReview })

    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining('invalid current selector') })
    expect(runReview).not.toHaveBeenCalled()
    expect(await readFile(join(bTurn, 'state.json'), 'utf8')).toBe(bStateBefore)
    expect(await readFile(join(bTurn, 'turn-context.json'), 'utf8')).toBe(bContextBefore)
    await expect(stat(join(bTurn, 'object-store'))).resolves.toBeDefined()
  })

  it.each([
    ['an unknown field', (current: Record<string, unknown>) => ({ ...current, unexpected: true })],
    ['an oversized turn id', (current: Record<string, unknown>) => ({ ...current, turnId: 'x'.repeat(1_025) })],
  ] as const)('rejects an otherwise valid current selector with %s', async (_name, mutate) => {
    const root = await repo('codetruss-hook-exact-selector-')
    const prompt = {
      session_id: `exact-selector-${_name}`,
      turn_id: 'exact-selector-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Require an exact bounded selector',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const session = stateDir(root, 'codex', prompt.session_id)
    const currentPath = join(session, 'current.json')
    const current = JSON.parse(await readFile(currentPath, 'utf8')) as Record<string, unknown>
    const statePath = join(session, String(current.turnKey), 'state.json')
    const stateBefore = await readFile(statePath, 'utf8')
    await writeFile(currentPath, `${JSON.stringify(mutate(current))}\n`, { mode: 0o600 })
    const runReview = vi.fn()

    const output = await handleAgentHook(root, 'codex', { ...prompt, hook_event_name: 'Stop' }, config(), { runReview })

    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining('invalid current selector') })
    expect(runReview).not.toHaveBeenCalled()
    expect(await readFile(statePath, 'utf8')).toBe(stateBefore)
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
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      requests.push(request)
      const environment = privateGitReadEnvironment(request.objectDirectory)
      expect(gitWithEnvironment(root, environment, 'show', `${request.baselineRef}:src/value.ts`)).toBe('export const value = "before"')
      expect(gitWithEnvironment(root, environment, 'show', `${request.finalRef}:src/value.ts`)).toBe('export const value = "after"')
      const session = stateDir(root, 'codex', 'session-stop')
      const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
      const persisted = JSON.parse(await readFile(join(session, current.turnKey, 'state.json'), 'utf8')) as Record<string, unknown>
      expect(persisted).toMatchObject({
        status: 'reviewing',
        finalCommit: request.finalRef,
        finalHead: request.finalHead,
        reviewAttemptId: request.attemptId,
      })
      return hookReviewResponse(request, 'PASS', 0, receipt)
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
      surface: 'codex',
      startCommit: git(root, 'rev-parse', 'HEAD'),
      finalHead: git(root, 'rev-parse', 'HEAD'),
      startedAt: startedAt.toISOString(),
      context: { task: 'Change the value', config: { allow: ['src/**'] } },
    })
    expect(requests[0].baselineDirtyFiles).toContain('src/value.ts')
    expect(requests[0].resultPath).toBe(join(
      stateDir(root, 'codex', 'session-stop'),
      createHash('sha256').update('id:turn-1').digest('hex').slice(0, 24),
      'review-results',
      `${requests[0].attemptId}.json`,
    ))
    await expect(readHookTurnContext(requests[0].contextPath, requests[0].contextSha256)).rejects.toMatchObject({ code: 'ENOENT' })
    expect(hookReviewEnvironment(requests[0], {} as NodeJS.ProcessEnv)).toEqual({
      CODETRUSS_INTERNAL_HOOK: '1',
      [CODETRUSS_HOOK_SURFACE_ENV]: 'codex',
      CODETRUSS_HOOK_START_COMMIT: git(root, 'rev-parse', 'HEAD'),
      CODETRUSS_HOOK_END_COMMIT: git(root, 'rev-parse', 'HEAD'),
      CODETRUSS_HOOK_STARTED_AT: startedAt.toISOString(),
      [CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV]: requests[0].objectDirectory,
      [CODETRUSS_HOOK_CONTEXT_PATH_ENV]: requests[0].contextPath,
      [CODETRUSS_HOOK_CONTEXT_SHA256_ENV]: requests[0].contextSha256,
      [CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV]: createHash('sha256').update(JSON.stringify(requests[0].baselineDirtyFiles)).digest('hex'),
      [CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV]: requests[0].attemptId,
      [CODETRUSS_HOOK_RESULT_PATH_ENV]: requests[0].resultPath,
    })
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', requests[0].baselineRef]).status).not.toBe(0)
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', requests[0].baselineRef], { env: privateGitReadEnvironment(requests[0].objectDirectory) }).status).not.toBe(0)
  })

  it('resumes reviewing with the persisted final OID and deterministic attempt instead of recapturing a later tree', async () => {
    const root = await repo('codetruss-hook-review-resume-')
    await mkdir(join(root, 'src'), { recursive: true })
    await writeFile(join(root, 'src', 'value.ts'), 'baseline\n')
    const prompt = {
      session_id: 'review-resume-session',
      turn_id: 'review-resume-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Review one immutable final tree',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const session = stateDir(root, 'codex', prompt.session_id)
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    const turnDir = join(session, current.turnKey)
    const statePath = join(turnDir, 'state.json')
    const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>
    await writeFile(join(root, 'src', 'value.ts'), 'persisted final\n')
    const store = await openPrivateGitObjectStore(root, join(turnDir, 'object-store'))
    const final = await createExactHookBaseline(root, join(turnDir, 'manual-final'), store)
    const attemptId = createHash('sha256').update([
      'codetruss-hook-review-v1',
      state.surface,
      state.sessionHash,
      state.worktreeIdentity,
      state.turnId ? `id:${String(state.turnId)}` : `key:${String(state.turnKey).slice(0, 24)}`,
      state.baselineCommit ?? '',
      final.commit,
      final.head,
      state.contextSha256 ?? '',
      state.createdAt,
    ].join('\0')).digest('hex')
    Object.assign(state, {
      status: 'reviewing',
      finalCommit: final.commit,
      finalHead: final.head,
      reviewAttemptId: attemptId,
    })
    await writeFile(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    await writeFile(join(root, 'src', 'value.ts'), 'later unreviewed tree\n')
    const receipt = join(
      root,
      '.codetruss',
      'receipts',
      `${hookSessionId(new Date(String(state.createdAt)), attemptId)}.md`,
    )
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, '# resumed\n')
    const resultParent = join(turnDir, 'review-results')
    const resultPath = join(resultParent, `${attemptId}.json`)
    await mkdir(resultParent, { recursive: true, mode: 0o700 })
    await writeFile(resultPath, `${JSON.stringify({
      version: 1,
      attemptId,
      verdict: 'PASS',
      receiptPath: receipt,
      reasons: ['durable result survived the hook crash'],
    })}\n`, { mode: 0o600 })
    const captureBaseline = vi.fn(() => { throw new Error('must not recapture a reviewing turn') })
    const runReview = vi.fn(() => { throw new Error('must not rerun an attempt with a durable result') })

    await expect(handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { captureBaseline, runReview })).resolves.toBeUndefined()

    expect(captureBaseline).not.toHaveBeenCalled()
    expect(runReview).not.toHaveBeenCalled()
    await expect(stat(resultParent)).rejects.toMatchObject({ code: 'ENOENT' })
  }, 30_000)

  it('keeps a pre-final-capture failure ready so the next Stop can recapture and complete', async () => {
    const root = await repo('codetruss-hook-final-capture-retry-')
    const receipt = join(root, '.codetruss', 'receipts', 'final-capture-retry.md')
    await mkdir(join(root, 'src'), { recursive: true })
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(join(root, 'src', 'value.ts'), 'before\n')
    await writeFile(receipt, '# recovered capture\n')
    const prompt = {
      session_id: 'final-capture-retry-session',
      turn_id: 'final-capture-retry-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Retry a transient final snapshot failure',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    await writeFile(join(root, 'src', 'value.ts'), 'after\n')
    let captureCalls = 0
    const captureBaseline = vi.fn(async (
      captureRoot: string,
      snapshotParent: string,
      objectStore: PrivateGitObjectStore,
    ) => {
      captureCalls += 1
      if (captureCalls === 1) throw new Error('transient final capture failure')
      return createExactHookBaseline(captureRoot, snapshotParent, objectStore)
    })
    const runReview = vi.fn((request: HookReviewRequest) => hookReviewResponse(request, 'PASS', 0, receipt))
    const stop = { ...prompt, hook_event_name: 'Stop', background_tasks: [] }

    const first = await handleAgentHook(root, 'codex', stop, config(), { captureBaseline, runReview })
    expect(first).toEqual({ decision: 'block', reason: expect.stringContaining('transient final capture failure') })
    expect(runReview).not.toHaveBeenCalled()
    const session = stateDir(root, 'codex', prompt.session_id)
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    const statePath = join(session, current.turnKey, 'state.json')
    expect(JSON.parse(await readFile(statePath, 'utf8'))).toMatchObject({ status: 'ready' })
    expect(await readFile(statePath, 'utf8')).not.toContain('finalCommit')

    await expect(handleAgentHook(root, 'codex', stop, config(), {
      captureBaseline,
      runReview,
    })).resolves.toBeUndefined()
    expect(captureBaseline).toHaveBeenCalledTimes(2)
    expect(runReview).toHaveBeenCalledTimes(1)
    expect(JSON.parse(await readFile(statePath, 'utf8'))).toMatchObject({
      status: 'completed',
      result: { verdict: 'PASS' },
    })
  }, 30_000)

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
        runReview: (request) => hookReviewResponse(request, verdict, status, receipt, ['protocol reason']),
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

  it('replays every persisted Stop verdict without rerunning review', async () => {
    const root = await repo('codetruss-hook-stop-replay-')
    await mkdir(join(root, '.codetruss', 'receipts'), { recursive: true })
    for (const [verdict, status] of [
      ['PASS', 0],
      ['REVIEW_REQUIRED', 1],
      ['FAILED', 2],
    ] as const) {
      const receipt = join(root, '.codetruss', 'receipts', `replay-${verdict}.md`)
      await writeFile(receipt, `# ${verdict}\n`)
      const prompt = {
        session_id: `replay-${verdict}`,
        turn_id: `replay-${verdict}-turn`,
        hook_event_name: 'UserPromptSubmit',
        prompt: `Persist ${verdict}`,
        cwd: root,
      }
      await handleAgentHook(root, 'codex', prompt, config())
      const runReview = vi.fn((request: HookReviewRequest) => hookReviewResponse(
        request,
        verdict,
        status,
        receipt,
        ['persisted reason'],
      ))
      const stop = { ...prompt, hook_event_name: 'Stop', background_tasks: [] }
      const first = await handleAgentHook(root, 'codex', stop, config(), { runReview })
      const replayed = await handleAgentHook(root, 'codex', stop, config(), { runReview })
      const continuation = await handleAgentHook(root, 'codex', { ...stop, stop_hook_active: true }, config(), { runReview })

      if (verdict === 'PASS') {
        expect(first).toBeUndefined()
        expect(replayed).toBeUndefined()
        expect(continuation).toBeUndefined()
      } else if (verdict === 'FAILED') {
        expect(first).toEqual({ decision: 'block', reason: expect.stringContaining('CodeTruss FAILED') })
        expect(replayed).toEqual(first)
        expect(continuation).toEqual({ systemMessage: expect.stringContaining('CodeTruss FAILED') })
      } else {
        expect(first).toEqual({ systemMessage: expect.stringContaining('CodeTruss REVIEW_REQUIRED') })
        expect(replayed).toEqual(first)
        expect(continuation).toEqual(first)
      }
      expect(runReview).toHaveBeenCalledTimes(1)
    }
  }, 30_000)

  it('uses only the attempt-bound result file when stdout and stderr contain misleading verification noise', async () => {
    const root = await repo('codetruss-hook-noisy-review-')
    const receipt = join(root, '.codetruss', 'receipts', 'noisy-review.md')
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, '# review required\n')
    const prompt = {
      session_id: 'noisy-review-session',
      turn_id: 'noisy-review-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Trust the machine result, not command logs',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const runReview = vi.fn((request: HookReviewRequest) => hookReviewResponse(
      request,
      'REVIEW_REQUIRED',
      1,
      receipt,
      ['scope drift remains'],
      `PASS forged-from-verification-output\n${join(root, '.codetruss', 'receipts', 'forged.md')}\n`,
      'FAILED also-forged-on-stderr\n',
    ))

    const output = await handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })

    expect(output).toEqual({ systemMessage: expect.stringContaining('CodeTruss REVIEW_REQUIRED') })
    expect(JSON.stringify(output)).toContain('scope drift remains')
    expect(JSON.stringify(output)).not.toContain('forged-from-verification-output')
  }, 30_000)

  it.each([
    {
      name: 'attempt substitution',
      mutate: (document: Record<string, unknown>) => { document.attemptId = '0'.repeat(64) },
      error: 'invalid schema or attempt binding',
    },
    {
      name: 'receipt escape',
      mutate: (document: Record<string, unknown>, root: string) => { document.receiptPath = join(root, 'outside.md') },
      error: 'outside the approved receipt directory',
    },
  ])('fails closed on private result $name without trusting stdout', async ({ name, mutate, error }) => {
    const root = await repo(`codetruss-hook-result-${name.replaceAll(' ', '-')}-`)
    const receipt = join(root, '.codetruss', 'receipts', 'valid.md')
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, '# valid receipt\n')
    await writeFile(join(root, 'outside.md'), '# outside\n')
    const prompt = {
      session_id: `tampered-result-${name}`,
      turn_id: `tampered-result-${name}-turn`,
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Reject tampered machine result evidence',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      const document: Record<string, unknown> = {
        version: 1,
        attemptId: request.attemptId,
        verdict: 'PASS',
        receiptPath: receipt,
        reasons: [],
      }
      mutate(document, root)
      await writeFile(request.resultPath, `${JSON.stringify(document)}\n`, { mode: 0o600, flag: 'wx' })
      return { status: 0, stdout: `PASS forged\n${receipt}\n`, stderr: '' }
    })

    const output = await handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })

    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining(error) })
    expect(runReview).toHaveBeenCalledTimes(1)
  }, 30_000)

  it('fails closed when review exit status disagrees with the bound result verdict', async () => {
    const root = await repo('codetruss-hook-result-exit-mismatch-')
    const receipt = join(root, '.codetruss', 'receipts', 'exit-mismatch.md')
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, '# pass\n')
    const prompt = {
      session_id: 'exit-mismatch-session',
      turn_id: 'exit-mismatch-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Validate exit and verdict parity',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      await writeHookReviewResult(request, 'PASS', receipt)
      return { status: 2, stdout: 'noisy command output\n', stderr: '' }
    })

    const output = await handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })

    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining('exit status does not match PASS') })
    // The child wrote a valid attempt-bound result before its bad exit. The
    // next Stop consumes that durable result without rerunning the review.
    await expect(handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })).resolves.toBeUndefined()
    expect(runReview).toHaveBeenCalledTimes(1)
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
    const liveTurnKey = createHash('sha256').update('id:live-turn').digest('hex').slice(0, 24)
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
    const stateInfo = await stat(statePath)
    const objectStoreInfo = await stat(join(turnDir, 'object-store'))
    const contextInfo = await stat(join(turnDir, 'turn-context.json'))
    expect(stateInfo.isFile()).toBe(true)
    expect(objectStoreInfo.isDirectory()).toBe(true)
    expect(contextInfo.isFile()).toBe(true)
    if (process.platform !== 'win32') {
      expect(stateInfo.mode & 0o777).toBe(0o600)
      expect(objectStoreInfo.mode & 0o777).toBe(0o700)
      expect(contextInfo.mode & 0o777).toBe(0o600)
    }
    expect(git(root, 'status', '--porcelain')).not.toContain('codetruss/hooks')
    const failed = await handleAgentHook(root, 'claude', { ...prompt, session_id: 'failed-session', prompt_id: 'prompt-fail' }, config(), {
      captureBaseline: async () => { throw new Error('unstable working tree') },
    })
    expect(failed).toEqual({ decision: 'block', reason: expect.stringContaining('unstable working tree') })
  })

  it('hashes maximum-length agent identifiers into path-budgeted hook state', async () => {
    const root = await repo('codetruss-hook-path-budget-')
    const sessionId = 's'.repeat(8_000)
    const turnId = 't'.repeat(1_024)
    const prompt = {
      session_id: sessionId,
      turn_id: turnId,
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Capture without putting raw agent identifiers on disk',
      cwd: root,
    }
    await expect(handleAgentHook(root, 'codex', prompt, config())).resolves.toBeUndefined()
    const session = stateDir(root, 'codex', sessionId)
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    expect(basename(session)).toMatch(/^[0-9a-f]{24}$/)
    expect(current.turnKey).toMatch(/^[0-9a-f]{24}$/)
    expect(session).not.toContain(sessionId)
    await expect(stat(join(session, current.turnKey, 'object-store', 'objects'))).resolves.toBeDefined()
  })

  it.each(['full', 'short'] as const)('migrates resumable v1 %s-key evidence into v2 and removes every private artifact after Stop', async (repositoryKey) => {
    const root = await repo(`codetruss-hook-migrate-${repositoryKey}-`)
    const session = `legacy-${repositoryKey}-session`
    const prompt = {
      session_id: session,
      turn_id: `legacy-${repositoryKey}-turn`,
      hook_event_name: 'UserPromptSubmit',
      prompt: `private ${repositoryKey} migration task`,
      cwd: root,
    }
    await expect(handleAgentHook(root, 'codex', prompt, config())).resolves.toBeUndefined()
    const legacy = await moveCurrentStateToLegacy(root, 'codex', session, repositoryKey)
    const receipt = join(root, '.codetruss', 'receipts', `migrated-${repositoryKey}.md`)
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, '# migrated\n')
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      expect(request.task).toBe(`private ${repositoryKey} migration task`)
      expect(request.objectDirectory).toContain(join('hooks', 'v2'))
      return hookReviewResponse(request, 'PASS', 0, receipt)
    })

    await expect(handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })).resolves.toBeUndefined()

    expect(runReview).toHaveBeenCalledTimes(1)
    await expect(stat(legacy.sessionDir)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(hookStateRoot(root, 'v1', 'full'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(hookStateRoot(root, 'v1', 'short'))).rejects.toMatchObject({ code: 'ENOENT' })
    const migratedSession = stateDir(root, 'codex', session)
    const current = JSON.parse(await readFile(join(migratedSession, 'current.json'), 'utf8')) as { turnKey: string }
    expect(current.turnKey).toMatch(/^[0-9a-f]{24}$/)
    const migratedTurn = join(migratedSession, current.turnKey)
    const migratedState = JSON.parse(await readFile(join(migratedTurn, 'state.json'), 'utf8')) as Record<string, unknown>
    expect(migratedState).toMatchObject({ status: 'completed', turnKey: current.turnKey })
    expect(migratedState.task).toBeUndefined()
    for (const name of ['object-store', 'turn-context.json', 's', 'f', 'snapshots', 'final-snapshots', 'review-results']) {
      await expect(stat(join(migratedTurn, name))).rejects.toMatchObject({ code: 'ENOENT' })
    }
  }, 30_000)

  it('prefers released v1 full-key evidence and securely removes a colliding short-key candidate session', async () => {
    const root = await repo('codetruss-hook-legacy-collision-')
    const session = 'legacy-collision-session'
    const basePrompt = {
      session_id: session,
      turn_id: 'legacy-collision-turn',
      hook_event_name: 'UserPromptSubmit',
      cwd: root,
    }
    const releasedPrompt = { ...basePrompt, prompt: 'released full-key task' }
    await handleAgentHook(root, 'codex', releasedPrompt, config())
    await moveCurrentStateToLegacy(root, 'codex', session, 'full')
    const fullRoot = hookStateRoot(root, 'v1', 'full')
    const holdingRoot = `${fullRoot}.holding`
    await rename(fullRoot, holdingRoot)
    const candidatePrompt = { ...basePrompt, prompt: 'unpublished short-key task' }
    await handleAgentHook(root, 'codex', candidatePrompt, config())
    const candidate = await moveCurrentStateToLegacy(root, 'codex', session, 'short')
    await rename(holdingRoot, fullRoot)
    const receipt = join(root, '.codetruss', 'receipts', 'legacy-collision.md')
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, '# collision\n')
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      expect(request.task).toBe('released full-key task')
      return hookReviewResponse(request, 'PASS', 0, receipt)
    })

    await expect(handleAgentHook(root, 'codex', {
      ...releasedPrompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })).resolves.toBeUndefined()

    expect(runReview).toHaveBeenCalledTimes(1)
    await expect(stat(candidate.sessionDir)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(hookStateRoot(root, 'v1', 'full'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(hookStateRoot(root, 'v1', 'short'))).rejects.toMatchObject({ code: 'ENOENT' })
    const currentSession = stateDir(root, 'codex', session)
    const current = JSON.parse(await readFile(join(currentSession, 'current.json'), 'utf8')) as { turnKey: string }
    const finalState = JSON.parse(await readFile(join(currentSession, current.turnKey, 'state.json'), 'utf8')) as Record<string, unknown>
    expect(finalState.status).toBe('completed')
    expect(finalState.task).toBeUndefined()
  }, 30_000)

  it.each([
    'target-created',
    'selector-temp',
    'selector-written',
    'turn-moved',
    'state-normalized',
  ] as const)('recovers the %s migration crash boundary and reviews the preserved baseline exactly once', async (boundary) => {
    const root = await repo(`codetruss-hook-migration-crash-${boundary}-`)
    const session = `migration-crash-${boundary}`
    const prompt = {
      session_id: session,
      turn_id: `migration-crash-${boundary}-turn`,
      hook_event_name: 'UserPromptSubmit',
      prompt: `preserve ${boundary} baseline`,
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const crash = await stageMigrationCrash(root, 'codex', session, boundary)
    const receipt = join(root, '.codetruss', 'receipts', `${boundary}.md`)
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, `# ${boundary}\n`)
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      expect(request.task).toBe(`preserve ${boundary} baseline`)
      return hookReviewResponse(request, 'PASS', 0, receipt)
    })

    await expect(handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })).resolves.toBeUndefined()
    await expect(handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })).resolves.toBeUndefined()

    expect(runReview).toHaveBeenCalledTimes(1)
    await expect(stat(crash.legacySession)).rejects.toMatchObject({ code: 'ENOENT' })
    const current = JSON.parse(await readFile(join(crash.targetSession, 'current.json'), 'utf8')) as { turnKey: string }
    const state = JSON.parse(await readFile(join(crash.targetSession, current.turnKey, 'state.json'), 'utf8')) as Record<string, unknown>
    expect(state).toMatchObject({ status: 'completed', turnKey: current.turnKey })
    expect(state.task).toBeUndefined()
    await expect(stat(join(crash.targetTurn, 'object-store'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(hookStateRoot(root, 'v1', 'full'))).rejects.toMatchObject({ code: 'ENOENT' })
  }, 30_000)

  it.each([
    'target-created',
    'selector-temp',
    'selector-written',
    'turn-moved',
    'state-normalized',
  ] as const)('recovers the %s crash boundary after a subsequent repository move and reviews exactly once', async (boundary) => {
    const originalRoot = await repo(`codetruss-hook-composed-crash-${boundary}-`)
    const session = `composed-crash-${boundary}`
    const prompt = {
      session_id: session,
      turn_id: `composed-crash-${boundary}-turn`,
      hook_event_name: 'UserPromptSubmit',
      prompt: `preserve composed ${boundary} baseline`,
      cwd: originalRoot,
    }
    await handleAgentHook(originalRoot, 'codex', prompt, config())
    await stageMigrationCrash(originalRoot, 'codex', session, boundary)
    const movedRoot = `${originalRoot}-moved`
    await rename(originalRoot, movedRoot)
    const oldV1Root = hookStateRootForPath(movedRoot, originalRoot, 'v1', 'full')
    const oldV2Root = hookStateRootForPath(movedRoot, originalRoot, 'v2', 'short')
    const receipt = join(movedRoot, '.codetruss', 'receipts', `composed-${boundary}.md`)
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, `# composed ${boundary}\n`)
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      expect(request.task).toBe(`preserve composed ${boundary} baseline`)
      return hookReviewResponse(request, 'PASS', 0, receipt)
    })
    const stop = { ...prompt, cwd: movedRoot, hook_event_name: 'Stop', background_tasks: [] }

    await expect(handleAgentHook(movedRoot, 'codex', stop, config(), { runReview })).resolves.toBeUndefined()
    await expect(handleAgentHook(movedRoot, 'codex', stop, config(), { runReview })).resolves.toBeUndefined()

    expect(runReview).toHaveBeenCalledTimes(1)
    await expect(stat(oldV1Root)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(oldV2Root)).rejects.toMatchObject({ code: 'ENOENT' })
    const migratedSession = stateDir(movedRoot, 'codex', session)
    const current = JSON.parse(await readFile(join(migratedSession, 'current.json'), 'utf8')) as { turnKey: string }
    const state = JSON.parse(await readFile(join(migratedSession, current.turnKey, 'state.json'), 'utf8')) as Record<string, unknown>
    expect(state).toMatchObject({ status: 'completed', turnKey: current.turnKey })
    expect(state.task).toBeUndefined()
  }, 30_000)

  it('fails closed and preserves both sides of an unknown mixed migration target', async () => {
    const root = await repo('codetruss-hook-migration-mixed-')
    const session = 'migration-mixed-session'
    const prompt = {
      session_id: session,
      turn_id: 'migration-mixed-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'preserve mixed migration evidence',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const crash = await stageMigrationCrash(root, 'codex', session, 'selector-written')
    const unknown = join(crash.targetSession, 'unknown-turn')
    await mkdir(unknown, { recursive: true })
    await writeFile(join(unknown, 'private.txt'), 'must remain\n')
    const runReview = vi.fn()

    const output = await handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })

    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining('migration is incomplete') })
    expect(runReview).not.toHaveBeenCalled()
    await expect(stat(join(crash.legacySession, createHash('sha256').update('id:migration-mixed-turn').digest('hex'), 'object-store'))).resolves.toBeDefined()
    expect(await readFile(join(unknown, 'private.txt'), 'utf8')).toBe('must remain\n')
  }, 30_000)

  it('fails closed without draining divergent equal-priority v2 roots for the same session and turn', async () => {
    const root = await repo('codetruss-hook-divergent-v2-')
    const session = 'divergent-v2-session'
    const basePrompt = {
      session_id: session,
      turn_id: 'divergent-v2-turn',
      hook_event_name: 'UserPromptSubmit',
      cwd: root,
    }
    const firstPrompt = { ...basePrompt, prompt: 'first divergent task' }
    await handleAgentHook(root, 'codex', firstPrompt, config())
    const versionDir = dirname(hookStateRoot(root, 'v2', 'short'))
    const firstRoot = join(versionDir, createHash('sha256').update('relocated-v2-one').digest('hex').slice(0, 24))
    await rename(hookStateRoot(root, 'v2', 'short'), firstRoot)
    const holdingRoot = `${firstRoot}.holding`
    await rename(firstRoot, holdingRoot)
    const secondPrompt = { ...basePrompt, prompt: 'second divergent task' }
    await handleAgentHook(root, 'codex', secondPrompt, config())
    const secondRoot = join(versionDir, createHash('sha256').update('relocated-v2-two').digest('hex').slice(0, 24))
    await rename(hookStateRoot(root, 'v2', 'short'), secondRoot)
    await rename(holdingRoot, firstRoot)
    const runReview = vi.fn()

    const output = await handleAgentHook(root, 'codex', {
      ...firstPrompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })

    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining('divergent or incomplete evidence') })
    expect(runReview).not.toHaveBeenCalled()
    const sessionKey = createHash('sha256').update(session).digest('hex').slice(0, 24)
    const turnKey = createHash('sha256').update('id:divergent-v2-turn').digest('hex').slice(0, 24)
    const firstTurn = join(firstRoot, 'codex', sessionKey, turnKey)
    const secondTurn = join(secondRoot, 'codex', sessionKey, turnKey)
    expect(await readFile(join(firstTurn, 'state.json'), 'utf8')).toContain('first divergent task')
    expect(await readFile(join(secondTurn, 'state.json'), 'utf8')).toContain('second divergent task')
    await expect(stat(join(firstTurn, 'object-store'))).resolves.toBeDefined()
    await expect(stat(join(secondTurn, 'object-store'))).resolves.toBeDefined()
  }, 30_000)

  it('ownership-checks and drains an unrequested stale relocated session on the next hook invocation', async () => {
    const root = await repo('codetruss-hook-stale-relocated-')
    const staleSession = 'stale-relocated-session'
    const stalePrompt = {
      session_id: staleSession,
      turn_id: 'stale-relocated-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'private stale relocated task',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', stalePrompt, config())
    const currentRoot = hookStateRoot(root, 'v2', 'short')
    const staleRoot = join(dirname(currentRoot), createHash('sha256').update('stale-relocated-root').digest('hex').slice(0, 24))
    await rename(currentRoot, staleRoot)
    const sessionKey = createHash('sha256').update(staleSession).digest('hex').slice(0, 24)
    const turnKey = createHash('sha256').update('id:stale-relocated-turn').digest('hex').slice(0, 24)
    const statePath = join(staleRoot, 'codex', sessionKey, turnKey, 'state.json')
    const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>
    state.updatedAt = '2000-01-01T00:00:00.000Z'
    await writeFile(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    const nextPrompt = {
      session_id: 'new-session-after-stale-drain',
      turn_id: 'new-session-after-stale-drain-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'capture after stale drain',
      cwd: root,
    }

    await expect(handleAgentHook(root, 'codex', nextPrompt, config())).resolves.toBeUndefined()

    await expect(stat(staleRoot)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(stateDir(root, 'codex', nextPrompt.session_id))).resolves.toBeDefined()
  }, 30_000)

  it.each([
    { version: 'v1' as const, repositoryKey: 'full' as const },
    { version: 'v2' as const, repositoryKey: 'short' as const },
  ])('recovers $version private evidence after the repository path moves and reviews exactly once', async ({ version, repositoryKey }) => {
    const originalRoot = await repo(`codetruss-hook-${version}-move-`)
    const session = `${version}-moved-session`
    const prompt = {
      session_id: session,
      turn_id: `${version}-moved-turn`,
      hook_event_name: 'UserPromptSubmit',
      prompt: `review ${version} after repository move`,
      cwd: originalRoot,
    }
    await handleAgentHook(originalRoot, 'codex', prompt, config())
    if (version === 'v1') await moveCurrentStateToLegacy(originalRoot, 'codex', session, 'full')
    const movedRoot = `${originalRoot}-moved`
    await rename(originalRoot, movedRoot)
    const oldStateRoot = hookStateRootForPath(movedRoot, originalRoot, version, repositoryKey)
    await expect(stat(oldStateRoot)).resolves.toBeDefined()
    const receipt = join(movedRoot, '.codetruss', 'receipts', `${version}-moved.md`)
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, `# ${version} moved\n`)
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      expect(request.root).toBe(movedRoot)
      expect(request.task).toBe(`review ${version} after repository move`)
      return hookReviewResponse(request, 'PASS', 0, receipt)
    })
    const stop = { ...prompt, cwd: movedRoot, hook_event_name: 'Stop', background_tasks: [] }

    await expect(handleAgentHook(movedRoot, 'codex', stop, config(), { runReview })).resolves.toBeUndefined()
    await expect(handleAgentHook(movedRoot, 'codex', stop, config(), { runReview })).resolves.toBeUndefined()

    expect(runReview).toHaveBeenCalledTimes(1)
    await expect(stat(oldStateRoot)).rejects.toMatchObject({ code: 'ENOENT' })
    const migratedSession = stateDir(movedRoot, 'codex', session)
    const current = JSON.parse(await readFile(join(migratedSession, 'current.json'), 'utf8')) as { turnKey: string }
    const state = JSON.parse(await readFile(join(migratedSession, current.turnKey, 'state.json'), 'utf8')) as Record<string, unknown>
    expect(state).toMatchObject({ status: 'completed', turnKey: current.turnKey })
    expect(state.task).toBeUndefined()
  }, 30_000)

  it('recovers a moved linked worktree while preserving the still-extant main worktree boundary', async () => {
    const root = await repo('codetruss-hook-linked-move-main-')
    const originalLinked = await mkdtemp(join(tmpdir(), 'codetruss-hook-linked-move-'))
    await rm(originalLinked, { recursive: true, force: true })
    git(root, 'worktree', 'add', '--quiet', '--detach', originalLinked)
    const session = 'moved-linked-session'
    const prompt = {
      session_id: session,
      turn_id: 'moved-linked-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'review moved linked worktree',
      cwd: originalLinked,
    }
    await handleAgentHook(originalLinked, 'codex', prompt, config())
    const movedLinked = `${originalLinked}-moved`
    await rename(originalLinked, movedLinked)
    const oldStateRoot = hookStateRootForPath(movedLinked, originalLinked, 'v2', 'short')
    const receipt = join(movedLinked, '.codetruss', 'receipts', 'moved-linked.md')
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, '# moved linked\n')
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      expect(request.root).toBe(movedLinked)
      expect(request.task).toBe('review moved linked worktree')
      return hookReviewResponse(request, 'PASS', 0, receipt)
    })

    await expect(handleAgentHook(movedLinked, 'codex', {
      ...prompt,
      cwd: movedLinked,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })).resolves.toBeUndefined()

    expect(runReview).toHaveBeenCalledTimes(1)
    await expect(stat(oldStateRoot)).rejects.toMatchObject({ code: 'ENOENT' })
    const migratedSession = stateDir(movedLinked, 'codex', session)
    const current = JSON.parse(await readFile(join(migratedSession, 'current.json'), 'utf8')) as { turnKey: string }
    const state = JSON.parse(await readFile(join(migratedSession, current.turnKey, 'state.json'), 'utf8')) as Record<string, unknown>
    expect(state).toMatchObject({ status: 'completed', turnKey: current.turnKey })
    expect(state.worktreeIdentity).toMatch(/^git-admin-v1:[0-9a-f]{64}$/)
    expect(state.worktreeIdentityHash).toBeUndefined()
  }, 30_000)

  it('never adopts exact-session evidence owned by another extant linked worktree', async () => {
    const root = await repo('codetruss-hook-worktree-owner-')
    const linked = await mkdtemp(join(tmpdir(), 'codetruss-hook-worktree-owner-linked-'))
    await rm(linked, { recursive: true, force: true })
    git(root, 'worktree', 'add', '--quiet', '--detach', linked)
    const session = 'shared-worktree-session'
    const linkedPrompt = {
      session_id: session,
      turn_id: 'shared-worktree-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'linked worktree private task',
      cwd: linked,
    }
    await handleAgentHook(linked, 'codex', linkedPrompt, config())
    const linkedSession = stateDir(linked, 'codex', session)
    const linkedCurrent = JSON.parse(await readFile(join(linkedSession, 'current.json'), 'utf8')) as { turnKey: string }
    const linkedTurn = join(linkedSession, linkedCurrent.turnKey)
    const linkedStateBefore = await readFile(join(linkedTurn, 'state.json'), 'utf8')
    const mainPrompt = { ...linkedPrompt, prompt: 'main worktree private task', cwd: root }

    await expect(handleAgentHook(root, 'codex', mainPrompt, config())).resolves.toBeUndefined()

    const mainSession = stateDir(root, 'codex', session)
    expect(resolve(mainSession)).not.toBe(resolve(linkedSession))
    expect(await readFile(join(linkedTurn, 'state.json'), 'utf8')).toBe(linkedStateBefore)
    await expect(stat(join(linkedTurn, 'object-store'))).resolves.toBeDefined()
    const mainCurrent = JSON.parse(await readFile(join(mainSession, 'current.json'), 'utf8')) as { turnKey: string }
    const mainState = JSON.parse(await readFile(join(mainSession, mainCurrent.turnKey, 'state.json'), 'utf8')) as Record<string, unknown>
    expect(mainState.task).toBe('main worktree private task')
    expect(mainState.task).not.toBe('linked worktree private task')
  }, 30_000)

  it.runIf(process.platform !== 'win32')('never adopts linked-worktree evidence through a live symlink at its registered path', async () => {
    const root = await repo('codetruss-hook-symlinked-worktree-main-')
    const originalLinked = await mkdtemp(join(tmpdir(), 'codetruss-hook-symlinked-worktree-'))
    await rm(originalLinked, { recursive: true, force: true })
    git(root, 'worktree', 'add', '--quiet', '--detach', originalLinked)
    const session = 'symlinked-worktree-session'
    const linkedPrompt = {
      session_id: session,
      turn_id: 'symlinked-worktree-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'symlinked linked-worktree private task',
      cwd: originalLinked,
    }
    await handleAgentHook(originalLinked, 'codex', linkedPrompt, config())
    const linkedSession = stateDir(originalLinked, 'codex', session)
    const linkedCurrent = JSON.parse(await readFile(join(linkedSession, 'current.json'), 'utf8')) as { turnKey: string }
    const linkedTurn = join(linkedSession, linkedCurrent.turnKey)
    const linkedStateBefore = await readFile(join(linkedTurn, 'state.json'), 'utf8')
    const movedLinked = `${originalLinked}-moved`
    await rename(originalLinked, movedLinked)
    await symlink(movedLinked, originalLinked, 'dir')
    const mainPrompt = { ...linkedPrompt, prompt: 'main task must remain isolated', cwd: root }

    await expect(handleAgentHook(root, 'codex', mainPrompt, config())).resolves.toBeUndefined()

    expect(await readFile(join(linkedTurn, 'state.json'), 'utf8')).toBe(linkedStateBefore)
    await expect(stat(join(linkedTurn, 'object-store'))).resolves.toBeDefined()
    const mainSession = stateDir(root, 'codex', session)
    const mainCurrent = JSON.parse(await readFile(join(mainSession, 'current.json'), 'utf8')) as { turnKey: string }
    const mainState = JSON.parse(await readFile(join(mainSession, mainCurrent.turnKey, 'state.json'), 'utf8')) as Record<string, unknown>
    expect(mainState.task).toBe('main task must remain isolated')
  }, 30_000)

  it.each(['full', 'short'] as const)('preserves live v1 %s-key evidence, then securely drains it after the lease dies', async (repositoryKey) => {
    const root = await repo(`codetruss-hook-live-legacy-${repositoryKey}-`)
    const session = `live-legacy-${repositoryKey}`
    const prompt = {
      session_id: session,
      turn_id: `live-legacy-${repositoryKey}-turn`,
      hook_event_name: 'UserPromptSubmit',
      prompt: `private live ${repositoryKey} task`,
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const legacy = await moveCurrentStateToLegacy(root, 'codex', session, repositoryKey)
    const state = JSON.parse(await readFile(legacy.statePath, 'utf8')) as Record<string, unknown>
    state.status = 'capturing'
    state.capturePid = process.pid
    await writeFile(legacy.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    const lockPath = join(legacy.turnDir, 'capture.lock')
    await writeFile(lockPath, `${JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() })}\n`, { mode: 0o600 })
    const nextPrompt = {
      session_id: `after-live-${repositoryKey}`,
      turn_id: `after-live-${repositoryKey}-turn`,
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Capture after legacy cleanup',
      cwd: root,
    }

    const blocked = await handleAgentHook(root, 'codex', nextPrompt, config())
    expect(blocked).toEqual({ decision: 'block', reason: expect.stringContaining('active lease') })
    await expect(stat(legacy.objectStorePath)).resolves.toBeDefined()
    await expect(stat(hookStateRoot(root, 'v1', repositoryKey))).resolves.toBeDefined()
    expect((await readFile(legacy.statePath, 'utf8'))).toContain(`private live ${repositoryKey} task`)
    await expect(stat(stateDir(root, 'codex', nextPrompt.session_id))).rejects.toMatchObject({ code: 'ENOENT' })

    state.capturePid = 2_147_483_647
    await writeFile(legacy.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    await writeFile(lockPath, `${JSON.stringify({ pid: 2_147_483_647, createdAt: '2000-01-01T00:00:00.000Z' })}\n`, { mode: 0o600 })
    await expect(handleAgentHook(root, 'codex', prompt, config())).resolves.toBeUndefined()
    await expect(stat(legacy.sessionDir)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(hookStateRoot(root, 'v1', 'full'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(hookStateRoot(root, 'v1', 'short'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(stateDir(root, 'codex', prompt.session_id))).resolves.toBeDefined()
  }, 30_000)

  it('keeps legacy task and context evidence intact when object-store ownership cannot be validated, then cleans it on retry', async () => {
    const root = await repo('codetruss-hook-legacy-owner-')
    const session = 'legacy-owner-session'
    const prompt = {
      session_id: session,
      turn_id: 'legacy-owner-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'private ownership validation task',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const legacy = await moveCurrentStateToLegacy(root, 'codex', session, 'full')
    const state = JSON.parse(await readFile(legacy.statePath, 'utf8')) as Record<string, unknown>
    state.status = 'completed'
    await writeFile(legacy.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    const ownershipPath = join(legacy.objectStorePath, 'codetruss-object-store.json')
    const ownership = await readFile(ownershipPath, 'utf8')
    await writeFile(ownershipPath, '{"invalid":true}\n', { mode: 0o600 })
    const nextPrompt = { ...prompt, prompt: 'Capture after validated cleanup' }

    const blocked = await handleAgentHook(root, 'codex', nextPrompt, config())
    expect(blocked).toEqual({ decision: 'block', reason: expect.stringContaining('securely cleaned') })
    expect(await readFile(legacy.statePath, 'utf8')).toContain('private ownership validation task')
    await expect(stat(hookStateRoot(root, 'v1', 'full'))).resolves.toBeDefined()
    await expect(stat(legacy.contextPath)).resolves.toBeDefined()
    await expect(stat(legacy.objectStorePath)).resolves.toBeDefined()

    await writeFile(ownershipPath, ownership, { mode: 0o600 })
    await expect(handleAgentHook(root, 'codex', nextPrompt, config())).resolves.toBeUndefined()
    await expect(stat(legacy.sessionDir)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(hookStateRoot(root, 'v1', 'full'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(hookStateRoot(root, 'v1', 'short'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(stateDir(root, 'codex', nextPrompt.session_id))).resolves.toBeDefined()
  }, 30_000)

  it('never adopts or drains a discovered root whose state has a different full session hash', async () => {
    const root = await repo('codetruss-hook-legacy-session-bind-')
    const session = 'requested-session-bind'
    const prompt = {
      session_id: session,
      turn_id: 'requested-session-bind-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'preserve exact session binding',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const legacy = await moveCurrentStateToLegacy(root, 'codex', session, 'full')
    const state = JSON.parse(await readFile(legacy.statePath, 'utf8')) as Record<string, unknown>
    state.sessionHash = createHash('sha256').update('different-session').digest('hex')
    await writeFile(legacy.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })

    const blocked = await handleAgentHook(root, 'codex', prompt, config())

    expect(blocked).toEqual({ decision: 'block', reason: expect.stringContaining('full session hash') })
    expect(await readFile(legacy.statePath, 'utf8')).toContain('preserve exact session binding')
    await expect(stat(legacy.contextPath)).resolves.toBeDefined()
    await expect(stat(legacy.objectStorePath)).resolves.toBeDefined()
    await expect(stat(hookStateRoot(root, 'v1', 'full'))).resolves.toBeDefined()
  }, 30_000)

  it('fails closed and preserves legacy evidence without a provable stable Git worktree identity', async () => {
    const root = await repo('codetruss-hook-legacy-worktree-identity-')
    const session = 'legacy-ambiguous-worktree-session'
    const prompt = {
      session_id: session,
      turn_id: 'legacy-ambiguous-worktree-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Do not adopt ambiguous worktree evidence',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const legacy = await moveCurrentStateToLegacy(root, 'codex', session, 'full')
    const state = JSON.parse(await readFile(legacy.statePath, 'utf8')) as Record<string, unknown>
    delete state.worktreeIdentity
    state.worktreeIdentityHash = createHash('sha256').update(resolve(root)).digest('hex')
    await writeFile(legacy.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    const runReview = vi.fn()

    const blocked = await handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })

    expect(blocked).toEqual({ decision: 'block', reason: expect.stringContaining('stable worktree identity') })
    expect(runReview).not.toHaveBeenCalled()
    expect(await readFile(legacy.statePath, 'utf8')).toContain('Do not adopt ambiguous worktree evidence')
    await expect(stat(legacy.contextPath)).resolves.toBeDefined()
    await expect(stat(legacy.objectStorePath)).resolves.toBeDefined()
  }, 30_000)

  it('does not replace current private evidence after its stable worktree ownership is removed', async () => {
    const root = await repo('codetruss-hook-current-worktree-identity-')
    const prompt = {
      session_id: 'current-ambiguous-worktree-session',
      turn_id: 'current-ambiguous-worktree-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Preserve current ambiguous evidence',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const session = stateDir(root, 'codex', prompt.session_id)
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    const turnDir = join(session, current.turnKey)
    const statePath = join(turnDir, 'state.json')
    const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>
    delete state.worktreeIdentity
    state.worktreeIdentityHash = createHash('sha256').update(resolve(root)).digest('hex')
    await writeFile(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    const stateBefore = await readFile(statePath, 'utf8')
    const contextBefore = await readFile(join(turnDir, 'turn-context.json'), 'utf8')

    const blocked = await handleAgentHook(root, 'codex', prompt, config())

    expect(blocked).toEqual({ decision: 'block', reason: expect.stringContaining('ownership cannot be proven') })
    expect(await readFile(statePath, 'utf8')).toBe(stateBefore)
    expect(await readFile(join(turnDir, 'turn-context.json'), 'utf8')).toBe(contextBefore)
    await expect(stat(join(turnDir, 'object-store'))).resolves.toBeDefined()
  }, 30_000)

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
    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining('context changed after prompt-time capture') })
    expect(runReview).not.toHaveBeenCalled()
    await expect(stat(join(turnDir, 'object-store'))).resolves.toBeDefined()
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

    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining('task evidence does not match prompt-time context') })
    expect(runReview).not.toHaveBeenCalled()
    await expect(stat(join(turnDir, 'object-store'))).resolves.toBeDefined()
  })

  it('fails closed before review or cleanup when state turn identity differs from the exact selector', async () => {
    const root = await repo('codetruss-hook-state-turn-binding-')
    const prompt = {
      session_id: 'state-turn-binding-session',
      turn_id: 'state-turn-binding-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Bind state to the exact selected turn',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const session = stateDir(root, 'codex', prompt.session_id)
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    const turnDir = join(session, current.turnKey)
    const statePath = join(turnDir, 'state.json')
    const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>
    state.turnId = 'another-turn'
    await writeFile(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    const runReview = vi.fn()

    const output = await handleAgentHook(root, 'codex', { ...prompt, hook_event_name: 'Stop' }, config(), { runReview })

    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining('does not exactly match') })
    expect(runReview).not.toHaveBeenCalled()
    await expect(stat(join(turnDir, 'object-store'))).resolves.toBeDefined()
  })

  it('blocks once on missing baseline evidence without claiming success or creating a Stop loop', async () => {
    const root = await repo()
    const stop = {
      session_id: 'no-baseline', hook_event_name: 'Stop', stop_hook_active: false, background_tasks: [],
    }
    const output = await handleAgentHook(root, 'claude', stop, config())
    expect(output).toEqual({ decision: 'block', reason: expect.stringContaining('no exact baseline') })
    expect(JSON.stringify(output)).not.toContain('PASS')
    expect(output).not.toHaveProperty('continue')
    await expect(handleAgentHook(root, 'claude', {
      ...stop,
      stop_hook_active: true,
    }, config())).resolves.toEqual({ systemMessage: expect.stringContaining('no exact baseline') })
  })

  it('never expires a demonstrably live old Stop owner and recovers once that owner is dead', async () => {
    const root = await repo('codetruss-hook-live-old-lock-')
    const receipt = join(root, '.codetruss', 'receipts', 'live-old-lock.md')
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, '# recovered\n')
    const prompt = {
      session_id: 'live-old-lock-session',
      turn_id: 'live-old-lock-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Do not steal a live review lease',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const session = stateDir(root, 'codex', prompt.session_id)
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    const turnDir = join(session, current.turnKey)
    const lockPath = join(turnDir, 'stop.lock')
    const token = 'a'.repeat(32)
    await writeFile(lockPath, `${JSON.stringify({
      version: 1,
      pid: process.pid,
      createdAt: '2000-01-01T00:00:00.000Z',
      token,
    })}\n`, { mode: 0o600 })
    const runReview = vi.fn((request: HookReviewRequest) => hookReviewResponse(request, 'PASS', 0, receipt))
    const stop = { ...prompt, hook_event_name: 'Stop', background_tasks: [] }

    const blocked = await handleAgentHook(root, 'codex', stop, config(), {
      runReview,
      now: () => new Date('2030-01-01T00:06:00.000Z'),
    })

    expect(blocked).toEqual({ decision: 'block', reason: expect.stringContaining('already in progress') })
    expect(runReview).not.toHaveBeenCalled()
    expect(JSON.parse(await readFile(lockPath, 'utf8'))).toMatchObject({ pid: process.pid, token })

    await writeFile(lockPath, `${JSON.stringify({
      version: 1,
      pid: 2_147_483_647,
      createdAt: '2000-01-01T00:00:00.000Z',
      token,
    })}\n`, { mode: 0o600 })
    await expect(handleAgentHook(root, 'codex', stop, config(), { runReview })).resolves.toBeUndefined()
    expect(runReview).toHaveBeenCalledTimes(1)
    await expect(stat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' })
  }, 30_000)

  it('revalidates the unique Stop owner token before release so an ABA replacement survives', async () => {
    const root = await repo('codetruss-hook-lock-aba-')
    const receipt = join(root, '.codetruss', 'receipts', 'aba.md')
    await mkdir(dirname(receipt), { recursive: true })
    await writeFile(receipt, '# ABA\n')
    const prompt = {
      session_id: 'aba-session',
      turn_id: 'aba-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Preserve a replacement lease',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const session = stateDir(root, 'codex', prompt.session_id)
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    const lockPath = join(session, current.turnKey, 'stop.lock')
    const replacementToken = 'f'.repeat(32)
    const runReview = vi.fn(async (request: HookReviewRequest) => {
      await rm(lockPath, { force: true })
      await writeFile(lockPath, `${JSON.stringify({
        version: 1,
        pid: process.pid,
        createdAt: new Date().toISOString(),
        token: replacementToken,
      })}\n`, { mode: 0o600 })
      return hookReviewResponse(request, 'PASS', 0, receipt)
    })

    await expect(handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })).resolves.toBeUndefined()

    expect(runReview).toHaveBeenCalledTimes(1)
    expect(JSON.parse(await readFile(lockPath, 'utf8'))).toMatchObject({ token: replacementToken })
    const duplicate = await handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), { runReview })
    expect(duplicate).toEqual({ systemMessage: expect.stringContaining('still finalizing') })
    expect(runReview).toHaveBeenCalledTimes(1)
  }, 30_000)

  it('replays a persisted FAILED result while cleanup is locked and after dead-owner recovery', async () => {
    const root = await repo('codetruss-hook-cleanup-replay-')
    const prompt = {
      session_id: 'cleanup-replay-session',
      turn_id: 'cleanup-replay-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Persist the failed review before cleanup',
      cwd: root,
    }
    await handleAgentHook(root, 'codex', prompt, config())
    const session = stateDir(root, 'codex', prompt.session_id)
    const current = JSON.parse(await readFile(join(session, 'current.json'), 'utf8')) as { turnKey: string }
    const turnDir = join(session, current.turnKey)
    const statePath = join(turnDir, 'state.json')
    const state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>
    const result = { verdict: 'FAILED', message: 'CodeTruss FAILED. Persisted before cleanup.' }
    Object.assign(state, {
      status: 'cleanup_pending',
      task: undefined,
      baselineDirtyFiles: undefined,
      result,
      error: 'Private snapshot cleanup is pending.',
    })
    await writeFile(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 })
    const lockPath = join(turnDir, 'stop.lock')
    const token = 'b'.repeat(32)
    await writeFile(lockPath, `${JSON.stringify({
      version: 1,
      pid: process.pid,
      createdAt: '2000-01-01T00:00:00.000Z',
      token,
    })}\n`, { mode: 0o600 })
    const stop = { ...prompt, hook_event_name: 'Stop', background_tasks: [] }

    const locked = await handleAgentHook(root, 'codex', stop, config())
    expect(locked).toEqual({ decision: 'block', reason: expect.stringContaining('Persisted before cleanup') })
    const continuation = await handleAgentHook(root, 'codex', { ...stop, stop_hook_active: true }, config())
    expect(continuation).toEqual({ systemMessage: expect.stringContaining('Persisted before cleanup') })
    await expect(stat(join(turnDir, 'object-store'))).resolves.toBeDefined()

    await writeFile(lockPath, `${JSON.stringify({
      version: 1,
      pid: 2_147_483_647,
      createdAt: '2000-01-01T00:00:00.000Z',
      token,
    })}\n`, { mode: 0o600 })
    const recovered = await handleAgentHook(root, 'codex', stop, config())
    expect(recovered).toEqual({ decision: 'block', reason: expect.stringContaining('Persisted before cleanup') })
    await expect(stat(join(turnDir, 'object-store'))).rejects.toMatchObject({ code: 'ENOENT' })
    const replayed = await handleAgentHook(root, 'codex', stop, config())
    expect(replayed).toEqual({ decision: 'block', reason: expect.stringContaining('Persisted before cleanup') })
  }, 30_000)

  it('recovers a stale Stop lock and preserves immutable evidence for retry after a review crash', async () => {
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
      runReview: (request) => hookReviewResponse(request, 'PASS', 0, receipt),
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
    expect(failed).toEqual({ decision: 'block', reason: expect.stringContaining('review process crashed') })
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', before.baselineCommit]).status).not.toBe(0)
    await expect(stat(join(secondTurn, 'object-store'))).resolves.toBeDefined()
    await expect(stat(join(secondTurn, 'stop.lock'))).rejects.toMatchObject({ code: 'ENOENT' })
    const rerunReview = vi.fn((request: HookReviewRequest) => hookReviewResponse(request, 'PASS', 0, receipt))
    await expect(handleAgentHook(root, 'codex', { ...secondPrompt, hook_event_name: 'Stop' }, config(), {
      runReview: rerunReview,
    })).resolves.toBeUndefined()
    expect(rerunReview).toHaveBeenCalledTimes(1)
    await expect(stat(join(secondTurn, 'object-store'))).rejects.toMatchObject({ code: 'ENOENT' })
  }, 30_000)

  it('reports the actionable child-process error when no review result was produced', async () => {
    const root = await repo('codetruss-hook-missing-result-')
    await writeConfig(root)
    const prompt = {
      session_id: 'missing-result-session',
      turn_id: 'missing-result-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Review with an untrusted command policy',
      cwd: root,
    }
    await expect(handleAgentHook(root, 'codex', prompt, config())).resolves.toBeUndefined()
    await writeFile(join(root, 'README.md'), 'changed\n')

    const result = await handleAgentHook(root, 'codex', {
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    }, config(), {
      runReview: async () => ({
        status: 3,
        stdout: '',
        stderr: 'codetruss: repository verification commands are not trusted; inspect them first',
      }),
    })

    expect(result).toEqual({
      decision: 'block',
      reason: expect.stringContaining(
        'review process failed before producing a receipt: codetruss: repository verification commands are not trusted',
      ),
    })
    expect((result as { reason: string }).reason).not.toContain('ENOENT')
  }, 30_000)
})
