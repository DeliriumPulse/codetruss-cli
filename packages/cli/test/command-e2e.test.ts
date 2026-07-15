import { spawnSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import type { Receipt } from '../src/types.js'

const CLI_ENTRY = fileURLToPath(new URL('../src/cli.ts', import.meta.url))
const TSX_BIN = fileURLToPath(import.meta.resolve('tsx/cli'))
const SYNTHETIC_AWS_KEY = `AKIA${'1'.repeat(16)}`
const cleanup: string[] = []

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function git(root: string, ...args: string[]): string {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' })
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`)
  return result.stdout
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'codetruss-command-e2e-'))
  cleanup.push(root, `${root}-home`)
  git(root, 'init', '--quiet')
  git(root, 'config', 'user.name', 'CodeTruss Test')
  git(root, 'config', 'user.email', 'test@codetruss.invalid')
  return root
}

async function installPersistentCliFixture(root: string): Promise<void> {
  await mkdir(join(root, 'node_modules', '.bin'), { recursive: true })
  const localCli = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
  await writeFile(localCli, process.platform === 'win32' ? '@exit /b 0\r\n' : '#!/bin/sh\nexit 0\n')
  await chmod(localCli, 0o755)
  const exclude = git(root, 'rev-parse', '--git-path', 'info/exclude').trim()
  await writeFile(isAbsolute(exclude) ? exclude : join(root, exclude), '/node_modules/\n', { flag: 'a' })
}

function runCli(
  root: string,
  args: string[],
  extraEnvironment: Partial<NodeJS.ProcessEnv> = {},
  input?: string,
) {
  return spawnSync(process.execPath, [TSX_BIN, CLI_ENTRY, ...args], {
    cwd: root,
    encoding: 'utf8',
    input,
    env: {
      ...process.env,
      ...extraEnvironment,
      HOME: `${root}-home`,
      USERPROFILE: `${root}-home`,
      CODETRUSS_SIGNING_KEY: join(root, '.codetruss', 'test-signing.pem'),
    },
    maxBuffer: 8 * 1024 * 1024,
  })
}

async function latestReceipt(root: string): Promise<Receipt> {
  const dir = join(root, '.codetruss', 'receipts')
  const names = (await readdir(dir)).filter((name) => name.endsWith('.json')).sort()
  return JSON.parse(await readFile(join(dir, names.at(-1)!), 'utf8')) as Receipt
}

describe('CLI snapshot and delta enforcement', () => {
  it('finishes the headline interactive setup command with confirmed suggested scope', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await mkdir(join(root, 'tests'))
    await installPersistentCliFixture(root)
    await writeFile(join(root, '.gitignore'), '/node_modules\n')

    const setup = runCli(root, ['setup'], {}, '\n\n')

    expect(setup.status, `${setup.stderr}\n${setup.stdout}`).toBe(0)
    expect(setup.stdout).toContain('Suggested allowed change roots: src/**, tests/**')
    expect(setup.stdout).toContain('READY: pre-commit and Claude automatic checks are active')
    const config = await readFile(join(root, '.codetruss.yml'), 'utf8')
    expect(config).toMatch(/allow:\n\s+- src\/\*\*\n\s+- tests\/\*\*/)
  }, 30_000)

  it('completes idempotent local-only setup and keeps generated evidence out of normal staging', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await mkdir(join(root, 'tests'))
    await installPersistentCliFixture(root)
    await writeFile(join(root, '.gitignore'), '/node_modules\n')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 1\n')
    await mkdir(`${root}-home`, { recursive: true })
    const networkBlocker = join(`${root}-home`, 'block-network.cjs')
    await writeFile(networkBlocker, [
      'const net = require("node:net")',
      'const blocked = () => { throw new Error("setup attempted network access") }',
      'const connect = net.connect',
      'const createConnection = net.createConnection',
      'const local = (value) => typeof value === "string" || (value && typeof value === "object" && typeof value.path === "string")',
      'net.connect = function (...args) { return local(args[0]) ? connect.apply(this, args) : blocked() }',
      'net.createConnection = function (...args) { return local(args[0]) ? createConnection.apply(this, args) : blocked() }',
      'global.fetch = blocked',
    ].join(';'))
    const offlineEnvironment = { NODE_OPTIONS: `--require=${networkBlocker}` }

    const configured = runCli(root, [
      'setup', '--yes', '--allow', 'src/**', '--allow', 'tests/**', '--hooks', 'all',
    ], offlineEnvironment)
    expect(configured.status, `${configured.stderr}\n${configured.stdout}`).toBe(0)
    expect(configured.stdout).toContain('local only; nothing is uploaded')
    expect(configured.stdout).toContain('READY: pre-commit and Claude automatic checks are active')
    expect(configured.stdout).toContain('ACTION REQUIRED FOR CODEX: open /hooks')
    expect(configured.stdout).toContain('Undo automatic checks: codetruss hooks uninstall all')
    expect(configured.stdout).toContain('Receipts stay on this machine unless you explicitly run codetruss sync')

    const installedFiles = [
      join(root, '.git', 'hooks', 'pre-commit'),
      join(root, '.claude', 'settings.json'),
      join(root, '.codex', 'hooks.json'),
      join(root, '.codetruss', 'hooks', 'agent.cjs'),
    ]
    const firstInstall = await Promise.all(installedFiles.map((path) => readFile(path, 'utf8')))
    const rerun = runCli(root, [
      'setup', '--yes', '--allow', 'src/**', '--allow', 'tests/**', '--hooks', 'all',
    ], offlineEnvironment)
    expect(rerun.status, `${rerun.stderr}\n${rerun.stdout}`).toBe(0)
    expect(await Promise.all(installedFiles.map((path) => readFile(path, 'utf8')))).toEqual(firstInstall)
    const configBeforeMismatch = await readFile(join(root, '.codetruss.yml'), 'utf8')
    const mismatch = runCli(root, ['setup', '--yes', '--allow', 'other/**', '--hooks', 'all'], offlineEnvironment)
    expect(mismatch.status).toBe(3)
    expect(mismatch.stderr).toContain('already exists with a different allow policy')
    expect(await readFile(join(root, '.codetruss.yml'), 'utf8')).toBe(configBeforeMismatch)
    expect(await Promise.all(installedFiles.map((path) => readFile(path, 'utf8')))).toEqual(firstInstall)

    await writeFile(join(root, '.codetruss', 'receipts', 'must-stay-local.patch'), 'private source diff\n')
    git(root, 'add', '.')
    expect(git(root, 'diff', '--cached', '--name-only')).not.toContain('.codetruss/')
  }, 30_000)

  it('rejects unrelated setup options instead of silently ignoring them', async () => {
    const root = await repository()
    const result = runCli(root, ['setup', '--allow', 'src/**', '--provider', 'openai'])
    expect(result.status).toBe(3)
    expect(result.stderr).toContain('setup does not accept --provider')
    await expect(readFile(join(root, '.codetruss.yml'))).rejects.toMatchObject({ code: 'ENOENT' })

    const forced = runCli(root, ['setup', '--allow', 'src/**', '--force'])
    expect(forced.status).toBe(3)
    expect(forced.stderr).toContain('setup does not accept --force')

    const misplacedTrust = runCli(root, ['review', '--trust-verify', '--task', 'Review the current change', '--no-verify'])
    expect(misplacedTrust.status).toBe(3)
    expect(misplacedTrust.stderr).toContain('--trust-verify is accepted only by codetruss setup')

    const typoHelp = runCli(root, ['revie', '--help'])
    expect(typoHelp.status).toBe(3)
    expect(typoHelp.stderr).toContain('unknown command revie')

    const versionOption = runCli(root, ['version', '--json'])
    expect(versionOption.status).toBe(3)
    expect(versionOption.stderr).toContain('version does not accept --json')

    const helpOption = runCli(root, ['help', '--llm'])
    expect(helpOption.status).toBe(3)
    expect(helpOption.stderr).toContain('help does not accept --llm')

    const commandHelp = runCli(root, ['run', '--help'])
    expect(commandHelp.status).toBe(0)
    expect(commandHelp.stdout).toContain('codetruss run --task')

    for (const args of [
      ['review', '--llm=false', '--task', 'Review the current change', '--no-verify'],
      ['review', '--no-verify=false', '--task', 'Review the current change'],
      ['setup', '--trust-verify=false', '--allow', 'src/**', '--hooks', 'none'],
    ]) {
      const inlineBoolean = runCli(root, args)
      expect(inlineBoolean.status).toBe(3)
      expect(inlineBoolean.stderr).toContain('does not accept a value')
    }

    const misspelledVerify = runCli(root, ['review', '--verfy', 'npm test', '--task', 'Review the current change', '--no-verify'])
    expect(misspelledVerify.status).toBe(3)
    expect(misspelledVerify.stderr).toContain('review does not accept --verfy')

    const blankVerify = runCli(root, ['review', '--verify', '   ', '--task', 'Review the current change'])
    expect(blankVerify.status).toBe(3)
    expect(blankVerify.stderr).toContain('--verify requires a non-empty value')

    const conflictingVerify = runCli(root, ['review', '--verify', 'npm test', '--no-verify', '--task', 'Review the current change'])
    expect(conflictingVerify.status).toBe(3)
    expect(conflictingVerify.stderr).toContain('--no-verify cannot be combined with --verify')

    const extraReportId = runCli(root, ['report', 'latest', 'extra'])
    expect(extraReportId.status).toBe(3)
    expect(extraReportId.stderr).toContain('report does not accept more than 1 positional argument')

    const equalsRoot = await repository()
    const equalsValue = runCli(equalsRoot, ['setup', '--yes', '--allow=src/**=literal', '--hooks', 'none'])
    expect(equalsValue.status, `${equalsValue.stderr}\n${equalsValue.stdout}`).toBe(0)
    expect(await readFile(join(equalsRoot, '.codetruss.yml'), 'utf8')).toContain('src/**=literal')

    const unattended = runCli(root, ['setup', '--yes', '--hooks', 'none'])
    expect(unattended.status).toBe(3)
    expect(unattended.stderr).toContain('non-interactive setup requires at least one explicit --allow')
  }, 60_000)

  it('leaves no active hook when verification trust is declined during setup', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 1\n')
    await writeFile(join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n')
    await writeFile(join(root, 'package.json'), `${JSON.stringify({
      private: true,
      scripts: { lint: 'node -e ""', test: 'node -e ""' },
    }, null, 2)}\n`)

    const declined = runCli(root, ['setup', '--allow', 'src/**', '--hooks', 'all'], {}, 'not now\n')
    expect(declined.status, `${declined.stderr}\n${declined.stdout}`).toBe(3)
    expect(declined.stdout).toContain('Verification fingerprint: ')
    expect(declined.stdout).toContain('Setup paused before hook installation')
    await expect(readFile(join(root, '.git', 'hooks', 'pre-commit'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(readFile(join(root, '.claude', 'settings.json'))).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(readFile(join(root, '.codex', 'hooks.json'))).rejects.toMatchObject({ code: 'ENOENT' })
  }, 30_000)

  it('honors explicit verification trust even when automatic hooks are skipped', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n')
    await writeFile(join(root, 'package.json'), `${JSON.stringify({
      private: true,
      scripts: { test: 'node -e ""' },
    }, null, 2)}\n`)

    const inspected = runCli(root, [
      'setup', '--yes', '--allow', 'src/**', '--hooks', 'none',
    ])
    expect(inspected.status, `${inspected.stderr}\n${inspected.stdout}`).toBe(0)
    expect(inspected.stdout).toContain('Verification fingerprint: ')
    expect(inspected.stdout).toContain('Verification commands remain untrusted')
    const untrusted = runCli(root, ['verify-policy', 'status'])
    expect(untrusted.status).toBe(1)
    expect(untrusted.stdout).toContain('untrusted ')

    const setup = runCli(root, [
      'setup', '--yes', '--allow', 'src/**', '--hooks', 'none', '--trust-verify',
    ])
    expect(setup.status, `${setup.stderr}\n${setup.stdout}`).toBe(0)
    expect(setup.stdout).toContain('Trusted the exact verification command list')
    expect(setup.stdout).toContain('Automatic hooks were not installed')
    const status = runCli(root, ['verify-policy', 'status'])
    expect(status.status, status.stderr).toBe(0)
    expect(status.stdout).toContain('trusted ')
  }, 30_000)

  it('initializes repeated scope flags and warns before leaving hooks unconfigured', async () => {
    const configuredRoot = await repository()
    await installPersistentCliFixture(configuredRoot)
    const configured = runCli(configuredRoot, [
      'init',
      '--allow', 'src/**',
      '--allow', 'tests/**',
      '--deny', 'infra/production/**',
    ])
    expect(configured.status, configured.stderr).toBe(0)
    expect(configured.stdout).not.toContain('No allow globs configured')
    expect(await readFile(join(configuredRoot, '.codetruss.yml'), 'utf8')).toMatch(
      /allow:\n\s+- src\/\*\*\n\s+- tests\/\*\*[\s\S]*deny:\n\s+- infra\/production\/\*\*/,
    )
    const installed = runCli(configuredRoot, ['hooks', 'install', 'all'])
    expect(installed.status, `${installed.stderr}\n${installed.stdout}`).toBe(0)
    expect(installed.stdout).toContain('installed ')
    await mkdir(join(configuredRoot, '.codetruss', 'receipts'), { recursive: true })
    await writeFile(join(configuredRoot, '.codetruss', 'receipts', 'must-stay-local.patch'), 'private source diff\n')
    git(configuredRoot, 'add', '.')
    expect(git(configuredRoot, 'diff', '--cached', '--name-only')).not.toContain('.codetruss/')
    expect(git(configuredRoot, 'check-ignore', '--no-index', '.codetruss/receipts/must-stay-local.patch')).toContain(
      '.codetruss/receipts/must-stay-local.patch',
    )

    const unconfiguredRoot = await repository()
    const unconfigured = runCli(unconfiguredRoot, ['init'])
    expect(unconfigured.status, unconfigured.stderr).toBe(0)
    expect(unconfigured.stdout).toContain('No allow globs configured')
    expect(unconfigured.stdout).toContain('agent hooks cannot be installed')
    expect(await readFile(join(unconfiguredRoot, '.codetruss.yml'), 'utf8')).toContain('allow: []')
    const refused = runCli(unconfiguredRoot, ['hooks', 'install', 'all'])
    expect(refused.status).toBe(3)
    expect(refused.stderr).toContain('agent hooks require at least one allow glob')
  }, 20_000)

  it('completes the real hook runtime to CLI result-file boundary', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, '.gitignore'), '.codetruss/\n')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 1\n')
    const initialized = runCli(root, ['init', '--allow', 'src/**'])
    expect(initialized.status, initialized.stderr).toBe(0)
    git(root, 'add', '.gitignore', '.codetruss.yml', 'src/value.ts')
    git(root, 'commit', '--quiet', '-m', 'baseline')

    const prompt = {
      session_id: 'packaged-boundary-session',
      turn_id: 'packaged-boundary-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Update the scoped value',
      cwd: root,
    }
    const captured = runCli(root, ['hooks', 'dispatch', 'codex'], {}, `${JSON.stringify(prompt)}\n`)
    expect(captured.status, `${captured.stderr}\n${captured.stdout}`).toBe(0)
    expect(captured.stdout).toBe('')

    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 2\n')
    const stopped = runCli(root, ['hooks', 'dispatch', 'codex'], {}, `${JSON.stringify({
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    })}\n`)
    expect(stopped.status, `${stopped.stderr}\n${stopped.stdout}`).toBe(0)
    expect(stopped.stdout).toBe('')

    const receipt = await latestReceipt(root)
    expect(receipt).toMatchObject({
      verdict: 'PASS',
      task: 'Update the scoped value',
      invocation: { kind: 'agent_hook', provenance: 'hook_context', surface: 'codex', cliVersion: expect.any(String) },
    })
    const verified = runCli(root, ['verify', receipt.sessionId])
    expect(verified.status, verified.stderr).toBe(0)
    expect(verified.stdout).toContain(`verified ${receipt.sessionId} (PASS)`)
  }, 30_000)

  it('protects an existing agent runner immediately when an upgraded hook dispatches', async () => {
    const root = await repository()
    await installPersistentCliFixture(root)
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 1\n')
    expect(runCli(root, ['init', '--allow', 'src/**']).status).toBe(0)
    expect(runCli(root, ['hooks', 'install', 'codex']).status).toBe(0)
    const exclude = git(root, 'rev-parse', '--git-path', 'info/exclude').trim()
    await writeFile(isAbsolute(exclude) ? exclude : join(root, exclude), '# local excludes\n/node_modules/\n')
    expect(spawnSync('git', ['-C', root, 'check-ignore', '--quiet', '--', '.codetruss/hooks/agent.cjs']).status).toBe(1)

    const dispatched = runCli(root, ['hooks', 'dispatch', 'codex'], {}, `${JSON.stringify({
      session_id: 'upgraded-unignored-runner',
      turn_id: 'upgraded-unignored-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Capture a protected baseline',
      cwd: root,
    })}\n`)

    expect(dispatched.status, `${dispatched.stderr}\n${dispatched.stdout}`).toBe(0)
    expect(git(root, 'check-ignore', '--no-index', '.codetruss/hooks/agent.cjs')).toContain(
      '.codetruss/hooks/agent.cjs',
    )
  }, 30_000)

  it('fails closed when a wrapped agent force-stages private evidence', async () => {
    const root = await repository()
    await writeFile(join(root, 'value.ts'), 'export const value = 1\n')
    git(root, 'add', 'value.ts')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    const agentScript = [
      'const { mkdirSync, writeFileSync } = require("node:fs")',
      'const { spawnSync } = require("node:child_process")',
      'mkdirSync(".codetruss/receipts", { recursive: true })',
      'writeFileSync(".codetruss/receipts/force-staged.patch", "private diff\\n")',
      'const result = spawnSync("git", ["add", "-f", ".codetruss/receipts/force-staged.patch"])',
      'process.exit(result.status ?? 1)',
    ].join(';')

    const result = runCli(root, [
      'run', '--task', 'Attempt to stage private CodeTruss evidence', '--allow', 'value.ts', '--no-verify',
      '--', process.execPath, '-e', agentScript,
    ])

    expect(result.status).toBe(3)
    expect(result.stderr).toContain('.codetruss/ already contains 1 Git-tracked file')
    expect(git(root, 'diff', '--cached', '--name-only')).toContain('.codetruss/receipts/force-staged.patch')
  }, 30_000)

  it('keeps noisy hook verification bounded without overflowing the child envelope', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, '.gitignore'), '.codetruss/\n')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 1\n')
    expect(runCli(root, ['init', '--allow', 'src/**']).status).toBe(0)
    const noisyCommand = `${JSON.stringify(process.execPath)} -e ${JSON.stringify('process.stdout.write("x".repeat(2_000_000))')}`
    const configPath = join(root, '.codetruss.yml')
    const initialized = await readFile(configPath, 'utf8')
    await writeFile(configPath, initialized.replace('verify: []', `verify:\n  - ${JSON.stringify(noisyCommand)}`))
    const trusted = runCli(root, ['verify-policy', 'trust'])
    expect(trusted.status, trusted.stderr).toBe(0)
    git(root, 'add', '.gitignore', '.codetruss.yml', 'src/value.ts')
    git(root, 'commit', '--quiet', '-m', 'baseline')

    const prompt = {
      session_id: 'noisy-hook-boundary-session',
      turn_id: 'noisy-hook-boundary-turn',
      hook_event_name: 'UserPromptSubmit',
      prompt: 'Update the value and retain bounded verification evidence',
      cwd: root,
    }
    expect(runCli(root, ['hooks', 'dispatch', 'codex'], {}, `${JSON.stringify(prompt)}\n`).status).toBe(0)
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 2\n')
    const stopped = runCli(root, ['hooks', 'dispatch', 'codex'], {}, `${JSON.stringify({
      ...prompt,
      hook_event_name: 'Stop',
      background_tasks: [],
    })}\n`)

    expect(stopped.status, `${stopped.stderr}\n${stopped.stdout}`).toBe(0)
    expect(stopped.stdout).toBe('')
    expect(stopped.stderr).not.toContain('x'.repeat(1_000))
    const receipt = await latestReceipt(root)
    expect(receipt).toMatchObject({ verdict: 'PASS' })
    expect(receipt.verifications).toEqual([
      expect.objectContaining({ exitCode: 0, truncated: true }),
    ])
    expect(receipt.verifications[0]!.output.length).toBeLessThanOrEqual(16_384)
    expect(runCli(root, ['verify', receipt.sessionId]).status).toBe(0)
  }, 30_000)

  it('creates and verifies a useful first receipt without repository configuration', async () => {
    const root = await repository()
    await writeFile(join(root, 'example.ts'), 'export const value = 1\n')
    git(root, 'add', 'example.ts')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'example.ts'), 'export const value = 2\n')

    const reviewed = runCli(root, ['review', '--task', 'Review my current agent changes'])
    expect(reviewed.status, `${reviewed.stderr}\n${reviewed.stdout}`).toBe(1)
    expect(reviewed.stdout).toContain('First signed receipt created')
    expect(reviewed.stdout).toContain('REVIEW_REQUIRED exits 1 by design')
    expect(reviewed.stdout).toContain('codetruss verify latest')
    expect(reviewed.stdout).toContain('Automate future checks: codetruss setup')
    expect((await readdir(join(root, '.codetruss', 'receipts'))).sort()).toHaveLength(4)
    expect((await latestReceipt(root)).invocation).toMatchObject({ kind: 'manual_review', provenance: 'direct', cliVersion: expect.any(String) })

    const verified = runCli(root, ['verify', 'latest'])
    expect(verified.status, verified.stderr).toBe(0)
    expect(verified.stdout).toContain('verified ')
    expect(verified.stdout).toContain('(REVIEW_REQUIRED)')

    const metrics = runCli(root, ['metrics', '--json'])
    expect(metrics.status, metrics.stderr).toBe(0)
    expect(JSON.parse(metrics.stdout)).toMatchObject({
      privacy: { localOnly: true, receiptLevelContentIncluded: false },
      receipts: { verified: 1, invocations: { manual_review: 1 } },
    })
    expect(metrics.stdout).not.toContain('Review my current agent changes')
  }, 20_000)

  it('gives configured repositories the next hook step instead of repeating setup', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 1\n')
    git(root, 'add', 'src/value.ts')
    git(root, 'commit', '--quiet', '-m', 'baseline')

    const setup = runCli(root, ['setup', '--yes', '--allow', 'src/**', '--hooks', 'none'])
    expect(setup.status, `${setup.stderr}\n${setup.stdout}`).toBe(0)
    git(root, 'add', '.codetruss.yml')
    git(root, 'commit', '--quiet', '-m', 'configure CodeTruss')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 2\n')

    const reviewed = runCli(root, ['review', '--task', 'Update the approved source file'])
    expect(reviewed.status, `${reviewed.stderr}\n${reviewed.stdout}`).toBe(0)
    expect(reviewed.stdout).toContain('First signed receipt created')
    expect(reviewed.stdout).toContain('Enable automatic checks: codetruss hooks install all')
    expect(reviewed.stdout).not.toContain('Automate future checks: codetruss setup')
  }, 20_000)

  it('points configured repositories with hooks at diagnostics', async () => {
    const root = await repository()
    await installPersistentCliFixture(root)
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 1\n')
    git(root, 'add', 'src/value.ts')
    git(root, 'commit', '--quiet', '-m', 'baseline')

    const setup = runCli(root, ['setup', '--yes', '--allow', 'src/**', '--hooks', 'none'])
    expect(setup.status, `${setup.stderr}\n${setup.stdout}`).toBe(0)
    git(root, 'add', '.codetruss.yml')
    git(root, 'commit', '--quiet', '-m', 'configure CodeTruss')
    const installed = runCli(root, ['hooks', 'install', 'pre-commit'])
    expect(installed.status, `${installed.stderr}\n${installed.stdout}`).toBe(0)
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 2\n')

    const reviewed = runCli(root, ['review', '--task', 'Update the approved source file'])
    expect(reviewed.status, `${reviewed.stderr}\n${reviewed.stdout}`).toBe(0)
    expect(reviewed.stdout).toContain('Check automatic hooks: codetruss hooks doctor all')
    expect(reviewed.stdout).not.toContain('codetruss setup')
  }, 20_000)

  it('records generated pre-commit reviews as automated provenance', async () => {
    const root = await repository()
    await writeFile(join(root, 'value.ts'), 'export const value = 1\n')
    git(root, 'add', 'value.ts')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'value.ts'), 'export const value = 2\n')
    git(root, 'add', 'value.ts')

    const result = runCli(
      root,
      ['review', '--staged', '--task', 'pre-commit', '--allow', 'value.ts', '--no-verify'],
      { CODETRUSS_INTERNAL_PRE_COMMIT: '1' },
    )
    expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0)
    expect(result.stdout).toContain('First signed receipt created. PASS exits 0.')
    expect(result.stdout).not.toContain('REVIEW_REQUIRED exits 1')
    expect((await latestReceipt(root)).invocation).toMatchObject({
      kind: 'pre_commit', provenance: 'self_attested', cliVersion: expect.any(String),
    })
  }, 20_000)

  it('supports global auth status and logout outside a Git repository', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-auth-command-'))
    cleanup.push(root, `${root}-home`)

    const status = runCli(root, ['auth', 'status'])
    expect(status.status, status.stderr).toBe(1)
    expect(status.stdout).toContain('Not signed in')
    expect(status.stderr).not.toContain('Git repository')

    const logout = runCli(root, ['auth', 'logout'])
    expect(logout.status, logout.stderr).toBe(0)
    expect(logout.stdout).toContain('Already signed out')
  })

  it('keeps legacy LLM settings compatible with deterministic reviews', async () => {
    const root = await repository()
    await writeFile(join(root, '.gitignore'), '.codetruss/\n')
    await writeFile(join(root, 'example.ts'), 'export const value = 1\n')

    for (const [message, config] of [
      ['legacy Codex provider', 'version: 1\nllm:\n  provider: codex\n'],
      ['legacy unscoped model', 'version: 1\nllm:\n  model: legacy-model\n'],
    ] as const) {
      await writeFile(join(root, '.codetruss.yml'), config)
      git(root, 'add', '.gitignore', '.codetruss.yml', 'example.ts')
      git(root, 'commit', '--quiet', '-m', message)

      const result = runCli(root, [
        'review', '--task', 'Confirm the clean deterministic state', '--allow', 'example.ts', '--no-verify',
      ])
      expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0)
      expect((await latestReceipt(root)).llm).toBeUndefined()
    }
  }, 20_000)

  it('analyzes exact staged bytes even when the working file hides a staged secret', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'config.ts'), 'export const region = "us-east-1"\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'src', 'config.ts'), `export const key = "${SYNTHETIC_AWS_KEY}"\n`)
    git(root, 'add', 'src/config.ts')
    await writeFile(join(root, 'src', 'config.ts'), 'export const region = "us-west-2"\n')

    const result = runCli(root, ['review', '--staged', '--task', 'Update the region', '--allow', 'src/**', '--no-verify'])
    expect(result.status, result.stderr).toBe(2)
    const receipt = await latestReceipt(root)
    expect(receipt.verdict).toBe('FAILED')
    expect(receipt.invocation).toMatchObject({ kind: 'manual_review', provenance: 'direct', cliVersion: expect.any(String) })
    expect(receipt.analyzers.findings.some((finding) => finding.title.includes('AWS access key'))).toBe(true)
    expect(receipt.diff.truncated).toBe(false)
    expect(await readFile(join(root, '.codetruss', 'receipts', receipt.evidence.patchFile!), 'utf8')).toContain(SYNTHETIC_AWS_KEY)
  }, 20_000)

  it('runs verification against the exact staged snapshot instead of unstaged bytes', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "baseline"\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "staged"\n')
    git(root, 'add', 'src/value.ts')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "working"\n')
    const verify = `${JSON.stringify(process.execPath)} -e "const fs=require('node:fs');process.exit(fs.readFileSync('src/value.ts','utf8').includes('staged')?0:1)"`

    const result = runCli(root, ['review', '--staged', '--task', 'Stage the approved value', '--allow', 'src/**', '--verify', verify])
    expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0)
    const receipt = await latestReceipt(root)
    expect(receipt.verdict).toBe('PASS')
    expect(receipt.invocation).toMatchObject({ kind: 'manual_review', provenance: 'direct', cliVersion: expect.any(String) })
    expect(receipt.verifications).toEqual([expect.objectContaining({ command: verify, exitCode: 0 })])
    expect(await readFile(join(root, 'src', 'value.ts'), 'utf8')).toContain('working')
  }, 20_000)

  it('exposes ignored installed Node tools to each exact verification snapshot', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await mkdir(join(root, 'node_modules', 'snapshot-probe'), { recursive: true })
    await writeFile(join(root, '.gitignore'), 'node_modules/\n')
    await writeFile(
      join(root, 'package.json'),
      `${JSON.stringify({ private: true, scripts: { test: 'node node_modules/snapshot-probe/probe.cjs' } }, null, 2)}\n`,
    )
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "baseline"\n')
    const probe = join(root, 'node_modules', 'snapshot-probe', 'probe.cjs')
    await writeFile(
      probe,
      [
        'const fs = require("node:fs")',
        'const cp = require("node:child_process")',
        'const linked = fs.lstatSync("node_modules").isSymbolicLink()',
        'const exact = fs.readFileSync("src/value.ts", "utf8").includes("staged")',
        'const cleanEnvironment = process.env.GIT_INDEX_FILE === undefined',
        'const isolated = cp.spawnSync("git", ["rev-parse", "--show-toplevel"], { stdio: "ignore" }).status !== 0',
        'process.exit(linked && exact && cleanEnvironment && isolated ? 0 : 1)',
        '',
      ].join('\n'),
    )
    git(root, 'add', '.gitignore', 'package.json', 'src/value.ts')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "staged"\n')
    git(root, 'add', 'src/value.ts')

    const result = runCli(root, [
      'review', '--staged', '--task', 'Use the repository test toolchain',
      '--allow', 'src/**', '--verify', 'npm test',
    ], { GIT_INDEX_FILE: join(root, '.git', 'index') })

    expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0)
    const receipt = await latestReceipt(root)
    expect(receipt.verifications).toEqual([
      expect.objectContaining({ command: 'npm test', exitCode: 0 }),
    ])
    expect(receipt.coverageNotes.at(-1)).toContain('installed Node dependencies')
  }, 20_000)

  it('does not fail a harmless edit because of an unchanged pre-existing finding', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'config.ts'), `export const key = "${SYNTHETIC_AWS_KEY}"\n`)
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'legacy secret')
    await writeFile(join(root, 'src', 'config.ts'), `export const key = "${SYNTHETIC_AWS_KEY}"\n// harmless documentation\n`)

    const result = runCli(root, ['review', '--task', 'Document legacy configuration', '--allow', 'src/**', '--no-verify'])
    expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0)
    const receipt = await latestReceipt(root)
    expect(receipt.verdict).toBe('PASS')
    expect(receipt.analyzers.findings).toHaveLength(0)
    expect(receipt.analyzers.delta).toMatchObject({ introduced: 0, worsened: 0 })
    expect(receipt.analyzers.delta!.recurring).toBeGreaterThanOrEqual(1)
  }, 20_000)

  it('fails closed and records byte counts when diff evidence is truncated', async () => {
    const root = await repository()
    await writeFile(join(root, 'large.txt'), '')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'large.txt'), Buffer.alloc(21 * 1024 * 1024, 65))

    const result = runCli(root, ['review', '--task', 'Update the large fixture', '--allow', 'large.txt', '--no-verify'])
    expect(result.status, result.stderr).toBe(2)
    const receipt = await latestReceipt(root)
    expect(receipt.verdict).toBe('FAILED')
    expect(receipt.diff.truncated).toBe(true)
    expect(receipt.diff.totalBytes).toBeGreaterThan(receipt.diff.bytes)
    expect(receipt.reasons.some((reason) => reason.includes('diff capture retained'))).toBe(true)
  }, 30_000)

  it('measures a first commit against the empty tree in an unborn session', async () => {
    const root = await repository()
    const agentScript = [
      'const fs = require("node:fs")',
      'const cp = require("node:child_process")',
      'fs.mkdirSync("src", { recursive: true })',
      'fs.writeFileSync("src/first.ts", "export const first = true\\n")',
      'cp.spawnSync("git", ["add", "."], { stdio: "inherit" })',
      'const commit = cp.spawnSync("git", ["commit", "--quiet", "-m", "first"], { stdio: "inherit" })',
      'process.exit(commit.status ?? 1)',
    ].join(';')

    const result = runCli(root, ['run', '--task', 'Create the first source file', '--allow', 'src/**', '--no-verify', '--', process.execPath, '-e', agentScript])
    expect([0, 1], result.stderr).toContain(result.status)
    const receipt = await latestReceipt(root)
    expect(receipt.startCommit).toBe('')
    expect(receipt.invocation).toMatchObject({ kind: 'manual_run', provenance: 'direct', cliVersion: expect.any(String) })
    expect(receipt.endCommit).toMatch(/^[0-9a-f]{40,64}$/)
    expect(receipt.files).toEqual(expect.arrayContaining([expect.objectContaining({ path: 'src/first.ts', change: 'added' })]))
    expect(receipt.reasons).not.toContain('no repository files changed')
  }, 20_000)

  it('compares an agent-modified untracked file with its exact dirty baseline bytes', async () => {
    const root = await repository()
    await writeFile(join(root, 'README.md'), 'baseline\n')
    git(root, 'add', 'README.md')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'draft.txt'), 'before the agent\n')
    const agentScript = 'require("node:fs").writeFileSync("draft.txt", "after the agent\\n")'

    const result = runCli(root, [
      'run', '--task', 'Update the draft', '--allow', 'draft.txt', '--no-verify',
      '--', process.execPath, '-e', agentScript,
    ])
    expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(1)
    const receipt = await latestReceipt(root)
    expect(receipt.verdict).toBe('REVIEW_REQUIRED')
    expect(receipt.startDirty).toBe(true)
    expect(receipt.startDirtyFiles).toContain('draft.txt')
    expect(receipt.files).toEqual([expect.objectContaining({ path: 'draft.txt', change: 'modified' })])
    expect(receipt.git).toEqual({
      baselineTree: expect.stringMatching(/^[0-9a-f]{40,64}$/),
      finalTree: expect.stringMatching(/^[0-9a-f]{40,64}$/),
    })
    expect(receipt.policy).toEqual({ sha256: expect.stringMatching(/^[0-9a-f]{64}$/) })
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', receipt.git!.baselineTree]).status).not.toBe(0)
    expect(spawnSync('git', ['-C', root, 'cat-file', '-e', receipt.git!.finalTree]).status).not.toBe(0)
    expect(await readdir(join(root, '.git', 'codetruss', 'commands', 'v1'))).toEqual([])
    const patch = await readFile(join(root, '.codetruss', 'receipts', receipt.evidence.patchFile!), 'utf8')
    expect(patch).toContain('-before the agent')
    expect(patch).toContain('+after the agent')
    expect(patch).not.toContain('new file mode')
  }, 20_000)

  it('gives every verification command a fresh copy of the immutable final tree', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await mkdir(join(root, 'verify'))
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "baseline"\n')
    await writeFile(join(root, 'verify', 'mutate.cjs'), "require('node:fs').writeFileSync('src/value.ts', 'corrupted\\n')\n")
    await writeFile(join(root, 'verify', 'assert-final.cjs'), [
      "const value = require('node:fs').readFileSync('src/value.ts', 'utf8')",
      "process.exit(value === 'export const value = \\\"intended\\\"\\n' ? 0 : 1)",
      '',
    ].join('\n'))
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "intended"\n')
    // Script files avoid platform-specific nested `node -e` shell quoting;
    // this test is about fresh materializations, not cmd.exe parsing.
    const mutate = `${JSON.stringify(process.execPath)} verify/mutate.cjs`
    const assertFinal = `${JSON.stringify(process.execPath)} verify/assert-final.cjs`

    const result = runCli(root, [
      'review', '--task', 'Set the intended value', '--allow', 'src/**',
      '--verify', mutate, '--verify', assertFinal,
    ])
    expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0)
    const receipt = await latestReceipt(root)
    expect(receipt.verdict).toBe('PASS')
    expect(receipt.verifications.map((verification) => verification.exitCode)).toEqual([0, 0])
    expect(receipt.coverageNotes.at(-1)).toContain('fresh materialization')
    expect(await readFile(join(root, 'src', 'value.ts'), 'utf8')).toBe('export const value = "intended"\n')
  }, 20_000)

  it('freezes the receipt end commit and tree ids before verification mutates the source repository', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 1\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    const agentScript = [
      'const fs = require("node:fs")',
      'const cp = require("node:child_process")',
      'fs.writeFileSync("src/value.ts", "export const value = 2\\n")',
      'cp.spawnSync("git", ["add", "src/value.ts"], { stdio: "inherit" })',
      'const commit = cp.spawnSync("git", ["commit", "--quiet", "-m", "agent result"], { stdio: "inherit" })',
      'process.exit(commit.status ?? 1)',
    ].join(';')
    const rootLiteral = JSON.stringify(root)
    const verifierScript = [
      'const fs = require("node:fs")',
      'const path = require("node:path")',
      'const cp = require("node:child_process")',
      `const root = ${rootLiteral}`,
      'fs.writeFileSync(path.join(root, "post-verify.txt"), "verification mutation\\n")',
      'cp.spawnSync("git", ["-C", root, "add", "post-verify.txt"], { stdio: "inherit" })',
      'const commit = cp.spawnSync("git", ["-C", root, "commit", "--quiet", "-m", "verification mutation"], { stdio: "inherit" })',
      'process.exit(commit.status ?? 1)',
    ].join(';')
    const verify = `${JSON.stringify(process.execPath)} -e ${JSON.stringify(verifierScript)}`

    const result = runCli(root, [
      'run', '--task', 'Update the value', '--allow', 'src/**', '--verify', verify,
      '--', process.execPath, '-e', agentScript,
    ])
    expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0)
    const receipt = await latestReceipt(root)
    const liveHead = git(root, 'rev-parse', 'HEAD').trim()
    const agentCommit = git(root, 'rev-parse', 'HEAD^').trim()
    expect(receipt.endCommit).toBe(agentCommit)
    expect(receipt.endCommit).not.toBe(liveHead)
    expect(receipt.git).toEqual({
      baselineTree: expect.stringMatching(/^[0-9a-f]{40,64}$/),
      finalTree: expect.stringMatching(/^[0-9a-f]{40,64}$/),
    })
    expect(receipt.files.map((file) => file.path)).toEqual(['src/value.ts'])
    expect(receipt.files.some((file) => file.path === 'post-verify.txt')).toBe(false)
  }, 30_000)

  it('requires user-local approval for repo verification commands and supports private sync preview', async () => {
    const root = await repository()
    await mkdir(join(root, 'src'))
    await writeFile(join(root, '.codetruss.yml'), JSON.stringify({
      version: 1,
      allow: ['src/**'],
      verify: ['node -e "process.exit(0)"'],
    }, null, 2))
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 1\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = 2\n')

    const refused = runCli(root, ['review', '--task', 'Update the value'])
    expect(refused.status).toBe(3)
    expect(refused.stderr).toContain('repository verification commands are not trusted')

    const trusted = runCli(root, ['verify-policy', 'trust'])
    expect(trusted.status, trusted.stderr).toBe(0)
    expect(trusted.stdout).toContain('node -e "process.exit(0)"')

    const reviewed = runCli(root, ['review', '--task', 'Update the value'])
    expect(reviewed.status, `${reviewed.stderr}\n${reviewed.stdout}`).toBe(0)
    const receipt = await latestReceipt(root)
    expect(receipt.verifications).toEqual([expect.objectContaining({ exitCode: 0 })])

    const preview = runCli(root, ['sync', 'latest', '--dry-run'])
    expect(preview.status, preview.stderr).toBe(0)
    expect(preview.stdout).toContain('signedReceipt')
    expect(preview.stdout).not.toContain(root)
    expect(preview.stdout).not.toContain('process.exit(0)')
  }, 30_000)
})
