import { spawnSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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

function runCli(root: string, args: string[], extraEnvironment: Partial<NodeJS.ProcessEnv> = {}) {
  return spawnSync(TSX_BIN, [CLI_ENTRY, ...args], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      ...extraEnvironment,
      HOME: `${root}-home`,
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
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "baseline"\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'baseline')
    await writeFile(join(root, 'src', 'value.ts'), 'export const value = "intended"\n')
    const mutate = `${JSON.stringify(process.execPath)} -e ${JSON.stringify("require('node:fs').writeFileSync('src/value.ts', 'corrupted\\n')")}`
    const assertFinal = `${JSON.stringify(process.execPath)} -e ${JSON.stringify("const value=require('node:fs').readFileSync('src/value.ts','utf8');process.exit(value === 'export const value = \\\"intended\\\"\\n' ? 0 : 1)")}`

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
