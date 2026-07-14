import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { allocatedVerificationTimeout, runVerification } from '../src/git.js'

const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, {
    recursive: true,
    force: true,
    maxRetries: 20,
    retryDelay: 50,
  })))
})

describe('verification command lifecycle', () => {
  it('fair-shares one internal deadline while preserving the per-command cap', () => {
    expect(allocatedVerificationTimeout(210_000, 30_000, 2)).toBe(90_000)
    expect(allocatedVerificationTimeout(210_000, 30_000, 1)).toBe(120_000)
    expect(allocatedVerificationTimeout(210_000, 210_001, 3)).toBe(0)
    expect(() => allocatedVerificationTimeout(210_000, 30_000, 0)).toThrow(/positive integer/)
  })

  it('returns a bounded, deterministic timeout failure', async () => {
    const root = await temporaryDirectory()
    const script = join(root, 'hang.cjs')
    await writeFile(script, 'process.stdout.write("started\\n"); setInterval(() => {}, 1_000)\n')

    const result = await runVerification(nodeCommand(script), root, 1_024, process.env, 500)

    expect(result).toMatchObject({ exitCode: 124, truncated: false })
    expect(result.output).toBe('started\n\nCodeTruss verification timed out after 500ms.\n')
    expect(result.durationMs).toBeLessThan(2_000)
  })

  it('keeps captured output within the configured byte ceiling', async () => {
    const root = await temporaryDirectory()
    const script = join(root, 'output.cjs')
    await writeFile(script, 'process.stdout.write("a".repeat(512)); process.stderr.write("tail-marker")\n')

    const result = await runVerification(nodeCommand(script), root, 128, process.env, 2_000)

    expect(result.exitCode).toBe(0)
    expect(result.truncated).toBe(true)
    expect(Buffer.byteLength(result.output)).toBeLessThanOrEqual(128)
    expect(result.output).toContain('… output truncated …')
    expect(result.output).toContain('tail-marker')
  })

  it('retains the deadline after a command leader exits while a detached child holds its pipes', async () => {
    const root = await temporaryDirectory()
    const descendantScript = join(root, 'escaped-descendant.cjs')
    const parentScript = join(root, 'escaped-parent.cjs')
    const pidFile = join(root, 'escaped-descendant.pid')
    await writeFile(descendantScript, 'setInterval(() => {}, 1_000)\n')
    await writeFile(parentScript, [
      "const { spawn } = require('node:child_process')",
      "const { writeFileSync } = require('node:fs')",
      `const child = spawn(process.execPath, [${JSON.stringify(descendantScript)}], { detached: true, stdio: ['ignore', 'inherit', 'inherit'] })`,
      'child.unref()',
      `writeFileSync(${JSON.stringify(pidFile)}, String(child.pid))`,
    ].join(';'))
    let descendantPid: number | undefined

    try {
      const result = await runVerification(nodeCommand(parentScript), root, 1_024, process.env, 500)
      expect(result.exitCode).toBe(124)
      expect(result.output).toContain('CodeTruss verification timed out after 500ms.')
      expect(result.durationMs).toBeLessThan(2_000)
      descendantPid = Number(await readFile(pidFile, 'utf8'))
      expect(Number.isSafeInteger(descendantPid)).toBe(true)
    } finally {
      if (descendantPid !== undefined && processExists(descendantPid)) {
        try { process.kill(descendantPid, 'SIGKILL') } catch { /* already gone */ }
        await expectProcessToExit(descendantPid)
      }
    }
  })

  it.runIf(process.platform !== 'win32')('terminates descendants in the verification process group', async () => {
    const root = await temporaryDirectory()
    const descendantScript = join(root, 'descendant.cjs')
    const parentScript = join(root, 'parent.cjs')
    const pidFile = join(root, 'descendant.pid')
    await writeFile(descendantScript, "process.on('SIGTERM', () => {}); setInterval(() => {}, 1_000)\n")
    await writeFile(parentScript, [
      "const { spawn } = require('node:child_process')",
      "const { writeFileSync } = require('node:fs')",
      `const child = spawn(process.execPath, [${JSON.stringify(descendantScript)}], { stdio: 'ignore' })`,
      `writeFileSync(${JSON.stringify(pidFile)}, String(child.pid))`,
      'setInterval(() => {}, 1_000)',
    ].join(';'))
    let descendantPid: number | undefined

    try {
      const result = await runVerification(nodeCommand(parentScript), root, 1_024, process.env, 500)
      expect(result.exitCode).toBe(124)
      descendantPid = Number(await readFile(pidFile, 'utf8'))
      expect(Number.isSafeInteger(descendantPid)).toBe(true)
      await expectProcessToExit(descendantPid)
    } finally {
      if (descendantPid !== undefined && processExists(descendantPid)) {
        try { process.kill(descendantPid, 'SIGKILL') } catch { /* already gone */ }
      }
    }
  })

  it.runIf(process.platform !== 'win32')('cleans up descendants after an otherwise successful verification', async () => {
    const root = await temporaryDirectory()
    const descendantScript = join(root, 'successful-descendant.cjs')
    const parentScript = join(root, 'successful-parent.cjs')
    const pidFile = join(root, 'successful-descendant.pid')
    await writeFile(descendantScript, "process.on('SIGTERM', () => {}); setInterval(() => {}, 1_000)\n")
    await writeFile(parentScript, [
      "const { spawn } = require('node:child_process')",
      "const { writeFileSync } = require('node:fs')",
      `const child = spawn(process.execPath, [${JSON.stringify(descendantScript)}], { stdio: 'ignore' })`,
      'child.unref()',
      `writeFileSync(${JSON.stringify(pidFile)}, String(child.pid))`,
    ].join(';'))
    let descendantPid: number | undefined

    try {
      const result = await runVerification(nodeCommand(parentScript), root, 1_024, process.env, 2_000)
      expect(result.exitCode).toBe(0)
      descendantPid = Number(await readFile(pidFile, 'utf8'))
      expect(Number.isSafeInteger(descendantPid)).toBe(true)
      await expectProcessToExit(descendantPid)
    } finally {
      if (descendantPid !== undefined && processExists(descendantPid)) {
        try { process.kill(descendantPid, 'SIGKILL') } catch { /* already gone */ }
      }
    }
  })
})

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'codetruss-verification-timeout-'))
  temporaryDirectories.push(directory)
  return directory
}

function nodeCommand(script: string): string {
  return `${JSON.stringify(process.execPath)} ${JSON.stringify(script)}`
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM'
  }
}

async function expectProcessToExit(pid: number): Promise<void> {
  const deadline = Date.now() + 2_000
  while (processExists(pid) && Date.now() < deadline) {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25))
  }
  expect(processExists(pid)).toBe(false)
}
