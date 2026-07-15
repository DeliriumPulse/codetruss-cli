import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { installHooks } from '../src/hooks.js'

const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })))
})

describe('installed agent hook deadlines', () => {
  it.each(['claude', 'codex'] as const)('gives the %s Stop envelope headroom beyond its five-minute child review', async (surface) => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-hook-timeout-'))
    temporaryDirectories.push(root)
    await mkdir(join(root, 'node_modules', '.bin'), { recursive: true })
    const localCli = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
    await writeFile(localCli, process.platform === 'win32' ? '@exit /b 0\r\n' : '#!/bin/sh\nexit 0\n')
    await chmod(localCli, 0o755)
    await writeFile(join(root, '.codetruss.yml'), 'version: 1\nallow:\n  - src/**\ndeny: []\nverify: []\n')

    await installHooks(root, surface)

    const path = join(root, surface === 'claude' ? '.claude/settings.json' : '.codex/hooks.json')
    const document = JSON.parse(await readFile(path, 'utf8')) as {
      hooks: Record<string, Array<{ hooks: Array<{ timeout?: number }> }>>
    }
    const timeout = document.hooks.Stop.flatMap((group) => group.hooks)[0]?.timeout
    expect(timeout).toBe(360)
    expect(timeout).toBeGreaterThan(5 * 60)
  })
})
