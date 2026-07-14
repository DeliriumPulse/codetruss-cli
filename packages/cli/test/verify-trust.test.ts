import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  revokeVerifyCommands,
  trustVerifyCommands,
  verifyCommandTrustHash,
  verifyCommandTrustStatus,
} from '../src/verify-trust.js'

describe('user-local verification command trust', () => {
  it('binds trust to the canonical repository and exact ordered commands without storing either', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-verify-trust-'))
    const root = join(parent, 'repo')
    const otherRoot = join(parent, 'other-repo')
    const trustFile = join(parent, 'user-config', 'verify-command-trust.json')
    const commands = ['pnpm lint', 'pnpm test -- --runInBand']

    const initial = await verifyCommandTrustStatus(root, commands, trustFile)
    expect(initial).toMatchObject({ trusted: false, trustFile })
    expect(initial.hash).toMatch(/^[0-9a-f]{64}$/)

    const trusted = await trustVerifyCommands(root, commands, trustFile, new Date('2026-07-14T12:00:00.000Z'))
    expect(trusted).toEqual({ hash: initial.hash, trusted: true, trustFile })
    await expect(verifyCommandTrustStatus(root, commands, trustFile)).resolves.toMatchObject({ trusted: true })
    await expect(verifyCommandTrustStatus(root, [...commands].reverse(), trustFile)).resolves.toMatchObject({ trusted: false })
    expect(await verifyCommandTrustHash(otherRoot, commands)).not.toBe(initial.hash)

    const stored = await readFile(trustFile, 'utf8')
    expect(JSON.parse(stored)).toEqual({
      version: 1,
      trusted: { [initial.hash]: { trustedAt: '2026-07-14T12:00:00.000Z' } },
    })
    expect(stored).not.toContain(root)
    expect(stored).not.toContain('pnpm lint')

    await expect(revokeVerifyCommands(root, commands, trustFile)).resolves.toMatchObject({ trusted: false })
    await expect(verifyCommandTrustStatus(root, commands, trustFile)).resolves.toMatchObject({ trusted: false })
  })

  it('fails closed on a corrupt user trust store', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-verify-trust-corrupt-'))
    const trustFile = join(parent, 'verify-command-trust.json')
    await writeFile(trustFile, '{"version":1,"trusted":{"not-a-hash":{}}}\n')
    await expect(verifyCommandTrustStatus(parent, ['npm test'], trustFile)).rejects.toThrow(
      'invalid; refusing to trust repository commands',
    )
  })
})
