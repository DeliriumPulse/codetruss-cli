import { lstat, mkdir, readFile, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mkdtemp } from 'node:fs/promises'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  cliAuthFilePath,
  clearCliAuth,
  loadCliAuth,
  loadSyncAuthentication,
  loadSyncBearer,
  saveCliAuth,
  type CliAuthCredential,
} from '../src/auth-storage.js'
import { hostedAuthStatus, loginHosted, logoutHosted } from '../src/hosted-auth.js'

const roots: string[] = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    const { rm } = await import('node:fs/promises')
    await rm(root, { recursive: true, force: true })
  }))
})

async function authPath(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'codetruss-auth-'))
  roots.push(root)
  return join(root, 'config', 'codetruss', 'auth.json')
}

function credential(overrides: Partial<CliAuthCredential> = {}): CliAuthCredential {
  return {
    version: 1,
    origin: 'https://codetruss.com',
    accessToken: `ct_cli_${'A'.repeat(32)}`,
    keyPrefix: 'ct_cli_AAAA',
    org: { id: 'org1', name: 'Acme', slug: 'acme' },
    scopes: ['receipts:read', 'receipts:write'],
    expiresAt: '2026-10-12T12:00:00.000Z',
    authenticatedAt: '2026-07-14T12:00:00.000Z',
    ...overrides,
  }
}

describe('private CLI auth storage', () => {
  it('rejects a relative XDG path instead of writing credentials into the working tree', () => {
    expect(() => cliAuthFilePath({ ...process.env, XDG_CONFIG_HOME: '.codetruss-user' }))
      .toThrow('absolute user config path')
  })

  it('writes atomically with private directory and file modes', async () => {
    const path = await authPath()
    await saveCliAuth(credential(), path)

    expect(await loadCliAuth(path)).toEqual(credential())
    expect(JSON.parse(await readFile(path, 'utf8')).accessToken).toMatch(/^ct_cli_/)
    if (process.platform !== 'win32') {
      expect((await lstat(path)).mode & 0o777).toBe(0o600)
      expect((await lstat(join(path, '..'))).mode & 0o777).toBe(0o700)
    }
  })

  it('refuses symlinked credential files and never follows them', async () => {
    if (process.platform === 'win32') return
    const path = await authPath()
    await mkdir(join(path, '..'), { recursive: true })
    const target = join(path, '..', 'target.json')
    await writeFile(target, JSON.stringify(credential()))
    await symlink(target, path)
    await expect(loadCliAuth(path)).rejects.toThrow('symlinked')
  })

  it('prefers an explicit CI API key without persisting it', async () => {
    const path = await authPath()
    await saveCliAuth(credential(), path)
    expect(await loadSyncBearer({ ...process.env, CODETRUSS_API_KEY: 'ct_live_ci' }, path)).toBe('ct_live_ci')
    expect((await loadCliAuth(path))?.accessToken).toBe(credential().accessToken)
  })

  it('binds a saved bearer to its approved origin and an environment bearer to the fixed origin', async () => {
    const path = await authPath()
    await saveCliAuth(credential(), path)
    await expect(loadSyncAuthentication({ ...process.env, CODETRUSS_API_KEY: undefined }, path))
      .resolves.toMatchObject({
        bearer: credential().accessToken,
        origin: 'https://codetruss.com',
        source: 'saved-login',
      })
    await expect(loadSyncAuthentication({ ...process.env, CODETRUSS_API_KEY: 'ct_live_ci' }, path))
      .resolves.toEqual({
        bearer: 'ct_live_ci',
        origin: 'https://codetruss.com',
        source: 'environment',
      })
  })
})

describe('hosted browser login', () => {
  it('opens the confirmation page, honors polling backoff, and saves only after success', async () => {
    const path = await authPath()
    const opened: string[] = []
    const sleeps: number[] = []
    const output: string[] = []
    let current = Date.parse('2026-07-14T12:00:00.000Z')
    let poll = 0
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.endsWith('/device')) {
        return Response.json({
          device_code: 'd'.repeat(43),
          user_code: 'BCDF-GHJK',
          verification_uri: 'https://codetruss.com/cli/authorize',
          verification_uri_complete: 'https://codetruss.com/cli/authorize?user_code=BCDF-GHJK',
          expires_in: 600,
          interval: 5,
        })
      }
      poll += 1
      if (poll === 1) return Response.json({ error: 'authorization_pending', interval: 5 }, { status: 400 })
      if (poll === 2) return Response.json({ error: 'slow_down', interval: 10 }, { status: 400 })
      return Response.json({
        access_token: `ct_cli_${'B'.repeat(32)}`,
        token_type: 'Bearer',
        expires_in: 7_776_000,
        scope: 'receipts:read receipts:write',
        key_prefix: 'ct_cli_BBBB',
        org: { id: 'org1', name: 'Acme', slug: 'acme' },
      })
    })

    const signedIn = await loginHosted({
      authFile: path,
      fetch: fetchMock as typeof fetch,
      openBrowser: async (url) => { opened.push(url); return true },
      sleep: async (milliseconds) => { sleeps.push(milliseconds); current += milliseconds },
      now: () => current,
      stdout: { write: (value) => { output.push(String(value)); return true } },
      stderr: { write: () => true },
      clientName: 'test-machine',
    })

    expect(opened).toEqual(['https://codetruss.com/cli/authorize?user_code=BCDF-GHJK'])
    expect(sleeps).toEqual([5_000, 5_000, 10_000])
    expect(output.join('')).toContain('BCDF-GHJK')
    expect(output.join('')).not.toContain(signedIn.accessToken)
    expect(await loadCliAuth(path)).toEqual(signedIn)
  })

  it('reports remote validity without printing or changing the saved bearer', async () => {
    const path = await authPath()
    await saveCliAuth(credential(), path)
    const status = await hostedAuthStatus({
      authFile: path,
      fetch: vi.fn(async () => Response.json({ authenticated: true })) as typeof fetch,
    })
    expect(status).toMatchObject({ state: 'authenticated', credential: { org: { slug: 'acme' } } })
    expect(await loadCliAuth(path)).toEqual(credential())
  })

  it('refuses to open a verification URL outside the authenticated CodeTruss origin', async () => {
    const path = await authPath()
    const opened = vi.fn(async () => true)
    await expect(loginHosted({
      authFile: path,
      fetch: vi.fn(async () => Response.json({
        device_code: 'd'.repeat(43),
        user_code: 'BCDF-GHJK',
        verification_uri: 'https://attacker.invalid/cli/authorize',
        verification_uri_complete: 'https://attacker.invalid/cli/authorize?user_code=BCDF-GHJK',
        expires_in: 600,
        interval: 5,
      })) as typeof fetch,
      openBrowser: opened,
      stdout: { write: () => true },
      stderr: { write: () => true },
    })).rejects.toThrow('outside the authenticated origin')
    expect(opened).not.toHaveBeenCalled()
    expect(await loadCliAuth(path)).toBeNull()
  })

  it('retains the local credential on server failure and clears it after revocation', async () => {
    const path = await authPath()
    await saveCliAuth(credential(), path)
    await expect(logoutHosted({
      authFile: path,
      fetch: vi.fn(async () => new Response('error', { status: 503 })) as typeof fetch,
    })).rejects.toThrow('retained for retry')
    expect(await loadCliAuth(path)).not.toBeNull()

    await expect(logoutHosted({
      authFile: path,
      fetch: vi.fn(async () => Response.json({ revoked: true })) as typeof fetch,
    })).resolves.toBe(true)
    expect(await loadCliAuth(path)).toBeNull()
    await clearCliAuth(path)
  })
})
