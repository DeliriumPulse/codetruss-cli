import { mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  APPROVED_RECEIPT_DIR,
  PRODUCTION_SYNC_ORIGIN,
  initialize,
  loadConfig,
  receiptDir,
  resolveSyncOrigin,
} from '../src/config.js'

const originalKey = process.env.CODETRUSS_SIGNING_KEY
const originalDevSyncOrigin = process.env.CODETRUSS_DEV_SYNC_ORIGIN
afterEach(() => {
  if (originalKey === undefined) delete process.env.CODETRUSS_SIGNING_KEY
  else process.env.CODETRUSS_SIGNING_KEY = originalKey
  if (originalDevSyncOrigin === undefined) delete process.env.CODETRUSS_DEV_SYNC_ORIGIN
  else process.env.CODETRUSS_DEV_SYNC_ORIGIN = originalDevSyncOrigin
})

describe('initialization', () => {
  it('does not invent failing package scripts from a lockfile alone', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-init-'))
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    await writeFile(join(root, 'package.json'), `${JSON.stringify({ scripts: { dev: 'node app.js' } })}\n`)
    await writeFile(join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n')
    await initialize(root)
    const config = await loadConfig(root)
    expect(config.verify).toEqual([])
    expect(config.signing.publicKey).toContain('BEGIN PUBLIC KEY')
    const configText = await readFile(join(root, '.codetruss.yml'), 'utf8')
    expect(configText).not.toContain('pnpm lint')
    expect(configText).not.toContain('sync:')
  })

  it('never accepts a repository-selected bearer-token destination', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-config-sync-'))
    await writeFile(join(root, '.codetruss.yml'), 'version: 1\nsync:\n  url: https://collector.invalid\n')
    await expect(loadConfig(root)).rejects.toThrow('cannot configure a sync destination')

    // Existing production-only configs remain readable, but the returned value
    // is still the application-owned invariant rather than repository input.
    await writeFile(join(root, '.codetruss.yml'), `version: 1\nsync:\n  url: ${PRODUCTION_SYNC_ORIGIN}\n`)
    await expect(loadConfig(root)).resolves.toMatchObject({ sync: { url: PRODUCTION_SYNC_ORIGIN } })
  })

  it('hard-binds production sync and permits only an explicit loopback dev origin', () => {
    delete process.env.CODETRUSS_DEV_SYNC_ORIGIN
    expect(resolveSyncOrigin(undefined)).toBe(PRODUCTION_SYNC_ORIGIN)
    expect(resolveSyncOrigin('http://localhost:3000')).toBe('http://localhost:3000')
    expect(resolveSyncOrigin('https://127.0.0.1:4443')).toBe('https://127.0.0.1:4443')
    expect(() => resolveSyncOrigin('https://collector.invalid')).toThrow('loopback origin')
    expect(() => resolveSyncOrigin('http://localhost:3000/steal')).toThrow('without credentials')
    expect(() => resolveSyncOrigin('http://token@localhost:3000')).toThrow('without credentials')
  })

  it('confines repository-configured receipt storage to the approved local tree', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-config-receipts-'))
    const config = await loadConfig(root)
    expect(receiptDir(root, config)).toBe(join(root, APPROVED_RECEIPT_DIR))

    config.receipts.dir = `${APPROVED_RECEIPT_DIR}/team-a`
    expect(receiptDir(root, config)).toBe(join(root, APPROVED_RECEIPT_DIR, 'team-a'))

    for (const unsafe of ['../receipts', '.codetruss/other', `${APPROVED_RECEIPT_DIR}-backup`, join(root, 'outside')]) {
      config.receipts.dir = unsafe
      expect(() => receiptDir(root, config)).toThrow(`must stay under ${APPROVED_RECEIPT_DIR}`)
    }

    if (process.platform !== 'win32') {
      const symlinkRoot = await mkdtemp(join(tmpdir(), 'codetruss-config-receipt-link-'))
      const outside = join(symlinkRoot, 'outside')
      await mkdir(outside)
      await symlink(outside, join(symlinkRoot, '.codetruss'), 'dir')
      config.receipts.dir = APPROVED_RECEIPT_DIR
      expect(() => receiptDir(symlinkRoot, config)).toThrow('must not traverse symbolic links')
    }
  })
})
