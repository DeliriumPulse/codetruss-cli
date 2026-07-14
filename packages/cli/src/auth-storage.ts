import { constants } from 'node:fs'
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { DEV_SYNC_ORIGIN_ENV, resolveSyncOrigin } from './config.js'

export interface CliAuthCredential {
  version: 1
  origin: string
  accessToken: string
  keyPrefix: string
  org: { id: string; name: string; slug: string }
  scopes: string[]
  expiresAt: string
  authenticatedAt: string
}

export function cliAuthFilePath(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.XDG_CONFIG_HOME?.trim()
  if (configured && !isAbsolute(configured)) {
    throw new Error('XDG_CONFIG_HOME must be an absolute user config path')
  }
  const configHome = configured || join(homedir(), '.config')
  return join(configHome, 'codetruss', 'auth.json')
}

function validHostedOrigin(origin: string): boolean {
  if (origin === 'https://codetruss.com') return true
  try {
    return resolveSyncOrigin(origin) === origin
  } catch {
    return false
  }
}

function validateCredential(value: unknown): CliAuthCredential {
  if (!value || typeof value !== 'object') throw new Error('saved CodeTruss login is invalid')
  const candidate = value as Partial<CliAuthCredential>
  if (candidate.version !== 1) throw new Error('saved CodeTruss login has an unsupported version')
  if (typeof candidate.origin !== 'string' || !validHostedOrigin(candidate.origin)) {
    throw new Error('saved CodeTruss login has an invalid hosted origin')
  }
  if (
    typeof candidate.accessToken !== 'string'
    || !/^ct_cli_[0-9A-Za-z]{32}$/.test(candidate.accessToken)
  ) {
    throw new Error('saved CodeTruss login credential is invalid')
  }
  if (typeof candidate.keyPrefix !== 'string' || !candidate.accessToken.startsWith(candidate.keyPrefix)) {
    throw new Error('saved CodeTruss login prefix is invalid')
  }
  if (
    !candidate.org
    || typeof candidate.org.id !== 'string'
    || typeof candidate.org.name !== 'string'
    || typeof candidate.org.slug !== 'string'
  ) {
    throw new Error('saved CodeTruss organization is invalid')
  }
  if (
    !Array.isArray(candidate.scopes)
    || candidate.scopes.slice().sort().join(' ') !== 'receipts:read receipts:write'
  ) {
    throw new Error('saved CodeTruss login does not have receipt-only scopes')
  }
  if (
    typeof candidate.expiresAt !== 'string'
    || !Number.isFinite(Date.parse(candidate.expiresAt))
    || typeof candidate.authenticatedAt !== 'string'
    || !Number.isFinite(Date.parse(candidate.authenticatedAt))
  ) {
    throw new Error('saved CodeTruss login timestamps are invalid')
  }
  return candidate as CliAuthCredential
}

async function rejectSymlink(path: string): Promise<void> {
  try {
    if ((await lstat(path)).isSymbolicLink()) {
      throw new Error('refusing to use a symlinked CodeTruss auth file')
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
}

/** Store the bearer only in a private user-level file, never repository config. */
export async function saveCliAuth(
  credential: CliAuthCredential,
  path = cliAuthFilePath(),
): Promise<void> {
  const validated = validateCredential(credential)
  const directory = dirname(path)
  await mkdir(directory, { recursive: true, mode: 0o700 })
  if (process.platform !== 'win32') await chmod(directory, 0o700)
  await rejectSymlink(path)

  const temp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  const handle = await open(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600)
  try {
    await handle.writeFile(`${JSON.stringify(validated, null, 2)}\n`, 'utf8')
    await handle.sync()
  } finally {
    await handle.close()
  }
  try {
    await rename(temp, path)
    if (process.platform !== 'win32') await chmod(path, 0o600)
  } catch (error) {
    await rm(temp, { force: true }).catch(() => {})
    throw error
  }
}

export async function loadCliAuth(path = cliAuthFilePath()): Promise<CliAuthCredential | null> {
  await rejectSymlink(path)
  let raw: string
  try {
    raw = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('saved CodeTruss login is not valid JSON')
  }
  const credential = validateCredential(parsed)
  if (process.platform !== 'win32') await chmod(path, 0o600)
  return credential
}

export async function clearCliAuth(path = cliAuthFilePath()): Promise<void> {
  await rm(path, { force: true })
}

export interface SyncAuthentication {
  bearer: string
  origin: string
  source: 'environment' | 'saved-login'
  credential?: CliAuthCredential
}

export async function loadSyncAuthentication(
  env: NodeJS.ProcessEnv = process.env,
  path = cliAuthFilePath(env),
): Promise<SyncAuthentication | null> {
  const explicit = env.CODETRUSS_API_KEY?.trim()
  if (explicit) {
    return {
      bearer: explicit,
      origin: resolveSyncOrigin(env[DEV_SYNC_ORIGIN_ENV]),
      source: 'environment',
    }
  }
  const credential = await loadCliAuth(path)
  return credential
    ? {
        bearer: credential.accessToken,
        origin: credential.origin,
        source: 'saved-login',
        credential,
      }
    : null
}

export async function loadSyncBearer(
  env: NodeJS.ProcessEnv = process.env,
  path = cliAuthFilePath(env),
): Promise<string | null> {
  return (await loadSyncAuthentication(env, path))?.bearer ?? null
}
