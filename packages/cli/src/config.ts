import { access, mkdir, readFile, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { lstatSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { parse, stringify } from 'yaml'
import { loadSigningKey, normalizePublicKey } from './signing.js'
import type { CliConfig } from './types.js'

export const CONFIG_FILE = '.codetruss.yml'
export const PRODUCTION_SYNC_ORIGIN = 'https://codetruss.com'
export const DEV_SYNC_ORIGIN_ENV = 'CODETRUSS_DEV_SYNC_ORIGIN'
export const APPROVED_RECEIPT_DIR = '.codetruss/receipts'
export const DEFAULT_CONFIG: CliConfig = {
  version: 1,
  allow: [],
  deny: [],
  verify: [],
  receipts: { dir: APPROVED_RECEIPT_DIR },
  llm: { maxDiffBytes: 200_000 },
  signing: {},
  sync: { url: PRODUCTION_SYNC_ORIGIN },
}

function objectValue(value: unknown, key: string): Record<string, unknown> {
  if (value === undefined) return {}
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${key} must be a YAML object`)
  return value as Record<string, unknown>
}

/**
 * A repository may retain the old production-only sync stanza for backwards
 * compatibility, but it can never choose where a bearer credential is sent.
 */
function assertSafeRepoSync(value: unknown): void {
  if (value === undefined) return
  const sync = objectValue(value, 'sync')
  const keys = Object.keys(sync)
  if (keys.length === 0) return
  if (keys.length === 1 && sync.url === PRODUCTION_SYNC_ORIGIN) return
  throw new Error(
    `${CONFIG_FILE} cannot configure a sync destination; production sync is fixed to ${PRODUCTION_SYNC_ORIGIN}`,
  )
}

export async function loadConfig(root: string): Promise<CliConfig> {
  const path = join(root, CONFIG_FILE)
  let raw: unknown
  try {
    raw = parse(await readFile(path, 'utf8'))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return structuredClone(DEFAULT_CONFIG)
    throw new Error(`could not read ${CONFIG_FILE}: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error(`${CONFIG_FILE} must contain a YAML object`)
  const value = raw as Record<string, unknown>
  const list = (key: string) => {
    const input = value[key]
    if (input === undefined) return []
    if (!Array.isArray(input) || input.some((item) => typeof item !== 'string' || !item.trim())) throw new Error(`${key} must be a list of non-empty strings`)
    return input as string[]
  }
  if (value.version !== undefined && value.version !== 1) throw new Error(`unsupported config version ${String(value.version)}`)
  const receipts = objectValue(value.receipts, 'receipts')
  const llm = objectValue(value.llm, 'llm')
  const signing = objectValue(value.signing, 'signing')
  assertSafeRepoSync(value.sync)
  const provider = llm.provider
  if (provider !== undefined && !['anthropic', 'openai', 'claude', 'codex'].includes(String(provider))) throw new Error(`unsupported llm.provider ${String(provider)}`)
  return {
    version: 1,
    allow: list('allow'),
    deny: list('deny'),
    verify: list('verify'),
    receipts: { dir: typeof receipts.dir === 'string' ? receipts.dir : DEFAULT_CONFIG.receipts.dir },
    llm: {
      provider: provider as CliConfig['llm']['provider'],
      model: typeof llm.model === 'string' ? llm.model : undefined,
      maxDiffBytes: typeof llm.maxDiffBytes === 'number' && llm.maxDiffBytes > 0 ? llm.maxDiffBytes : DEFAULT_CONFIG.llm.maxDiffBytes,
    },
    signing: {
      publicKey: typeof signing.publicKey === 'string' && signing.publicKey.trim()
        ? normalizePublicKey(signing.publicKey)
        : undefined,
    },
    // This value is an application invariant, never repository configuration.
    sync: { url: PRODUCTION_SYNC_ORIGIN },
  }
}

export function receiptDir(root: string, config: CliConfig): string {
  const requested = config.receipts.dir.trim()
  if (!requested || isAbsolute(requested)) {
    throw new Error(`receipts.dir must stay under ${APPROVED_RECEIPT_DIR}`)
  }
  const repoRoot = resolve(root)
  const approvedRoot = resolve(repoRoot, APPROVED_RECEIPT_DIR)
  const candidate = resolve(repoRoot, requested)
  const withinApprovedRoot = relative(approvedRoot, candidate)
  if (withinApprovedRoot === '..' || withinApprovedRoot.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(withinApprovedRoot)) {
    throw new Error(`receipts.dir must stay under ${APPROVED_RECEIPT_DIR}`)
  }
  let cursor = repoRoot
  for (const part of relative(repoRoot, candidate).split(sep).filter(Boolean)) {
    cursor = join(cursor, part)
    try {
      if (lstatSync(cursor).isSymbolicLink()) {
        throw new Error(`receipts.dir must not traverse symbolic links under ${APPROVED_RECEIPT_DIR}`)
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') break
      throw error
    }
  }
  return candidate
}

/**
 * Resolve the only destination to which the CLI may attach CODETRUSS_API_KEY.
 * Production is hard-bound to CodeTruss over HTTPS. The sole override is an
 * explicit user-owned environment value and is deliberately limited to a
 * loopback development server.
 */
export function resolveSyncOrigin(explicitDevOrigin = process.env[DEV_SYNC_ORIGIN_ENV]): string {
  if (explicitDevOrigin === undefined || explicitDevOrigin.trim() === '') return PRODUCTION_SYNC_ORIGIN
  let parsed: URL
  try {
    parsed = new URL(explicitDevOrigin)
  } catch {
    throw new Error(`${DEV_SYNC_ORIGIN_ENV} must be an http(s) loopback origin`)
  }
  const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])
  const hasOnlyOrigin = parsed.pathname === '/' && !parsed.search && !parsed.hash && !parsed.username && !parsed.password
  if (!['http:', 'https:'].includes(parsed.protocol) || !loopbackHosts.has(parsed.hostname) || !hasOnlyOrigin) {
    throw new Error(`${DEV_SYNC_ORIGIN_ENV} must be an http(s) loopback origin without credentials, path, query, or fragment`)
  }
  return parsed.origin
}

export async function initialize(root: string, force = false): Promise<string> {
  const path = join(root, CONFIG_FILE)
  if (!force) {
    try { await access(path); throw new Error(`${CONFIG_FILE} already exists; pass --force to replace it`) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
  }
  const detected = await detectVerify(root)
  const key = await loadSigningKey(true)
  const value = {
    version: DEFAULT_CONFIG.version,
    allow: DEFAULT_CONFIG.allow,
    deny: DEFAULT_CONFIG.deny,
    verify: detected,
    receipts: DEFAULT_CONFIG.receipts,
    llm: DEFAULT_CONFIG.llm,
    signing: { publicKey: key.publicKey },
  }
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, `# CodeTruss local agent guardrails. Deny wins; unmatched paths are unexpected.\n${stringify(value)}`, 'utf8')
  await mkdir(join(root, DEFAULT_CONFIG.receipts.dir), { recursive: true })
  return path
}

async function detectVerify(root: string): Promise<string[]> {
  const exists = async (name: string) => access(join(root, name)).then(() => true, () => false)
  const available = (command: string) => !spawnSync(command, ['--version'], { stdio: 'ignore' }).error
  const packageScripts = async (): Promise<Record<string, unknown>> => {
    try {
      const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as { scripts?: unknown }
      return pkg.scripts && typeof pkg.scripts === 'object' && !Array.isArray(pkg.scripts)
        ? pkg.scripts as Record<string, unknown>
        : {}
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {}
      throw new Error(`could not inspect package.json: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  if (await exists('pnpm-lock.yaml')) {
    const scripts = await packageScripts()
    return available('pnpm') ? ['lint', 'test'].filter((name) => typeof scripts[name] === 'string').map((name) => `pnpm ${name}`) : []
  }
  if (await exists('package-lock.json')) {
    const scripts = await packageScripts()
    return available('npm') && typeof scripts.test === 'string' ? ['npm test'] : []
  }
  if (await exists('yarn.lock')) {
    const scripts = await packageScripts()
    return available('yarn') && typeof scripts.test === 'string' ? ['yarn test'] : []
  }
  if ((await exists('go.mod')) && available('go')) return ['go test ./...']
  if ((await exists('Cargo.toml')) && available('cargo')) return ['cargo test']
  if (((await exists('pyproject.toml')) || (await exists('requirements.txt'))) && available('pytest')) return ['pytest']
  return []
}
