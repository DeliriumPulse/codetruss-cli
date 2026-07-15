import { createHash, randomUUID } from 'node:crypto'
import { chmod, lstat, mkdir, open, readFile, readdir, realpath, rename, rm, stat, writeFile } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path'
import type { CliConfig } from './types.js'
import { receiptDir } from './config.js'
import { createExactSnapshotCommit, deleteLegacyHookBaseline, type ExactSnapshotCommit } from './hook-baseline.js'
import { classifyPath, isDependencyFile, sensitiveCategory } from './policy.js'
import { runGit, runGitText } from './git-process.js'
import { runLocalCommand } from './local-command.js'
import {
  CODETRUSS_HOOK_RESULT_PATH_ENV,
  CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV,
} from './hook-result.js'
import {
  CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV,
  initializePrivateGitObjectStore,
  openPrivateGitObjectStore,
  removePrivateGitObjectStore,
  type PrivateGitObjectStore,
} from './private-git-object-store.js'

export type AgentHookSurface = 'claude' | 'codex'

type HookInput = Record<string, unknown>
type HookOutput = Record<string, unknown>

interface HookState {
  version: 1
  surface: AgentHookSurface
  sessionHash: string
  /** Deprecated path-derived identity. It is never sufficient to establish ownership. */
  worktreeIdentityHash?: string
  /** Stable identity derived from this worktree's Git administrative directory. */
  worktreeIdentity?: string
  turnKey: string
  turnId?: string
  task?: string
  taskHash: string
  /** Only present for prerelease state that wrote snapshots into the user ODB. */
  baselineRef?: string
  baselineCommit?: string
  baselineHead?: string
  baselineDirtyFiles?: string[]
  objectStoreVersion?: 1
  contextSha256?: string
  capturePid?: number
  status: 'capturing' | 'ready' | 'reviewing' | 'cleanup_pending' | 'completed' | 'failed'
  finalCommit?: string
  finalHead?: string
  reviewAttemptId?: string
  createdAt: string
  updatedAt: string
  result?: { verdict: 'PASS' | 'REVIEW_REQUIRED' | 'FAILED' | 'ERROR'; receiptPath?: string; message: string }
  error?: string
}

interface CurrentTurn {
  version: 1
  turnKey: string
  turnId?: string
}

export interface HookReviewRequest {
  root: string
  surface: AgentHookSurface
  task: string
  /** Raw private-store commit OID accepted by Git wherever a treeish is accepted. */
  baselineRef: string
  /** Raw private-store commit OID accepted by Git wherever a treeish is accepted. */
  finalRef: string
  startCommit: string
  finalHead: string
  startedAt: string
  objectDirectory: string
  contextPath: string
  contextSha256: string
  baselineDirtyFiles: string[]
  context: HookTurnContext
  /** Stable across retries of the same immutable baseline/final pair. */
  attemptId: string
  /** Private machine-readable result path bound to this attempt. */
  resultPath: string
}

export interface HookTurnContext {
  version: 1
  /** Optional only while reading prompt contexts captured by older CLI builds. */
  surface?: AgentHookSurface
  task: string
  config: CliConfig
  baselineDirtyFiles: string[]
}

export interface HookReviewResult {
  status: number | null
  stdout: string
  stderr: string
  error?: string
}

export interface HookRuntimeDependencies {
  captureBaseline?: (root: string, snapshotParent: string, objectStore: PrivateGitObjectStore) => Promise<ExactSnapshotCommit>
  runReview?: (request: HookReviewRequest) => Promise<HookReviewResult> | HookReviewResult
  now?: () => Date
}

const MAX_HOOK_INPUT_BYTES = 16 * 1024 * 1024
const MAX_TASK_CHARS = 8_000
const MAX_TURN_ID_CHARS = 1_024
const MAX_SELECTOR_BYTES = 16 * 1024
const MAX_STATE_BYTES = 256 * 1024
const MAX_REVIEW_OUTPUT_CHARS = 6_000
const REVIEW_TIMEOUT_MS = 5 * 60 * 1_000
const STATE_VERSION_DIR = 'v2'
const LEGACY_STATE_VERSION_DIR = 'v1'
const PATH_KEY_HEX_CHARS = 24
const PATH_KEY_PATTERN = /^[0-9a-f]{24}$/
const LEGACY_PATH_KEY_PATTERN = /^(?:[0-9a-f]{24}|[0-9a-f]{64})$/
export const CODETRUSS_HOOK_CONTEXT_PATH_ENV = 'CODETRUSS_HOOK_CONTEXT_PATH'
export const CODETRUSS_HOOK_CONTEXT_SHA256_ENV = 'CODETRUSS_HOOK_CONTEXT_SHA256'
export const CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV = 'CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256'
export const CODETRUSS_HOOK_SURFACE_ENV = 'CODETRUSS_HOOK_SURFACE'

function hash(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex')
}

// Hook identifiers are attacker-controlled and must not appear raw on disk.
// A 96-bit SHA-256 prefix keeps collision resistance high while leaving enough
// Windows path budget for private object databases and materialized snapshots.
function pathKey(value: string): string {
  return hash(value).slice(0, PATH_KEY_HEX_CHARS)
}

function deleteLegacyStateRefs(root: string, baselineRef: string): void {
  deleteLegacyHookBaseline(root, baselineRef)
  const finalRef = `${baselineRef.slice(0, baselineRef.lastIndexOf('/'))}/${hash('final')}`
  deleteLegacyHookBaseline(root, finalRef)
}

function asNonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined
}

function hookEvent(input: HookInput): string | undefined {
  return asNonEmptyString(input.hook_event_name)
}

function safeError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).replaceAll('\0', '').slice(0, 2_000)
}

function blockDecision(message: string): HookOutput {
  return { decision: 'block', reason: message.slice(0, 10_000) }
}

function systemMessage(message: string): HookOutput {
  return { systemMessage: message.slice(0, 10_000) }
}

/**
 * Stop failures get one blocking turn so an agent cannot silently finish
 * without a receipt. Claude marks the resulting continuation with
 * stop_hook_active; emitting another block there would create a Stop loop.
 */
function stopFailureOutput(input: HookInput, message: string): HookOutput {
  return input.stop_hook_active === true ? systemMessage(message) : blockDecision(message)
}

function postToolFeedback(message: string): HookOutput {
  return {
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext: message.slice(0, 10_000),
    },
  }
}

function stopReviewOutput(
  input: HookInput,
  result: NonNullable<HookState['result']>,
  message = result.message,
  forceNotice = false,
): HookOutput | undefined {
  if (result.verdict === 'PASS' && !forceNotice) return undefined
  if (result.verdict === 'FAILED' || result.verdict === 'ERROR') return stopFailureOutput(input, message)
  return systemMessage(message)
}

interface PreparedGitState {
  base: string
  worktreeIdentity: string
  legacyBlockReason?: string
}

function gitDirectory(root: string, argument: '--git-common-dir' | '--git-dir'): string {
  const raw = runGitText(root, ['rev-parse', argument]).trim()
  return isAbsolute(raw) ? resolve(raw) : resolve(root, raw)
}

async function stableWorktreeIdentity(root: string): Promise<string> {
  const common = await realpath(gitDirectory(root, '--git-common-dir'))
  const administrative = await realpath(gitDirectory(root, '--git-dir'))
  const relativeAdministrative = relative(common, administrative).replaceAll('\\', '/')
  if (relativeAdministrative === '..' || relativeAdministrative.startsWith('../') || isAbsolute(relativeAdministrative)) {
    throw new Error('Git worktree administrative directory is outside the repository common directory')
  }
  const identity = relativeAdministrative || '.'
  if (identity !== '.' && !/^worktrees\/[^/]+$/.test(identity)) {
    throw new Error('Git worktree administrative directory has an unsupported layout')
  }
  return `git-admin-v1:${hash(identity)}`
}

async function gitStateRoot(
  root: string,
  surface: AgentHookSurface,
  sessionId: string,
): Promise<PreparedGitState> {
  const common = gitDirectory(root, '--git-common-dir')
  const worktreeIdentity = await stableWorktreeIdentity(root)
  const hooksRoot = join(common, 'codetruss', 'hooks')
  const state = join(hooksRoot, STATE_VERSION_DIR, pathKey(resolve(root)))
  await ensurePrivateDirectory(state)
  const now = new Date()
  // One common-dir lock serializes recovery even when the checkout path (and
  // therefore the v2 repository key) changes between hook processes.
  const migrationLock = await acquireNamedLock(hooksRoot, 'migration.lock', now)
  if (!migrationLock) {
    return {
      base: state,
      worktreeIdentity,
      ...(await legacyStateExists(hooksRoot, state, root, worktreeIdentity)
        ? { legacyBlockReason: 'legacy hook-state migration is already running; retry after the active hook finishes' }
        : {}),
    }
  }
  try {
    const legacyBlockReason = await migrateLegacyHookState(
      hooksRoot,
      state,
      root,
      worktreeIdentity,
      surface,
      sessionId,
    )
    return {
      base: state,
      worktreeIdentity,
      ...(legacyBlockReason ? { legacyBlockReason } : {}),
    }
  } finally {
    await releaseNamedLock(migrationLock)
  }
}

function sessionStateDir(base: string, surface: AgentHookSurface, sessionId: string): string {
  return join(base, surface, pathKey(sessionId))
}

async function writePrivateJson(path: string, value: unknown): Promise<void> {
  await writePrivateText(path, `${JSON.stringify(value)}\n`)
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 })
  const info = await lstat(path)
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${path} is not a safe private directory`)
  await chmod(path, 0o700)
}

async function writePrivateText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const nonce = randomUUID().replaceAll('-', '').slice(0, 12)
  const temporary = `${path}.${process.pid}.${nonce}.tmp`
  await writeFile(temporary, value, { encoding: 'utf8', mode: 0o600, flag: 'wx' })
  await rename(temporary, path)
  await chmod(path, 0o600)
}

async function readJson<T>(path: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as T
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
}

async function readBoundedRegularJson<T>(path: string, maxBytes: number): Promise<T | undefined> {
  let info
  try {
    info = await lstat(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${path} is not a safe regular file`)
  if (info.size > maxBytes) throw new Error(`${path} exceeds ${maxBytes} bytes`)
  const bytes = await readFile(path)
  if (bytes.length > maxBytes) throw new Error(`${path} exceeds ${maxBytes} bytes`)
  return JSON.parse(bytes.toString('utf8')) as T
}

function validTurnId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_TURN_ID_CHARS
    && value === value.trim() && !value.includes('\0')
}

function exactCurrentTurn(value: unknown): value is CurrentTurn {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const current = value as Record<string, unknown>
  return Object.keys(current).every((key) => ['version', 'turnKey', 'turnId'].includes(key))
    && Object.keys(current).length === (current.turnId === undefined ? 2 : 3)
    && current.version === 1
    && typeof current.turnKey === 'string' && PATH_KEY_PATTERN.test(current.turnKey)
    && (current.turnId === undefined || validTurnId(current.turnId))
}

function exactLegacyCurrentTurn(value: unknown): value is CurrentTurn {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const current = value as Record<string, unknown>
  return Object.keys(current).every((key) => ['version', 'turnKey', 'turnId'].includes(key))
    && Object.keys(current).length === (current.turnId === undefined ? 2 : 3)
    && current.version === 1
    && typeof current.turnKey === 'string' && LEGACY_PATH_KEY_PATTERN.test(current.turnKey)
    && (current.turnId === undefined || validTurnId(current.turnId))
}

function stateMatchesSelector(state: HookState, current: CurrentTurn): boolean {
  return state.turnKey === current.turnKey && state.turnId === current.turnId
}

function containedTurnDirectory(sessionDir: string, turnKey: string): string {
  if (!PATH_KEY_PATTERN.test(turnKey)) throw new Error('current selector turn key is invalid')
  const parent = resolve(sessionDir)
  const candidate = resolve(parent, turnKey)
  const within = relative(parent, candidate).replaceAll('\\', '/')
  if (within !== turnKey || isAbsolute(within) || within === '..' || within.startsWith('../')) {
    throw new Error('current selector resolves outside its session directory')
  }
  return candidate
}

async function readStopSelector(sessionDir: string): Promise<{ current: CurrentTurn; turnDir: string }> {
  const sessionInfo = await lstat(sessionDir)
  if (!sessionInfo.isDirectory() || sessionInfo.isSymbolicLink()) throw new Error('hook session is not a safe directory')
  const current = await readBoundedRegularJson<unknown>(join(sessionDir, 'current.json'), MAX_SELECTOR_BYTES)
  if (!exactCurrentTurn(current)) throw new Error('current selector must be an exact version 1 object with a 24-hex turn key')
  const turnDir = containedTurnDirectory(sessionDir, current.turnKey)
  const turnInfo = await lstat(turnDir)
  if (!turnInfo.isDirectory() || turnInfo.isSymbolicLink()) throw new Error('selected hook turn is not a safe child directory')
  return { current, turnDir }
}

function frozenConfig(config: CliConfig): CliConfig {
  return {
    version: 1,
    allow: [...config.allow],
    deny: [...config.deny],
    verify: [...config.verify],
    receipts: { dir: config.receipts.dir },
    llm: {
      ...(config.llm.provider ? { provider: config.llm.provider } : {}),
      ...(config.llm.model ? { model: config.llm.model } : {}),
      maxDiffBytes: config.llm.maxDiffBytes,
    },
    signing: { ...(config.signing.publicKey ? { publicKey: config.signing.publicKey } : {}) },
    sync: { url: config.sync.url },
  }
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function validateHookTurnContext(value: unknown): HookTurnContext {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('hook turn context must be an object')
  const context = value as Partial<HookTurnContext>
  const config = context.config as Partial<CliConfig> | undefined
  if (context.version !== 1 || typeof context.task !== 'string'
    || !context.task.trim() || context.task !== context.task.trim() || context.task.length > MAX_TASK_CHARS
    || (context.surface !== undefined && context.surface !== 'claude' && context.surface !== 'codex')
    || !config || config.version !== 1
    || !isStringArray(config.allow) || !isStringArray(config.deny) || !isStringArray(config.verify)
    || !config.receipts || typeof config.receipts.dir !== 'string'
    || !config.llm || !Number.isFinite(config.llm.maxDiffBytes) || config.llm.maxDiffBytes <= 0
    // `codex` is accepted only while authenticating pending legacy hook
    // context. Active provider selection intentionally no longer offers it.
    || (config.llm.provider !== undefined && !['anthropic', 'openai', 'claude', 'codex'].includes(config.llm.provider))
    || (config.llm.model !== undefined && typeof config.llm.model !== 'string')
    || !config.signing || (config.signing.publicKey !== undefined && typeof config.signing.publicKey !== 'string')
    || !config.sync || typeof config.sync.url !== 'string'
    || !isStringArray(context.baselineDirtyFiles)) {
    throw new Error('hook turn context is invalid')
  }
  return context as HookTurnContext
}

/** Read and authenticate the prompt-time policy/evidence passed to an internal review. */
export async function readHookTurnContext(path: string, expectedSha256: string): Promise<HookTurnContext> {
  if (!/^[0-9a-f]{64}$/.test(expectedSha256)) throw new Error('hook turn context hash is invalid')
  const bytes = await readFile(path)
  if (hash(bytes) !== expectedSha256) throw new Error('hook turn context changed after prompt-time capture')
  let value: unknown
  try {
    value = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    throw new Error(`hook turn context is not valid JSON: ${error instanceof Error ? error.message : String(error)}`)
  }
  return validateHookTurnContext(value)
}

function turnContextPath(turnDir: string): string {
  return join(turnDir, 'turn-context.json')
}

function turnObjectStorePath(turnDir: string): string {
  return join(turnDir, 'object-store')
}

async function pruneTurnState(root: string, sessionDir: string, worktreeIdentity: string, keep = 20): Promise<void> {
  let entries
  try {
    entries = await readdir(sessionDir, { withFileTypes: true })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  const current = await readJson<CurrentTurn>(join(sessionDir, 'current.json')).catch(() => undefined)
  const turns: Array<{ path: string; mtimeMs: number; state?: HookState }> = []
  for (const entry of entries) {
    if (!entry.isDirectory() || !PATH_KEY_PATTERN.test(entry.name)) continue
    const path = join(sessionDir, entry.name)
    const info = await stat(path)
    const state = await readJson<HookState>(join(path, 'state.json')).catch(() => undefined)
    turns.push({ path, mtimeMs: info.mtimeMs, state })
  }
  turns.sort((left, right) => right.mtimeMs - left.mtimeMs)
  let retained = 0
  for (const turn of turns) {
    if (turn.state?.turnKey === current?.turnKey) continue
    if (!turn.state || turn.state.worktreeIdentity !== worktreeIdentity) continue
    if (await turnHasLiveLease(turn.path, turn.state)) continue
    if (retained++ < keep) continue
    if (turn.state?.baselineRef) deleteLegacyStateRefs(root, turn.state.baselineRef)
    await rm(turn.path, { recursive: true, force: true })
  }
}

async function turnHasLiveLease(turnDir: string, state?: HookState): Promise<boolean> {
  if (state?.status === 'capturing' && processExists(state.capturePid ?? 0)) return true
  for (const name of ['capture.lock', 'stop.lock']) {
    const lock = await readJson<{ pid?: unknown }>(join(turnDir, name)).catch(() => undefined)
    if (typeof lock?.pid === 'number' && processExists(lock.pid)) return true
  }
  return false
}

type HookStateVersionDir = 'v1' | 'v2'

interface HookStateRootCandidate {
  version: HookStateVersionDir
  key: string
  path: string
  priority: number
  protectedWorktreeIdentities: Set<string>
}

interface HookStateSessionCandidate {
  root: HookStateRootCandidate
  surface: AgentHookSurface
  sessionName: string
  path: string
}

function lexicalPathVariants(path: string): Set<string> {
  const normalized = resolve(path)
  const variants = new Set([normalized])
  if (normalized.startsWith('/private/')) variants.add(normalized.slice('/private'.length))
  return variants
}

async function protectedWorktreeEvidence(root: string, currentIdentity: string): Promise<{
  pathKeys: Set<string>
  identities: Set<string>
}> {
  const protectedKeys = new Set<string>()
  const identities = new Set<string>()
  const currentVariants = lexicalPathVariants(root)
  currentVariants.add(await realpath(root))
  const records = runGit(root, ['worktree', 'list', '--porcelain', '-z']).stdout.toString('utf8').split('\0\0')
  for (const record of records) {
    const fields = record.split('\0').filter(Boolean)
    const worktree = fields.find((field) => field.startsWith('worktree '))?.slice('worktree '.length)
    if (!worktree || fields.some((field) => field === 'prunable' || field.startsWith('prunable '))) continue
    try {
      // A moved linked worktree may retain its registered path as a symlink to
      // the new checkout. Follow only a live directory target; broken links
      // and non-directories cannot establish ownership of private hook state.
      if (!(await stat(worktree)).isDirectory()) continue
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue
      throw error
    }
    const variants = lexicalPathVariants(worktree)
    variants.add(await realpath(worktree))
    const identity = await stableWorktreeIdentity(worktree)
    if (identity === currentIdentity || [...variants].some((variant) => currentVariants.has(variant))) continue
    // Git reports canonical /private paths on macOS even when hooks were
    // invoked through the equivalent /var or /tmp spelling.
    for (const variant of variants) {
      const worktreeHash = hash(variant)
      protectedKeys.add(worktreeHash)
      protectedKeys.add(worktreeHash.slice(0, PATH_KEY_HEX_CHARS))
    }
    identities.add(identity)
  }
  return { pathKeys: protectedKeys, identities }
}

async function discoverStateRootCandidates(
  hooksRoot: string,
  currentBase: string,
  root: string,
  currentIdentity: string,
): Promise<HookStateRootCandidate[]> {
  const protectedWorktrees = await protectedWorktreeEvidence(root, currentIdentity)
  const candidates: HookStateRootCandidate[] = []
  for (const version of [LEGACY_STATE_VERSION_DIR, STATE_VERSION_DIR] as const) {
    const entries = await readdir(join(hooksRoot, version), { withFileTypes: true }).catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw error
    })
    for (const entry of entries) {
      if (!entry.isDirectory() || !LEGACY_PATH_KEY_PATTERN.test(entry.name)) continue
      const path = join(hooksRoot, version, entry.name)
      if (resolve(path) === resolve(currentBase) || protectedWorktrees.pathKeys.has(entry.name)) continue
      candidates.push({
        version,
        key: entry.name,
        path,
        protectedWorktreeIdentities: protectedWorktrees.identities,
        // A relocated v2 session is newer than v1. Within v1, released
        // full-key evidence wins over the unpublished short-key candidate.
        priority: version === STATE_VERSION_DIR ? 0 : entry.name.length === 64 ? 1 : 2,
      })
    }
  }
  return candidates.sort((left, right) => left.priority - right.priority || left.path.localeCompare(right.path))
}

async function sessionBelongsToProtectedWorktree(
  stateRoot: HookStateRootCandidate,
  sessionPath: string,
): Promise<boolean> {
  const current = await readJson<CurrentTurn>(join(sessionPath, 'current.json')).catch(() => undefined)
  if (!exactLegacyCurrentTurn(current)) return false
  const state = await readJson<HookState>(join(sessionPath, current.turnKey, 'state.json')).catch(() => undefined)
  return Boolean(state && stateMatchesSelector(state, current) && typeof state.worktreeIdentity === 'string'
    && stateRoot.protectedWorktreeIdentities.has(state.worktreeIdentity))
}

async function sessionsInStateRoots(roots: HookStateRootCandidate[]): Promise<HookStateSessionCandidate[]> {
  const sessions: HookStateSessionCandidate[] = []
  for (const stateRoot of roots) {
    for (const surface of ['claude', 'codex'] as const) {
      const entries = await readdir(join(stateRoot.path, surface), { withFileTypes: true }).catch((error: unknown) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
        throw error
      })
      for (const entry of entries) {
        if (!entry.isDirectory() || !LEGACY_PATH_KEY_PATTERN.test(entry.name)) continue
        const path = join(stateRoot.path, surface, entry.name)
        if (await sessionBelongsToProtectedWorktree(stateRoot, path)) continue
        sessions.push({ root: stateRoot, surface, sessionName: entry.name, path })
      }
    }
  }
  return sessions
}

async function requestedStateSessions(
  roots: HookStateRootCandidate[],
  surface: AgentHookSurface,
  sessionId: string,
): Promise<HookStateSessionCandidate[]> {
  const sessionHash = hash(sessionId)
  const expectedNames = new Set([sessionHash, sessionHash.slice(0, PATH_KEY_HEX_CHARS)])
  return (await sessionsInStateRoots(roots))
    .filter((session) => session.surface === surface && expectedNames.has(session.sessionName))
    .sort((left, right) => left.root.priority - right.root.priority
      || (right.sessionName.length - left.sessionName.length) || left.path.localeCompare(right.path))
}

function validPartialSourceSelector(value: unknown): value is CurrentTurn {
  return exactCurrentTurn(value)
}

async function removeRecognizedPartialSource(session: HookStateSessionCandidate): Promise<boolean> {
  if (session.root.version !== STATE_VERSION_DIR) return false
  const entries = await readdir(session.path, { withFileTypes: true })
  for (const entry of entries) {
    if (entry.isDirectory()) return false
    if (entry.name === 'current.json') {
      const current = await readJson<CurrentTurn>(join(session.path, entry.name)).catch(() => undefined)
      if (!validPartialSourceSelector(current)) return false
      continue
    }
    if (!/^current\.json\.\d+\.[0-9a-f]{12}\.tmp$/.test(entry.name)) return false
  }
  // v2 migration targets never write prompt, context, or object data directly
  // in the session directory. With no turn directories, this is an incomplete
  // selector transaction and can be removed without discarding evidence.
  await rm(session.path, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
  return true
}

async function legacyStateExists(
  hooksRoot: string,
  currentBase: string,
  root: string,
  worktreeIdentity: string,
): Promise<boolean> {
  return (await discoverStateRootCandidates(hooksRoot, currentBase, root, worktreeIdentity)).length > 0
}

async function removeEmptyStateRoot(stateRoot: HookStateRootCandidate): Promise<void> {
  const entries = await readdir(stateRoot.path, { withFileTypes: true }).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  })
  if (!entries) return
  for (const entry of entries) {
    if (!entry.isDirectory() || !['claude', 'codex'].includes(entry.name)) return
    if ((await readdir(join(stateRoot.path, entry.name))).length > 0) return
  }
  await rm(stateRoot.path, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
}

async function legacySessionHasLiveLease(sessionDir: string): Promise<boolean> {
  const turns = await readdir(sessionDir, { withFileTypes: true }).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
    throw error
  })
  for (const turn of turns) {
    if (!turn.isDirectory()) continue
    const turnDir = join(sessionDir, turn.name)
    const state = await readJson<HookState>(join(turnDir, 'state.json')).catch(() => undefined)
    if (await turnHasLiveLease(turnDir, state)) return true
  }
  return false
}

async function cleanupLegacyTurn(root: string, turnDir: string, state?: HookState): Promise<void> {
  // The object-store ownership manifest is checked before prompt/context/state
  // is removed. If validation fails, leave the complete turn in place and make
  // the hook fail closed so a later invocation can retry safely.
  await cleanupTurnEvidence(root, turnDir)
  if (state?.baselineRef) deleteLegacyStateRefs(root, state.baselineRef)
  await rm(turnDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
}

function validHookResult(value: unknown): value is NonNullable<HookState['result']> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const result = value as Record<string, unknown>
  return Object.keys(result).every((key) => ['verdict', 'receiptPath', 'message'].includes(key))
    && Object.keys(result).length === (result.receiptPath === undefined ? 2 : 3)
    && ['PASS', 'REVIEW_REQUIRED', 'FAILED', 'ERROR'].includes(String(result.verdict))
    && typeof result.message === 'string' && result.message.length > 0 && result.message.length <= 10_000
    && (result.receiptPath === undefined
      || (typeof result.receiptPath === 'string' && result.receiptPath.length > 0 && result.receiptPath.length <= 4_096))
}

function exactStateIdentity(
  state: HookState | undefined,
  surface: AgentHookSurface,
  sessionHash: string,
  turnKeys: string[],
  worktreeIdentity: string,
): state is HookState {
  return Boolean(state && state.version === 1 && state.surface === surface
    && typeof state.sessionHash === 'string' && state.sessionHash === sessionHash
    && state.worktreeIdentity === worktreeIdentity
    && typeof state.turnKey === 'string' && turnKeys.includes(state.turnKey)
    && typeof state.taskHash === 'string' && /^[0-9a-f]{64}$/.test(state.taskHash)
    && ['capturing', 'ready', 'reviewing', 'cleanup_pending', 'completed', 'failed'].includes(state.status))
}

async function cleanupLegacySession(
  root: string,
  session: HookStateSessionCandidate,
  expectedSessionHash: string,
  worktreeIdentity: string,
  exceptTurn?: string,
): Promise<void> {
  const sessionDir = session.path
  const turns = await readdir(sessionDir, { withFileTypes: true }).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
    throw error
  })
  for (const turn of turns) {
    if (!turn.isDirectory() || turn.name === exceptTurn) continue
    const turnDir = join(sessionDir, turn.name)
    const state = await readJson<HookState>(join(turnDir, 'state.json')).catch(() => undefined)
    if (!exactStateIdentity(state, session.surface, expectedSessionHash, [turn.name], worktreeIdentity)) {
      throw new Error(`legacy hook turn ${JSON.stringify(turn.name)} does not match the requested surface, full session hash, and stable worktree identity`)
    }
    if (await turnHasLiveLease(turnDir, state)) throw new Error('legacy hook turn still has an active lease')
    await cleanupLegacyTurn(root, turnDir, state)
  }
}

async function resumableLegacyTurn(
  root: string,
  surface: AgentHookSurface,
  sessionHash: string,
  worktreeIdentity: string,
  turnName: string,
  turnDir: string,
  state: HookState | undefined,
): Promise<boolean> {
  if (!exactStateIdentity(state, surface, sessionHash, [turnName], worktreeIdentity)) return false
  if (state.status === 'cleanup_pending') return validHookResult(state.result)
  if (!['ready', 'reviewing'].includes(state.status) || state.objectStoreVersion !== 1
    || typeof state.baselineCommit !== 'string' || typeof state.contextSha256 !== 'string'
    || !isStringArray(state.baselineDirtyFiles) || typeof state.task !== 'string') return false
  if (state.status === 'reviewing' && (typeof state.finalCommit !== 'string' || typeof state.finalHead !== 'string'
    || typeof state.reviewAttemptId !== 'string' || !/^[0-9a-f]{64}$/.test(state.reviewAttemptId)
    || state.reviewAttemptId !== reviewAttemptId(state, state.finalCommit, state.finalHead))) return false
  try {
    await openPrivateGitObjectStore(root, turnObjectStorePath(turnDir))
    const context = await readHookTurnContext(turnContextPath(turnDir), state.contextSha256)
    return context.task === state.task && hash(context.task) === state.taskHash
      && JSON.stringify(context.baselineDirtyFiles) === JSON.stringify(state.baselineDirtyFiles)
  } catch {
    return false
  }
}

interface TargetSessionInspection {
  kind: 'missing' | 'partial' | 'coherent' | 'invalid'
  reason?: string
  current?: CurrentTurn
  turnDir?: string
  state?: HookState
}

function validCurrentTurn(value: unknown, turnKey: string, turnId?: string): value is CurrentTurn {
  return exactCurrentTurn(value) && value.turnKey === turnKey
    && (turnId === undefined ? value.turnId === undefined : value.turnId === turnId)
}

async function selectorOnlyTarget(
  targetSession: string,
  entries: Array<{ name: string; isDirectory(): boolean }>,
  targetTurnKey: string,
  turnId?: string,
): Promise<boolean> {
  for (const entry of entries) {
    if (entry.isDirectory()) return false
    if (entry.name === 'current.json') {
      const current = await readJson<CurrentTurn>(join(targetSession, entry.name)).catch(() => undefined)
      if (!validCurrentTurn(current, targetTurnKey, turnId)) return false
      continue
    }
    if (!/^current\.json\.\d+\.[0-9a-f]{12}\.tmp$/.test(entry.name)) return false
  }
  return true
}

async function targetObjectStoreKind(root: string, turnDir: string): Promise<'missing' | 'valid' | 'invalid'> {
  const storePath = turnObjectStorePath(turnDir)
  try {
    const info = await lstat(storePath)
    if (!info.isDirectory() || info.isSymbolicLink()) return 'invalid'
    await openPrivateGitObjectStore(root, storePath)
    return 'valid'
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return 'missing'
    return 'invalid'
  }
}

async function inspectTargetSession(
  root: string,
  targetSession: string,
  source: HookStateSessionCandidate,
  expectedSessionHash: string,
  worktreeIdentity: string,
  sourceTurnName: string,
  turnId?: string,
): Promise<TargetSessionInspection> {
  let info
  try {
    info = await lstat(targetSession)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'missing' }
    throw error
  }
  if (!info.isDirectory() || info.isSymbolicLink()) return { kind: 'invalid', reason: 'v2 migration target is not a safe directory' }
  const entries = await readdir(targetSession, { withFileTypes: true })
  if (entries.length === 0) return { kind: 'partial' }
  const targetTurnKey = sourceTurnName.slice(0, PATH_KEY_HEX_CHARS)
  const current = await readJson<CurrentTurn>(join(targetSession, 'current.json')).catch(() => undefined)
  if (!current) {
    return await selectorOnlyTarget(targetSession, entries, targetTurnKey, turnId)
      ? { kind: 'partial' }
      : { kind: 'invalid', reason: 'v2 migration target is missing a coherent current selector' }
  }
  if (!validCurrentTurn(current, targetTurnKey, turnId)) {
    return { kind: 'invalid', reason: 'v2 migration target has an incoherent current selector' }
  }
  const targetTurnDir = join(targetSession, targetTurnKey)
  let turnInfo
  try {
    turnInfo = await lstat(targetTurnDir)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    return await selectorOnlyTarget(targetSession, entries, targetTurnKey, turnId)
      ? { kind: 'partial' }
      : { kind: 'invalid', reason: 'v2 migration target selector points to missing evidence in a mixed session' }
  }
  if (!turnInfo.isDirectory() || turnInfo.isSymbolicLink()) {
    return { kind: 'invalid', reason: 'v2 migration target turn is not a safe directory' }
  }
  const state = await readJson<HookState>(join(targetTurnDir, 'state.json')).catch(() => undefined)
  if (!exactStateIdentity(state, source.surface, expectedSessionHash, [targetTurnKey, sourceTurnName], worktreeIdentity)) {
    return { kind: 'invalid', reason: 'v2 migration target state does not match the requested surface, session, turn, and stable worktree identity' }
  }
  if (state.turnId !== current.turnId) {
    return { kind: 'invalid', reason: 'v2 migration target state turn identity does not match its current selector' }
  }
  for (const entry of entries) {
    if (entry.name === 'current.json' || /^current\.json\.\d+\.[0-9a-f]{12}\.tmp$/.test(entry.name)
      || entry.name === targetTurnKey) continue
    if (!entry.isDirectory() || !PATH_KEY_PATTERN.test(entry.name)) {
      return { kind: 'invalid', reason: 'v2 migration target contains unknown mixed state' }
    }
    const otherState = await readJson<HookState>(join(targetSession, entry.name, 'state.json')).catch(() => undefined)
    if (!exactStateIdentity(otherState, source.surface, expectedSessionHash, [entry.name], worktreeIdentity)) {
      return { kind: 'invalid', reason: 'v2 migration target contains a turn from another session or surface' }
    }
  }
  if (['ready', 'reviewing'].includes(state.status)) {
    const evidenceValid = await resumableLegacyTurn(
      root,
      source.surface,
      expectedSessionHash,
      worktreeIdentity,
      state.turnKey,
      targetTurnDir,
      state,
    )
    if (!evidenceValid) return { kind: 'invalid', reason: 'v2 migration target contains invalid private baseline evidence' }
  } else if (state.status === 'capturing') {
    return { kind: 'invalid', reason: 'v2 migration target still contains an incomplete capture' }
  } else if (state.status === 'cleanup_pending') {
    if ((state.result && !validHookResult(state.result)) || await targetObjectStoreKind(root, targetTurnDir) === 'invalid') {
      return { kind: 'invalid', reason: 'v2 migration target contains invalid cleanup evidence' }
    }
  } else if (state.status === 'completed') {
    if (!validHookResult(state.result) || await targetObjectStoreKind(root, targetTurnDir) !== 'missing') {
      return { kind: 'invalid', reason: 'v2 migration target contains an invalid completed result' }
    }
  } else if (state.status === 'failed') {
    if ((state.result && !validHookResult(state.result)) || await targetObjectStoreKind(root, targetTurnDir) !== 'missing') {
      return { kind: 'invalid', reason: 'v2 migration target contains an invalid failed result' }
    }
  }
  return { kind: 'coherent', current, turnDir: targetTurnDir, state }
}

async function normalizeMigratedTarget(
  root: string,
  targetSession: string,
  targetTurnKey: string,
  turnId: string | undefined,
  inspection: TargetSessionInspection,
): Promise<void> {
  const state = inspection.state
  const turnDir = inspection.turnDir
  if (!state || !turnDir) throw new Error('v2 migration target cannot be normalized without coherent state')
  if (state.baselineRef) deleteLegacyStateRefs(root, state.baselineRef)
  if (state.turnKey !== targetTurnKey || state.baselineRef !== undefined) {
    const normalized: HookState = {
      ...state,
      turnKey: targetTurnKey,
      baselineRef: undefined,
    }
    if (normalized.status === 'reviewing' && normalized.finalCommit && typeof normalized.finalHead === 'string') {
      normalized.reviewAttemptId = reviewAttemptId(normalized, normalized.finalCommit, normalized.finalHead)
    }
    await writePrivateJson(join(turnDir, 'state.json'), normalized)
  }
  await writePrivateJson(join(targetSession, 'current.json'), {
    version: 1,
    turnKey: targetTurnKey,
    ...(turnId ? { turnId } : {}),
  } satisfies CurrentTurn)
}

async function migrateLegacySession(
  root: string,
  currentBase: string,
  legacy: HookStateSessionCandidate,
  expectedSessionHash: string,
  worktreeIdentity: string,
): Promise<void> {
  const targetSession = join(currentBase, legacy.surface, legacy.sessionName.slice(0, PATH_KEY_HEX_CHARS))
  const current = await readJson<CurrentTurn>(join(legacy.path, 'current.json')).catch(() => undefined)
  if (!exactLegacyCurrentTurn(current)) {
    throw new Error('legacy hook session has an invalid current selector')
  }
  const sourceTurnName = current?.turnKey
  const sourceTurnDir = join(legacy.path, sourceTurnName)
  let sourceTurnExists = false
  try {
    const sourceInfo = await lstat(sourceTurnDir)
    if (!sourceInfo.isDirectory() || sourceInfo.isSymbolicLink()) throw new Error('legacy hook turn is not a safe directory')
    sourceTurnExists = true
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  const state = sourceTurnExists
    ? await readJson<HookState>(join(sourceTurnDir, 'state.json')).catch(() => undefined)
    : undefined
  const sourceStateKeys = [sourceTurnName]
  if (legacy.root.version === STATE_VERSION_DIR && typeof state?.turnKey === 'string'
    && LEGACY_PATH_KEY_PATTERN.test(state.turnKey)
    && state.turnKey.slice(0, PATH_KEY_HEX_CHARS) === sourceTurnName) sourceStateKeys.push(state.turnKey)
  if (state && !exactStateIdentity(state, legacy.surface, expectedSessionHash, sourceStateKeys, worktreeIdentity)) {
    throw new Error('legacy hook state does not match the requested surface, full session hash, and stable worktree identity')
  }
  if (state && state.turnId !== current.turnId) throw new Error('legacy hook state turn identity does not match its current selector')

  let target = await inspectTargetSession(
    root,
    targetSession,
    legacy,
    expectedSessionHash,
    worktreeIdentity,
    sourceTurnName,
    current.turnId,
  )
  if (target.kind === 'invalid') throw new Error(target.reason ?? 'v2 migration target is incoherent')
  if (target.kind === 'partial') {
    await rm(targetSession, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
    target = { kind: 'missing' }
  }
  if (target.kind === 'coherent') {
    const targetTurnKey = sourceTurnName.slice(0, PATH_KEY_HEX_CHARS)
    await normalizeMigratedTarget(root, targetSession, targetTurnKey, current.turnId, target)
    await cleanupLegacySession(root, legacy, expectedSessionHash, worktreeIdentity)
    await rm(legacy.path, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
    return
  }

  if (!sourceTurnExists || !state) throw new Error('legacy hook evidence is missing from both the source and migration target')
  const resumable = await resumableLegacyTurn(
    root,
    legacy.surface,
    expectedSessionHash,
    worktreeIdentity,
    state.turnKey,
    sourceTurnDir,
    state,
  )
  await cleanupLegacySession(root, legacy, expectedSessionHash, worktreeIdentity, sourceTurnName)
  if (!resumable) {
    await cleanupLegacyTurn(root, sourceTurnDir, state)
    await rm(legacy.path, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
    return
  }

  const targetTurnKey = sourceTurnName.slice(0, PATH_KEY_HEX_CHARS)
  const targetTurnDir = join(targetSession, targetTurnKey)
  await ensurePrivateDirectory(targetSession)
  try {
    // Publish the destination selector before the atomic rename. A crash after
    // the move can still reach and clean/review the private evidence; a crash
    // before it leaves the legacy turn available for the next migration retry.
    await writePrivateJson(join(targetSession, 'current.json'), {
      version: 1,
      turnKey: targetTurnKey,
      ...(current?.turnId ? { turnId: current.turnId } : {}),
    } satisfies CurrentTurn)
    await rename(sourceTurnDir, targetTurnDir)
  } catch (error) {
    await rm(targetSession, { recursive: true, force: true }).catch(() => undefined)
    throw error
  }
  await normalizeMigratedTarget(root, targetSession, targetTurnKey, current.turnId, {
    kind: 'coherent',
    current: { version: 1, turnKey: targetTurnKey, ...(current.turnId ? { turnId: current.turnId } : {}) },
    turnDir: targetTurnDir,
    state,
  })
  await rm(legacy.path, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
}

async function migrationEvidenceFingerprint(
  session: HookStateSessionCandidate,
  expectedSessionHash: string,
  worktreeIdentity: string,
): Promise<string | undefined> {
  const current = await readJson<CurrentTurn>(join(session.path, 'current.json')).catch(() => undefined)
  if (!exactLegacyCurrentTurn(current)) return undefined
  const state = await readJson<HookState>(join(session.path, current.turnKey, 'state.json')).catch(() => undefined)
  if (!exactStateIdentity(state, session.surface, expectedSessionHash, [current.turnKey], worktreeIdentity)) return undefined
  if (!stateMatchesSelector(state, current)) return undefined
  return JSON.stringify({
    current: { turnKey: current.turnKey.slice(0, PATH_KEY_HEX_CHARS), turnId: current.turnId },
    state: {
      version: state.version,
      surface: state.surface,
      sessionHash: state.sessionHash,
      worktreeIdentity: state.worktreeIdentity,
      turnKey: state.turnKey.slice(0, PATH_KEY_HEX_CHARS),
      turnId: state.turnId,
      task: state.task,
      taskHash: state.taskHash,
      baselineCommit: state.baselineCommit,
      baselineHead: state.baselineHead,
      baselineDirtyFiles: state.baselineDirtyFiles,
      objectStoreVersion: state.objectStoreVersion,
      contextSha256: state.contextSha256,
      status: state.status,
      finalCommit: state.finalCommit,
      finalHead: state.finalHead,
      reviewAttemptId: state.reviewAttemptId,
      createdAt: state.createdAt,
      result: state.result,
      error: state.error,
    },
  })
}

async function divergentEqualPriorityEvidence(
  sessions: HookStateSessionCandidate[],
  expectedSessionHash: string,
  worktreeIdentity: string,
): Promise<boolean> {
  const groups = new Map<number, HookStateSessionCandidate[]>()
  for (const session of sessions) {
    const group = groups.get(session.root.priority) ?? []
    group.push(session)
    groups.set(session.root.priority, group)
  }
  for (const group of groups.values()) {
    if (group.length < 2) continue
    const fingerprints = await Promise.all(group.map((session) => migrationEvidenceFingerprint(
      session,
      expectedSessionHash,
      worktreeIdentity,
    )))
    if (fingerprints.some((fingerprint) => fingerprint === undefined) || new Set(fingerprints).size !== 1) return true
  }
  return false
}

function stateBelongsToSessionDirectory(
  state: HookState | undefined,
  session: HookStateSessionCandidate,
  turnName: string,
  worktreeIdentity: string,
): state is HookState {
  return Boolean(state && typeof state.sessionHash === 'string' && /^[0-9a-f]{64}$/.test(state.sessionHash)
    && (state.sessionHash === session.sessionName || state.sessionHash.startsWith(session.sessionName))
    && exactStateIdentity(state, session.surface, state.sessionHash, [turnName], worktreeIdentity))
}

async function pruneUnrequestedStateSessions(
  root: string,
  sessions: HookStateSessionCandidate[],
  requestedPaths: Set<string>,
  worktreeIdentity: string,
): Promise<string | undefined> {
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1_000
  for (const session of sessions) {
    if (requestedPaths.has(resolve(session.path))) continue
    const turns = await readdir(session.path, { withFileTypes: true }).catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw error
    })
    for (const turn of turns) {
      if (!turn.isDirectory()) continue
      const turnDir = join(session.path, turn.name)
      const state = await readJson<HookState>(join(turnDir, 'state.json')).catch(() => undefined)
      if (!stateBelongsToSessionDirectory(state, session, turn.name, worktreeIdentity)) continue
      const updatedAt = Date.parse(state.updatedAt)
      const terminal = state.status === 'completed' || state.status === 'failed' || state.status === 'capturing'
      const stale = Number.isFinite(updatedAt) && updatedAt < cutoff
      if (!terminal && !stale) continue
      try {
        await cleanupLegacyTurn(root, turnDir, state)
      } catch (error) {
        return `stale hook evidence could not be securely cleaned: ${safeError(error)}`
      }
    }
    const remaining = await readdir(session.path, { withFileTypes: true }).catch(() => [])
    if (remaining.every((entry) => !entry.isDirectory()
      && (entry.name === 'current.json' || /^current\.json\.\d+\.[0-9a-f]{12}\.tmp$/.test(entry.name)))) {
      await rm(session.path, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
    }
  }
  return undefined
}

async function migrateLegacyHookState(
  hooksRoot: string,
  currentBase: string,
  root: string,
  worktreeIdentity: string,
  requestedSurface: AgentHookSurface,
  requestedSessionId: string,
): Promise<string | undefined> {
  const requestedSessionHash = hash(requestedSessionId)
  const roots = await discoverStateRootCandidates(hooksRoot, currentBase, root, worktreeIdentity)
  for (const session of await sessionsInStateRoots(roots)) {
    if (await legacySessionHasLiveLease(session.path)) {
      return `legacy ${session.surface} hook evidence still has an active lease; retry after the active hook finishes`
    }
  }
  let blockReason: string | undefined
  const requestedSessions: HookStateSessionCandidate[] = []
  for (const session of await requestedStateSessions(roots, requestedSurface, requestedSessionId)) {
    if (!await removeRecognizedPartialSource(session)) requestedSessions.push(session)
  }
  if (await divergentEqualPriorityEvidence(requestedSessions, requestedSessionHash, worktreeIdentity)) {
    return 'multiple equal-priority hook-state roots contain divergent or incomplete evidence; preserving every copy for manual recovery'
  }
  for (const legacy of requestedSessions) {
    try {
      await migrateLegacySession(root, currentBase, legacy, requestedSessionHash, worktreeIdentity)
    } catch (error) {
      blockReason ??= `legacy hook evidence could not be migrated or securely cleaned: ${safeError(error)}`
      break
    }
  }
  if (!blockReason) {
    blockReason = await pruneUnrequestedStateSessions(
      root,
      await sessionsInStateRoots(roots),
      new Set(requestedSessions.map((session) => resolve(session.path))),
      worktreeIdentity,
    )
  }
  for (const stateRoot of roots) await removeEmptyStateRoot(stateRoot)
  return blockReason
}

async function pruneRepoState(
  root: string,
  base: string,
  currentSessionDir: string,
  worktreeIdentity: string,
): Promise<void> {
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1_000
  for (const surface of ['claude', 'codex']) {
    const surfaceDir = join(base, surface)
    let entries
    try {
      entries = await readdir(surfaceDir, { withFileTypes: true })
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue
      throw error
    }
    const sessions: Array<{ path: string; mtimeMs: number }> = []
    for (const entry of entries) {
      if (!entry.isDirectory() || !PATH_KEY_PATTERN.test(entry.name)) continue
      const path = join(surfaceDir, entry.name)
      sessions.push({ path, mtimeMs: (await stat(path)).mtimeMs })
    }
    sessions.sort((left, right) => right.mtimeMs - left.mtimeMs)
    for (const session of sessions) {
      if (resolve(session.path) === resolve(currentSessionDir)) continue
      const index = sessions.indexOf(session)
      if (index < 100 && session.mtimeMs >= cutoff) continue
      const turns = await readdir(session.path, { withFileTypes: true }).catch(() => [])
      let live = false
      for (const turn of turns) {
        if (!turn.isDirectory()) continue
        const state = await readJson<HookState>(join(session.path, turn.name, 'state.json')).catch(() => undefined)
        if (!state || state.worktreeIdentity !== worktreeIdentity || state.surface !== surface
          || typeof state.sessionHash !== 'string' || !state.sessionHash.startsWith(basename(session.path))
          || state.turnKey !== turn.name) {
          // Unknown or legacy path-only ownership is never a pruning license.
          live = true
          break
        }
        const updatedAt = state?.updatedAt ? Date.parse(state.updatedAt) : Number.NaN
        const protectedState = state && ['capturing', 'ready', 'reviewing', 'cleanup_pending'].includes(state.status)
          && Number.isFinite(updatedAt) && updatedAt >= cutoff
        if (protectedState || await turnHasLiveLease(join(session.path, turn.name), state)) {
          live = true
          break
        }
      }
      if (live) continue
      for (const turn of turns) {
        if (!turn.isDirectory()) continue
        const state = await readJson<HookState>(join(session.path, turn.name, 'state.json')).catch(() => undefined)
        if (state?.baselineRef) deleteLegacyStateRefs(root, state.baselineRef)
      }
      await rm(session.path, { recursive: true, force: true })
    }
  }
}

function inputTurnId(input: HookInput): string | undefined {
  const turnId = asNonEmptyString(input.turn_id) ?? asNonEmptyString(input.prompt_id)
  if (turnId && turnId.length > MAX_TURN_ID_CHARS) throw new Error(`turn identifier exceeds ${MAX_TURN_ID_CHARS} characters`)
  return turnId
}

function inputTask(input: HookInput): string | undefined {
  const prompt = asNonEmptyString(input.prompt)
  return prompt?.slice(0, MAX_TASK_CHARS)
}

type NamedLockName = 'capture.lock' | 'stop.lock' | 'migration.lock'

interface NamedLockRecord {
  version: 1
  pid: number
  createdAt: string
  token: string
}

interface NamedLockLease {
  path: string
  token: string
}

interface LockObservation {
  bytes: string
  pid: number
  token?: string
}

async function lockObservation(path: string): Promise<LockObservation | undefined> {
  let bytes: string
  try {
    bytes = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  try {
    const parsed = JSON.parse(bytes) as Record<string, unknown>
    return {
      bytes,
      pid: typeof parsed.pid === 'number' ? parsed.pid : 0,
      ...(typeof parsed.token === 'string' && /^[0-9a-f]{32}$/.test(parsed.token) ? { token: parsed.token } : {}),
    }
  } catch {
    return { bytes, pid: 0 }
  }
}

async function createLockFile(path: string, now: Date): Promise<NamedLockLease | undefined> {
  const token = randomUUID().replaceAll('-', '')
  const record: NamedLockRecord = { version: 1, pid: process.pid, createdAt: now.toISOString(), token }
  try {
    const handle = await open(path, 'wx', 0o600)
    try {
      await handle.writeFile(`${JSON.stringify(record)}\n`)
      await handle.sync()
    } finally {
      await handle.close()
    }
    return { path, token }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return undefined
    throw error
  }
}

async function releaseNamedLock(lease: NamedLockLease): Promise<void> {
  const observed = await lockObservation(lease.path).catch(() => undefined)
  if (observed?.token !== lease.token) return
  // A lock cannot be replaced while its pathname exists. Revalidating the
  // unique token immediately before unlink prevents an old owner from
  // deleting a later owner's lease (the classic lock-file ABA race).
  const confirmed = await lockObservation(lease.path).catch(() => undefined)
  if (confirmed?.token === lease.token && confirmed.bytes === observed.bytes) await rm(lease.path, { force: true })
}

async function acquireRecoveryLock(lockPath: string, now: Date): Promise<NamedLockLease | undefined> {
  const recoveryPath = `${lockPath}.recovery`
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const created = await createLockFile(recoveryPath, now)
    if (created) return created
    const observed = await lockObservation(recoveryPath)
    if (!observed || processExists(observed.pid)) return undefined
    // Atomically move the exact dead recovery lease out of the lock name.
    // Revalidate its token/bytes after the rename before deleting it; if an
    // ABA replacement won the race, restore it instead of reaping it.
    const quarantine = `${recoveryPath}.reap.${process.pid}.${randomUUID().replaceAll('-', '').slice(0, 12)}`
    try {
      await rename(recoveryPath, quarantine)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue
      throw error
    }
    const moved = await lockObservation(quarantine)
    if (moved?.bytes !== observed.bytes || moved.token !== observed.token) {
      try { await rename(quarantine, recoveryPath) } catch { /* Preserve whichever contender now owns the name. */ }
      return undefined
    }
    await rm(quarantine, { force: true })
  }
  return undefined
}

async function acquireNamedLock(
  turnDir: string,
  name: NamedLockName,
  now: Date,
): Promise<NamedLockLease | undefined> {
  const lockPath = join(turnDir, name)
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const created = await createLockFile(lockPath, now)
    if (created) return created
    const observed = await lockObservation(lockPath)
    if (!observed) continue
    // Age is never evidence of staleness while the owning process is alive.
    if (processExists(observed.pid)) return undefined
    const recovery = await acquireRecoveryLock(lockPath, now)
    if (!recovery) return undefined
    try {
      const confirmed = await lockObservation(lockPath)
      if (!confirmed) continue
      if (confirmed.bytes !== observed.bytes || confirmed.token !== observed.token || processExists(confirmed.pid)) {
        continue
      }
      await rm(lockPath, { force: true })
    } finally {
      await releaseNamedLock(recovery)
    }
  }
  return undefined
}

async function capturePromptBaseline(
  root: string,
  surface: AgentHookSurface,
  input: HookInput,
  config: CliConfig,
  dependencies: HookRuntimeDependencies,
): Promise<HookOutput | undefined> {
  const sessionId = asNonEmptyString(input.session_id)
  const task = inputTask(input)
  if (!sessionId) return blockDecision('CodeTruss could not capture an exact turn baseline: hook input is missing session_id.')
  if (!task) return blockDecision('CodeTruss could not capture an exact turn baseline: hook input is missing the submitted prompt.')

  let turnId: string | undefined
  try {
    turnId = inputTurnId(input)
  } catch (error) {
    return blockDecision(`CodeTruss could not capture an exact turn baseline: ${safeError(error)}.`)
  }
  const prepared = await gitStateRoot(root, surface, sessionId)
  if (prepared.legacyBlockReason) {
    return blockDecision(`CodeTruss could not safely migrate private hook evidence: ${prepared.legacyBlockReason}.`)
  }
  const base = prepared.base
  const sessionDir = sessionStateDir(base, surface, sessionId)
  await ensurePrivateDirectory(sessionDir)
  await pruneRepoState(root, base, sessionDir, prepared.worktreeIdentity)
  await pruneTurnState(root, sessionDir, prepared.worktreeIdentity)
  const turnKey = pathKey(turnId ? `id:${turnId}` : `nonce:${randomUUID()}`)
  const turnDir = join(sessionDir, turnKey)
  const statePath = join(turnDir, 'state.json')
  const currentPath = join(sessionDir, 'current.json')
  await ensurePrivateDirectory(turnDir)
  const now = dependencies.now?.() ?? new Date()
  const lock = await acquireNamedLock(turnDir, 'capture.lock', now)
  if (!lock) return blockDecision('CodeTruss exact baseline capture is already running for this agent turn.')
  try {
    const contextPath = turnContextPath(turnDir)
    const storePath = turnObjectStorePath(turnDir)
    let existing: HookState | undefined
    try {
      existing = await readBoundedRegularJson<HookState>(statePath, MAX_STATE_BYTES)
    } catch (error) {
      return blockDecision(`CodeTruss refused to replace unsafe or invalid existing turn state: ${safeError(error)}.`)
    }
    if (existing && (!exactStateIdentity(existing, surface, hash(sessionId), [turnKey], prepared.worktreeIdentity)
      || existing.turnId !== turnId)) {
      return blockDecision('CodeTruss refused to replace hook evidence whose session, surface, turn, or stable Git worktree ownership cannot be proven.')
    }
    if (existing && existing.taskHash !== hash(task)) {
      return blockDecision('CodeTruss refused to reuse exact turn evidence for a different prompt task.')
    }
    if (exactStateIdentity(existing, surface, hash(sessionId), [turnKey], prepared.worktreeIdentity)
      && existing.turnId === turnId && existing.status === 'ready' && existing.objectStoreVersion === 1
      && existing.baselineCommit && existing.contextSha256) {
      try {
        await openPrivateGitObjectStore(root, storePath)
        const context = await readHookTurnContext(contextPath, existing.contextSha256)
        if (context.task !== task || existing.taskHash !== hash(context.task)) {
          return blockDecision('CodeTruss refused to reuse an exact baseline for a different prompt task.')
        }
        await writePrivateJson(currentPath, { version: 1, turnKey, ...(turnId ? { turnId } : {}) } satisfies CurrentTurn)
        return undefined
      } catch {
        // A partial/crashed cleanup invalidates the old ready marker. Recapture
        // under this exclusive lock before allowing the turn to proceed.
      }
    }
    if (existing?.baselineRef) deleteLegacyStateRefs(root, existing.baselineRef)
    const initial: HookState = {
      version: 1,
      surface,
      sessionHash: hash(sessionId),
      worktreeIdentity: prepared.worktreeIdentity,
      turnKey,
      ...(turnId ? { turnId } : {}),
      task,
      taskHash: hash(task),
      objectStoreVersion: 1,
      capturePid: process.pid,
      status: 'capturing',
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
    }
    await writePrivateJson(statePath, initial)
    await writePrivateJson(currentPath, { version: 1, turnKey, ...(turnId ? { turnId } : {}) } satisfies CurrentTurn)
    let objectStore: PrivateGitObjectStore | undefined
    try {
      objectStore = await initializePrivateGitObjectStore(root, storePath)
      const baseline = await (dependencies.captureBaseline ?? createExactSnapshotCommit)(root, join(turnDir, 's'), objectStore)
      const context: HookTurnContext = {
        version: 1,
        surface,
        task,
        config: frozenConfig(config),
        baselineDirtyFiles: [...baseline.dirtyFiles],
      }
      const contextText = `${JSON.stringify(context)}\n`
      await writePrivateText(contextPath, contextText)
      const ready: HookState = {
        ...initial,
        capturePid: undefined,
        baselineCommit: baseline.commit,
        baselineHead: baseline.head,
        baselineDirtyFiles: baseline.dirtyFiles,
        contextSha256: hash(contextText),
        status: 'ready',
        updatedAt: (dependencies.now?.() ?? new Date()).toISOString(),
      }
      await writePrivateJson(statePath, ready)
      return undefined
    } catch (error) {
      let cleanupError: string | undefined
      try { await objectStore?.cleanup() } catch (cleanupFailure) { cleanupError = safeError(cleanupFailure) }
      await rm(contextPath, { force: true })
      const message = `CodeTruss could not capture an exact turn baseline: ${safeError(error)}${cleanupError ? ` Private snapshot cleanup is pending: ${cleanupError}` : ''}`
      await writePrivateJson(statePath, {
        ...initial,
        task: undefined,
        capturePid: undefined,
        status: 'failed',
        error: message,
        updatedAt: (dependencies.now?.() ?? new Date()).toISOString(),
      } satisfies HookState)
      return blockDecision(message)
    }
  } finally {
    await releaseNamedLock(lock)
  }
}

function stringsAtKnownPathKeys(value: unknown): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  const record = value as Record<string, unknown>
  return ['file_path', 'filePath', 'path']
    .map((key) => record[key])
    .filter((candidate): candidate is string => typeof candidate === 'string' && Boolean(candidate.trim()))
}

function patchPaths(value: unknown): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  const record = value as Record<string, unknown>
  const patches = ['patch', 'input', 'content']
    .map((key) => record[key])
    .filter((candidate): candidate is string => typeof candidate === 'string' && candidate.includes('***'))
  return patches.flatMap((patch) => [...patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm)].map((match) => match[1].trim()))
}

interface NormalizedHookPath {
  path?: string
  outside?: string
}

function normalizeHookPath(root: string, cwd: string | undefined, inputPath: string): NormalizedHookPath {
  const trimmed = inputPath.trim().replace(/^"|"$/g, '')
  if (!trimmed || trimmed.includes('\0')) return { outside: inputPath }
  let absolute: string
  if (isAbsolute(trimmed)) absolute = resolve(trimmed)
  else if (trimmed === '..' || trimmed.startsWith('../') || trimmed.startsWith('./')) absolute = resolve(cwd ?? root, trimmed)
  else absolute = resolve(root, trimmed)
  const candidate = relative(resolve(root), absolute).replaceAll('\\', '/')
  if (!candidate || candidate === '..' || candidate.startsWith('../') || isAbsolute(candidate)) return { outside: inputPath }
  return { path: candidate }
}

function fastPathFeedback(
  root: string,
  input: HookInput,
  config: CliConfig,
): HookOutput | undefined {
  const cwd = asNonEmptyString(input.cwd)
  const rawPaths = [
    ...stringsAtKnownPathKeys(input.tool_input),
    ...stringsAtKnownPathKeys(input.tool_response),
    ...patchPaths(input.tool_input),
  ]
  const normalized = rawPaths.map((path) => normalizeHookPath(root, cwd, path))
  const outside = [...new Set(normalized.flatMap((item) => item.outside ? [item.outside] : []))]
  const paths = [...new Set(normalized.flatMap((item) => item.path ? [item.path] : []))].sort()
  const warnings: string[] = []
  for (const path of paths) {
    const classification = classifyPath(path, undefined, config.allow, config.deny)
    const sensitive = sensitiveCategory(path)
    const dependency = isDependencyFile(path)
    if (classification === 'denied') warnings.push(`${path}: denied by the task scope`)
    else if (classification === 'unexpected') warnings.push(`${path}: outside the allowed task scope`)
    if (sensitive) warnings.push(`${path}: sensitive ${sensitive} surface`)
    if (dependency) warnings.push(`${path}: dependency or lockfile surface`)
  }
  for (const path of outside) warnings.push(`${path}: resolves outside the repository`)
  if (warnings.length === 0) return undefined
  return postToolFeedback(`CodeTruss fast scope check:\n${warnings.map((warning) => `- ${warning}`).join('\n')}\nA full analyzer receipt will run once when this turn stops.`)
}

export function hookReviewEnvironment(
  request: HookReviewRequest,
  base: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  return {
    ...base,
    CODETRUSS_INTERNAL_HOOK: '1',
    [CODETRUSS_HOOK_SURFACE_ENV]: request.surface,
    CODETRUSS_HOOK_START_COMMIT: request.startCommit,
    CODETRUSS_HOOK_END_COMMIT: request.finalHead,
    CODETRUSS_HOOK_STARTED_AT: request.startedAt,
    [CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV]: request.objectDirectory,
    [CODETRUSS_HOOK_CONTEXT_PATH_ENV]: request.contextPath,
    [CODETRUSS_HOOK_CONTEXT_SHA256_ENV]: request.contextSha256,
    [CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV]: hash(JSON.stringify(request.baselineDirtyFiles)),
    [CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV]: request.attemptId,
    [CODETRUSS_HOOK_RESULT_PATH_ENV]: request.resultPath,
  }
}

async function defaultRunReview(request: HookReviewRequest): Promise<HookReviewResult> {
  const entry = process.argv[1]
  if (!entry) return { status: null, stdout: '', stderr: '', error: 'could not locate the active CodeTruss CLI entrypoint' }
  try {
    const result = await runLocalCommand({
      command: process.execPath,
      args: [...process.execArgv, entry, 'review', '--task', request.task, '--base', request.baselineRef, '--final', request.finalRef],
      cwd: request.root,
      env: hookReviewEnvironment(request),
      timeoutMs: REVIEW_TIMEOUT_MS,
      maxOutputBytes: 1024 * 1024,
    })
    return {
      status: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
      ...(result.signal ? { error: `review process terminated by ${result.signal}` } : {}),
    }
  } catch (error) {
    return { status: null, stdout: '', stderr: '', error: safeError(error) }
  }
}

interface HookReviewResultDocument {
  version: 1
  attemptId: string
  verdict: 'PASS' | 'REVIEW_REQUIRED' | 'FAILED'
  receiptPath: string
  reasons: string[]
}

function isContainedPath(parent: string, candidate: string): boolean {
  const within = relative(parent, candidate)
  return within === '' || (!within.startsWith('..') && !isAbsolute(within))
}

function exactReviewResultDocument(value: unknown, attemptId: string): value is HookReviewResultDocument {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const document = value as Record<string, unknown>
  return Object.keys(document).sort().join(',') === 'attemptId,reasons,receiptPath,verdict,version'
    && document.version === 1
    && document.attemptId === attemptId
    && /^[0-9a-f]{64}$/.test(document.attemptId)
    && ['PASS', 'REVIEW_REQUIRED', 'FAILED'].includes(String(document.verdict))
    && typeof document.receiptPath === 'string' && document.receiptPath.length > 0
      && document.receiptPath.length <= 4_096
    && Array.isArray(document.reasons) && document.reasons.length <= 100
    && document.reasons.every((reason) => typeof reason === 'string' && reason.length <= 2_000)
}

async function prepareReviewResultPath(turnDir: string, attemptId: string): Promise<string> {
  if (!/^[0-9a-f]{64}$/.test(attemptId)) throw new Error('hook review attempt id is invalid')
  const parent = join(turnDir, 'review-results')
  await ensurePrivateDirectory(parent)
  const [turnReal, parentReal] = await Promise.all([realpath(turnDir), realpath(parent)])
  if (!isContainedPath(turnReal, parentReal) || parentReal !== resolve(turnReal, 'review-results')) {
    throw new Error('hook review result parent escapes the selected private turn')
  }
  return join(parent, `${attemptId}.json`)
}

async function reviewResultExists(path: string): Promise<boolean> {
  try {
    await lstat(path)
    return true
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw error
  }
}

async function assertReviewResultLocation(turnDir: string, resultPath: string, attemptId: string): Promise<void> {
  const expected = join(resolve(turnDir), 'review-results', `${attemptId}.json`)
  if (resultPath !== expected) throw new Error('private review result path does not match its deterministic attempt location')
  const parent = dirname(resultPath)
  const [turnInfo, parentInfo, resultInfo] = await Promise.all([
    lstat(turnDir),
    lstat(parent),
    lstat(resultPath),
  ])
  if (!turnInfo.isDirectory() || turnInfo.isSymbolicLink() || !parentInfo.isDirectory() || parentInfo.isSymbolicLink()) {
    throw new Error('private review result parent is not a safe contained directory')
  }
  if (!resultInfo.isFile() || resultInfo.isSymbolicLink()) throw new Error('private review result is not a safe regular file')
  if (process.platform !== 'win32' && (resultInfo.mode & 0o077) !== 0) {
    throw new Error('private review result permissions are not private')
  }
  const [turnReal, parentReal] = await Promise.all([realpath(turnDir), realpath(parent)])
  if (parentReal !== resolve(turnReal, 'review-results') || !isContainedPath(turnReal, parentReal)) {
    throw new Error('private review result parent escapes the selected turn')
  }
}

async function readVerifiedReviewResult(
  root: string,
  context: HookTurnContext,
  turnDir: string,
  resultPath: string,
  attemptId: string,
): Promise<HookReviewResultDocument> {
  await assertReviewResultLocation(turnDir, resultPath, attemptId)
  const document = await readBoundedRegularJson<unknown>(resultPath, MAX_STATE_BYTES)
  if (!exactReviewResultDocument(document, attemptId)) {
    throw new Error('private review result has an invalid schema or attempt binding')
  }
  if (!isAbsolute(document.receiptPath) || resolve(document.receiptPath) !== document.receiptPath
    || !document.receiptPath.endsWith('.md')) {
    throw new Error('private review result has an invalid receipt path')
  }
  const approved = receiptDir(root, context.config)
  const candidate = resolve(document.receiptPath)
  if (!isContainedPath(approved, candidate)) throw new Error('private review result receipt is outside the approved receipt directory')
  const receiptInfo = await lstat(candidate)
  if (!receiptInfo.isFile() || receiptInfo.isSymbolicLink()) throw new Error('private review result receipt is not a safe regular file')
  const [approvedReal, receiptReal] = await Promise.all([realpath(approved), realpath(candidate)])
  if (!isContainedPath(approvedReal, receiptReal)) throw new Error('private review result receipt traverses outside the approved directory')
  return document
}

async function discardInvalidReviewResult(turnDir: string, resultPath: string, attemptId: string): Promise<void> {
  const expected = join(resolve(turnDir), 'review-results', `${attemptId}.json`)
  if (resultPath !== expected) return
  try {
    const info = await lstat(resultPath)
    // Never recursively remove an unexpected directory. A regular file,
    // symlink, or other leaf can be unlinked without following its target.
    if (info.isDirectory() && !info.isSymbolicLink()) return
    await rm(resultPath, { force: true })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
}

async function reviewSummary(
  root: string,
  context: HookTurnContext,
  turnDir: string,
  resultPath: string,
  attemptId: string,
  result?: HookReviewResult,
): Promise<NonNullable<HookState['result']>> {
  let document: HookReviewResultDocument
  try {
    document = await readVerifiedReviewResult(root, context, turnDir, resultPath, attemptId)
  } catch (error) {
    // Invalid attempt output must not permanently poison this immutable
    // baseline/final pair. Remove only the exact leaf so the next Stop can
    // rerun the child review against the same persisted OIDs.
    await discardInvalidReviewResult(turnDir, resultPath, attemptId).catch(() => undefined)
    const processLog = result
      ? (result.error || result.stderr || result.stdout || `review exited with status ${String(result.status)}`).trim()
      : ''
    const missingResult = (error as NodeJS.ErrnoException).code === 'ENOENT'
    const primary = missingResult && processLog
      ? `review process failed before producing a receipt: ${safeError(processLog)}`
      : `${safeError(error)}${processLog ? `. Review process detail: ${safeError(processLog)}` : ''}`
    return {
      verdict: 'ERROR',
      message: `CodeTruss hook review could not produce a verified receipt: ${primary}`,
    }
  }
  const expectedStatuses = { PASS: 0, REVIEW_REQUIRED: 1, FAILED: 2 } as const
  if (result?.error || (result && (result.status === null || result.status !== expectedStatuses[document.verdict]))) {
    const logs = (result?.error || result?.stderr || result?.stdout || `review exited with status ${String(result?.status)}`)
      .trim().slice(0, MAX_REVIEW_OUTPUT_CHARS)
    return {
      verdict: 'ERROR',
      message: `CodeTruss hook review could not produce a verified receipt: review exit status does not match ${document.verdict}${logs ? ` (${logs})` : ''}`,
    }
  }
  const reasons = document.reasons.slice(0, 5).map((reason) => `- ${reason}`).join('\n')
  const message = `CodeTruss ${document.verdict}. Receipt: ${document.receiptPath}${reasons ? `\n${reasons}` : ''}`
  return {
    verdict: document.verdict,
    receiptPath: document.receiptPath,
    message: message.slice(0, 10_000),
  }
}

function hasBackgroundTasks(input: HookInput): boolean {
  return Array.isArray(input.background_tasks) && input.background_tasks.length > 0
}

function processExists(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid < 1) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM'
  }
}

async function acquireStopLock(turnDir: string, now: Date): Promise<NamedLockLease | undefined> {
  return acquireNamedLock(turnDir, 'stop.lock', now)
}

async function cleanupTurnEvidence(root: string, turnDir: string): Promise<void> {
  await removePrivateGitObjectStore(root, turnObjectStorePath(turnDir))
  await rm(turnContextPath(turnDir), { force: true })
  await rm(join(turnDir, 's'), { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
  await rm(join(turnDir, 'f'), { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
  await rm(join(turnDir, 'snapshots'), { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
  await rm(join(turnDir, 'final-snapshots'), { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
  await rm(join(turnDir, 'review-results'), { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
}

function exactStopState(
  state: HookState | undefined,
  surface: AgentHookSurface,
  sessionId: string,
  current: CurrentTurn,
  worktreeIdentity: string,
): state is HookState {
  return exactStateIdentity(state, surface, hash(sessionId), [current.turnKey], worktreeIdentity)
    && stateMatchesSelector(state, current)
}

function reviewAttemptId(state: HookState, finalCommit: string, finalHead: string): string {
  return hash([
    'codetruss-hook-review-v1',
    state.surface,
    state.sessionHash,
    state.worktreeIdentity,
    state.turnId ? `id:${state.turnId}` : `key:${state.turnKey.slice(0, PATH_KEY_HEX_CHARS)}`,
    state.baselineCommit ?? '',
    finalCommit,
    finalHead,
    state.contextSha256 ?? '',
    state.createdAt,
  ].join('\0'))
}

function lockedStopOutput(input: HookInput, state: HookState): HookOutput {
  if (validHookResult(state.result)) {
    return stopReviewOutput(
      input,
      state.result,
      `${state.result.message}\nCodeTruss is still finalizing this persisted review outcome.`,
      true,
    ) as HookOutput
  }
  return stopFailureOutput(input, 'CodeTruss hook review is already in progress for this exact turn; retry Stop after it finishes.')
}

function terminalStopOutput(input: HookInput, state: HookState): HookOutput | undefined {
  if (validHookResult(state.result)) return stopReviewOutput(input, state.result)
  return stopFailureOutput(input, state.error ?? 'CodeTruss hook review ended without a valid persisted result.')
}

async function reviewAtStop(
  root: string,
  surface: AgentHookSurface,
  input: HookInput,
  dependencies: HookRuntimeDependencies,
): Promise<HookOutput | undefined> {
  const sessionId = asNonEmptyString(input.session_id)
  if (!sessionId) return stopFailureOutput(input, 'CodeTruss hook review did not run: Stop input is missing session_id, so no exact turn baseline can be selected.')
  let inputId: string | undefined
  try {
    inputId = inputTurnId(input)
  } catch (error) {
    return stopFailureOutput(input, `CodeTruss hook review did not run: ${safeError(error)}.`)
  }
  let prepared: PreparedGitState
  try {
    prepared = await gitStateRoot(root, surface, sessionId)
  } catch (error) {
    return stopFailureOutput(input, `CodeTruss hook review did not run: ${safeError(error)}.`)
  }
  if (prepared.legacyBlockReason) {
    return stopFailureOutput(input, `CodeTruss hook review did not run because private hook evidence migration is incomplete: ${prepared.legacyBlockReason}.`)
  }
  const base = prepared.base
  const sessionDir = sessionStateDir(base, surface, sessionId)
  let selection: { current: CurrentTurn; turnDir: string }
  try {
    selection = await readStopSelector(sessionDir)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return stopFailureOutput(input, 'CodeTruss hook review did not run: no exact baseline was captured for this agent turn.')
    }
    return stopFailureOutput(input, `CodeTruss hook review did not run: unsafe or invalid current selector: ${safeError(error)}.`)
  }
  const { current, turnDir } = selection
  if (inputId && inputId !== current.turnId) {
    return stopFailureOutput(input, 'CodeTruss hook review did not run: the Stop event does not match the captured agent turn baseline.')
  }
  const statePath = join(turnDir, 'state.json')
  let state: HookState | undefined
  try {
    state = await readBoundedRegularJson<HookState>(statePath, MAX_STATE_BYTES)
  } catch (error) {
    return stopFailureOutput(input, `CodeTruss hook review did not run: selected state is unsafe or invalid: ${safeError(error)}.`)
  }
  if (!exactStopState(state, surface, sessionId, current, prepared.worktreeIdentity)) {
    return stopFailureOutput(input, 'CodeTruss hook review did not run: selected state does not exactly match this session, surface, turn, and stable Git worktree identity.')
  }
  const now = dependencies.now?.() ?? new Date()
  if (state.status === 'completed' || (state.status === 'failed' && state.result)) {
    const replayLock = await acquireStopLock(turnDir, now)
    if (!replayLock) return lockedStopOutput(input, state)
    await releaseNamedLock(replayLock)
    return terminalStopOutput(input, state)
  }
  if (hasBackgroundTasks(input)) return undefined
  if (state.status === 'failed') return terminalStopOutput(input, state)
  if (state.status === 'capturing') {
    return stopFailureOutput(input, 'CodeTruss hook review did not run: exact baseline capture is still in progress for this turn.')
  }
  if (state.status !== 'cleanup_pending' && (state.objectStoreVersion !== 1 || !state.baselineCommit
    || !state.contextSha256 || !state.baselineDirtyFiles || state.task === undefined)) {
    const detail = state?.error ? ` ${state.error}` : ''
    return stopFailureOutput(input, `CodeTruss hook review did not run: exact baseline evidence is missing.${detail}`)
  }
  const lock = await acquireStopLock(turnDir, now)
  if (!lock) return lockedStopOutput(input, state)
  try {
    const lockedState = await readBoundedRegularJson<HookState>(statePath, MAX_STATE_BYTES)
    if (!exactStopState(lockedState, surface, sessionId, current, prepared.worktreeIdentity)) {
      return stopFailureOutput(input, 'CodeTruss hook review stopped because state ownership changed while acquiring its exclusive lock.')
    }
    state = lockedState
    if (state.status === 'completed' || state.status === 'failed') return terminalStopOutput(input, state)
    if (state.status === 'cleanup_pending') {
      if (!validHookResult(state.result)) {
        return stopFailureOutput(input, 'CodeTruss review evidence cleanup is pending, but its persisted result is invalid; preserving evidence for recovery.')
      }
      try {
        await cleanupTurnEvidence(root, turnDir)
        await writePrivateJson(statePath, {
          ...state,
          status: state.result.verdict === 'ERROR' ? 'failed' : 'completed',
          error: state.result.verdict === 'ERROR' ? state.result.message : undefined,
          updatedAt: (dependencies.now?.() ?? new Date()).toISOString(),
        } satisfies HookState)
        return stopReviewOutput(input, state.result, `${state.result.message}\nCodeTruss private snapshot cleanup completed.`)
      } catch (error) {
        return stopReviewOutput(
          input,
          state.result,
          `${state.result.message}\nPrivate snapshot cleanup is still pending: ${safeError(error)}`,
          true,
        )
      }
    }
    if (!['ready', 'reviewing'].includes(state.status)) {
      return stopFailureOutput(input, `CodeTruss hook review did not run from unexpected state ${JSON.stringify(state.status)}.`)
    }
    const task = state.task
    const baselineCommit = state.baselineCommit
    const contextSha256 = state.contextSha256
    const baselineDirtyFiles = state.baselineDirtyFiles
    if (task === undefined || !baselineCommit || !contextSha256 || !baselineDirtyFiles) {
      return stopFailureOutput(input, 'CodeTruss hook review did not run: exact baseline evidence became incomplete while acquiring its lock.')
    }
    let summary: NonNullable<HookState['result']>
    try {
      const contextPath = turnContextPath(turnDir)
      const objectStore = await openPrivateGitObjectStore(root, turnObjectStorePath(turnDir))
      const context = await readHookTurnContext(contextPath, contextSha256)
      if (context.task !== task || hash(context.task) !== state.taskHash) {
        throw new Error('hook task evidence does not match prompt-time context')
      }
      if (JSON.stringify(context.baselineDirtyFiles) !== JSON.stringify(baselineDirtyFiles)) {
        throw new Error('hook baseline dirty-file evidence does not match prompt-time context')
      }
      objectStore.assertObjectId(baselineCommit, 'baseline snapshot commit')
      let finalCommit: string
      let finalHead: string
      let attemptId: string
      if (state.status === 'ready') {
        if (state.finalCommit || state.finalHead || state.reviewAttemptId) {
          throw new Error('ready hook state contains an unexpected partial final review identity')
        }
        const final = await (dependencies.captureBaseline ?? createExactSnapshotCommit)(root, join(turnDir, 'f'), objectStore)
        objectStore.assertObjectId(final.commit, 'final snapshot commit')
        finalCommit = final.commit
        finalHead = final.head
        attemptId = reviewAttemptId(state, finalCommit, finalHead)
        state = {
          ...state,
          finalCommit,
          finalHead,
          reviewAttemptId: attemptId,
          status: 'reviewing',
          updatedAt: (dependencies.now?.() ?? new Date()).toISOString(),
        }
        // The immutable final OID and deterministic attempt are durable before
        // any review process starts. A process crash resumes this exact pair.
        await writePrivateJson(statePath, state)
      } else {
        if (!state.finalCommit || typeof state.finalHead !== 'string'
          || !state.reviewAttemptId || !/^[0-9a-f]{64}$/.test(state.reviewAttemptId)) {
          throw new Error('reviewing hook state is missing its persisted immutable final review identity')
        }
        objectStore.assertObjectId(state.finalCommit, 'persisted final snapshot commit')
        finalCommit = state.finalCommit
        finalHead = state.finalHead
        attemptId = state.reviewAttemptId
        if (attemptId !== reviewAttemptId(state, finalCommit, finalHead)) {
          throw new Error('persisted hook review attempt does not match its immutable evidence')
        }
      }
      const resultPath = await prepareReviewResultPath(turnDir, attemptId)
      if (await reviewResultExists(resultPath)) {
        // The CLI may have durably written the attempt result immediately
        // before this hook process crashed. Replay it without rerunning review.
        summary = await reviewSummary(root, context, turnDir, resultPath, attemptId)
      } else {
        const result = await (dependencies.runReview ?? defaultRunReview)({
          root,
          surface,
          task,
          baselineRef: baselineCommit,
          finalRef: finalCommit,
          startCommit: state.baselineHead ?? '',
          finalHead,
          startedAt: state.createdAt,
          objectDirectory: objectStore.objectDirectory,
          contextPath,
          contextSha256,
          baselineDirtyFiles: [...baselineDirtyFiles],
          context,
          attemptId,
          resultPath,
        })
        summary = await reviewSummary(root, context, turnDir, resultPath, attemptId, result)
      }
    } catch (error) {
      summary = { verdict: 'ERROR', message: `CodeTruss hook review could not produce a verified receipt: ${safeError(error)}` }
    }
    if (summary.verdict === 'ERROR') {
      // Preserve the exact lifecycle phase. A failure before final capture
      // remains ready and may recapture; only a state whose immutable final
      // pair was already persisted remains reviewing. Never delete the private
      // evidence until a verified verdict has been consumed.
      await writePrivateJson(statePath, {
        ...state,
        status: state.status,
        result: undefined,
        error: summary.message,
        updatedAt: (dependencies.now?.() ?? new Date()).toISOString(),
      } satisfies HookState)
      return stopFailureOutput(
        input,
        `${summary.message}\nCodeTruss preserved the exact private evidence; retry Stop to complete this same review attempt.`,
      )
    }
    const cleanupPending: HookState = {
      ...state,
      task: undefined,
      baselineDirtyFiles: undefined,
      status: 'cleanup_pending',
      result: summary,
      error: 'Private snapshot cleanup is pending.',
      updatedAt: (dependencies.now?.() ?? new Date()).toISOString(),
    }
    // Persist the review outcome before deleting its object database. A crash
    // from this point forward can retry cleanup without ever rerunning review.
    await writePrivateJson(statePath, cleanupPending)
    let cleanupError: string | undefined
    try {
      await cleanupTurnEvidence(root, turnDir)
    } catch (error) {
      cleanupError = safeError(error)
    }
    await writePrivateJson(statePath, {
      ...cleanupPending,
      status: cleanupError ? 'cleanup_pending' : 'completed',
      result: summary,
      error: cleanupError ? `Private snapshot cleanup is pending: ${cleanupError}` : undefined,
      updatedAt: (dependencies.now?.() ?? new Date()).toISOString(),
    } satisfies HookState)
    const message = `${summary.message}${cleanupError ? `\nPrivate snapshot cleanup is pending: ${cleanupError}` : ''}`
    return stopReviewOutput(input, summary, message, Boolean(cleanupError))
  } finally {
    await releaseNamedLock(lock)
  }
}

export async function handleAgentHook(
  root: string,
  surface: AgentHookSurface,
  input: HookInput,
  config: CliConfig,
  dependencies: HookRuntimeDependencies = {},
): Promise<HookOutput | undefined> {
  const event = hookEvent(input)
  if (event === 'UserPromptSubmit') return capturePromptBaseline(root, surface, input, config, dependencies)
  if (event === 'PostToolUse') return fastPathFeedback(root, input, config)
  if (event === 'Stop') {
    try {
      return await reviewAtStop(root, surface, input, dependencies)
    } catch (error) {
      return stopFailureOutput(input, `CodeTruss hook review failed safely: ${safeError(error)}`)
    }
  }
  return systemMessage(`CodeTruss ignored unsupported hook event ${JSON.stringify(event ?? '(missing)')}.`)
}

async function readHookInput(): Promise<HookInput> {
  const chunks: Buffer[] = []
  let bytes = 0
  for await (const value of process.stdin) {
    const chunk = Buffer.from(value as Buffer | string)
    bytes += chunk.length
    if (bytes > MAX_HOOK_INPUT_BYTES) throw new Error(`hook input exceeds ${MAX_HOOK_INPUT_BYTES} bytes`)
    chunks.push(chunk)
  }
  const parsed: unknown = JSON.parse(Buffer.concat(chunks, bytes).toString('utf8'))
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('hook input must be a JSON object')
  return parsed as HookInput
}

export async function dispatchAgentHook(root: string, surface: AgentHookSurface, config: CliConfig): Promise<number> {
  let input: HookInput = {}
  try {
    input = await readHookInput()
    const output = await handleAgentHook(root, surface, input, config)
    if (output) process.stdout.write(`${JSON.stringify(output)}\n`)
    return 0
  } catch (error) {
    const message = `CodeTruss hook failed safely: ${safeError(error)}`
    const event = hookEvent(input)
    const output = event === 'UserPromptSubmit'
      ? blockDecision(message)
      : event === 'Stop' ? stopFailureOutput(input, message) : systemMessage(message)
    process.stdout.write(`${JSON.stringify(output)}\n`)
    return 0
  }
}
