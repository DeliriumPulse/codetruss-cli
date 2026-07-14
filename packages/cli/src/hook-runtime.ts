import { createHash, randomUUID } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { chmod, mkdir, open, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import type { CliConfig } from './types.js'
import { createExactSnapshotCommit, deleteLegacyHookBaseline, type ExactSnapshotCommit } from './hook-baseline.js'
import { classifyPath, isDependencyFile, sensitiveCategory } from './policy.js'
import { runGitText } from './git-process.js'
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
}

export interface HookTurnContext {
  version: 1
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
const MAX_REVIEW_OUTPUT_CHARS = 6_000
const REVIEW_TIMEOUT_MS = 5 * 60 * 1_000
const STATE_VERSION_DIR = 'v1'
export const CODETRUSS_HOOK_CONTEXT_PATH_ENV = 'CODETRUSS_HOOK_CONTEXT_PATH'
export const CODETRUSS_HOOK_CONTEXT_SHA256_ENV = 'CODETRUSS_HOOK_CONTEXT_SHA256'
export const CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV = 'CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256'

function hash(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex')
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
  if (result.verdict !== 'FAILED' || input.stop_hook_active === true) return systemMessage(message)
  return blockDecision(message)
}

async function gitStateRoot(root: string): Promise<string> {
  const raw = runGitText(root, ['rev-parse', '--git-common-dir']).trim()
  const common = isAbsolute(raw) ? resolve(raw) : resolve(root, raw)
  const state = join(common, 'codetruss', 'hooks', STATE_VERSION_DIR, hash(resolve(root)))
  await mkdir(state, { recursive: true, mode: 0o700 })
  await chmod(state, 0o700)
  return state
}

function sessionStateDir(base: string, surface: AgentHookSurface, sessionId: string): string {
  return join(base, surface, hash(sessionId))
}

async function writePrivateJson(path: string, value: unknown): Promise<void> {
  await writePrivateText(path, `${JSON.stringify(value)}\n`)
}

async function writePrivateText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`
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
    || !config || config.version !== 1
    || !isStringArray(config.allow) || !isStringArray(config.deny) || !isStringArray(config.verify)
    || !config.receipts || typeof config.receipts.dir !== 'string'
    || !config.llm || !Number.isFinite(config.llm.maxDiffBytes) || config.llm.maxDiffBytes <= 0
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

async function pruneTurnState(root: string, sessionDir: string, keep = 20): Promise<void> {
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
    if (!entry.isDirectory() || !/^[0-9a-f]{64}$/.test(entry.name)) continue
    const path = join(sessionDir, entry.name)
    const info = await stat(path)
    const state = await readJson<HookState>(join(path, 'state.json')).catch(() => undefined)
    turns.push({ path, mtimeMs: info.mtimeMs, state })
  }
  turns.sort((left, right) => right.mtimeMs - left.mtimeMs)
  let retained = 0
  for (const turn of turns) {
    if (turn.state?.turnKey === current?.turnKey) continue
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

async function pruneRepoState(root: string, base: string, currentSessionDir: string): Promise<void> {
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
      if (!entry.isDirectory() || !/^[0-9a-f]{64}$/.test(entry.name)) continue
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
  return asNonEmptyString(input.turn_id) ?? asNonEmptyString(input.prompt_id)
}

function inputTask(input: HookInput): string | undefined {
  const prompt = asNonEmptyString(input.prompt)
  return prompt?.slice(0, MAX_TASK_CHARS)
}

async function acquireNamedLock(
  turnDir: string,
  name: 'capture.lock' | 'stop.lock',
  now: Date,
  staleAfterMs: number,
): Promise<string | undefined> {
  const lockPath = join(turnDir, name)
  try {
    const handle = await open(lockPath, 'wx', 0o600)
    await handle.writeFile(`${JSON.stringify({ pid: process.pid, createdAt: now.toISOString() })}\n`)
    await handle.close()
    return lockPath
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
    const existing = await readJson<{ pid?: unknown; createdAt?: unknown }>(lockPath).catch(() => undefined)
    const pid = typeof existing?.pid === 'number' ? existing.pid : 0
    const createdAt = typeof existing?.createdAt === 'string' ? Date.parse(existing.createdAt) : Number.NaN
    const stale = !processExists(pid) || !Number.isFinite(createdAt) || now.getTime() - createdAt > staleAfterMs
    if (!stale) return undefined
    await rm(lockPath, { force: true })
    return acquireNamedLock(turnDir, name, now, staleAfterMs)
  }
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

  const base = await gitStateRoot(root)
  const sessionDir = sessionStateDir(base, surface, sessionId)
  await mkdir(sessionDir, { recursive: true, mode: 0o700 })
  await chmod(sessionDir, 0o700)
  await pruneRepoState(root, base, sessionDir)
  await pruneTurnState(root, sessionDir)
  const turnId = inputTurnId(input)
  const turnKey = hash(turnId ? `id:${turnId}` : `nonce:${randomUUID()}`)
  const turnDir = join(sessionDir, turnKey)
  const statePath = join(turnDir, 'state.json')
  const currentPath = join(sessionDir, 'current.json')
  await mkdir(turnDir, { recursive: true, mode: 0o700 })
  await chmod(turnDir, 0o700)
  const now = dependencies.now?.() ?? new Date()
  const lockPath = await acquireNamedLock(turnDir, 'capture.lock', now, REVIEW_TIMEOUT_MS)
  if (!lockPath) return blockDecision('CodeTruss exact baseline capture is already running for this agent turn.')
  try {
    const contextPath = turnContextPath(turnDir)
    const storePath = turnObjectStorePath(turnDir)
    const existing = await readJson<HookState>(statePath)
    if (existing?.status === 'ready' && existing.objectStoreVersion === 1 && existing.baselineCommit && existing.contextSha256) {
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
      const baseline = await (dependencies.captureBaseline ?? createExactSnapshotCommit)(root, join(turnDir, 'snapshots'), objectStore)
      const context: HookTurnContext = {
        version: 1,
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
    await rm(lockPath, { force: true })
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
    CODETRUSS_HOOK_START_COMMIT: request.startCommit,
    CODETRUSS_HOOK_END_COMMIT: request.finalHead,
    CODETRUSS_HOOK_STARTED_AT: request.startedAt,
    [CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV]: request.objectDirectory,
    [CODETRUSS_HOOK_CONTEXT_PATH_ENV]: request.contextPath,
    [CODETRUSS_HOOK_CONTEXT_SHA256_ENV]: request.contextSha256,
    [CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV]: hash(JSON.stringify(request.baselineDirtyFiles)),
  }
}

function defaultRunReview(request: HookReviewRequest): HookReviewResult {
  const entry = process.argv[1]
  if (!entry) return { status: null, stdout: '', stderr: '', error: 'could not locate the active CodeTruss CLI entrypoint' }
  const result = spawnSync(
    process.execPath,
    [entry, 'review', '--task', request.task, '--base', request.baselineRef, '--final', request.finalRef],
    {
      cwd: request.root,
      env: hookReviewEnvironment(request),
      encoding: 'utf8',
      timeout: REVIEW_TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
    },
  )
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    ...(result.error ? { error: result.error.message } : {}),
  }
}

function reviewSummary(root: string, result: HookReviewResult): NonNullable<HookState['result']> {
  const stdout = result.stdout.slice(0, MAX_REVIEW_OUTPUT_CHARS)
  const stderr = result.stderr.slice(0, MAX_REVIEW_OUTPUT_CHARS)
  const lines = stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  const first = lines[0] ?? ''
  const match = /^(PASS|REVIEW_REQUIRED|FAILED)\s+\S+/.exec(first)
  const receiptPath = lines.slice(1).find((line) => {
    if (!line.endsWith('.md') || !isAbsolute(line)) return false
    const approved = resolve(root, '.codetruss', 'receipts')
    const candidate = resolve(line)
    const within = relative(approved, candidate)
    return within !== '..' && !within.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && !isAbsolute(within)
  })
  const expectedStatuses = { PASS: 0, REVIEW_REQUIRED: 1, FAILED: 2 } as const
  if (!result.error && result.status !== null && match && receiptPath && result.status === expectedStatuses[match[1] as keyof typeof expectedStatuses]) {
    const verdict = match[1] as 'PASS' | 'REVIEW_REQUIRED' | 'FAILED'
    const reasons = lines.slice(2, 7).join('\n')
    return {
      verdict,
      receiptPath,
      message: `CodeTruss ${verdict}. Receipt: ${receiptPath}${reasons ? `\n${reasons}` : ''}`,
    }
  }
  const detail = (result.error || stderr || stdout || `review exited with status ${String(result.status)}`).trim().slice(0, MAX_REVIEW_OUTPUT_CHARS)
  return {
    verdict: 'ERROR',
    message: `CodeTruss hook review could not produce a verified receipt: ${detail}`,
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

async function acquireStopLock(turnDir: string, now: Date): Promise<string | undefined> {
  return acquireNamedLock(turnDir, 'stop.lock', now, REVIEW_TIMEOUT_MS + 30_000)
}

async function cleanupTurnEvidence(root: string, turnDir: string): Promise<void> {
  await removePrivateGitObjectStore(root, turnObjectStorePath(turnDir))
  await rm(turnContextPath(turnDir), { force: true })
  await rm(join(turnDir, 'snapshots'), { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
  await rm(join(turnDir, 'final-snapshots'), { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
}

async function reviewAtStop(
  root: string,
  surface: AgentHookSurface,
  input: HookInput,
  dependencies: HookRuntimeDependencies,
): Promise<HookOutput | undefined> {
  if (hasBackgroundTasks(input)) return undefined
  const sessionId = asNonEmptyString(input.session_id)
  if (!sessionId) return systemMessage('CodeTruss hook review did not run: Stop input is missing session_id, so no exact turn baseline can be selected.')
  const base = await gitStateRoot(root)
  const sessionDir = sessionStateDir(base, surface, sessionId)
  const current = await readJson<CurrentTurn>(join(sessionDir, 'current.json'))
  if (!current) return systemMessage('CodeTruss hook review did not run: no exact baseline was captured for this agent turn.')
  const turnId = inputTurnId(input)
  if (turnId && current.turnId && turnId !== current.turnId) {
    return systemMessage('CodeTruss hook review did not run: the Stop event does not match the captured agent turn baseline.')
  }
  const turnDir = join(sessionDir, current.turnKey)
  const statePath = join(turnDir, 'state.json')
  const state = await readJson<HookState>(statePath)
  if (state?.status === 'completed' || (state?.status === 'failed' && state.result)) return undefined
  const now = dependencies.now?.() ?? new Date()
  if (state?.status === 'cleanup_pending') {
    const lockPath = await acquireStopLock(turnDir, now)
    if (!lockPath) return undefined
    try {
      try {
        await cleanupTurnEvidence(root, turnDir)
        const result = state.result ?? { verdict: 'ERROR' as const, message: 'CodeTruss review evidence cleanup completed after an unknown result.' }
        await writePrivateJson(statePath, {
          ...state,
          status: result.verdict === 'ERROR' ? 'failed' : 'completed',
          result,
          updatedAt: (dependencies.now?.() ?? new Date()).toISOString(),
        } satisfies HookState)
        return stopReviewOutput(input, result, `${result.message}\nCodeTruss private snapshot cleanup completed.`)
      } catch (error) {
        return systemMessage(`${state.result?.message ?? 'CodeTruss review finished.'}\nPrivate snapshot cleanup is still pending: ${safeError(error)}`)
      }
    } finally {
      await rm(lockPath, { force: true })
    }
  }
  if (state?.status === 'failed') return systemMessage(state.error ?? 'CodeTruss hook review did not run because baseline capture failed.')
  if (!state || state.status === 'capturing' || state.objectStoreVersion !== 1 || !state.baselineCommit
    || !state.contextSha256 || !state.baselineDirtyFiles || state.task === undefined) {
    const detail = state?.error ? ` ${state.error}` : ''
    return systemMessage(`CodeTruss hook review did not run: exact baseline evidence is missing.${detail}`)
  }
  const lockPath = await acquireStopLock(turnDir, now)
  if (!lockPath) return undefined

  const reviewing: HookState = {
    ...state,
    status: 'reviewing',
    updatedAt: now.toISOString(),
  }
  await writePrivateJson(statePath, reviewing)
  try {
    let summary: NonNullable<HookState['result']>
    try {
      const contextPath = turnContextPath(turnDir)
      const objectStore = await openPrivateGitObjectStore(root, turnObjectStorePath(turnDir))
      const context = await readHookTurnContext(contextPath, state.contextSha256)
      if (context.task !== state.task || hash(context.task) !== state.taskHash) {
        throw new Error('hook task evidence does not match prompt-time context')
      }
      if (JSON.stringify(context.baselineDirtyFiles) !== JSON.stringify(state.baselineDirtyFiles)) {
        throw new Error('hook baseline dirty-file evidence does not match prompt-time context')
      }
      objectStore.assertObjectId(state.baselineCommit, 'baseline snapshot commit')
      const final = await (dependencies.captureBaseline ?? createExactSnapshotCommit)(root, join(turnDir, 'final-snapshots'), objectStore)
      objectStore.assertObjectId(final.commit, 'final snapshot commit')
      const result = await (dependencies.runReview ?? defaultRunReview)({
        root,
        task: state.task,
        baselineRef: state.baselineCommit,
        finalRef: final.commit,
        startCommit: state.baselineHead ?? '',
        finalHead: final.head,
        startedAt: state.createdAt,
        objectDirectory: objectStore.objectDirectory,
        contextPath,
        contextSha256: state.contextSha256,
        baselineDirtyFiles: [...state.baselineDirtyFiles],
        context,
      })
      summary = reviewSummary(root, result)
    } catch (error) {
      summary = { verdict: 'ERROR', message: `CodeTruss hook review could not produce a verified receipt: ${safeError(error)}` }
    }
    const cleanupPending: HookState = {
      ...reviewing,
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
      status: cleanupError ? 'cleanup_pending' : summary.verdict === 'ERROR' ? 'failed' : 'completed',
      result: summary,
      error: cleanupError
        ? `Private snapshot cleanup is pending: ${cleanupError}`
        : summary.verdict === 'ERROR' ? summary.message : undefined,
      updatedAt: (dependencies.now?.() ?? new Date()).toISOString(),
    } satisfies HookState)
    const message = `${summary.message}${cleanupError ? `\nPrivate snapshot cleanup is pending: ${cleanupError}` : ''}`
    return stopReviewOutput(input, summary, message, Boolean(cleanupError))
  } finally {
    await rm(lockPath, { force: true })
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
  if (event === 'Stop') return reviewAtStop(root, surface, input, dependencies)
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
    const output = hookEvent(input) === 'UserPromptSubmit' ? blockDecision(message) : systemMessage(message)
    process.stdout.write(`${JSON.stringify(output)}\n`)
    return 0
  }
}
