import { randomUUID } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { access, chmod, lstat, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { basename, delimiter, dirname, isAbsolute, join, resolve } from 'node:path'
import { loadConfig } from './config.js'
import { runGitText } from './git-process.js'
import { verifyCommandTrustStatus } from './verify-trust.js'

type HookHandler = { type?: string; command?: string; args?: string[]; [key: string]: unknown }
type HookGroup = { matcher?: string; hooks?: HookHandler[]; [key: string]: unknown }
type HookDocument = { hooks?: Record<string, unknown>; [key: string]: unknown }
type HookTarget = 'pre-commit' | 'claude' | 'codex'

export interface HookDoctorCheck {
  level: 'ok' | 'warning' | 'error'
  target: HookTarget | 'config' | 'runtime' | 'agent-runtime'
  message: string
  path?: string
}

export interface HookDoctorResult {
  ok: boolean
  checks: HookDoctorCheck[]
}

export type HookHealthStatus = 'not_installed' | 'healthy' | 'warning' | 'unhealthy'

export interface LocalHookHealth {
  preCommit: HookHealthStatus
  claude: HookHealthStatus
  codex: HookHealthStatus
}

interface PlannedWrite {
  path: string
  contents: Buffer
  defaultMode: number
  forceMode?: number
}

interface FileSnapshot {
  path: string
  exists: boolean
  contents?: Buffer
  mode?: number
}

interface HookInstallPlan {
  writes: PlannedWrite[]
  installedPaths: string[]
}

const MARKER = 'codetruss-agent-guard'
export const CODETRUSS_PRE_COMMIT_ENV = 'CODETRUSS_INTERNAL_PRE_COMMIT'
const SUPPORTS_POSIX_FILE_MODES = process.platform !== 'win32'
const BEGIN_MARKER = `# ${MARKER}:begin`
const END_MARKER = `# ${MARKER}:end`
const AGENT_EVENTS = ['UserPromptSubmit', 'PostToolUse', 'Stop'] as const
// The internal Stop review has a five-minute hard deadline. Keep the installed
// agent envelope wider so it can persist a failure result and clean private Git
// evidence before the host terminates the hook process.
const STOP_HOOK_TIMEOUT_SECONDS = 6 * 60
const AGENT_RUNNER = `'use strict'
const { existsSync } = require('node:fs')
const { execFileSync, spawnSync } = require('node:child_process')
const { join } = require('node:path')

const surface = process.argv[2]
const maxInputBytes = 16 * 1024 * 1024
if (surface !== 'claude' && surface !== 'codex') {
  process.stderr.write('codetruss hook: expected claude or codex\\n')
  process.exit(3)
}

function safeFailure(input, message) {
  let event
  let stopHookActive = false
  const textInput = input.toString('utf8')
  try {
    const parsed = JSON.parse(textInput)
    event = parsed.hook_event_name
    stopHookActive = parsed.stop_hook_active === true
  } catch {
    const prefix = textInput.slice(0, 64 * 1024)
    event = /"hook_event_name"\\s*:\\s*"([^"]+)"/.exec(prefix)?.[1]
    stopHookActive = /"stop_hook_active"\\s*:\\s*true/.test(prefix)
  }
  const text = ('CodeTruss hook failed safely: ' + message).slice(0, 9000)
  if (event === 'UserPromptSubmit' || (event === 'Stop' && !stopHookActive)) {
    return { decision: 'block', reason: text }
  }
  return { systemMessage: text }
}

const chunks = []
let inputBytes = 0
let tooLarge = false
process.stdin.on('data', (value) => {
  const chunk = Buffer.from(value)
  inputBytes += chunk.length
  if (inputBytes > maxInputBytes) tooLarge = true
  else chunks.push(chunk)
})
process.stdin.on('end', () => {
  const input = Buffer.concat(chunks)
  if (tooLarge) {
    process.stdout.write(JSON.stringify(safeFailure(input, 'hook input exceeded 16 MiB')) + '\\n')
    process.exit(0)
  }
  let root
  try {
    root = execFileSync('git', ['-c', 'core.longpaths=true', 'rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim()
  } catch {
    process.stdout.write(JSON.stringify(safeFailure(input, 'could not resolve the Git repository root')) + '\\n')
    process.exit(0)
  }
  const local = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
  const command = existsSync(local) ? local : 'codetruss'
  const result = spawnSync(command, ['hooks', 'dispatch', surface], {
    cwd: root,
    input,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    maxBuffer: 64 * 1024,
  })
  if (result.error || result.status !== 0) {
    const detail = result.error ? result.error.message : (result.stderr || 'dispatch exited with status ' + String(result.status)).trim()
    process.stdout.write(JSON.stringify(safeFailure(input, detail)) + '\\n')
    process.exit(0)
  }
  if (result.stderr) process.stderr.write(result.stderr)
  if (result.stdout) process.stdout.write(result.stdout)
  process.exit(0)
})
`

function plannedWrite(path: string, contents: string | Buffer, defaultMode: number, forceMode?: number): PlannedWrite {
  return {
    path: resolve(path),
    contents: Buffer.isBuffer(contents) ? Buffer.from(contents) : Buffer.from(contents, 'utf8'),
    defaultMode,
    ...(forceMode === undefined ? {} : { forceMode }),
  }
}

async function snapshotFile(path: string): Promise<FileSnapshot> {
  try {
    const metadata = await lstat(path)
    if (!metadata.isFile()) {
      throw new Error(`refusing to replace non-regular hook file ${path}`)
    }
    return {
      path,
      exists: true,
      contents: await readFile(path),
      mode: metadata.mode & 0o777,
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { path, exists: false }
    throw error
  }
}

async function snapshotStillMatches(snapshot: FileSnapshot): Promise<boolean> {
  try {
    const metadata = await lstat(snapshot.path)
    if (!snapshot.exists || !metadata.isFile()) return false
    const contents = await readFile(snapshot.path)
    return contents.equals(snapshot.contents!) && (metadata.mode & 0o777) === snapshot.mode
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return !snapshot.exists
    throw error
  }
}

async function writeTemporaryFile(write: PlannedWrite, mode: number): Promise<string> {
  await mkdir(dirname(write.path), { recursive: true })
  const temporary = join(dirname(write.path), `.${basename(write.path)}.codetruss-${process.pid}-${randomUUID()}.tmp`)
  try {
    await writeFile(temporary, write.contents, { flag: 'wx', mode })
    await chmod(temporary, mode)
    return temporary
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined)
    throw error
  }
}

function mergePlannedWrites(plans: HookInstallPlan[]): { writes: PlannedWrite[]; installedPaths: string[] } {
  const writes = new Map<string, PlannedWrite>()
  const installedPaths = new Set<string>()
  for (const plan of plans) {
    for (const path of plan.installedPaths) installedPaths.add(path)
    for (const write of plan.writes) {
      const existing = writes.get(write.path)
      if (existing && (!existing.contents.equals(write.contents)
        || existing.defaultMode !== write.defaultMode || existing.forceMode !== write.forceMode)) {
        throw new Error(`hook installation planned conflicting writes to ${write.path}`)
      }
      writes.set(write.path, write)
    }
  }
  return { writes: [...writes.values()], installedPaths: [...installedPaths] }
}

/**
 * Stage every replacement in its destination directory before publishing any
 * of them. If publication fails, restore the exact bytes and mode captured at
 * the start of the transaction. A concurrent editor is detected before the
 * first rename so CodeTruss never knowingly overwrites a newer hook config.
 */
async function commitPlannedWrites(writes: PlannedWrite[]): Promise<void> {
  const snapshots = new Map<string, FileSnapshot>()
  const temporaryFiles = new Map<string, string>()
  const committed: PlannedWrite[] = []
  for (const write of writes) snapshots.set(write.path, await snapshotFile(write.path))
  try {
    for (const write of writes) {
      const snapshot = snapshots.get(write.path)!
      const mode = write.forceMode ?? snapshot.mode ?? write.defaultMode
      temporaryFiles.set(write.path, await writeTemporaryFile(write, mode))
    }
    for (const snapshot of snapshots.values()) {
      if (!await snapshotStillMatches(snapshot)) {
        throw new Error(`hook file changed during installation and was left untouched: ${snapshot.path}`)
      }
    }
    for (const write of writes) {
      await rename(temporaryFiles.get(write.path)!, write.path)
      temporaryFiles.delete(write.path)
      committed.push(write)
    }
  } catch (error) {
    const rollbackErrors: string[] = []
    for (const write of committed.reverse()) {
      const snapshot = snapshots.get(write.path)!
      try {
        if (!snapshot.exists) {
          await rm(write.path, { force: true })
        } else {
          const restore = plannedWrite(write.path, snapshot.contents!, snapshot.mode!, snapshot.mode!)
          const temporary = await writeTemporaryFile(restore, snapshot.mode!)
          await rename(temporary, write.path)
        }
      } catch (rollbackError) {
        rollbackErrors.push(`${write.path}: ${rollbackError instanceof Error ? rollbackError.message : String(rollbackError)}`)
      }
    }
    if (rollbackErrors.length) {
      throw new Error(`${error instanceof Error ? error.message : String(error)}; hook rollback also failed: ${rollbackErrors.join('; ')}`)
    }
    throw error
  } finally {
    await Promise.all([...temporaryFiles.values()].map((path) => rm(path, { force: true }).catch(() => undefined)))
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

async function readHookDocument(path: string): Promise<HookDocument> {
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {}
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch (error) {
    throw new Error(`refusing to overwrite invalid JSON in ${path}: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!isRecord(parsed)) throw new Error(`refusing to overwrite ${path}: top-level JSON must be an object`)
  if (parsed.hooks !== undefined && !isRecord(parsed.hooks)) {
    throw new Error(`refusing to overwrite ${path}: hooks must be an object`)
  }
  return parsed as HookDocument
}

function eventGroups(doc: HookDocument, path: string, event: string): HookGroup[] {
  doc.hooks ??= {}
  const value = doc.hooks[event]
  if (value === undefined) {
    const groups: HookGroup[] = []
    doc.hooks[event] = groups
    return groups
  }
  if (!Array.isArray(value) || value.some((group) => !isRecord(group))) {
    throw new Error(`refusing to overwrite ${path}: hooks.${event} must be an array of objects`)
  }
  for (const group of value as HookGroup[]) {
    if (group.hooks !== undefined && (!Array.isArray(group.hooks) || group.hooks.some((handler) => !isRecord(handler)))) {
      throw new Error(`refusing to overwrite ${path}: hooks.${event}[].hooks must be an array of objects`)
    }
  }
  return value as HookGroup[]
}

function isCodeTrussHandler(handler: HookHandler): boolean {
  return [handler.command, ...(handler.args ?? [])].some((value) => typeof value === 'string' && value.includes('.codetruss/hooks/agent.cjs'))
}

function removeCodeTrussHandlers(groups: HookGroup[]): void {
  for (let index = groups.length - 1; index >= 0; index--) {
    const group = groups[index]
    if (!Array.isArray(group.hooks)) continue
    group.hooks = group.hooks.filter((handler) => !isCodeTrussHandler(handler))
    if (group.hooks.length === 0) groups.splice(index, 1)
  }
}

function agentCommand(surface: 'claude' | 'codex'): HookHandler {
  if (surface === 'claude') {
    return {
      command: 'node',
      args: ['${CLAUDE_PROJECT_DIR}/.codetruss/hooks/agent.cjs', 'claude'],
    }
  }
  return {
    command: 'node "$(git -c core.longpaths=true rev-parse --show-toplevel)/.codetruss/hooks/agent.cjs" codex',
    commandWindows: "$root = git -c core.longpaths=true rev-parse --show-toplevel; if ($LASTEXITCODE -eq 0) { node (Join-Path $root '.codetruss/hooks/agent.cjs') codex }",
  }
}

function agentHandler(surface: 'claude' | 'codex', event: typeof AGENT_EVENTS[number]): HookHandler {
  const timeout = event === 'PostToolUse' ? 10 : event === 'UserPromptSubmit' ? 60 : STOP_HOOK_TIMEOUT_SECONDS
  const statusMessage = event === 'PostToolUse'
    ? 'Checking scope with CodeTruss'
    : event === 'UserPromptSubmit'
      ? 'Capturing CodeTruss turn baseline'
      : 'Writing CodeTruss review receipt'
  return { type: 'command', ...agentCommand(surface), timeout, statusMessage }
}

async function planAgentHook(root: string, surface: 'claude' | 'codex'): Promise<HookInstallPlan> {
  const dir = join(root, surface === 'claude' ? '.claude' : '.codex')
  const path = join(dir, surface === 'claude' ? 'settings.json' : 'hooks.json')
  const doc = await readHookDocument(path)
  for (const event of AGENT_EVENTS) {
    const groups = eventGroups(doc, path, event)
    removeCodeTrussHandlers(groups)
    groups.push({
      ...(event === 'PostToolUse' ? { matcher: 'Edit|Write' } : {}),
      hooks: [agentHandler(surface, event)],
    })
  }
  const runnerPath = join(root, '.codetruss', 'hooks', 'agent.cjs')
  return {
    writes: [
      plannedWrite(runnerPath, AGENT_RUNNER, 0o644),
      plannedWrite(path, `${JSON.stringify(doc, null, 2)}\n`, 0o600),
    ],
    installedPaths: [path],
  }
}

function effectivePreCommitPath(root: string): string {
  const raw = runGitText(root, ['rev-parse', '--git-path', 'hooks/pre-commit']).trim()
  if (!raw) throw new Error('Git did not return an effective pre-commit hook path')
  return isAbsolute(raw) ? resolve(raw) : resolve(root, raw)
}

function stripCodeTrussPreCommit(existing: string): string {
  const begin = existing.indexOf(BEGIN_MARKER)
  if (begin >= 0) {
    const lineStart = existing.lastIndexOf('\n', begin - 1) + 1
    const end = existing.indexOf(END_MARKER, begin)
    if (end < 0) throw new Error('existing CodeTruss pre-commit block is missing its end marker')
    const lineEnd = existing.indexOf('\n', end)
    return `${existing.slice(0, lineStart)}${lineEnd < 0 ? '' : existing.slice(lineEnd + 1)}`.replace(/\n{3,}$/g, '\n')
  }
  const legacy = existing.indexOf(`# ${MARKER}`)
  if (legacy >= 0) {
    const lineStart = existing.lastIndexOf('\n', legacy - 1) + 1
    return existing.slice(0, lineStart).replace(/\n{3,}$/g, '\n')
  }
  return existing
}

function preCommitBlock(): string {
  return `${BEGIN_MARKER}
ROOT="$(git -c core.longpaths=true rev-parse --show-toplevel 2>/dev/null)" || exit 0
CODETRUSS_STATUS=0
if [ -x "$ROOT/node_modules/.bin/codetruss" ]; then
  ${CODETRUSS_PRE_COMMIT_ENV}=1 "$ROOT/node_modules/.bin/codetruss" review --staged --task "pre-commit" || CODETRUSS_STATUS=$?
else
  ${CODETRUSS_PRE_COMMIT_ENV}=1 codetruss review --staged --task "pre-commit" || CODETRUSS_STATUS=$?
fi
case "$CODETRUSS_STATUS" in
  0) ;;
  1)
    printf '%s\n' 'CodeTruss REVIEW_REQUIRED: receipt created; commit allowed for human review.' >&2
    ;;
  2)
    printf '%s\n' 'CodeTruss FAILED: commit blocked. Review the receipt before retrying.' >&2
    exit 2
    ;;
  *)
    printf '%s\n' "CodeTruss could not produce a trustworthy receipt (exit $CODETRUSS_STATUS); commit blocked." >&2
    exit "$CODETRUSS_STATUS"
    ;;
esac
${END_MARKER}`
}

async function planPreCommit(root: string): Promise<HookInstallPlan> {
  const path = effectivePreCommitPath(root)
  let existing = ''
  try {
    existing = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  existing = stripCodeTrussPreCommit(existing)
  if (existing) {
    const shebang = existing.split(/\r?\n/, 1)[0]
    if (!/^#!.*\b(?:ba|da|k|z)?sh(?:\s|$)/.test(shebang)) {
      throw new Error(`existing ${path} is not a POSIX shell hook and was left unchanged; invoke "codetruss review --staged --task pre-commit" from that hook or your hook manager`)
    }
  } else {
    existing = '#!/bin/sh\n'
  }
  // Normalize only the separator we own. This preserves user hook bytes while
  // making repeated installation byte-for-byte idempotent.
  existing = `${existing.replace(/(?:\r?\n)+$/g, '')}\n`
  existing += `\n${preCommitBlock()}\n`
  return {
    writes: [plannedWrite(path, existing, 0o755, 0o755)],
    installedPaths: [path],
  }
}

function parseTargets(target: string): HookTarget[] {
  const valid = new Set(['pre-commit', 'claude', 'codex', 'all'])
  if (!valid.has(target)) throw new Error(`unknown hook target ${target}; expected pre-commit, claude, codex, or all`)
  return target === 'all' ? ['pre-commit', 'claude', 'codex'] : [target as HookTarget]
}

async function assertHookPolicyReady(root: string, targets: HookTarget[]): Promise<void> {
  const config = await loadConfig(root)
  if (targets.some((target) => target === 'claude' || target === 'codex') && config.allow.length === 0) {
    throw new Error('agent hooks require at least one allow glob in .codetruss.yml; run codetruss init, define the intended task surface, then install again')
  }
  if (config.verify.length) {
    const trust = await verifyCommandTrustStatus(root, config.verify)
    if (!trust.trusted) {
      throw new Error(`hooks require trusted repository verification commands (${trust.hash.slice(0, 12)}); inspect them and run codetruss verify-policy trust`)
    }
  }
}

export async function installHooks(root: string, target: string): Promise<void> {
  const targets = parseTargets(target)
  await assertHookPolicyReady(root, targets)
  if (!await executablePath(root)) {
    throw new Error('automatic hooks require a persistent CodeTruss CLI installed in this repository or on PATH')
  }
  // Build and validate every mutation before publishing any one of them. This
  // keeps `all` from leaving a half-installed hook set when a later user-owned
  // JSON file is malformed or unwritable.
  const plans = await Promise.all(targets.map((name) => (
    name === 'pre-commit' ? planPreCommit(root) : planAgentHook(root, name)
  )))
  const plan = mergePlannedWrites(plans)
  await commitPlannedWrites(plan.writes)
  for (const path of plan.installedPaths) process.stdout.write(`installed ${path}\n`)
}

async function uninstallAgentHook(root: string, surface: 'claude' | 'codex'): Promise<void> {
  const dir = join(root, surface === 'claude' ? '.claude' : '.codex')
  const path = join(dir, surface === 'claude' ? 'settings.json' : 'hooks.json')
  const doc = await readHookDocument(path)
  let changed = false
  for (const event of AGENT_EVENTS) {
    const groups = eventGroups(doc, path, event)
    const before = JSON.stringify(groups)
    removeCodeTrussHandlers(groups)
    if (before !== JSON.stringify(groups)) changed = true
    if (groups.length === 0) delete doc.hooks?.[event]
  }
  if (changed) await writeFile(path, `${JSON.stringify(doc, null, 2)}\n`, 'utf8')
  process.stdout.write(`${changed ? 'uninstalled' : 'not installed'} ${path}\n`)
}

async function uninstallPreCommit(root: string): Promise<void> {
  const path = effectivePreCommitPath(root)
  let existing: string
  try {
    existing = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      process.stdout.write(`not installed ${path}\n`)
      return
    }
    throw error
  }
  const stripped = stripCodeTrussPreCommit(existing)
  if (stripped === existing) {
    process.stdout.write(`not installed ${path}\n`)
    return
  }
  if (/^#![^\n]+\n\s*$/.test(stripped)) await rm(path, { force: true })
  else await writeFile(path, stripped, 'utf8')
  process.stdout.write(`uninstalled ${path}\n`)
}

export async function uninstallHooks(root: string, target: string): Promise<void> {
  for (const name of parseTargets(target)) {
    if (name === 'pre-commit') await uninstallPreCommit(root)
    else await uninstallAgentHook(root, name)
  }
}

async function agentInstalled(root: string, surface: 'claude' | 'codex'): Promise<boolean> {
  const path = join(root, surface === 'claude' ? '.claude/settings.json' : '.codex/hooks.json')
  const doc = await readHookDocument(path)
  return AGENT_EVENTS.every((event) => eventGroups(doc, path, event).some((group) => group.hooks?.some(isCodeTrussHandler)))
}

async function executablePath(root: string): Promise<string | undefined> {
  const local = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
  if (await access(local, fsConstants.X_OK).then(() => true, () => false)) return local
  const extensions = process.platform === 'win32'
    ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';')
    : ['']
  for (const directory of (process.env.PATH ?? '').split(delimiter).filter(Boolean)) {
    for (const extension of extensions) {
      const candidate = join(directory, `codetruss${extension.toLowerCase()}`)
      if (await access(candidate, fsConstants.X_OK).then(() => true, () => false)) return candidate
    }
  }
  return undefined
}

function exactAgentHandler(handler: HookHandler, expected: HookHandler): boolean {
  return handler.type === expected.type
    && handler.command === expected.command
    && JSON.stringify(handler.args) === JSON.stringify(expected.args)
    && handler.commandWindows === expected.commandWindows
    && handler.timeout === expected.timeout
    && handler.statusMessage === expected.statusMessage
}

async function inspectAgentHook(
  root: string,
  surface: 'claude' | 'codex',
  add: (check: HookDoctorCheck) => void,
): Promise<void> {
  const path = join(root, surface === 'claude' ? '.claude/settings.json' : '.codex/hooks.json')
  let doc: HookDocument
  try {
    doc = await readHookDocument(path)
  } catch (error) {
    add({ level: 'error', target: surface, message: error instanceof Error ? error.message : String(error), path })
    return
  }
  for (const event of AGENT_EVENTS) {
    let groups: HookGroup[]
    try {
      groups = eventGroups(doc, path, event)
    } catch (error) {
      add({ level: 'error', target: surface, message: error instanceof Error ? error.message : String(error), path })
      return
    }
    const installed = groups.flatMap((group) => (group.hooks ?? []).map((handler) => ({ group, handler })))
      .filter(({ handler }) => isCodeTrussHandler(handler))
    if (installed.length !== 1) {
      add({
        level: 'error',
        target: surface,
        message: `${event} must contain exactly one CodeTruss handler (found ${installed.length})`,
        path,
      })
      continue
    }
    const expected = agentHandler(surface, event)
    const expectedMatcher = event === 'PostToolUse' ? 'Edit|Write' : undefined
    if (!exactAgentHandler(installed[0].handler, expected) || installed[0].group.matcher !== expectedMatcher) {
      add({ level: 'error', target: surface, message: `${event} handler differs from the current safe installation`, path })
      continue
    }
    add({ level: 'ok', target: surface, message: `${event} handler is current`, path })
  }
  try {
    const metadata = await lstat(path)
    if (SUPPORTS_POSIX_FILE_MODES && (metadata.mode & 0o022) !== 0) {
      add({ level: 'error', target: surface, message: 'hook configuration is writable by group or other users', path })
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      add({ level: 'error', target: surface, message: error instanceof Error ? error.message : String(error), path })
    }
  }
}

async function inspectRunner(root: string, add: (check: HookDoctorCheck) => void): Promise<void> {
  const path = join(root, '.codetruss', 'hooks', 'agent.cjs')
  try {
    const [contents, metadata] = await Promise.all([readFile(path, 'utf8'), lstat(path)])
    if (!metadata.isFile()) {
      add({ level: 'error', target: 'agent-runtime', message: 'agent hook runner is not a regular file', path })
    } else if (contents !== AGENT_RUNNER) {
      add({ level: 'error', target: 'agent-runtime', message: 'agent hook runner differs from this CLI version; reinstall hooks', path })
    } else if (SUPPORTS_POSIX_FILE_MODES && (metadata.mode & 0o022) !== 0) {
      add({ level: 'error', target: 'agent-runtime', message: 'agent hook runner is writable by group or other users', path })
    } else {
      add({
        level: 'ok',
        target: 'agent-runtime',
        message: SUPPORTS_POSIX_FILE_MODES
          ? 'agent hook runner is current and owner-controlled'
          : 'agent hook runner is current; POSIX permission checks do not apply on Windows',
        path,
      })
    }
  } catch (error) {
    add({
      level: 'error',
      target: 'agent-runtime',
      message: (error as NodeJS.ErrnoException).code === 'ENOENT'
        ? 'agent hook runner is missing; reinstall hooks'
        : error instanceof Error ? error.message : String(error),
      path,
    })
  }
}

async function inspectPreCommit(root: string, add: (check: HookDoctorCheck) => void): Promise<void> {
  const path = effectivePreCommitPath(root)
  try {
    const [contents, metadata] = await Promise.all([readFile(path, 'utf8'), lstat(path)])
    const beginCount = contents.split(BEGIN_MARKER).length - 1
    const endCount = contents.split(END_MARKER).length - 1
    const begin = contents.indexOf(BEGIN_MARKER)
    const end = contents.indexOf(END_MARKER, begin) + END_MARKER.length
    if (beginCount !== 1 || endCount !== 1 || begin < 0 || contents.slice(begin, end) !== preCommitBlock()) {
      add({ level: 'error', target: 'pre-commit', message: 'installed block is missing, duplicated, or stale; reinstall hooks', path })
    } else {
      add({ level: 'ok', target: 'pre-commit', message: 'staged-review block is current', path })
    }
    if (!SUPPORTS_POSIX_FILE_MODES) {
      add({ level: 'ok', target: 'pre-commit', message: 'hook file is present; POSIX permission checks do not apply on Windows', path })
    } else if ((metadata.mode & 0o100) === 0) {
      add({ level: 'error', target: 'pre-commit', message: 'hook is not executable by its owner', path })
    } else if ((metadata.mode & 0o022) !== 0) {
      add({ level: 'error', target: 'pre-commit', message: 'hook is writable by group or other users', path })
    } else {
      add({ level: 'ok', target: 'pre-commit', message: 'hook permissions are owner-controlled and executable', path })
    }
  } catch (error) {
    add({
      level: 'error',
      target: 'pre-commit',
      message: (error as NodeJS.ErrnoException).code === 'ENOENT'
        ? 'hook is not installed'
        : error instanceof Error ? error.message : String(error),
      path,
    })
  }
}

export async function inspectHookDoctor(root: string, target: string): Promise<HookDoctorResult> {
  const targets = parseTargets(target)
  const checks: HookDoctorCheck[] = []
  const add = (check: HookDoctorCheck) => checks.push(check)
  const agentTargets = targets.filter((name): name is 'claude' | 'codex' => name !== 'pre-commit')
  try {
    const config = await loadConfig(root)
    if (config.verify.length) {
      const trust = await verifyCommandTrustStatus(root, config.verify)
      add({
        level: trust.trusted ? 'ok' : 'error',
        target: 'config',
        message: trust.trusted
          ? `repository verification commands are trusted (${trust.hash.slice(0, 12)})`
          : `repository verification commands are untrusted (${trust.hash.slice(0, 12)}); inspect them and run codetruss verify-policy trust`,
        path: join(root, '.codetruss.yml'),
      })
    }
  } catch (error) {
    add({ level: 'error', target: 'config', message: error instanceof Error ? error.message : String(error), path: join(root, '.codetruss.yml') })
  }
  if (agentTargets.length) {
    try {
      const config = await loadConfig(root)
      if (config.allow.length) {
        add({ level: 'ok', target: 'config', message: `${config.allow.length} allowed task-scope glob${config.allow.length === 1 ? '' : 's'} configured`, path: join(root, '.codetruss.yml') })
      } else {
        add({ level: 'error', target: 'config', message: 'agent hooks require at least one allow glob in .codetruss.yml', path: join(root, '.codetruss.yml') })
      }
    } catch (error) {
      add({ level: 'error', target: 'config', message: error instanceof Error ? error.message : String(error), path: join(root, '.codetruss.yml') })
    }
    await inspectRunner(root, add)
  }
  const cliPath = await executablePath(root)
  if (cliPath) add({ level: 'ok', target: 'runtime', message: 'CodeTruss CLI is resolvable by installed hooks', path: cliPath })
  else add({ level: 'error', target: 'runtime', message: 'CodeTruss CLI is not available locally or on PATH' })
  for (const name of targets) {
    if (name === 'pre-commit') await inspectPreCommit(root, add)
    else {
      await inspectAgentHook(root, name, add)
      if (name === 'codex') {
        add({
          level: 'warning',
          target: 'codex',
          message: 'hook trust cannot be verified here; open /hooks in Codex and trust this exact project hook. New or changed hook definitions require review again',
          path: join(root, '.codex', 'hooks.json'),
        })
      }
    }
  }
  const errors = checks.filter((check) => check.level === 'error').length
  return { ok: errors === 0, checks }
}

async function hookInstallations(root: string): Promise<Record<HookTarget, boolean>> {
  const agentPresent = async (surface: 'claude' | 'codex'): Promise<boolean> => {
    const path = join(root, surface === 'claude' ? '.claude/settings.json' : '.codex/hooks.json')
    return readFile(path, 'utf8').then((text) => text.includes('.codetruss/hooks/agent.cjs'), () => false)
  }
  return {
    'pre-commit': await readFile(effectivePreCommitPath(root), 'utf8')
      .then((text) => text.includes(BEGIN_MARKER), () => false),
    claude: await agentPresent('claude'),
    codex: await agentPresent('codex'),
  }
}

/** Privacy-safe health summary: no hook path, command, or diagnostic text leaves this function. */
export async function inspectLocalHookHealth(root: string): Promise<LocalHookHealth> {
  const [installed, doctor] = await Promise.all([
    hookInstallations(root),
    inspectHookDoctor(root, 'all'),
  ])
  const status = (target: HookTarget): HookHealthStatus => {
    if (!installed[target]) return 'not_installed'
    const relevant = doctor.checks.filter((check) => (
      check.target === target
      || check.target === 'runtime'
      || (target !== 'pre-commit' && check.target === 'agent-runtime')
      || (target !== 'pre-commit' && check.target === 'config')
    ))
    if (relevant.some((check) => check.level === 'error')) return 'unhealthy'
    if (relevant.some((check) => check.level === 'warning')) return 'warning'
    return 'healthy'
  }
  return {
    preCommit: status('pre-commit'),
    claude: status('claude'),
    codex: status('codex'),
  }
}

export async function doctorHooks(root: string, target: string): Promise<HookDoctorResult> {
  const result = await inspectHookDoctor(root, target)
  for (const check of result.checks) {
    process.stdout.write(`${check.level.toUpperCase()}\t${check.target}\t${check.message}${check.path ? `\t${check.path}` : ''}\n`)
  }
  const errors = result.checks.filter((check) => check.level === 'error').length
  const warnings = result.checks.filter((check) => check.level === 'warning').length
  process.stdout.write(`doctor\t${result.ok ? 'healthy' : 'unhealthy'}\t${errors} error(s), ${warnings} warning(s)\n`)
  return result
}

export async function hookStatus(root: string, target: string): Promise<void> {
  for (const name of parseTargets(target)) {
    let installed: boolean
    let path: string
    if (name === 'pre-commit') {
      path = effectivePreCommitPath(root)
      installed = await readFile(path, 'utf8').then((text) => text.includes(BEGIN_MARKER), () => false)
    } else {
      path = join(root, name === 'claude' ? '.claude/settings.json' : '.codex/hooks.json')
      installed = await agentInstalled(root, name)
    }
    process.stdout.write(`${installed ? 'installed' : 'not installed'}\t${name}\t${path}\n`)
  }
}
