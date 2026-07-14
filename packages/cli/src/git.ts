import { spawn, spawnSync } from 'node:child_process'
import { readFile, stat } from 'node:fs/promises'
import { devNull } from 'node:os'
import { join, resolve } from 'node:path'
import type { ChangedFile, ScopeClassification, VerificationResult } from './types.js'
import { runGit, runGitText, streamGit, type GitStreamOptions } from './git-process.js'

const DEFAULT_DIFF_CAPTURE_BYTES = 20 * 1024 * 1024
export const VERIFICATION_TIMEOUT_MS = 2 * 60 * 1_000
export const INTERNAL_HOOK_WORK_BUDGET_MS = 3 * 60 * 1_000 + 30 * 1_000
const VERIFICATION_OUTPUT_MARKER = Buffer.from('\n… output truncated …\n')
const VERIFICATION_TERMINATION_GRACE_MS = 150

/**
 * Git's no-index implementation recognizes only the literal `nul` spelling
 * on native Windows. Node's `os.devNull` is `\\.\nul`, which Windows can open
 * but Git does not classify as its missing-file sentinel and can consequently
 * emit a header without the untracked file body.
 */
export const GIT_NULL_DEVICE = process.platform === 'win32' ? 'NUL' : devNull

/** Fair-share a bounded internal-hook budget across commands still to run. */
export function allocatedVerificationTimeout(
  deadlineMs: number,
  nowMs: number,
  commandsRemaining: number,
  maximumMs = VERIFICATION_TIMEOUT_MS,
): number {
  if (!Number.isSafeInteger(commandsRemaining) || commandsRemaining < 1) {
    throw new Error('commandsRemaining must be a positive integer')
  }
  if (!Number.isFinite(deadlineMs) || !Number.isFinite(nowMs)) {
    throw new Error('verification deadline values must be finite')
  }
  return Math.min(maximumMs, Math.max(0, Math.floor((deadlineMs - nowMs) / commandsRemaining)))
}

export function findRepoRoot(cwd = process.cwd()): string {
  return resolve(runGitText(cwd, ['rev-parse', '--show-toplevel']).trim())
}

/** Current commit, or an empty string for an unborn branch. */
export function head(root: string): string {
  const result = runGit(root, ['rev-parse', '--verify', 'HEAD^{commit}'], { allowedExitCodes: [0, 128] })
  return result.status === 0 ? result.stdout.toString('utf8').trim() : ''
}

/** Repository-format-aware empty tree (works for SHA-1 and SHA-256 repos). */
export function emptyTree(root: string, environment?: NodeJS.ProcessEnv): string {
  return runGitText(root, ['hash-object', '-t', 'tree', '--stdin'], {
    ...(environment ? { env: environment } : {}),
    input: Buffer.alloc(0),
  }).trim()
}

/** Resolve the caller's base without letting an unborn HEAD float to a later commit. */
export function resolveDiffBase(root: string, base: string, environment?: NodeJS.ProcessEnv): string {
  if (!base) return emptyTree(root, environment)
  if (base === 'HEAD') return head(root) || emptyTree(root, environment)
  return base
}

export interface GitStatusEntry {
  indexStatus: string
  worktreeStatus: string
  path: string
  oldPath?: string
  untracked: boolean
}

function splitNul(output: Buffer): string[] {
  const tokens: string[] = []
  let start = 0
  for (let i = 0; i < output.length; i++) {
    if (output[i] !== 0) continue
    tokens.push(output.subarray(start, i).toString('utf8'))
    start = i + 1
  }
  if (start < output.length) tokens.push(output.subarray(start).toString('utf8'))
  return tokens
}

export function parseStatusZ(output: Buffer): GitStatusEntry[] {
  const tokens = splitNul(output)
  const entries: GitStatusEntry[] = []
  for (let i = 0; i < tokens.length; i++) {
    const record = tokens[i]
    if (!record) continue
    if (record.length < 3 || record[2] !== ' ') throw new Error(`unexpected git status record ${JSON.stringify(record)}`)
    const indexStatus = record[0]
    const worktreeStatus = record[1]
    const entry: GitStatusEntry = {
      indexStatus,
      worktreeStatus,
      path: record.slice(3),
      untracked: indexStatus === '?' && worktreeStatus === '?',
    }
    if (indexStatus === 'R' || indexStatus === 'C' || worktreeStatus === 'R' || worktreeStatus === 'C') {
      if (i + 1 >= tokens.length) throw new Error(`git status rename record is missing its origin: ${JSON.stringify(record)}`)
      entry.oldPath = tokens[++i]
    }
    entries.push(entry)
  }
  return entries
}

export function statusEntries(root: string): GitStatusEntry[] {
  return parseStatusZ(runGit(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']).stdout)
}

export function dirtyFiles(root: string): string[] {
  return statusEntries(root)
    .map((entry) => entry.path)
    .filter((path) => !path.startsWith('.codetruss/'))
    .sort()
}

interface RawChange { status: string; path: string; oldPath?: string }

export function parseNameStatusZ(output: Buffer): RawChange[] {
  const tokens = splitNul(output)
  const changes: RawChange[] = []
  for (let i = 0; i < tokens.length; i++) {
    const status = tokens[i]
    if (!status) continue
    if (!/^[A-Z]/.test(status)) throw new Error(`unexpected git name-status record ${JSON.stringify(status)}`)
    if (/^[RC]/.test(status)) {
      if (i + 2 >= tokens.length) throw new Error(`git rename/copy record ${status} is missing paths`)
      changes.push({ status, oldPath: tokens[++i], path: tokens[++i] })
    } else {
      if (i + 1 >= tokens.length) throw new Error(`git name-status record ${status} is missing a path`)
      changes.push({ status, path: tokens[++i] })
    }
  }
  return changes
}

export interface GitNumstat {
  additions: number
  deletions: number
  binary: boolean
}

export function parseNumstatZ(output: Buffer): Map<string, GitNumstat> {
  const tokens = splitNul(output)
  const result = new Map<string, GitNumstat>()
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]
    if (!token) continue
    const firstTab = token.indexOf('\t')
    const secondTab = token.indexOf('\t', firstTab + 1)
    if (firstTab < 0 || secondTab < 0) throw new Error(`unexpected git numstat record ${JSON.stringify(token)}`)
    const additionsText = token.slice(0, firstTab)
    const deletionsText = token.slice(firstTab + 1, secondTab)
    let path = token.slice(secondTab + 1)
    if (!path) {
      if (i + 2 >= tokens.length) throw new Error(`git numstat rename record is missing paths`)
      i++ // origin
      path = tokens[++i] // destination
    }
    const binary = additionsText === '-' && deletionsText === '-'
    const additions = binary ? 0 : Number(additionsText)
    const deletions = binary ? 0 : Number(deletionsText)
    if ((!binary && (!Number.isSafeInteger(additions) || !Number.isSafeInteger(deletions))) || !path) {
      throw new Error(`unexpected git numstat record ${JSON.stringify(token)}`)
    }
    result.set(path, { additions, deletions, binary })
  }
  return result
}

function diffArgs(operation: string[], base: string, staged: boolean, target?: string): string[] {
  return ['diff', ...operation, '--find-renames', ...(target ? [base, target] : [...(staged ? ['--cached'] : []), base]), '--']
}

export function diffNumstat(
  root: string,
  base: string,
  staged: boolean,
  targetTreeish?: string,
  environment?: NodeJS.ProcessEnv,
): Map<string, GitNumstat> {
  const resolvedBase = resolveDiffBase(root, base, environment)
  const resolvedTarget = targetTreeish ? resolveDiffBase(root, targetTreeish, environment) : undefined
  return parseNumstatZ(runGit(root, diffArgs(['--numstat', '-z'], resolvedBase, staged, resolvedTarget), {
    ...(environment ? { env: environment } : {}),
  }).stdout)
}

function untrackedPaths(root: string, environment?: NodeJS.ProcessEnv): Set<string> {
  return new Set(splitNul(runGit(root, ['ls-files', '--others', '--exclude-standard', '-z'], {
    ...(environment ? { env: environment } : {}),
  }).stdout).filter(Boolean))
}

export interface GitEvidenceOptions {
  /** Explicit private object environment for internal Git plumbing only. */
  env?: NodeJS.ProcessEnv
}

export async function changedFiles(
  root: string,
  base: string,
  staged: boolean,
  classify: (path: string, oldPath?: string) => ScopeClassification,
  sensitive: (path: string) => string | undefined,
  dependency: (path: string) => boolean,
  targetTreeish?: string,
  options: GitEvidenceOptions = {},
): Promise<ChangedFile[]> {
  const resolvedBase = resolveDiffBase(root, base, options.env)
  const resolvedTarget = targetTreeish ? resolveDiffBase(root, targetTreeish, options.env) : undefined
  const raw = parseNameStatusZ(runGit(root, diffArgs(['--name-status', '-z'], resolvedBase, staged, resolvedTarget), options).stdout)
  const untracked = staged || resolvedTarget ? new Set<string>() : untrackedPaths(root, options.env)
  if (!staged && !resolvedTarget) {
    const tracked = new Set(raw.flatMap((item) => [item.path, item.oldPath].filter(Boolean) as string[]))
    for (const path of untracked) {
      if (!tracked.has(path)) raw.push({ status: 'A', path })
    }
  }
  const numstat = parseNumstatZ(runGit(root, diffArgs(['--numstat', '-z'], resolvedBase, staged, resolvedTarget), options).stdout)
  const files: ChangedFile[] = []
  for (const item of raw) {
    if (item.path.startsWith('.codetruss/')) continue
    const lineStats = numstat.get(item.path) ?? (untracked.has(item.path) ? await untrackedStats(root, item.path) : { additions: 0, deletions: 0 })
    files.push({
      path: item.path,
      oldPath: item.oldPath,
      change: item.status.startsWith('A') || item.status.startsWith('C') ? 'added' : item.status.startsWith('D') ? 'deleted' : item.status.startsWith('R') ? 'renamed' : 'modified',
      classification: classify(item.path, item.oldPath),
      sensitive: sensitive(item.path) ?? (item.oldPath ? sensitive(item.oldPath) : undefined),
      dependency: dependency(item.path) || Boolean(item.oldPath && dependency(item.oldPath)),
      additions: lineStats.additions,
      deletions: lineStats.deletions,
    })
  }
  return files.sort((a, b) => a.path.localeCompare(b.path))
}

async function untrackedStats(root: string, path: string): Promise<{ additions: number; deletions: number }> {
  try {
    const info = await stat(join(root, path))
    if (!info.isFile() || info.size > 1_000_000) return { additions: 0, deletions: 0 }
    const bytes = await readFile(join(root, path))
    if (bytes.includes(0)) return { additions: 0, deletions: 0 }
    let additions = 0
    for (const byte of bytes) if (byte === 10) additions++
    if (bytes.length > 0 && bytes.at(-1) !== 10) additions++
    return { additions, deletions: 0 }
  } catch {
    return { additions: 0, deletions: 0 }
  }
}

class BoundedDiffCollector {
  private readonly chunks: Buffer[] = []
  private captured = 0
  private total = 0
  private lastByte: number | undefined

  constructor(private readonly maxBytes: number) {}

  add(chunk: Buffer | string): void {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    if (!bytes.length) return
    this.total += bytes.length
    this.lastByte = bytes.at(-1)
    const remaining = this.maxBytes - this.captured
    if (remaining <= 0) return
    const kept = bytes.subarray(0, remaining)
    this.chunks.push(kept)
    this.captured += kept.length
  }

  needsSeparator(): boolean { return this.total > 0 && this.lastByte !== 10 }

  result(): DiffCapture {
    const patch = Buffer.concat(this.chunks, this.captured)
    return { patch, capturedBytes: patch.length, totalBytes: this.total, truncated: this.total > patch.length }
  }
}

export interface DiffCapture {
  patch: Buffer
  capturedBytes: number
  totalBytes: number
  truncated: boolean
}

export interface DiffCaptureOptions extends GitStreamOptions {
  maxCapturedBytes?: number
  /** Optional immutable final tree; when present, no live index/worktree bytes are read. */
  targetTreeish?: string
}

function quotedPatchPath(prefix: 'a' | 'b', path: string): string {
  const value = `${prefix}/${path}`
  return /[\s"\\]/.test(value) ? JSON.stringify(value) : value
}

/** Capture tracked and untracked evidence without buffering the complete diff. */
export async function captureDiffEvidence(
  root: string,
  base: string,
  staged: boolean,
  files: Pick<ChangedFile, 'path' | 'change'>[],
  options: DiffCaptureOptions = {},
): Promise<DiffCapture> {
  const maxCapturedBytes = options.maxCapturedBytes ?? DEFAULT_DIFF_CAPTURE_BYTES
  if (!Number.isSafeInteger(maxCapturedBytes) || maxCapturedBytes < 0) throw new Error('maxCapturedBytes must be a non-negative safe integer')
  const resolvedBase = resolveDiffBase(root, base, options.env)
  const resolvedTarget = options.targetTreeish ? resolveDiffBase(root, options.targetTreeish, options.env) : undefined
  const streamOptions: GitStreamOptions = {
    ...(options.allowedExitCodes ? { allowedExitCodes: options.allowedExitCodes } : {}),
    ...(options.env ? { env: options.env } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
  }
  const collector = new BoundedDiffCollector(maxCapturedBytes)
  await streamGit(
    root,
    diffArgs(['--no-ext-diff', '--binary'], resolvedBase, staged, resolvedTarget),
    (chunk) => collector.add(chunk),
    streamOptions,
  )
  if (!staged && !resolvedTarget) {
    const untracked = untrackedPaths(root, options.env)
    for (const file of files) {
      if (file.change !== 'added' || !untracked.has(file.path)) continue
      let emitted = false
      await streamGit(
        root,
        ['diff', '--no-index', '--no-ext-diff', '--binary', '--', GIT_NULL_DEVICE, file.path],
        (chunk) => {
          if (!emitted) {
            if (collector.needsSeparator()) collector.add('\n')
            emitted = true
          }
          collector.add(chunk)
        },
        { ...streamOptions, allowedExitCodes: [0, 1] },
      )
      if (!emitted) {
        if (collector.needsSeparator()) collector.add('\n')
        collector.add(`diff --git ${quotedPatchPath('a', file.path)} ${quotedPatchPath('b', file.path)}\nnew file mode 100644\n`)
      }
    }
  }
  return collector.result()
}

/** Compatibility helper. New orchestration should persist DiffCapture metadata. */
export async function captureDiff(root: string, base: string, staged: boolean, files: ChangedFile[]): Promise<string> {
  const evidence = await captureDiffEvidence(root, base, staged, files)
  if (evidence.truncated) {
    throw new Error(`diff exceeded ${evidence.capturedBytes} captured bytes (${evidence.totalBytes} total); use captureDiffEvidence to record truncation explicitly`)
  }
  return evidence.patch.toString('utf8')
}

export async function runAgent(command: string[], cwd: string): Promise<{ exitCode: number; durationMs: number; startError?: string }> {
  const started = Date.now()
  return new Promise((resolveResult) => {
    const child = spawn(command[0], command.slice(1), { cwd, stdio: 'inherit', env: process.env })
    child.once('error', (error) => resolveResult({ exitCode: 127, durationMs: Date.now() - started, startError: error.message }))
    child.once('exit', (code, signal) => resolveResult({ exitCode: code ?? (signal ? 128 : 1), durationMs: Date.now() - started }))
  })
}

class BoundedVerificationOutput {
  private readonly prefix: Buffer[] = []
  private prefixBytes = 0
  private tail = Buffer.alloc(0)
  private totalBytes = 0

  constructor(private readonly maxBytes: number) {}

  add(chunk: Buffer | string): void {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    if (!bytes.length) return
    this.totalBytes += bytes.length

    const prefixRemaining = this.maxBytes - this.prefixBytes
    if (prefixRemaining > 0) {
      const kept = bytes.subarray(0, prefixRemaining)
      this.prefix.push(Buffer.from(kept))
      this.prefixBytes += kept.length
    }

    if (bytes.length >= this.maxBytes) {
      this.tail = Buffer.from(bytes.subarray(bytes.length - this.maxBytes))
      return
    }
    const combined = this.tail.length ? Buffer.concat([this.tail, bytes]) : bytes
    this.tail = Buffer.from(combined.subarray(Math.max(0, combined.length - this.maxBytes)))
  }

  result(suffix = ''): { output: string; truncated: boolean } {
    const suffixBytes = Buffer.from(suffix)
    if (suffixBytes.length >= this.maxBytes) {
      return {
        // Preserve the beginning of an operational failure suffix so even an
        // unusually small capture budget retains the deterministic reason.
        output: suffixBytes.subarray(0, this.maxBytes).toString('utf8'),
        truncated: this.totalBytes > 0 || suffixBytes.length > this.maxBytes,
      }
    }

    const outputBudget = this.maxBytes - suffixBytes.length
    const output = this.render(outputBudget)
    return {
      output: Buffer.concat([output.bytes, suffixBytes]).toString('utf8'),
      truncated: output.truncated,
    }
  }

  private render(limit: number): { bytes: Buffer; truncated: boolean } {
    if (this.totalBytes <= limit) {
      return { bytes: Buffer.concat(this.prefix, this.totalBytes), truncated: false }
    }
    if (limit <= VERIFICATION_OUTPUT_MARKER.length) {
      return {
        bytes: Buffer.concat(this.prefix, this.prefixBytes).subarray(0, limit),
        truncated: true,
      }
    }
    const available = limit - VERIFICATION_OUTPUT_MARKER.length
    const headBytes = Math.ceil(available / 2)
    const tailBytes = available - headBytes
    const head = Buffer.concat(this.prefix, this.prefixBytes).subarray(0, headBytes)
    const tail = this.tail.subarray(Math.max(0, this.tail.length - tailBytes))
    return {
      bytes: Buffer.concat([head, VERIFICATION_OUTPUT_MARKER, tail]),
      truncated: true,
    }
  }
}

function signalVerificationProcessGroup(pid: number, signal: NodeJS.Signals): boolean {
  try {
    process.kill(-pid, signal)
    return true
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ESRCH') return false
    return code === 'EPERM'
  }
}

function verificationDelay(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds))
}

async function terminateVerificationProcessTree(pid: number): Promise<void> {
  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/pid', String(pid), '/t', '/f'], {
      stdio: 'ignore',
      timeout: 2_000,
      windowsHide: true,
    })
    return
  }
  if (!signalVerificationProcessGroup(pid, 'SIGTERM')) return
  await verificationDelay(VERIFICATION_TERMINATION_GRACE_MS)
  signalVerificationProcessGroup(pid, 'SIGKILL')
}

export async function runVerification(
  command: string,
  cwd: string,
  maxBytes = 16_384,
  environment: NodeJS.ProcessEnv = process.env,
  timeoutMs = VERIFICATION_TIMEOUT_MS,
  streamOutput = true,
): Promise<VerificationResult> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new Error('verification maxBytes must be a positive integer')
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new Error('verification timeoutMs must be a positive integer')
  const started = Date.now()
  return new Promise((resolveResult) => {
    const child = spawn(command, {
      cwd,
      shell: true,
      env: environment,
      detached: process.platform !== 'win32',
      windowsHide: true,
    })
    const output = new BoundedVerificationOutput(maxBytes)
    let settled = false
    let cleanupPromise: Promise<void> | undefined

    const cleanup = (): Promise<void> => {
      cleanupPromise ??= child.pid === undefined ? Promise.resolve() : terminateVerificationProcessTree(child.pid)
      return cleanupPromise
    }
    const finish = (exitCode: number, suffix = ''): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      const captured = output.result(suffix)
      resolveResult({
        command,
        exitCode,
        durationMs: Date.now() - started,
        output: captured.output,
        truncated: captured.truncated,
      })
    }
    const cleanupAndFinish = (exitCode: number, suffix = ''): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      void cleanup().finally(() => {
        child.stdout.destroy()
        child.stderr.destroy()
        const captured = output.result(suffix)
        resolveResult({
          command,
          exitCode,
          durationMs: Date.now() - started,
          output: captured.output,
          truncated: captured.truncated,
        })
      })
    }

    child.stdout.on('data', (chunk: Buffer | string) => {
      if (streamOutput) process.stdout.write(chunk)
      output.add(chunk)
    })
    child.stderr.on('data', (chunk: Buffer | string) => {
      if (streamOutput) process.stderr.write(chunk)
      output.add(chunk)
    })

    const timer = setTimeout(() => {
      cleanupAndFinish(124, `${output.result().output ? '\n' : ''}CodeTruss verification timed out after ${timeoutMs}ms.\n`)
    }, timeoutMs)
    timer.unref()

    child.once('error', (error) => cleanupAndFinish(127, `${output.result().output ? '\n' : ''}${error.message}`))
    child.once('exit', () => {
      // A verification may fork a background process that keeps inherited
      // pipes open. Terminate the whole isolated group before awaiting close,
      // but retain the deadline until close: on Windows an already-exited
      // leader may no longer be addressable by taskkill, and an escaped child
      // must not make the CLI wait forever on its inherited pipe handles.
      void cleanup()
    })
    child.once('close', (code) => {
      clearTimeout(timer)
      void cleanup().finally(() => finish(code ?? 1))
    })
  })
}
