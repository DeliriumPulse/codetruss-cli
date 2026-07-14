import { spawn } from 'node:child_process'
import { readFile, stat } from 'node:fs/promises'
import { devNull } from 'node:os'
import { join, resolve } from 'node:path'
import type { ChangedFile, ScopeClassification, VerificationResult } from './types.js'
import { runGit, runGitText, streamGit, type GitStreamOptions } from './git-process.js'

const DEFAULT_DIFF_CAPTURE_BYTES = 20 * 1024 * 1024

/** The current platform's null device, used only as Git's empty no-index side. */
export const GIT_NULL_DEVICE = devNull

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

export async function runVerification(
  command: string,
  cwd: string,
  maxBytes = 16_384,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<VerificationResult> {
  const started = Date.now()
  return new Promise((resolveResult) => {
    const child = spawn(command, { cwd, shell: true, env: environment })
    const chunks: Buffer[] = []
    child.stdout.on('data', (chunk) => { process.stdout.write(chunk); chunks.push(Buffer.from(chunk)) })
    child.stderr.on('data', (chunk) => { process.stderr.write(chunk); chunks.push(Buffer.from(chunk)) })
    child.once('error', (error) => resolveResult({ command, exitCode: 127, durationMs: Date.now() - started, output: error.message, truncated: false }))
    child.once('exit', (code) => {
      const all = Buffer.concat(chunks)
      const truncated = all.length > maxBytes
      const kept = truncated ? Buffer.concat([all.subarray(0, maxBytes / 2), Buffer.from('\n… output truncated …\n'), all.subarray(all.length - maxBytes / 2)]) : all
      resolveResult({ command, exitCode: code ?? 1, durationMs: Date.now() - started, output: kept.toString('utf8'), truncated })
    })
  })
}
