import { spawn, spawnSync } from 'node:child_process'

const DEFAULT_METADATA_BUFFER = 64 * 1024 * 1024
const STDERR_LIMIT = 64 * 1024

export interface GitRunOptions {
  allowedExitCodes?: number[]
  env?: NodeJS.ProcessEnv
  input?: Buffer | string
  maxBuffer?: number
}

export class GitCommandError extends Error {
  readonly args: string[]
  readonly exitCode: number | null
  readonly stderr: string

  constructor(args: string[], exitCode: number | null, stderr: string, cause?: unknown) {
    const command = `git ${args.join(' ')}`
    const detail = stderr.trim() || (cause instanceof Error ? cause.message : String(cause ?? 'unknown error'))
    super(`${command} failed${exitCode === null ? '' : ` with exit code ${exitCode}`}: ${detail}`)
    this.name = 'GitCommandError'
    this.args = args
    this.exitCode = exitCode
    this.stderr = stderr
    if (cause !== undefined) this.cause = cause
  }
}

export interface GitRunResult {
  status: number
  stdout: Buffer
  stderr: Buffer
}

/** Run a bounded Git metadata command, surfacing spawn/maxBuffer failures. */
export function runGit(root: string, args: string[], options: GitRunOptions = {}): GitRunResult {
  const allowedExitCodes = options.allowedExitCodes ?? [0]
  const result = spawnSync('git', ['-C', root, ...args], {
    encoding: null,
    env: options.env ?? process.env,
    input: options.input,
    maxBuffer: options.maxBuffer ?? DEFAULT_METADATA_BUFFER,
  })
  const stdout = result.stdout ?? Buffer.alloc(0)
  const stderr = result.stderr ?? Buffer.alloc(0)
  if (result.error) {
    throw new GitCommandError(args, result.status, stderr.toString('utf8'), result.error)
  }
  if (result.status === null || !allowedExitCodes.includes(result.status)) {
    throw new GitCommandError(args, result.status, stderr.toString('utf8'))
  }
  return { status: result.status, stdout, stderr }
}

export function runGitText(root: string, args: string[], options: GitRunOptions = {}): string {
  return runGit(root, args, options).stdout.toString('utf8')
}

export interface GitStreamOptions {
  allowedExitCodes?: number[]
  env?: NodeJS.ProcessEnv
  signal?: AbortSignal
}

/** Stream arbitrarily large Git output while retaining only bounded stderr. */
export async function streamGit(
  root: string,
  args: string[],
  onStdout: (chunk: Buffer) => void,
  options: GitStreamOptions = {},
): Promise<number> {
  const allowedExitCodes = options.allowedExitCodes ?? [0]
  return new Promise<number>((resolve, reject) => {
    const child = spawn('git', ['-C', root, ...args], {
      env: options.env ?? process.env,
      signal: options.signal,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const stderr: Buffer[] = []
    let stderrBytes = 0
    let settled = false
    child.stdout.on('data', (value: Buffer | string) => onStdout(Buffer.from(value)))
    child.stderr.on('data', (value: Buffer | string) => {
      if (stderrBytes >= STDERR_LIMIT) return
      const chunk = Buffer.from(value)
      const kept = chunk.subarray(0, STDERR_LIMIT - stderrBytes)
      stderr.push(kept)
      stderrBytes += kept.length
    })
    child.once('error', (error) => {
      if (settled) return
      settled = true
      reject(new GitCommandError(args, null, Buffer.concat(stderr).toString('utf8'), error))
    })
    child.once('close', (code) => {
      if (settled) return
      settled = true
      if (code === null || !allowedExitCodes.includes(code)) {
        reject(new GitCommandError(args, code, Buffer.concat(stderr).toString('utf8')))
      } else {
        resolve(code)
      }
    })
  })
}
