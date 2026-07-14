import { spawn, spawnSync } from 'node:child_process'

export const LOCAL_COMMAND_MAX_OUTPUT_BYTES = 2_000_000

export type LocalCommandFailureReason = 'spawn' | 'timeout' | 'output-limit'

export class LocalCommandError extends Error {
  constructor(
    readonly command: string,
    readonly reason: LocalCommandFailureReason,
    readonly timeoutMs?: number,
  ) {
    const detail = reason === 'timeout' && timeoutMs !== undefined
      ? ` timed out after ${timeoutMs}ms`
      : reason === 'output-limit'
        ? ' exceeded the output limit'
        : ' could not be started'
    super(`${command}${detail}`)
    this.name = 'LocalCommandError'
  }
}

export interface LocalCommandRequest {
  command: string
  args: string[]
  cwd: string
  input?: string
  timeoutMs: number
  maxOutputBytes?: number
}

export interface LocalCommandResult {
  stdout: string
  stderr: string
  exitCode: number | null
  signal: NodeJS.Signals | null
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

function signalProcessGroup(pid: number, signal: NodeJS.Signals): boolean {
  try {
    process.kill(-pid, signal)
    return true
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ESRCH') return false
    return code === 'EPERM'
  }
}

async function terminateProcessTree(pid: number): Promise<void> {
  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/pid', String(pid), '/t', '/f'], {
      stdio: 'ignore',
      timeout: 2_000,
      windowsHide: true,
    })
    return
  }

  if (!signalProcessGroup(pid, 'SIGTERM')) return
  await delay(150)
  signalProcessGroup(pid, 'SIGKILL')
}

/**
 * Run an untrusted local provider without a shell. The caller supplies prompt
 * bytes through stdin; the command line contains provider options only.
 */
export function runLocalCommand(request: LocalCommandRequest): Promise<LocalCommandResult> {
  const maxOutputBytes = request.maxOutputBytes ?? LOCAL_COMMAND_MAX_OUTPUT_BYTES
  if (!Number.isSafeInteger(request.timeoutMs) || request.timeoutMs <= 0) {
    throw new Error('local command timeoutMs must be a positive integer')
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new Error('local command maxOutputBytes must be a positive integer')
  }

  return new Promise((resolve, reject) => {
    const child = spawn(request.command, request.args, {
      cwd: request.cwd,
      detached: process.platform !== 'win32',
      env: process.env,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    let outputBytes = 0
    let failure: LocalCommandError | undefined
    let settled = false
    let cleanupPromise: Promise<void> | undefined

    const cleanup = () => {
      cleanupPromise ??= child.pid === undefined ? Promise.resolve() : terminateProcessTree(child.pid)
      return cleanupPromise
    }
    const fail = (reason: LocalCommandFailureReason) => {
      if (failure) return
      failure = new LocalCommandError(request.command, reason, reason === 'timeout' ? request.timeoutMs : undefined)
      clearTimeout(timer)
      child.stdin.destroy()
      void cleanup().finally(() => {
        child.stdout.destroy()
        child.stderr.destroy()
        child.unref()
        if (settled) return
        settled = true
        reject(failure)
      })
    }
    const collect = (target: Buffer[], chunk: Buffer | string) => {
      if (failure) return
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      outputBytes += buffer.byteLength
      if (outputBytes > maxOutputBytes) {
        fail('output-limit')
        return
      }
      target.push(buffer)
    }

    child.stdout.on('data', (chunk: Buffer | string) => collect(stdout, chunk))
    child.stderr.on('data', (chunk: Buffer | string) => collect(stderr, chunk))
    child.stdin.on('error', () => {
      // EPIPE is expected when a provider exits before consuming all input.
    })

    const timer = setTimeout(() => fail('timeout'), request.timeoutMs)
    timer.unref()

    child.once('error', () => {
      fail('spawn')
    })

    child.once('exit', () => {
      // A provider must not leave background descendants running after review.
      void cleanup()
    })

    child.once('close', (exitCode, signal) => {
      clearTimeout(timer)
      child.stdin.destroy()
      void cleanup().finally(() => {
        if (settled) return
        settled = true
        if (failure) {
          reject(failure)
          return
        }
        resolve({
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
          exitCode,
          signal,
        })
      })
    })

    child.stdin.end(request.input ?? '')
  })
}
