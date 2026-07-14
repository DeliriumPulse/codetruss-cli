import { randomUUID } from 'node:crypto'
import { chmod, lstat, open, realpath, rename, rm } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve } from 'node:path'

export const CODETRUSS_HOOK_RESULT_PATH_ENV = 'CODETRUSS_HOOK_RESULT_PATH'
export const CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV = 'CODETRUSS_HOOK_REVIEW_ATTEMPT_ID'

const ATTEMPT_ID = /^[0-9a-f]{64}$/
const MAX_RESULT_BYTES = 256 * 1024
const MAX_RESULT_REASONS = 100
const MAX_RESULT_REASON_CHARS = 2_000

export interface InternalHookResultRequest {
  attemptId: string
  path: string
}

export interface InternalHookResult {
  verdict: 'PASS' | 'REVIEW_REQUIRED' | 'FAILED'
  receiptPath: string
  reasons: string[]
}

function present(value: string | undefined): boolean {
  return value !== undefined
}

export function parseInternalHookResultRequest(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): InternalHookResultRequest | undefined {
  const path = environment[CODETRUSS_HOOK_RESULT_PATH_ENV]
  const attemptId = environment[CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV]
  if (!present(path) && !present(attemptId)) return undefined
  if (environment.CODETRUSS_INTERNAL_HOOK !== '1') {
    throw new Error('CodeTruss hook result output is reserved for an authenticated internal hook review')
  }
  if (!path || !attemptId) {
    throw new Error(`CodeTruss hook result output requires both ${CODETRUSS_HOOK_RESULT_PATH_ENV} and ${CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV}`)
  }
  if (!ATTEMPT_ID.test(attemptId)) {
    throw new Error(`${CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV} must be exactly 64 lowercase hexadecimal characters`)
  }
  if (!isAbsolute(path) || resolve(path) !== path) {
    throw new Error(`${CODETRUSS_HOOK_RESULT_PATH_ENV} must be an absolute normalized path`)
  }
  return { attemptId, path }
}

function isContained(parent: string, child: string): boolean {
  const nested = relative(parent, child)
  return nested === '' || (!nested.startsWith('..') && !isAbsolute(nested))
}

async function assertPrivateResultLocation(request: InternalHookResultRequest, contextPath: string): Promise<void> {
  if (!isAbsolute(contextPath) || resolve(contextPath) !== contextPath) {
    throw new Error('CodeTruss hook context path must be absolute and normalized before writing a hook result')
  }
  const context = await lstat(contextPath)
  if (context.isSymbolicLink() || !context.isFile()) {
    throw new Error('CodeTruss hook context is not a regular private file')
  }

  const turnPath = dirname(contextPath)
  const parentPath = dirname(request.path)
  const lexicalParent = resolve(parentPath)
  const lexicalTurn = resolve(turnPath)
  if (!isContained(lexicalTurn, lexicalParent) || request.path === lexicalTurn) {
    throw new Error('CodeTruss hook result path is outside the authenticated private turn')
  }
  const [turnRealPath, parentRealPath] = await Promise.all([realpath(turnPath), realpath(parentPath)])
  const expectedParentRealPath = resolve(turnRealPath, relative(lexicalTurn, lexicalParent))
  if (parentRealPath !== expectedParentRealPath) {
    throw new Error('CodeTruss hook result path traverses a symbolic-link parent')
  }
  if (!isContained(turnRealPath, parentRealPath)) {
    throw new Error('CodeTruss hook result path is outside the authenticated private turn')
  }

  try {
    const target = await lstat(request.path)
    if (target.isSymbolicLink() || !target.isFile()) {
      throw new Error('CodeTruss hook result target is not a regular private file')
    }
    throw new Error('CodeTruss hook result target already exists')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
}

export async function writeInternalHookResult(
  request: InternalHookResultRequest,
  contextPath: string,
  result: InternalHookResult,
): Promise<void> {
  await assertPrivateResultLocation(request, contextPath)
  if (!isAbsolute(result.receiptPath) || resolve(result.receiptPath) !== result.receiptPath) {
    throw new Error('CodeTruss hook result receipt path must be absolute and normalized')
  }
  const receipt = await lstat(result.receiptPath)
  if (receipt.isSymbolicLink() || !receipt.isFile()) {
    throw new Error('CodeTruss hook result receipt is not a regular file')
  }
  if (!Array.isArray(result.reasons) || result.reasons.some((reason) => typeof reason !== 'string')) {
    throw new Error('CodeTruss hook result reasons must be strings')
  }
  // The receipt remains the canonical, complete reason set. This private
  // handoff carries only the bounded summary that the Stop-hook consumer can
  // accept and display.
  const reasons = result.reasons
    .slice(0, MAX_RESULT_REASONS)
    .map((reason) => reason.slice(0, MAX_RESULT_REASON_CHARS))

  const value = `${JSON.stringify({
    version: 1,
    attemptId: request.attemptId,
    verdict: result.verdict,
    receiptPath: result.receiptPath,
    reasons,
  })}\n`
  if (Buffer.byteLength(value) > MAX_RESULT_BYTES) {
    throw new Error(`CodeTruss hook result exceeds ${MAX_RESULT_BYTES} bytes`)
  }

  const temporary = `${request.path}.${process.pid}.${randomUUID()}.tmp`
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(temporary, 'wx', 0o600)
    await handle.writeFile(value, 'utf8')
    await handle.sync()
    await handle.close()
    handle = undefined
    await chmod(temporary, 0o600)
    // Recheck immediately before the atomic replacement so an owned stale
    // attempt can never be silently overwritten by a retry.
    try {
      await lstat(request.path)
      throw new Error('CodeTruss hook result target appeared during the review')
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
    await rename(temporary, request.path)
    await chmod(request.path, 0o600)
  } catch (error) {
    await handle?.close().catch(() => undefined)
    await rm(temporary, { force: true }).catch(() => undefined)
    throw error
  }
}
