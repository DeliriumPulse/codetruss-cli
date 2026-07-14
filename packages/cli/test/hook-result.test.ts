import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  CODETRUSS_HOOK_RESULT_PATH_ENV,
  CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV,
  parseInternalHookResultRequest,
  writeInternalHookResult,
} from '../src/hook-result.js'

const cleanup: string[] = []
const attemptId = 'a'.repeat(64)

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function fixture(): Promise<{ contextPath: string; receiptPath: string; resultPath: string; turn: string }> {
  const root = await mkdtemp(join(tmpdir(), 'codetruss-hook-result-'))
  cleanup.push(root)
  const turn = join(root, 'turn')
  const attempts = join(turn, 'attempts')
  await mkdir(attempts, { recursive: true, mode: 0o700 })
  await chmod(turn, 0o700)
  await chmod(attempts, 0o700)
  const contextPath = join(turn, 'turn-context.json')
  const receiptPath = join(root, 'receipt.md')
  const resultPath = join(attempts, 'result.json')
  await writeFile(contextPath, '{}\n', { mode: 0o600 })
  await writeFile(receiptPath, '# receipt\n', { mode: 0o600 })
  return { contextPath, receiptPath, resultPath, turn }
}

describe('private internal hook result contract', () => {
  it('requires the complete authenticated environment tuple', () => {
    expect(parseInternalHookResultRequest({})).toBeUndefined()
    expect(() => parseInternalHookResultRequest({
      [CODETRUSS_HOOK_RESULT_PATH_ENV]: '/tmp/result.json',
      [CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV]: attemptId,
    })).toThrow(/authenticated internal hook review/)
    expect(() => parseInternalHookResultRequest({
      CODETRUSS_INTERNAL_HOOK: '1',
      [CODETRUSS_HOOK_RESULT_PATH_ENV]: '/tmp/result.json',
    })).toThrow(/requires both/)
    expect(() => parseInternalHookResultRequest({
      CODETRUSS_INTERNAL_HOOK: '1',
      [CODETRUSS_HOOK_RESULT_PATH_ENV]: '/tmp/result.json',
      [CODETRUSS_HOOK_REVIEW_ATTEMPT_ID_ENV]: 'A'.repeat(64),
    })).toThrow(/64 lowercase hexadecimal/)
  })

  it('atomically writes an exact attempt-bound mode-0600 result', async () => {
    const files = await fixture()
    await writeInternalHookResult(
      { path: files.resultPath, attemptId },
      files.contextPath,
      { verdict: 'REVIEW_REQUIRED', receiptPath: files.receiptPath, reasons: ['outside allowed scope'] },
    )

    expect(JSON.parse(await readFile(files.resultPath, 'utf8'))).toEqual({
      version: 1,
      attemptId,
      verdict: 'REVIEW_REQUIRED',
      receiptPath: files.receiptPath,
      reasons: ['outside allowed scope'],
    })
    if (process.platform !== 'win32') expect((await lstat(files.resultPath)).mode & 0o777).toBe(0o600)
    await expect(writeInternalHookResult(
      { path: files.resultPath, attemptId },
      files.contextPath,
      { verdict: 'PASS', receiptPath: files.receiptPath, reasons: [] },
    )).rejects.toThrow(/already exists/)
  })

  it('writes a consumer-safe bounded reason summary while the receipt remains canonical', async () => {
    const files = await fixture()
    await writeInternalHookResult(
      { path: files.resultPath, attemptId },
      files.contextPath,
      {
        verdict: 'FAILED',
        receiptPath: files.receiptPath,
        reasons: Array.from({ length: 101 }, (_, index) => `${index}:${'x'.repeat(2_100)}`),
      },
    )

    const document = JSON.parse(await readFile(files.resultPath, 'utf8')) as { reasons: string[] }
    expect(document.reasons).toHaveLength(100)
    expect(document.reasons.every((reason) => reason.length <= 2_000)).toBe(true)
    expect(document.reasons[0]).toMatch(/^0:/)
    expect(document.reasons.at(-1)).toMatch(/^99:/)
  })

  it('refuses traversal and symbolic-link result surfaces', async () => {
    const files = await fixture()
    await expect(writeInternalHookResult(
      { path: join(files.turn, '..', 'outside.json'), attemptId },
      files.contextPath,
      { verdict: 'PASS', receiptPath: files.receiptPath, reasons: [] },
    )).rejects.toThrow(/outside the authenticated private turn/)

    const linkedParent = join(files.turn, 'linked-attempts')
    await symlink(join(files.turn, 'attempts'), linkedParent, process.platform === 'win32' ? 'junction' : 'dir')
    await expect(writeInternalHookResult(
      { path: join(linkedParent, 'result.json'), attemptId },
      files.contextPath,
      { verdict: 'PASS', receiptPath: files.receiptPath, reasons: [] },
    )).rejects.toThrow(/symbolic-link parent/)

    const target = join(files.turn, 'attempts', 'target.json')
    await symlink(files.receiptPath, target, process.platform === 'win32' ? 'file' : undefined)
    await expect(writeInternalHookResult(
      { path: target, attemptId },
      files.contextPath,
      { verdict: 'PASS', receiptPath: files.receiptPath, reasons: [] },
    )).rejects.toThrow(/not a regular private file/)
  })
})
