import { afterEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_CONFIG } from '../src/config.js'
import { LOCAL_LLM_TIMEOUT_MS, reviewWithLlm } from '../src/llm.js'
import { LocalCommandError } from '../src/local-command.js'
import type { LlmLocalRuntime } from '../src/llm.js'
import type { LocalCommandRequest, LocalCommandResult } from '../src/local-command.js'

const originalKey = process.env.ANTHROPIC_API_KEY
afterEach(() => {
  vi.unstubAllGlobals()
  if (originalKey === undefined) delete process.env.ANTHROPIC_API_KEY
  else process.env.ANTHROPIC_API_KEY = originalKey
})

describe('developer-owned LLM review', () => {
  it('sends only the task and bounded diff directly to the selected provider', async () => {
    process.env.ANTHROPIC_API_KEY = 'developer-key'
    let requestBody = ''
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      requestBody = String(init?.body)
      return new Response(JSON.stringify({ content: [{ type: 'text', text: '{"verdict":"review","summary":"Too much abstraction","findings":["Unused factory"]}' }] }), { status: 200 })
    }))
    const config = structuredClone(DEFAULT_CONFIG)
    const includedDiff = 'changed line'
    const omittedDiff = ' another line'
    config.llm.maxDiffBytes = Buffer.byteLength(includedDiff)
    const result = await reviewWithLlm('Fix auth', `${includedDiff}${omittedDiff}`, config, 'anthropic')
    expect(result).toMatchObject({ provider: 'anthropic', verdict: 'review', model: 'claude-sonnet-5' })
    expect(requestBody).toContain('Fix auth')
    expect(requestBody).toContain(includedDiff)
    expect(requestBody).not.toContain(omittedDiff)
  })

  it('fails closed instead of using a CodeTruss key', async () => {
    delete process.env.ANTHROPIC_API_KEY
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'anthropic')).rejects.toThrow('ANTHROPIC_API_KEY')
  })

  it('pipes the task and diff to Claude stdin with local-auth isolation options', async () => {
    const requests: LocalCommandRequest[] = []
    const runtime = fakeRuntime(requests)
    const config = structuredClone(DEFAULT_CONFIG)
    config.llm.provider = 'claude'
    config.llm.model = 'sonnet'
    const task = 'TASK_MARKER_never_put_me_in_argv'
    const diff = 'DIFF_MARKER_never_put_me_in_argv'

    const result = await reviewWithLlm(task, diff, config, undefined, runtime)

    expect(result).toMatchObject({ provider: 'claude', verdict: 'clean', model: 'sonnet' })
    expect(runtime.available).toHaveBeenCalledExactlyOnceWith('claude')
    expect(requests).toHaveLength(1)
    expect(requests[0]).toMatchObject({
      command: 'claude',
      timeoutMs: LOCAL_LLM_TIMEOUT_MS,
      args: [
        '-p',
        '--no-session-persistence',
        '--safe-mode',
        '--input-format', 'text',
        '--output-format', 'text',
        '--tools', '',
        '--model', 'sonnet',
      ],
    })
    expect(requests[0].args.join('\n')).not.toContain(task)
    expect(requests[0].args.join('\n')).not.toContain(diff)
    expect(requests[0].input).toContain(task)
    expect(requests[0].input).toContain(diff)
  })

  it('lets an explicit Codex request override local config and pipes the prompt to stdin', async () => {
    const requests: LocalCommandRequest[] = []
    const runtime = fakeRuntime(requests)
    const config = structuredClone(DEFAULT_CONFIG)
    config.llm.provider = 'claude'
    const task = 'EXPLICIT_CODEX_TASK_MARKER'
    const diff = 'EXPLICIT_CODEX_DIFF_MARKER'

    const result = await reviewWithLlm(task, diff, config, 'codex', runtime)

    expect(result).toMatchObject({ provider: 'codex', verdict: 'clean' })
    expect(runtime.available).toHaveBeenCalledExactlyOnceWith('codex')
    expect(requests).toHaveLength(1)
    expect(requests[0]).toMatchObject({
      command: 'codex',
      timeoutMs: LOCAL_LLM_TIMEOUT_MS,
      args: [
        'exec',
        '--sandbox', 'read-only',
        '--skip-git-repo-check',
        '--ephemeral',
        '--ignore-user-config',
        '--ignore-rules',
        '--color', 'never',
        '-',
      ],
    })
    expect(requests[0].args.join('\n')).not.toContain(task)
    expect(requests[0].args.join('\n')).not.toContain(diff)
    expect(requests[0].input).toContain(task)
    expect(requests[0].input).toContain(diff)
  })

  it('fails closed without echoing provider stderr or prompt bytes', async () => {
    const marker = 'PRIVATE_TASK_AND_DIFF_MARKER'
    const runtime = fakeRuntime([], {
      stdout: '',
      stderr: `provider echoed ${marker}`,
      exitCode: 17,
      signal: null,
    })

    const error = await reviewWithLlm(marker, marker, DEFAULT_CONFIG, 'claude', runtime).catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toBe('claude review failed with exit code 17')
    expect((error as Error).message).not.toContain(marker)
  })

  it('maps local process timeouts to a bounded, prompt-free failure', async () => {
    const marker = 'PRIVATE_TIMEOUT_MARKER'
    const runtime = fakeRuntime([])
    vi.mocked(runtime.run).mockRejectedValueOnce(new LocalCommandError('claude', 'timeout', 5))

    const error = await reviewWithLlm(marker, marker, DEFAULT_CONFIG, 'claude', runtime).catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toBe(`claude review timed out after ${LOCAL_LLM_TIMEOUT_MS}ms`)
    expect((error as Error).message).not.toContain(marker)
  })
})

function fakeRuntime(
  requests: LocalCommandRequest[],
  result: LocalCommandResult = {
    stdout: '{"verdict":"clean","summary":"Focused change","findings":[]}',
    stderr: '',
    exitCode: 0,
    signal: null,
  },
): LlmLocalRuntime {
  return {
    available: vi.fn(async () => true),
    run: vi.fn(async (request) => {
      requests.push(structuredClone(request))
      return result
    }),
  }
}
