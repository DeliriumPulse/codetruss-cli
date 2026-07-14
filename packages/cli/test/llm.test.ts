import { afterEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_CONFIG } from '../src/config.js'
import {
  LLM_REVIEW_SCHEMA,
  LOCAL_LLM_TIMEOUT_MS,
  PROVIDER_RESPONSE_MAX_BYTES,
  reviewWithLlm,
} from '../src/llm.js'
import { LocalCommandError } from '../src/local-command.js'
import type { LlmLocalRuntime } from '../src/llm.js'
import type { LocalCommandRequest, LocalCommandResult } from '../src/local-command.js'

const ENVIRONMENT_NAMES = [
  'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'OPENAI_API_KEY', 'ANTHROPIC_MODEL', 'OPENAI_MODEL',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'CODETRUSS_API_KEY', 'DATABASE_URL', 'CODETRUSS_TEST_SECRET_MARKER',
] as const
const originalEnvironment = new Map(ENVIRONMENT_NAMES.map((name) => [name, process.env[name]]))

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
  for (const [name, value] of originalEnvironment) {
    if (value === undefined) delete process.env[name]
    else process.env[name] = value
  }
})

const cleanReview = JSON.stringify({ verdict: 'clean', summary: 'Focused change', findings: [] })
const flaggedReview = JSON.stringify({ verdict: 'review', summary: 'Too much abstraction', findings: ['Unused factory'] })

function anthropicResponse(text = cleanReview, stopReason = 'end_turn'): Response {
  return new Response(JSON.stringify({ stop_reason: stopReason, content: [{ type: 'text', text }] }), { status: 200 })
}

function openAiResponse(text = cleanReview, overrides: Record<string, unknown> = {}): Response {
  return new Response(JSON.stringify({
    status: 'completed',
    error: null,
    incomplete_details: null,
    output: [{ type: 'message', status: 'completed', content: [{ type: 'output_text', text }] }],
    ...overrides,
  }), { status: 200 })
}

function claudeResponse(text = cleanReview, overrides: Record<string, unknown> = {}): string {
  const structuredOutput = JSON.parse(text) as Record<string, unknown>
  return JSON.stringify({
    type: 'result',
    subtype: 'success',
    is_error: false,
    api_error_status: null,
    num_turns: 2,
    result: JSON.stringify(structuredOutput),
    stop_reason: 'tool_use',
    permission_denials: [],
    structured_output: structuredOutput,
    terminal_reason: 'completed',
    ...overrides,
  })
}

describe('developer-owned LLM review', () => {
  it('uses current Anthropic structured output and records partial diff coverage', async () => {
    process.env.ANTHROPIC_API_KEY = 'developer-key'
    let requestBody: Record<string, unknown> = {}
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>
      return anthropicResponse(flaggedReview)
    }))
    const config = structuredClone(DEFAULT_CONFIG)
    const includedDiff = 'changed line'
    const omittedDiff = ' another line'
    const observedDiffBytes = Buffer.byteLength(`${includedDiff}${omittedDiff}`) + 100
    config.llm.maxDiffBytes = Buffer.byteLength(includedDiff)

    const result = await reviewWithLlm(
      'Fix auth', `${includedDiff}${omittedDiff}`, config, 'anthropic', undefined, observedDiffBytes,
    )

    expect(result).toMatchObject({
      provider: 'anthropic', verdict: 'review', model: 'claude-sonnet-5',
      diffCoverage: {
        totalBytes: observedDiffBytes,
        reviewedBytes: Buffer.byteLength(includedDiff),
        truncated: true,
      },
    })
    expect(JSON.stringify(requestBody)).toContain('Fix auth')
    expect(JSON.stringify(requestBody)).toContain(includedDiff)
    expect(JSON.stringify(requestBody)).not.toContain(omittedDiff)
    expect(requestBody).toMatchObject({
      model: 'claude-sonnet-5',
      max_tokens: 1200,
      thinking: { type: 'disabled' },
      output_config: { format: { type: 'json_schema', schema: LLM_REVIEW_SCHEMA } },
    })
  })

  it('disables OpenAI storage, bounds output, and uses strict Responses JSON schema', async () => {
    process.env.ANTHROPIC_API_KEY = 'also-present'
    process.env.OPENAI_API_KEY = 'developer-openai-key'
    let requestBody: Record<string, unknown> = {}
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>
      return openAiResponse()
    }))

    const result = await reviewWithLlm('Review auth', 'diff', DEFAULT_CONFIG, 'openai')

    expect(result).toMatchObject({
      provider: 'openai', model: 'gpt-5.6-terra', verdict: 'clean',
      diffCoverage: { totalBytes: 4, reviewedBytes: 4, truncated: false },
    })
    expect(requestBody).toMatchObject({
      model: 'gpt-5.6-terra',
      store: false,
      max_output_tokens: 1200,
      text: {
        format: {
          type: 'json_schema', name: 'codetruss_llm_review', strict: true, schema: LLM_REVIEW_SCHEMA,
        },
      },
    })
  })

  it('fails closed instead of using a CodeTruss or platform-owned key', async () => {
    delete process.env.ANTHROPIC_API_KEY
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'anthropic')).rejects.toThrow('ANTHROPIC_API_KEY')
  })

  it('runs Claude with tools/customizations disabled, strict schema, and an allowlisted environment', async () => {
    process.env.ANTHROPIC_API_KEY = 'must-not-reach-claude'
    process.env.ANTHROPIC_AUTH_TOKEN = 'must-not-reach-claude'
    process.env.CLAUDE_CODE_OAUTH_TOKEN = 'allowed-claude-login-token'
    process.env.OPENAI_API_KEY = 'must-not-reach-claude'
    process.env.CODETRUSS_API_KEY = 'must-not-reach-claude'
    process.env.DATABASE_URL = 'must-not-reach-claude'
    process.env.CODETRUSS_TEST_SECRET_MARKER = 'must-not-reach-claude'
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
    const request = requests[0]
    expect(request).toMatchObject({ command: 'claude', timeoutMs: LOCAL_LLM_TIMEOUT_MS, maxOutputBytes: 64_000 })
    expect(request.args).toEqual(expect.arrayContaining([
      '-p', '--no-session-persistence', '--safe-mode', '--disable-slash-commands', '--no-chrome',
      '--setting-sources', '', '--strict-mcp-config', '--tools', '', '--json-schema',
    ]))
    expect(request.args).toEqual(expect.arrayContaining(['--output-format', 'json']))
    expect(request.args).not.toContain('--max-turns')
    const schemaIndex = request.args.indexOf('--json-schema')
    expect(JSON.parse(request.args[schemaIndex + 1])).toEqual(LLM_REVIEW_SCHEMA)
    expect(request.args.join('\n')).not.toContain(task)
    expect(request.args.join('\n')).not.toContain(diff)
    expect(request.input).toContain(task)
    expect(request.input).toContain(diff)
    expect(request.env).toMatchObject({ CLAUDE_CODE_SAFE_MODE: '1', CLAUDE_CODE_SKIP_PROMPT_HISTORY: '1', NO_COLOR: '1' })
    expect(request.env?.CLAUDE_CODE_OAUTH_TOKEN).toBe('allowed-claude-login-token')
    expect(request.env?.ANTHROPIC_API_KEY).toBeUndefined()
    expect(request.env?.ANTHROPIC_AUTH_TOKEN).toBeUndefined()
    expect(request.env?.OPENAI_API_KEY).toBeUndefined()
    expect(request.env?.CODETRUSS_API_KEY).toBeUndefined()
    expect(request.env?.DATABASE_URL).toBeUndefined()
    expect(request.env?.CODETRUSS_TEST_SECRET_MARKER).toBeUndefined()
  })

  it('rejects an older PATH-resolved Claude binary instead of dropping isolation flags', async () => {
    const runtime = fakeRuntime([])
    vi.mocked(runtime.available).mockResolvedValueOnce({
      status: 'upgrade-required',
      missingFlags: ['--safe-mode', '--json-schema'],
    })
    const config = structuredClone(DEFAULT_CONFIG)
    config.llm.provider = 'claude'

    await expect(reviewWithLlm('task', 'diff', config, undefined, runtime)).rejects.toThrow(
      'claude CLI lacks required isolation support (missing --safe-mode, --json-schema); upgrade Claude Code and ensure the upgraded binary appears first on PATH',
    )
    expect(runtime.run).not.toHaveBeenCalled()
  })

  it('rejects local Claude results that are incomplete or attempted disallowed access', async () => {
    const config = structuredClone(DEFAULT_CONFIG)
    config.llm.provider = 'claude'
    const incomplete = fakeRuntime([], {
      stdout: claudeResponse(cleanReview, { terminal_reason: 'error' }),
      stderr: '', exitCode: 0, signal: null,
    })
    await expect(reviewWithLlm('task', 'diff', config, undefined, incomplete)).rejects.toThrow(
      'claude review did not complete',
    )

    const denied = fakeRuntime([], {
      stdout: claudeResponse(cleanReview, { permission_denials: [{ tool_name: 'Read' }] }),
      stderr: '', exitCode: 0, signal: null,
    })
    await expect(reviewWithLlm('task', 'diff', config, undefined, denied)).rejects.toThrow(
      'claude review attempted disallowed access',
    )
  })

  it('does not expose Codex as an LLM provider while preserving a clear error', async () => {
    const runtime = fakeRuntime([])
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'codex', runtime)).rejects.toThrow(
      'llm.provider codex is no longer available for review; use anthropic, openai, or claude',
    )
    const legacyConfig = structuredClone(DEFAULT_CONFIG)
    legacyConfig.llm.provider = 'codex'
    await expect(reviewWithLlm('task', 'diff', legacyConfig, undefined, runtime)).rejects.toThrow(
      'llm.provider codex is no longer available for review; use anthropic, openai, or claude',
    )
    expect(runtime.available).not.toHaveBeenCalled()
    expect(runtime.run).not.toHaveBeenCalled()
  })

  it('rejects a legacy unscoped model only when LLM review is requested', async () => {
    const config = structuredClone(DEFAULT_CONFIG)
    config.llm.model = 'legacy-model'
    await expect(reviewWithLlm('task', 'diff', config, undefined, fakeRuntime([]))).rejects.toThrow(
      'llm.model requires llm.provider',
    )
  })

  it('rejects a provider override when the configured model belongs to another provider', async () => {
    process.env.OPENAI_API_KEY = 'developer-key'
    const config = structuredClone(DEFAULT_CONFIG)
    config.llm.provider = 'claude'
    config.llm.model = 'sonnet'

    await expect(reviewWithLlm('task', 'diff', config, 'openai', fakeRuntime([]))).rejects.toThrow(
      '--provider openai conflicts with model sonnet configured for claude',
    )
  })

  it('times out the complete API exchange, including a stalled response body', async () => {
    process.env.ANTHROPIC_API_KEY = 'developer-key'
    vi.useFakeTimers()
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      const signal = init?.signal
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          signal?.addEventListener('abort', () => controller.error(new DOMException('Aborted', 'AbortError')), { once: true })
        },
      })
      return new Response(stream, { status: 200 })
    }))

    const pending = reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'anthropic')
    const assertion = expect(pending).rejects.toThrow(`Anthropic request timed out after ${LOCAL_LLM_TIMEOUT_MS}ms`)
    await vi.advanceTimersByTimeAsync(LOCAL_LLM_TIMEOUT_MS)
    await assertion
  })

  it('rejects incomplete and refused provider responses even when HTTP succeeds', async () => {
    process.env.OPENAI_API_KEY = 'developer-key'
    vi.stubGlobal('fetch', vi.fn(async () => openAiResponse(cleanReview, { status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' } })))
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'openai')).rejects.toThrow('OpenAI review did not complete')

    vi.stubGlobal('fetch', vi.fn(async () => openAiResponse(cleanReview, { incomplete_details: undefined })))
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'openai')).rejects.toThrow('OpenAI review did not complete')

    vi.stubGlobal('fetch', vi.fn(async () => openAiResponse('', {
      output: [{ type: 'message', status: 'completed', content: [{ type: 'refusal', refusal: 'declined' }] }],
    })))
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'openai')).rejects.toThrow('OpenAI review was refused')

    process.env.ANTHROPIC_API_KEY = 'developer-key'
    vi.stubGlobal('fetch', vi.fn(async () => anthropicResponse(cleanReview, 'max_tokens')))
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'anthropic')).rejects.toThrow('Anthropic review did not complete')

    vi.stubGlobal('fetch', vi.fn(async () => anthropicResponse('', 'refusal')))
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'anthropic')).rejects.toThrow('Anthropic review was refused')
  })

  it('rejects preambles, contradictory verdicts, oversized fields, and oversized envelopes', async () => {
    process.env.ANTHROPIC_API_KEY = 'developer-key'
    vi.stubGlobal('fetch', vi.fn(async () => anthropicResponse(`preamble\n${cleanReview}`)))
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'anthropic')).rejects.toThrow('invalid JSON review')

    vi.stubGlobal('fetch', vi.fn(async () => anthropicResponse(JSON.stringify({ verdict: 'clean', summary: 'clean', findings: ['contradiction'] }))))
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'anthropic')).rejects.toThrow('inconsistent review')

    vi.stubGlobal('fetch', vi.fn(async () => anthropicResponse(JSON.stringify({ verdict: 'review', summary: 'x'.repeat(2_001), findings: ['finding'] }))))
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'anthropic')).rejects.toThrow('invalid review shape')

    vi.stubGlobal('fetch', vi.fn(async () => new Response('x', {
      status: 200,
      headers: { 'content-length': String(PROVIDER_RESPONSE_MAX_BYTES + 1) },
    })))
    await expect(reviewWithLlm('task', 'diff', DEFAULT_CONFIG, 'anthropic')).rejects.toThrow('Anthropic returned an oversized response')
  })

  it('fails closed without echoing provider stderr or prompt bytes', async () => {
    const marker = 'PRIVATE_TASK_AND_DIFF_MARKER'
    const runtime = fakeRuntime([], {
      stdout: '',
      stderr: `provider echoed ${marker}`,
      exitCode: 17,
      signal: null,
    })

    const error = await reviewWithLlm(marker, marker, { ...structuredClone(DEFAULT_CONFIG), llm: { ...DEFAULT_CONFIG.llm, provider: 'claude' } }, 'claude', runtime).catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toBe('claude review failed with exit code 17')
    expect((error as Error).message).not.toContain(marker)
  })

  it('maps local process timeouts to a bounded, prompt-free failure', async () => {
    const marker = 'PRIVATE_TIMEOUT_MARKER'
    const runtime = fakeRuntime([])
    vi.mocked(runtime.run).mockRejectedValueOnce(new LocalCommandError('claude', 'timeout', 5))
    const config = structuredClone(DEFAULT_CONFIG)
    config.llm.provider = 'claude'

    const error = await reviewWithLlm(marker, marker, config, 'claude', runtime).catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toBe(`claude review timed out after ${LOCAL_LLM_TIMEOUT_MS}ms`)
    expect((error as Error).message).not.toContain(marker)
  })
})

function fakeRuntime(
  requests: LocalCommandRequest[],
  result: LocalCommandResult = {
    stdout: claudeResponse(),
    stderr: '',
    exitCode: 0,
    signal: null,
  },
): LlmLocalRuntime {
  return {
    available: vi.fn(async () => ({ status: 'ready' as const })),
    run: vi.fn(async (request) => {
      requests.push(structuredClone(request))
      return result
    }),
  }
}
