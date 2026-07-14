import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalCommandError, runLocalCommand } from './local-command.js'
import type { CliConfig } from './types.js'
import type { LlmReview } from './types.js'

type Provider = NonNullable<CliConfig['llm']['provider']>

export const LOCAL_LLM_TIMEOUT_MS = 120_000
const LOCAL_CLI_PROBE_TIMEOUT_MS = 5_000

export interface LlmLocalRuntime {
  available(command: 'claude' | 'codex'): Promise<boolean>
  run(request: Parameters<typeof runLocalCommand>[0]): Promise<Awaited<ReturnType<typeof runLocalCommand>>>
}

const DEFAULT_LOCAL_RUNTIME: LlmLocalRuntime = {
  async available(command) {
    try {
      const result = await runLocalCommand({
        command,
        args: ['--version'],
        cwd: tmpdir(),
        timeoutMs: LOCAL_CLI_PROBE_TIMEOUT_MS,
        maxOutputBytes: 64_000,
      })
      return result.exitCode === 0
    } catch {
      return false
    }
  },
  run: runLocalCommand,
}

async function choose(config: CliConfig, requested: string | undefined, runtime: LlmLocalRuntime): Promise<Provider> {
  const explicit = requested ?? config.llm.provider
  if (explicit) {
    if (!['anthropic', 'openai', 'claude', 'codex'].includes(explicit)) throw new Error(`unsupported LLM provider ${explicit}`)
    if (explicit === 'anthropic' && !process.env.ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY is not set')
    if (explicit === 'openai' && !process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY is not set')
    if ((explicit === 'claude' || explicit === 'codex') && !(await runtime.available(explicit))) throw new Error(`${explicit} CLI is not installed or not executable`)
    return explicit as Provider
  }
  if (process.env.ANTHROPIC_API_KEY) return 'anthropic'
  if (process.env.OPENAI_API_KEY) return 'openai'
  if (await runtime.available('claude')) return 'claude'
  if (await runtime.available('codex')) return 'codex'
  throw new Error('--llm requires ANTHROPIC_API_KEY, OPENAI_API_KEY, or an authenticated claude/codex CLI')
}

function prompt(task: string, diff: string): string {
  return `You are a strict reviewer of an AI coding agent's diff. Review only the supplied task and diff. Flag code that is unrelated to the task, unnecessary abstraction, speculative compatibility layers, duplicated logic, placeholders, excessive comments, fake tests, weakened checks, or other AI slop. Do not request repository context. Return JSON only: {"verdict":"clean"|"review","summary":"...","findings":["..."]}.\n\nTASK:\n${task}\n\nDIFF:\n${diff}`
}

function parseReview(provider: string, raw: string, bytes: number, model?: string): LlmReview {
  const candidate = raw.match(/\{[\s\S]*\}/)?.[0]
  if (!candidate) throw new Error(`${provider} returned no JSON review`)
  const parsed = JSON.parse(candidate) as { verdict?: string; summary?: string; findings?: unknown }
  if (!['clean', 'review'].includes(parsed.verdict ?? '') || typeof parsed.summary !== 'string' || !Array.isArray(parsed.findings)) throw new Error(`${provider} returned an invalid review shape`)
  return { provider, model, transmittedBytes: bytes, verdict: parsed.verdict as 'clean' | 'review', summary: parsed.summary, findings: parsed.findings.map(String) }
}

export async function reviewWithLlm(task: string, rawDiff: string, config: CliConfig, requested?: string, runtime = DEFAULT_LOCAL_RUNTIME): Promise<LlmReview> {
  const provider = await choose(config, requested, runtime)
  const diff = Buffer.from(rawDiff).subarray(0, config.llm.maxDiffBytes).toString('utf8')
  const input = prompt(task, diff)
  const transmittedBytes = Buffer.byteLength(input)
  process.stderr.write(`codetruss: sending ${transmittedBytes} bytes directly to local provider ${provider}\n`)

  if (provider === 'anthropic') {
    const key = process.env.ANTHROPIC_API_KEY
    if (!key) throw new Error('ANTHROPIC_API_KEY is not set')
    const model = config.llm.model ?? process.env.ANTHROPIC_MODEL ?? 'claude-sonnet-5'
    const response = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model, max_tokens: 1200, thinking: { type: 'disabled' }, messages: [{ role: 'user', content: input }] }) })
    if (!response.ok) throw new Error(`Anthropic request failed with HTTP ${response.status}`)
    const body = await response.json() as { content?: Array<{ type: string; text?: string }> }
    return parseReview(provider, body.content?.find((item) => item.type === 'text')?.text ?? '', transmittedBytes, model)
  }
  if (provider === 'openai') {
    const key = process.env.OPENAI_API_KEY
    if (!key) throw new Error('OPENAI_API_KEY is not set')
    const model = config.llm.model ?? process.env.OPENAI_MODEL ?? 'gpt-5.6-terra'
    const response = await fetch('https://api.openai.com/v1/responses', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` }, body: JSON.stringify({ model, input }) })
    if (!response.ok) throw new Error(`OpenAI request failed with HTTP ${response.status}`)
    const body = await response.json() as { output_text?: string; output?: Array<{ content?: Array<{ text?: string }> }> }
    const text = body.output_text ?? body.output?.flatMap((item) => item.content ?? []).map((item) => item.text ?? '').join('') ?? ''
    return parseReview(provider, text, transmittedBytes, model)
  }

  const cwd = mkdtempSync(join(tmpdir(), 'codetruss-llm-'))
  try {
    if (provider === 'claude') {
      const args = [
        '-p',
        '--no-session-persistence',
        '--safe-mode',
        '--input-format', 'text',
        '--output-format', 'text',
        '--tools', '',
      ]
      if (config.llm.model) args.push('--model', config.llm.model)
      const result = await runLocalProvider('claude', args, cwd, input, runtime)
      return parseReview(provider, result.stdout, transmittedBytes, config.llm.model)
    }
    const args = [
      'exec',
      '--sandbox', 'read-only',
      '--skip-git-repo-check',
      '--ephemeral',
      '--ignore-user-config',
      '--ignore-rules',
      '--color', 'never',
    ]
    if (config.llm.model) args.push('--model', config.llm.model)
    args.push('-')
    const result = await runLocalProvider('codex', args, cwd, input, runtime)
    return parseReview(provider, result.stdout, transmittedBytes, config.llm.model)
  } finally { rmSync(cwd, { recursive: true, force: true }) }
}

async function runLocalProvider(
  provider: 'claude' | 'codex',
  args: string[],
  cwd: string,
  input: string,
  runtime: LlmLocalRuntime,
): Promise<Awaited<ReturnType<typeof runLocalCommand>>> {
  let result: Awaited<ReturnType<typeof runLocalCommand>>
  try {
    result = await runtime.run({
      command: provider,
      args,
      cwd,
      input,
      timeoutMs: LOCAL_LLM_TIMEOUT_MS,
    })
  } catch (error) {
    if (error instanceof LocalCommandError) {
      const detail = error.reason === 'timeout'
        ? `timed out after ${LOCAL_LLM_TIMEOUT_MS}ms`
        : error.reason === 'output-limit'
          ? 'exceeded the output limit'
          : 'could not be started'
      throw new Error(`${provider} review ${detail}`)
    }
    throw new Error(`${provider} review failed to run`)
  }
  if (result.exitCode !== 0) {
    const detail = result.signal ? `signal ${result.signal}` : `exit code ${result.exitCode ?? 'unknown'}`
    throw new Error(`${provider} review failed with ${detail}`)
  }
  return result
}
