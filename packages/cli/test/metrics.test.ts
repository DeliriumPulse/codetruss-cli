import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { collectLocalMetrics } from '../src/metrics.js'
import { newSessionId, writeReceipt } from '../src/receipt.js'
import { LOCAL_ANALYSIS_PROFILE, type Receipt } from '../src/types.js'

const originalKey = process.env.CODETRUSS_SIGNING_KEY

afterEach(() => {
  if (originalKey === undefined) delete process.env.CODETRUSS_SIGNING_KEY
  else process.env.CODETRUSS_SIGNING_KEY = originalKey
  vi.unstubAllGlobals()
})

function git(root: string, ...args: string[]): void {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' })
  if (result.status !== 0) throw new Error(result.stderr)
}

function fixture(root: string, createdAt: string, invocation?: Receipt['invocation']): Receipt {
  const patch = 'SECRET_DIFF_BYTES'
  return {
    receiptVersion: 1,
    sessionId: newSessionId(new Date(createdAt)),
    createdAt,
    finishedAt: createdAt,
    durationMs: 0,
    mode: 'review',
    ...(invocation ? { invocation } : {}),
    task: 'SECRET_TASK_TEXT',
    repoRoot: join(root, 'SECRET_REPOSITORY_NAME'),
    startCommit: 'a'.repeat(40),
    endCommit: 'a'.repeat(40),
    git: { baselineTree: 'b'.repeat(40), finalTree: 'c'.repeat(40) },
    policy: { sha256: 'd'.repeat(64) },
    startDirty: false,
    startDirtyFiles: [],
    scope: { allow: ['SECRET_ALLOW_GLOB/**'], deny: [] },
    files: [{
      path: 'SECRET_FILE_PATH.ts',
      change: 'modified',
      classification: 'allowed',
      dependency: false,
      additions: 1,
      deletions: 1,
    }],
    diff: {
      sha256: createHash('sha256').update(patch).digest('hex'),
      bytes: Buffer.byteLength(patch),
      totalBytes: Buffer.byteLength(patch),
      truncated: false,
    },
    analyzers: {
      passes: [],
      findings: [{
        category: 'BUG_RISK',
        severity: 'MEDIUM',
        title: 'SECRET_FINDING_TITLE',
        description: 'SECRET_FINDING_DESCRIPTION',
        filePath: 'SECRET_FILE_PATH.ts',
        impactScore: 50,
      }],
      analysisProfile: LOCAL_ANALYSIS_PROFILE,
      index: { totalLoc: 1, languages: { TypeScript: 1 }, primaryLanguage: 'TypeScript' },
    },
    verifications: [{
      command: 'SECRET_VERIFY_COMMAND',
      exitCode: 0,
      durationMs: 1,
      output: 'SECRET_VERIFY_OUTPUT',
      truncated: false,
    }],
    coverageNotes: ['SECRET_COVERAGE_NOTE'],
    verdict: 'PASS',
    reasons: ['SECRET_VERDICT_REASON'],
    evidence: {},
  }
}

describe('privacy-safe local metrics', () => {
  it('aggregates only verified receipts, reports D7 use, and performs no fetch', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-metrics-'))
    const dir = join(root, '.codetruss', 'receipts')
    git(root, 'init', '--quiet')
    process.env.CODETRUSS_SIGNING_KEY = join(root, '.codetruss', 'SECRET_SIGNING_KEY.pem')

    const first = fixture(root, '2026-07-01T12:00:00.000Z', {
      kind: 'manual_review', provenance: 'direct', cliVersion: '0.2.14',
    })
    const retained = fixture(root, '2026-07-08T12:00:00.000Z', {
      kind: 'agent_hook', provenance: 'hook_context', surface: 'codex', cliVersion: '0.2.14',
    })
    const legacy = fixture(root, '2026-07-08T18:00:00.000Z')
    const preCommitClaim = fixture(root, '2026-07-08T20:00:00.000Z', {
      kind: 'pre_commit', provenance: 'self_attested', cliVersion: '0.2.14',
    })
    for (const receipt of [first, retained, legacy, preCommitClaim]) {
      await writeReceipt(dir, receipt, 'SECRET_DIFF_BYTES')
    }
    const unsafeInvocation = fixture(root, '2026-07-08T19:00:00.000Z', {
      kind: 'SECRET_INVOCATION_KIND', cliVersion: '0.2.14',
    } as unknown as Receipt['invocation'])
    await writeReceipt(dir, unsafeInvocation, 'SECRET_DIFF_BYTES')
    await writeFile(join(dir, 'duplicate-alias.json'), await readFile(join(dir, `${first.sessionId}.json`)))
    await writeFile(join(dir, 'invalid.json'), '{"SECRET_INVALID_RECEIPT":true}\n')

    const fetchSpy = vi.fn(() => { throw new Error('network access is forbidden') })
    vi.stubGlobal('fetch', fetchSpy)
    const metrics = await collectLocalMetrics(root, dir, undefined, {
      now: new Date('2026-07-20T12:00:00.000Z'),
    })

    expect(fetchSpy).not.toHaveBeenCalled()
    expect(metrics).toMatchObject({
      metricsVersion: 1,
      privacy: { localOnly: true, receiptLevelContentIncluded: false },
      receipts: {
        verified: 4,
        invalid: 3,
        firstActiveUtcDate: '2026-07-01',
        lastActiveUtcDate: '2026-07-08',
        activeUtcDays: 2,
        verdicts: { PASS: 4, REVIEW_REQUIRED: 0, FAILED: 0 },
        invocations: {
          manual_run: 0,
          manual_review: 1,
          pre_commit: 1,
          agent_hook: 1,
          legacy_unknown: 1,
        },
        agentHookSurfaces: { claude: 0, codex: 1 },
      },
      d7: {
        status: 'observed',
        totalVerifiedReceipts: 4,
        totalActiveUtcDays: 2,
        verifiedReceiptsInWindow: 3,
        agentHookReceiptsInWindow: 1,
      },
    })

    const serialized = JSON.stringify(metrics)
    expect(serialized).not.toContain('2026-07-01T12:00:00.000Z')
    expect(serialized).not.toContain('2026-07-08T18:00:00.000Z')
    for (const secret of [
      'SECRET_TASK_TEXT',
      'SECRET_REPOSITORY_NAME',
      'SECRET_FILE_PATH',
      'SECRET_FINDING',
      'SECRET_VERIFY',
      'SECRET_DIFF',
      'SECRET_SIGNING_KEY',
      'SECRET_ALLOW_GLOB',
      'SECRET_INVOCATION_KIND',
      first.sessionId,
    ]) {
      expect(serialized).not.toContain(secret)
    }
  })

  it('returns an explicit no-receipts D7 signal without creating telemetry', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-empty-metrics-'))
    git(root, 'init', '--quiet')
    process.env.CODETRUSS_SIGNING_KEY = join(root, '.codetruss', 'signing.pem')
    const metrics = await collectLocalMetrics(root, join(root, '.codetruss', 'receipts'))
    expect(metrics.receipts.verified).toBe(0)
    expect(metrics.receipts).toMatchObject({ firstActiveUtcDate: null, lastActiveUtcDate: null, activeUtcDays: 0 })
    expect(metrics.d7).toMatchObject({
      status: 'no_receipts',
      totalVerifiedReceipts: 0,
      totalActiveUtcDays: 0,
      verifiedReceiptsInWindow: 0,
      agentHookReceiptsInWindow: 0,
    })
  })

  it('uses the closed 144-to-192-hour D7 observation window', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-d7-metrics-'))
    const dir = join(root, '.codetruss', 'receipts')
    git(root, 'init', '--quiet')
    process.env.CODETRUSS_SIGNING_KEY = join(root, '.codetruss', 'signing.pem')
    await writeReceipt(dir, fixture(root, '2026-07-01T12:00:00.000Z', {
      kind: 'manual_review', provenance: 'direct', cliVersion: '0.2.14',
    }), 'SECRET_DIFF_BYTES')
    const inspectHooks = async () => ({
      preCommit: 'not_installed' as const,
      claude: 'not_installed' as const,
      codex: 'not_installed' as const,
    })

    await expect(collectLocalMetrics(root, dir, undefined, {
      now: new Date('2026-07-07T11:59:59.999Z'), inspectHooks,
    })).resolves.toMatchObject({ d7: { status: 'not_eligible' } })
    await expect(collectLocalMetrics(root, dir, undefined, {
      now: new Date('2026-07-07T12:00:00.000Z'), inspectHooks,
    })).resolves.toMatchObject({ d7: { status: 'pending' } })
    await expect(collectLocalMetrics(root, dir, undefined, {
      now: new Date('2026-07-09T12:00:00.000Z'), inspectHooks,
    })).resolves.toMatchObject({ d7: { status: 'not_observed' } })
  })

  it('includes 144 hours, excludes 192 hours, and labels manual-only use as a receipt pattern', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-d7-boundaries-'))
    const dir = join(root, '.codetruss', 'receipts')
    git(root, 'init', '--quiet')
    process.env.CODETRUSS_SIGNING_KEY = join(root, '.codetruss', 'signing.pem')
    const invocation = { kind: 'manual_review', provenance: 'direct', cliVersion: '0.2.15' } as const
    for (const createdAt of [
      '2026-07-01T12:00:00.000Z',
      '2026-07-07T12:00:00.000Z',
      '2026-07-09T12:00:00.000Z',
    ]) {
      await writeReceipt(dir, fixture(root, createdAt, invocation), 'SECRET_DIFF_BYTES')
    }
    const inspectHooks = async () => ({
      preCommit: 'not_installed' as const,
      claude: 'not_installed' as const,
      codex: 'not_installed' as const,
    })

    await expect(collectLocalMetrics(root, dir, undefined, {
      now: new Date('2026-07-07T12:00:00.000Z'), inspectHooks,
    })).resolves.toMatchObject({
      d7: {
        status: 'observed',
        totalVerifiedReceipts: 2,
        totalActiveUtcDays: 2,
        verifiedReceiptsInWindow: 1,
        agentHookReceiptsInWindow: 0,
      },
    })
    await expect(collectLocalMetrics(root, dir, undefined, {
      now: new Date('2026-07-09T12:00:00.000Z'), inspectHooks,
    })).resolves.toMatchObject({
      d7: {
        status: 'observed',
        totalVerifiedReceipts: 3,
        totalActiveUtcDays: 3,
        verifiedReceiptsInWindow: 1,
        agentHookReceiptsInWindow: 0,
      },
    })
  })

  it('does not call a future-dated verified receipt an empty receipt history', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-future-metrics-'))
    const dir = join(root, '.codetruss', 'receipts')
    git(root, 'init', '--quiet')
    process.env.CODETRUSS_SIGNING_KEY = join(root, '.codetruss', 'signing.pem')
    await writeReceipt(dir, fixture(root, '2026-07-20T12:00:00.000Z', {
      kind: 'manual_review', provenance: 'direct', cliVersion: '0.2.14',
    }), 'SECRET_DIFF_BYTES')
    const metrics = await collectLocalMetrics(root, dir, undefined, {
      now: new Date('2026-07-14T12:00:00.000Z'),
      inspectHooks: async () => ({
        preCommit: 'not_installed', claude: 'not_installed', codex: 'not_installed',
      }),
    })
    expect(metrics.receipts.verified).toBe(1)
    expect(metrics.d7).toMatchObject({ status: 'not_eligible', totalVerifiedReceipts: 0 })
  })
})
