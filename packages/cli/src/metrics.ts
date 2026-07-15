import { inspectLocalHookHealth, type LocalHookHealth } from './hooks.js'
import { receiptIds, verifyReceipt } from './receipt.js'
import type { Receipt, ReceiptInvocationKind, Verdict } from './types.js'
import { CLI_VERSION } from './version.js'

const DAY_MS = 24 * 60 * 60 * 1_000
const D7_START_DAY = 6
const D7_END_DAY_EXCLUSIVE = 8

export type D7SignalStatus = 'no_receipts' | 'not_eligible' | 'pending' | 'observed' | 'not_observed'

export interface LocalMetricsV1 {
  metricsVersion: 1
  cliVersion: string
  privacy: {
    localOnly: true
    receiptLevelContentIncluded: false
  }
  receipts: {
    verified: number
    invalid: number
    firstActiveUtcDate: string | null
    lastActiveUtcDate: string | null
    activeUtcDays: number
    verdicts: Record<Verdict, number>
    invocations: Record<ReceiptInvocationKind | 'legacy_unknown', number>
    agentHookSurfaces: { claude: number; codex: number }
  }
  d7: {
    window: { startHour: 144; endHourExclusive: 192 }
    status: D7SignalStatus
    totalVerifiedReceipts: number
    totalActiveUtcDays: number
    verifiedReceiptsInWindow: number
    agentHookReceiptsInWindow: number
  }
  hooks: LocalHookHealth
}

export interface LocalMetricsOptions {
  now?: Date
  inspectHooks?: (root: string) => Promise<LocalHookHealth>
}

function receiptTimestamp(receipt: Receipt): number | undefined {
  const timestamp = Date.parse(receipt.createdAt)
  return Number.isFinite(timestamp) ? timestamp : undefined
}

function activeUtcDays(timestamps: number[]): number {
  return new Set(timestamps.map((timestamp) => new Date(timestamp).toISOString().slice(0, 10))).size
}

function receiptRange(receipts: Receipt[]): Pick<LocalMetricsV1['receipts'], 'firstActiveUtcDate' | 'lastActiveUtcDate' | 'activeUtcDays'> {
  const timestamps = receipts
    .map(receiptTimestamp)
    .filter((timestamp): timestamp is number => timestamp !== undefined)
    .sort((left, right) => left - right)
  return {
    firstActiveUtcDate: timestamps.length ? new Date(timestamps[0]).toISOString().slice(0, 10) : null,
    lastActiveUtcDate: timestamps.length ? new Date(timestamps.at(-1)!).toISOString().slice(0, 10) : null,
    activeUtcDays: activeUtcDays(timestamps),
  }
}

function metricsSafeReceipt(receipt: Receipt, id: string): boolean {
  if (receipt.sessionId !== id || !['PASS', 'REVIEW_REQUIRED', 'FAILED'].includes(receipt.verdict)) return false
  if (receiptTimestamp(receipt) === undefined) return false
  const invocation = (receipt as { invocation?: unknown }).invocation
  if (invocation === undefined) return true
  if (!invocation || typeof invocation !== 'object' || Array.isArray(invocation)) return false
  const value = invocation as Record<string, unknown>
  if (typeof value.cliVersion !== 'string' || !value.cliVersion || value.cliVersion.includes('\0')) return false
  if (value.kind === 'manual_run') {
    return receipt.mode === 'run' && value.provenance === 'direct' && value.surface === undefined
  }
  if (value.kind === 'manual_review' || value.kind === 'pre_commit') {
    const expected = value.kind === 'pre_commit' ? 'self_attested' : 'direct'
    return receipt.mode === 'review' && value.provenance === expected && value.surface === undefined
  }
  return value.kind === 'agent_hook'
    && receipt.mode === 'review'
    && value.provenance === 'hook_context'
    && (value.surface === 'claude' || value.surface === 'codex')
}

function d7Signal(receipts: Receipt[], now: Date): LocalMetricsV1['d7'] {
  const nowMs = now.getTime()
  const timestamps = receipts
    .map((receipt) => ({ receipt, timestamp: receiptTimestamp(receipt) }))
    .filter((entry): entry is { receipt: Receipt; timestamp: number } => entry.timestamp !== undefined)
    .sort((left, right) => left.timestamp - right.timestamp)
  const observedThroughNow = timestamps.filter(({ timestamp }) => timestamp <= nowMs)
  const first = observedThroughNow[0]?.timestamp
  if (first === undefined) {
    return {
      window: { startHour: 144, endHourExclusive: 192 },
      status: timestamps.length ? 'not_eligible' : 'no_receipts',
      totalVerifiedReceipts: 0,
      totalActiveUtcDays: 0,
      verifiedReceiptsInWindow: 0,
      agentHookReceiptsInWindow: 0,
    }
  }
  const start = first + (D7_START_DAY * DAY_MS)
  const end = first + (D7_END_DAY_EXCLUSIVE * DAY_MS)
  const inWindow = observedThroughNow.filter(({ timestamp }) => timestamp >= start && timestamp < end)
  const totalDays = activeUtcDays(observedThroughNow.map(({ timestamp }) => timestamp))
  const patternObserved = observedThroughNow.length >= 2 && totalDays >= 2 && inWindow.length >= 1
  const status: D7SignalStatus = nowMs < start
    ? 'not_eligible'
    : patternObserved
      ? 'observed'
      : nowMs < end
        ? 'pending'
        : 'not_observed'
  return {
    window: { startHour: 144, endHourExclusive: 192 },
    status,
    totalVerifiedReceipts: observedThroughNow.length,
    totalActiveUtcDays: totalDays,
    verifiedReceiptsInWindow: inWindow.length,
    agentHookReceiptsInWindow: inWindow.filter(({ receipt }) => receipt.invocation?.kind === 'agent_hook').length,
  }
}

/**
 * Aggregate cryptographically verified local receipts without copying any
 * receipt-level content into the result. This function performs no network I/O.
 */
export async function collectLocalMetrics(
  root: string,
  dir: string,
  pinnedPublicKey?: string,
  options: LocalMetricsOptions = {},
): Promise<LocalMetricsV1> {
  const ids = await receiptIds(dir)
  const receipts: Receipt[] = []
  let invalid = 0
  for (const id of ids) {
    try {
      const receipt = await verifyReceipt(dir, id, pinnedPublicKey)
      if (!metricsSafeReceipt(receipt, id)) throw new Error('receipt fields are unsafe to aggregate')
      receipts.push(receipt)
    } catch {
      invalid += 1
    }
  }

  const verdicts: Record<Verdict, number> = { PASS: 0, REVIEW_REQUIRED: 0, FAILED: 0 }
  const invocations: LocalMetricsV1['receipts']['invocations'] = {
    manual_run: 0,
    manual_review: 0,
    pre_commit: 0,
    agent_hook: 0,
    legacy_unknown: 0,
  }
  const agentHookSurfaces = { claude: 0, codex: 0 }
  for (const receipt of receipts) {
    verdicts[receipt.verdict] += 1
    invocations[receipt.invocation?.kind ?? 'legacy_unknown'] += 1
    if (receipt.invocation?.kind === 'agent_hook') agentHookSurfaces[receipt.invocation.surface] += 1
  }

  const hooks = await (options.inspectHooks ?? inspectLocalHookHealth)(root)
  const range = receiptRange(receipts)
  return {
    metricsVersion: 1,
    cliVersion: CLI_VERSION,
    privacy: { localOnly: true, receiptLevelContentIncluded: false },
    receipts: {
      verified: receipts.length,
      invalid,
      ...range,
      verdicts,
      invocations,
      agentHookSurfaces,
    },
    d7: d7Signal(receipts, options.now ?? new Date()),
    hooks,
  }
}

export function renderLocalMetrics(metrics: LocalMetricsV1): string {
  const lines = [
    `Verified local receipts: ${metrics.receipts.verified} (${metrics.receipts.invalid} invalid or unverifiable)`,
    `Active UTC dates: ${metrics.receipts.firstActiveUtcDate ?? 'none'} to ${metrics.receipts.lastActiveUtcDate ?? 'none'} across ${metrics.receipts.activeUtcDays} day(s)`,
    `Verdicts: ${metrics.receipts.verdicts.PASS} PASS, ${metrics.receipts.verdicts.REVIEW_REQUIRED} REVIEW_REQUIRED, ${metrics.receipts.verdicts.FAILED} FAILED`,
    `Invocation: ${metrics.receipts.invocations.manual_run} manual run, ${metrics.receipts.invocations.manual_review} manual review, ${metrics.receipts.invocations.pre_commit} pre-commit, ${metrics.receipts.invocations.agent_hook} agent hook, ${metrics.receipts.invocations.legacy_unknown} legacy unknown`,
    `D7 receipt pattern: ${metrics.d7.status} (${metrics.d7.verifiedReceiptsInWindow} in-window receipt(s), ${metrics.d7.agentHookReceiptsInWindow} agent-hook; ${metrics.d7.totalVerifiedReceipts} observed through now across ${metrics.d7.totalActiveUtcDays} UTC day(s))`,
    `Hooks: pre-commit ${metrics.hooks.preCommit}, Claude ${metrics.hooks.claude}, Codex ${metrics.hooks.codex}`,
    'Privacy: computed locally from verified receipts; no receipt-level content or network request is included.',
  ]
  return `${lines.join('\n')}\n`
}
