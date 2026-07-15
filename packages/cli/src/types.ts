import type { AnalyzerFinding, AnalyzerPass, RepoIndex, Scores } from '@codetruss/analyzer-engine'

export type Verdict = 'PASS' | 'REVIEW_REQUIRED' | 'FAILED'
export type ScopeClassification = 'allowed' | 'denied' | 'unexpected'
export const RECEIPT_INVOCATION_KINDS = ['manual_run', 'manual_review', 'pre_commit', 'agent_hook'] as const
export type ReceiptInvocationKind = typeof RECEIPT_INVOCATION_KINDS[number]
export const AGENT_HOOK_SURFACES = ['claude', 'codex'] as const
export type AgentHookReceiptSurface = typeof AGENT_HOOK_SURFACES[number]
export const LLM_PROVIDERS = ['anthropic', 'openai', 'claude'] as const
export type LlmProvider = typeof LLM_PROVIDERS[number]
/** `codex` remains readable so pre-0.2 repository config does not break deterministic commands. */
export const CONFIG_LLM_PROVIDERS = [...LLM_PROVIDERS, 'codex'] as const
export type ConfiguredLlmProvider = typeof CONFIG_LLM_PROVIDERS[number]
export const MAX_LLM_DIFF_BYTES = 2_000_000

/** Honest local-analysis contract: registry passes run locally; hosted-only passes and scores do not. */
export const LOCAL_ANALYSIS_PROFILE = {
  id: 'local-registry-v1',
  omittedPasses: ['graph', 'sast'],
  scoreStatus: 'not-computed',
} as const
export type LocalAnalysisProfile = typeof LOCAL_ANALYSIS_PROFILE

export interface CliConfig {
  version: 1
  allow: string[]
  deny: string[]
  verify: string[]
  receipts: { dir: string }
  llm: {
    provider?: ConfiguredLlmProvider
    model?: string
    maxDiffBytes: number
  }
  signing: { publicKey?: string }
  sync: { url: string }
}

export interface SyncEnvelope {
  signedReceipt: string
  signature: string
}

export interface ChangedFile {
  path: string
  oldPath?: string
  change: 'added' | 'modified' | 'deleted' | 'renamed'
  classification: ScopeClassification
  sensitive?: string
  dependency: boolean
  additions: number
  deletions: number
}

export interface VerificationResult {
  command: string
  exitCode: number
  durationMs: number
  output: string
  truncated: boolean
}

export interface LlmReview {
  provider: string
  model?: string
  transmittedBytes: number
  /** Optional only so receipts issued before this coverage field was introduced remain verifiable. */
  diffCoverage?: {
    totalBytes: number
    reviewedBytes: number
    truncated: boolean
  }
  verdict: 'clean' | 'review'
  summary: string
  findings: string[]
}

interface AnalyzerReceiptEvidence {
  passes: AnalyzerPass[]
  /** Only findings introduced or worsened between the reviewed snapshots. */
  findings: AnalyzerFinding[]
  delta?: { introduced: number; worsened: number; recurring: number; resolved: number }
  index: Pick<RepoIndex, 'totalLoc' | 'languages' | 'primaryLanguage'>
}

export type AnalyzerReceipt = AnalyzerReceiptEvidence & (
  | {
      /** Current local receipts never infer hosted Health scores from an incomplete pass set. */
      analysisProfile: LocalAnalysisProfile
      scores?: never
      baselineScores?: never
    }
  | {
      /** Compatibility shape for signed receipt-v1 files written by earlier CLI versions. */
      analysisProfile?: never
      scores: Scores
      baselineScores?: Scores
    }
)

export interface Receipt {
  receiptVersion: 1
  sessionId: string
  createdAt: string
  finishedAt: string
  durationMs: number
  mode: 'run' | 'review'
  /**
   * How this receipt was invoked. Optional only for signed receipt-v1 files
   * issued before provenance was introduced; every current receipt includes it.
  */
  invocation?:
    | { kind: 'manual_run' | 'manual_review'; provenance: 'direct'; cliVersion: string }
    | { kind: 'pre_commit'; provenance: 'self_attested'; cliVersion: string }
    | { kind: 'agent_hook'; provenance: 'hook_context'; surface: AgentHookReceiptSurface; cliVersion: string }
  task: string
  repoRoot: string
  startCommit: string
  endCommit: string
  /** Immutable Git trees that produced every file, diff, analyzer, and verification fact. Present on current receipts; omitted by early v1 clients. */
  git?: { baselineTree: string; finalTree: string }
  /** Stable digest of effective scope, verification, and optional LLM policy. Present on current receipts; omitted by early v1 clients. */
  policy?: { sha256: string }
  startDirty: boolean
  startDirtyFiles: string[]
  agent?: { command: string[]; exitCode: number; durationMs: number; startError?: string }
  scope: { allow: string[]; deny: string[] }
  files: ChangedFile[]
  diff: { sha256: string; bytes: number; totalBytes?: number; truncated: boolean }
  analyzers: AnalyzerReceipt
  verifications: VerificationResult[]
  llm?: LlmReview
  coverageNotes: string[]
  verdict: Verdict
  reasons: string[]
  evidence: { markdownSha256?: string; patchFile?: string; patchSha256?: string; signatureFile?: string; publicKey?: string; keyFingerprint?: string }
}

export interface ReviewOptions {
  mode: 'run' | 'review'
  task: string
  allow: string[]
  deny: string[]
  verify: string[]
  llm: boolean
  provider?: string
  staged: boolean
  agentCommand?: string[]
}
