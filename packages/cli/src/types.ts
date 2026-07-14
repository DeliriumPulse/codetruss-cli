import type { AnalyzerFinding, AnalyzerPass, RepoIndex, Scores } from '@codetruss/analyzer-engine'

export type Verdict = 'PASS' | 'REVIEW_REQUIRED' | 'FAILED'
export type ScopeClassification = 'allowed' | 'denied' | 'unexpected'

export interface CliConfig {
  version: 1
  allow: string[]
  deny: string[]
  verify: string[]
  receipts: { dir: string }
  llm: {
    provider?: 'anthropic' | 'openai' | 'claude' | 'codex'
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
  verdict: 'clean' | 'review'
  summary: string
  findings: string[]
}

export interface Receipt {
  receiptVersion: 1
  sessionId: string
  createdAt: string
  finishedAt: string
  durationMs: number
  mode: 'run' | 'review'
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
  analyzers: {
    passes: AnalyzerPass[]
    /** Only findings introduced or worsened between the reviewed snapshots. */
    findings: AnalyzerFinding[]
    scores: Scores
    baselineScores?: Scores
    delta?: { introduced: number; worsened: number; recurring: number; resolved: number }
    index: Pick<RepoIndex, 'totalLoc' | 'languages' | 'primaryLanguage'>
  }
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
