export type FindingCategory =
  | 'TECH_DEBT'
  | 'BUG_RISK'
  | 'DEAD_CODE'
  | 'DUPLICATION'
  | 'SECURITY_HYGIENE'
  | 'DOCUMENTATION'
  | 'ARCHITECTURE'
  | 'TESTING'
  | 'DEPENDENCY'
  | 'PERFORMANCE'
  | 'STRUCTURE'
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export interface FrameworkSignal {
  name: string
  evidence: string
}
export type RepoType = 'library' | 'application'

export interface IndexedFile {
  path: string
  language: string | null
  kind: string
  sizeBytes: number
  loc: number
  sha: string | null
  content: string | null
}

export interface IndexCoverage {
  discoveredFiles: number
  maxFiles: number
  truncated: boolean
  textCandidates: number
  contentLoaded: number
  oversizedTextFiles: number
  unreadableTextFiles: number
  binaryTextFiles: number
}

export interface RepoIndex {
  root: string
  files: IndexedFile[]
  languages: Record<string, number>
  frameworks: FrameworkSignal[]
  packageManagers: string[]
  databases: string[]
  dependencies: Set<string>
  totalLoc: number
  primaryLanguage: string | null
  repoType: RepoType
  vendoredDirs: Record<string, number>
  generatedFiles?: Record<string, number>
  coverage?: IndexCoverage
}

export interface AnalyzerFinding {
  category: FindingCategory
  severity: FindingSeverity
  title: string
  description: string
  filePath?: string
  line?: number
  suggestion?: string
  impactScore: number
  effort?: 'low' | 'medium' | 'high'
  metadata?: Record<string, unknown>
  analyzerId?: string
}

export interface AnalyzerRunResult {
  findings: AnalyzerFinding[]
  complete: boolean
  truncated?: boolean
  detail?: string
  metrics?: Record<string, string | number | boolean | null>
}

const COMPLETION = Symbol('codetruss.analyzer-completion')
type FindingList = AnalyzerFinding[] & { [COMPLETION]?: Omit<AnalyzerRunResult, 'findings'> }

export function incompleteAnalyzerOutput(
  findings: AnalyzerFinding[],
  status: Omit<AnalyzerRunResult, 'findings' | 'complete'>,
): AnalyzerFinding[] {
  Object.defineProperty(findings, COMPLETION, {
    value: { ...status, complete: false },
    enumerable: false,
  })
  return findings
}

export function annotatedAnalyzerOutput(
  findings: AnalyzerFinding[],
  status: Omit<AnalyzerRunResult, 'findings' | 'complete' | 'truncated'>,
): AnalyzerFinding[] {
  Object.defineProperty(findings, COMPLETION, {
    value: { ...status, complete: true },
    enumerable: false,
  })
  return findings
}

export function analyzerResult(output: AnalyzerFinding[]): AnalyzerRunResult {
  const status = (output as FindingList)[COMPLETION]
  return { findings: output, complete: status?.complete ?? true, ...status }
}

export interface Analyzer {
  id: string
  name: string
  description: string
  run(index: RepoIndex): Promise<AnalyzerFinding[]>
}
