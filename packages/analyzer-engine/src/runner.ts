import { getAnalyzers } from './registry'
import { analyzerResult, type AnalyzerFinding, type AnalyzerRunResult, type RepoIndex } from './types'

export interface AnalyzerPass {
  id: string
  result: AnalyzerRunResult
  error?: string
}

/** Run every deterministic analyzer without allowing one failed pass to abort the suite. */
export async function runAnalyzers(
  index: RepoIndex,
): Promise<{ findings: AnalyzerFinding[]; passes: AnalyzerPass[] }> {
  const findings: AnalyzerFinding[] = []
  const passes: AnalyzerPass[] = []
  for (const analyzer of getAnalyzers()) {
    try {
      const raw = analyzerResult(await analyzer.run(index))
      const result = {
        ...raw,
        findings: raw.findings.map((finding) => ({ ...finding, analyzerId: analyzer.id })),
      }
      findings.push(...result.findings)
      passes.push({ id: analyzer.id, result })
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      passes.push({
        id: analyzer.id,
        result: { findings: [], complete: false, detail },
        error: detail,
      })
    }
  }
  return { findings, passes }
}
