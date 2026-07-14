import { incompleteAnalyzerOutput, type Analyzer, type AnalyzerFinding } from './types'

const MARKER = /(?:\/\/|#|\/\*|<!--)\s*(TODO|FIXME|HACK|XXX)\b[:\s]?(.{0,120})/

/** Surfaces accumulated TODO/FIXME/HACK markers as trackable debt. */
export const todosAnalyzer: Analyzer = {
  id: 'todos',
  name: 'TODO Tracker',
  description: 'Aggregates TODO, FIXME, and HACK comments into visible technical debt.',
  async run(index) {
    const hits: Array<{ path: string; line: number; kind: string; text: string }> = []

    const hitLimit = 500
    for (const file of index.files) {
      if (!file.content || file.kind === 'doc' || file.kind === 'asset') continue
      const lines = file.content.split('\n')
      for (let i = 0; i < lines.length && hits.length < hitLimit; i++) {
        const m = lines[i].match(MARKER)
        if (m) hits.push({ path: file.path, line: i + 1, kind: m[1], text: m[2].trim() })
      }
    }

    if (hits.length === 0) return []

    const fixmes = hits.filter((h) => h.kind === 'FIXME' || h.kind === 'XXX' || h.kind === 'HACK')
    const findings: AnalyzerFinding[] = []

    if (hits.length >= 10) {
      findings.push({
        category: 'TECH_DEBT',
        severity: hits.length >= 50 ? 'MEDIUM' : 'LOW',
        title: `${hits.length} TODO/FIXME markers across the codebase`,
        description: `The codebase carries ${hits.length} deferred-work markers (${fixmes.length} FIXME/HACK). Unowned TODOs are debt with no repayment plan.`,
        suggestion: 'Convert real TODOs into tracked issues and delete stale ones.',
        impactScore: Math.min(60, 20 + hits.length),
        effort: 'medium',
        metadata: { total: hits.length, sample: hits.slice(0, 20) },
      })
    }

    for (const h of fixmes.slice(0, 5)) {
      findings.push({
        category: 'BUG_RISK',
        severity: 'LOW',
        title: `${h.kind} marker: ${h.text.slice(0, 60) || 'unlabelled'}`,
        description: `${h.path}:${h.line} carries a ${h.kind} marker${h.text ? `: "${h.text}"` : ''}. FIXME/HACK markers usually indicate known-broken behavior.`,
        filePath: h.path,
        line: h.line,
        suggestion: 'Fix the underlying issue or document why the workaround is safe.',
        impactScore: 35,
        effort: 'low',
      })
    }

    return hits.length >= hitLimit
      ? incompleteAnalyzerOutput(findings, {
          truncated: true,
          detail: `TODO analysis stopped after ${hitLimit} markers.`,
          metrics: { markers: hits.length, hitLimit },
        })
      : findings
  },
}
