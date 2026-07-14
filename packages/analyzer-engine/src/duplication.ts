import { createHash } from 'crypto'
import {
  annotatedAnalyzerOutput,
  incompleteAnalyzerOutput,
  type Analyzer,
  type AnalyzerFinding,
} from './types'

const WINDOW = 12 // lines per shingle
const MIN_LINE_LENGTH = 12 // ignore trivial lines when shingling

/**
 * Cross-file duplicate logic detection via normalized line shingles.
 * Deliberately conservative: only reports blocks duplicated across files.
 */
export const duplicationAnalyzer: Analyzer = {
  id: 'duplication',
  name: 'Duplicated Logic',
  description: 'Finds substantial code blocks duplicated across files.',
  async run(index) {
    const findings: AnalyzerFinding[] = []
    // shingle hash -> [{file, line}]
    const seen = new Map<string, { path: string; line: number }>()
    const reportedPairs = new Set<string>()

    const candidates = index.files.filter(
      (f) =>
        f.content &&
        (f.kind === 'source' || f.kind === 'component' || f.kind === 'route') &&
        f.loc >= WINDOW,
    )

    const candidateLimit = 2000
    for (const file of candidates.slice(0, candidateLimit)) {
      const lines = file
        .content!.split('\n')
        .map((l) => l.trim())
      // build windows of meaningful lines
      for (let i = 0; i + WINDOW <= lines.length; i++) {
        const windowLines = lines.slice(i, i + WINDOW)
        const meaningful = windowLines.filter(
          (l) => l.length >= MIN_LINE_LENGTH && !l.startsWith('//') && !l.startsWith('*') && !l.startsWith('#'),
        )
        if (meaningful.length < WINDOW * 0.75) continue
        const hash = createHash('sha1').update(meaningful.join('\n')).digest('hex')
        const prior = seen.get(hash)
        if (prior && prior.path !== file.path) {
          const pairKey = [prior.path, file.path].sort().join('::')
          if (!reportedPairs.has(pairKey)) {
            reportedPairs.add(pairKey)
            findings.push({
              category: 'DUPLICATION',
              severity: 'MEDIUM',
              title: `Duplicated logic: ${shortPath(prior.path)} and ${shortPath(file.path)}`,
              description: `A block of ~${WINDOW}+ lines appears in both ${prior.path} (line ${prior.line}) and ${file.path} (line ${i + 1}). Duplicated logic drifts apart over time and doubles bug-fix cost.`,
              filePath: file.path,
              line: i + 1,
              suggestion: 'Extract the shared logic into a single module and import it from both call sites.',
              impactScore: 55,
              effort: 'medium',
              metadata: { otherFile: prior.path, otherLine: prior.line },
            })
          }
        } else if (!prior) {
          seen.set(hash, { path: file.path, line: i + 1 })
        }
      }
    }

    const findingLimit = 25
    const output = findings.slice(0, findingLimit)
    // Scanning fewer candidates is real coverage loss. Capping the number of
    // persisted duplicate pairs after every candidate was compared is only an
    // output bound and keeps the pass authoritative.
    if (candidates.length > candidateLimit) {
      return incompleteAnalyzerOutput(output, {
        truncated: true,
        detail: `Duplication analysis hit a candidate bound (${candidates.length} candidate files, ${findings.length} matches).`,
        metrics: { candidates: candidates.length, candidateLimit, matches: findings.length, findingLimit },
      })
    }
    if (findings.length > findingLimit) {
      return annotatedAnalyzerOutput(output, {
        detail: `Duplication output capped at ${findingLimit} of ${findings.length} matches.`,
        metrics: { candidates: candidates.length, candidateLimit, matches: findings.length, findingLimit },
      })
    }
    return output
  },
}

/** Repo-relative path, shortened to the last two segments when long, so
 * titles stay distinguishable (basenames alone made "page.tsx and page.tsx"). */
function shortPath(p: string): string {
  const parts = p.split('/')
  return parts.length <= 2 ? p : parts.slice(-2).join('/')
}
