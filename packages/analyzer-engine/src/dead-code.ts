import {
  annotatedAnalyzerOutput,
  incompleteAnalyzerOutput,
  type Analyzer,
  type AnalyzerFinding,
} from './types'

/**
 * Dead-code candidates: JS/TS modules that are never imported anywhere.
 * Heuristic (static string matching), so results are labeled candidates.
 */
export const deadCodeAnalyzer: Analyzer = {
  id: 'dead-code',
  name: 'Dead Code Candidates',
  description: 'Finds source modules that no other file appears to import.',
  async run(index) {
    const findings: AnalyzerFinding[] = []

    // Haystack: ALL indexed JS/TS files with content (routes, tests, configs
    // included) — imports from page.tsx/route.ts files must count as usage.
    const haystackFiles = index.files.filter(
      (f) => f.content && /\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/.test(f.path),
    )
    // Candidates: only plain source/component modules can be "dead".
    const jsFiles = haystackFiles.filter(
      (f) => f.kind === 'source' || f.kind === 'component',
    )
    if (jsFiles.length < 5) return findings

    // Entry-point-ish files that are loaded by convention, not by import
    // (proxy.ts is Next 16's middleware — deleting it would drop the auth gate)
    const CONVENTION = /(page|layout|route|loading|error|not-found|template|default|middleware|proxy|instrumentation|opengraph-image|twitter-image|icon|apple-icon|sitemap|robots|manifest|index|main|app|server|config|next-env|globals)\.[jt]sx?$|\.(d|config|test|spec)\.[cm]?[jt]s$/

    const allContent = haystackFiles.map((f) => f.content!).join('\n')

    const candidateLimit = 1500
    for (const file of jsFiles.slice(0, candidateLimit)) {
      // CLI/tooling entry points are invoked by runners, not imports
      if (/(^|\/)(scripts|bin|tools)\//.test(file.path)) continue
      const base = file.path.split('/').pop()!
      if (CONVENTION.test(base)) continue
      const stem = base.replace(/\.[cm]?[jt]sx?$/, '')
      if (stem.length < 3) continue // too ambiguous to match safely
      // Imported anywhere? look for `/stem'`, `/stem"`, or `from './stem`-style
      // refs — or a bare quoted `stem.ext` (a spawn-by-string worker path built
      // from segments, e.g. join(cwd, 'src', 'lib', 'batch-process.ts')).
      const needle = new RegExp(
        `['"\`](?:[^'"\`]*/${escapeRegExp(stem)}(\\.[cm]?[jt]sx?)?|${escapeRegExp(stem)}\\.[cm]?[jt]sx?)['"\`]`,
      )
      if (!needle.test(allContent)) {
        findings.push({
          category: 'DEAD_CODE',
          severity: 'LOW',
          title: `Possibly unused module: ${file.path}`,
          description: `No other file appears to import "${stem}". If it is not loaded by convention or tooling, it is dead code.`,
          filePath: file.path,
          suggestion: 'Verify with your bundler or `knip`/`ts-prune`, then delete if truly unused.',
          impactScore: 35,
          effort: 'low',
        })
      }
    }
    const findingLimit = 20
    // Only the candidate-file cap is real coverage loss; the finding cap just
    // bounds OUTPUT over an analysis that covered every candidate file.
    const truncated = jsFiles.length > candidateLimit
    const output = findings.slice(0, findingLimit)
    if (truncated) {
      return incompleteAnalyzerOutput(output, {
        truncated: true,
        detail: `Dead-code analysis hit a bound (${jsFiles.length} candidate files, ${findings.length} matches).`,
        metrics: { candidates: jsFiles.length, candidateLimit, matches: findings.length, findingLimit },
      })
    }
    if (findings.length > findingLimit) {
      return annotatedAnalyzerOutput(output, {
        detail: `Dead-code output capped at ${findingLimit} of ${findings.length} matches.`,
        metrics: { candidates: jsFiles.length, candidateLimit, matches: findings.length, findingLimit },
      })
    }
    return output
  },
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
