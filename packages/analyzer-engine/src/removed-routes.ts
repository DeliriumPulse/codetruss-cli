import { annotatedAnalyzerOutput, type Analyzer, type AnalyzerFinding } from './types'

/**
 * Removed-but-present route surface: page trees the middleware/proxy
 * permanently blocks (410/404) that still live in the app directory. The
 * convention-based dead-code analyzer deliberately never flags route files —
 * this closes that blind spot for the one case where a route is provably
 * unreachable: its prefix is terminated before routing ever sees it.
 *
 * Precision-first extraction: only Next's conventional middleware/proxy file
 * locations count, the file must actually return a terminal status, and only
 * list-item-shaped path literals (a line that is nothing but '/prefix',) are
 * treated as blocked prefixes — an inline redirect target like
 * `new URL('/login', req.url)` never matches.
 */

/** Next's middleware conventions: middleware.ts / proxy.ts at root or src/. */
const PROXY_FILE_RE = /^(src\/)?(middleware|proxy)\.[jt]sx?$/
/** A line consisting solely of a quoted root path (an array list item). */
const LIST_ITEM_PATH_RE = /^\s*['"](\/[a-z0-9][a-z0-9/_-]*)['"],?\s*$/
/** Evidence the file terminates requests rather than only redirecting. */
const TERMINAL_STATUS_RE = /status:\s*(410|404)\b/

const FINDING_LIMIT = 30

export const removedRoutesAnalyzer: Analyzer = {
  id: 'removed-routes',
  name: 'Removed Route Surface',
  description: 'Finds page trees still present in the repo whose routes the middleware permanently blocks.',
  async run(index) {
    const findings: AnalyzerFinding[] = []

    for (const proxy of index.files) {
      if (!proxy.content || !PROXY_FILE_RE.test(proxy.path)) continue
      if (!TERMINAL_STATUS_RE.test(proxy.content)) continue

      const prefixes = new Set<string>()
      for (const line of proxy.content.split('\n')) {
        const m = LIST_ITEM_PATH_RE.exec(line)
        if (m) prefixes.add(m[1])
      }

      for (const prefix of [...prefixes].sort()) {
        const trees = index.files.filter(
          (f) =>
            (f.path.startsWith(`src/app${prefix}/`) || f.path.startsWith(`app${prefix}/`)) &&
            /\.[jt]sx?$/.test(f.path),
        )
        if (trees.length === 0) continue
        const loc = trees.reduce((sum, f) => sum + f.loc, 0)
        const appDir = trees[0].path.startsWith('src/') ? 'src/app' : 'app'
        findings.push({
          category: 'DEAD_CODE',
          severity: 'MEDIUM',
          title: `Removed route surface still present: ${prefix}`,
          description:
            `${proxy.path} returns a terminal response for every request under ${prefix}, ` +
            `but ${trees.length} page/route file${trees.length === 1 ? '' : 's'} (~${loc.toLocaleString()} LOC) ` +
            `still live under ${appDir}${prefix}. They can never be served.`,
          filePath: `${appDir}${prefix}`,
          suggestion:
            'Delete the unreachable page tree (git history preserves it), or remove the middleware block if the surface should be live.',
          impactScore: 55,
          effort: 'low',
          metadata: { prefix, files: trees.length, loc },
        })
      }
    }

    if (findings.length > FINDING_LIMIT) {
      return annotatedAnalyzerOutput(findings.slice(0, FINDING_LIMIT), {
        detail: `Removed-route output capped at ${FINDING_LIMIT} of ${findings.length} prefixes.`,
        metrics: { prefixes: findings.length, findingLimit: FINDING_LIMIT },
      })
    }
    return findings
  },
}
