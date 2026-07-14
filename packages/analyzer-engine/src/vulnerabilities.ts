import { readFile } from 'fs/promises'
import { join } from 'path'
import { incompleteAnalyzerOutput, type Analyzer, type AnalyzerFinding } from './types'
import type { RepoIndex } from './types'

/**
 * Known-vulnerability scan against the OSV.dev database. Extracts exact
 * installed versions (lockfiles first, manifest ranges as fallback) for
 * direct dependencies and queries /v1/querybatch. Fail-soft by design:
 * a network problem never fails the scan — it yields a single INFO finding
 * so the absence of vulnerability findings is never mistaken for a clean bill.
 */
const OSV_URL = 'https://api.osv.dev/v1/querybatch'
const BATCH_SIZE = 100
const MAX_BATCHES = 2
const BATCH_TIMEOUT_MS = 10_000
const MAX_MANIFESTS = 5

interface PackageQuery {
  name: string
  version: string
  ecosystem: 'npm' | 'PyPI'
  /** manifest file the dependency was declared in */
  manifest: string
}

interface OsvVuln {
  id: string
  summary?: string
  severity?: Array<{ type: string; score: string }>
  database_specific?: { severity?: string }
  affected?: Array<{ ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }> }>
}

const SEVERITY_RANK: Record<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
}
const IMPACT: Record<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', number> = {
  LOW: 35,
  MEDIUM: 55,
  HIGH: 75,
  CRITICAL: 90,
}

export const vulnerabilityAnalyzer: Analyzer = {
  id: 'vulnerabilities',
  name: 'Known Vulnerabilities',
  description: 'Checks installed dependency versions against the OSV.dev vulnerability database.',
  async run(index) {
    const collected = await collectPackages(index)
    const { queries } = collected
    if (queries.length === 0) {
      return collected.truncated
        ? incompleteAnalyzerOutput([], {
            truncated: true,
            detail: 'Dependency manifests exceeded the vulnerability analyzer manifest bound.',
            metrics: { packages: 0, manifestLimit: MAX_MANIFESTS },
          })
        : []
    }

    // Local agent-time consumers can require a zero-network deterministic
    // pass. We still parse and report the package coverage, but never transmit
    // dependency metadata. Hosted scans retain the existing OSV behavior.
    if (process.env.CODETRUSS_OFFLINE === '1') {
      return incompleteAnalyzerOutput(
        [unavailableFinding(queries, new Error('offline policy'))],
        {
          detail: 'OSV lookup skipped by the local offline policy.',
          metrics: { packages: queries.length, offline: true },
        },
      )
    }

    // Two batches max — direct dependencies are collected first, so the cap
    // naturally prioritizes them.
    const limited = queries.slice(0, BATCH_SIZE * MAX_BATCHES)
    const results: Array<{ vulns?: OsvVuln[] } | null> = []
    try {
      for (let i = 0; i < limited.length; i += BATCH_SIZE) {
        const batch = limited.slice(i, i + BATCH_SIZE)
        const res = await fetch(OSV_URL, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            queries: batch.map((q) => ({ package: { name: q.name, ecosystem: q.ecosystem }, version: q.version })),
          }),
          signal: AbortSignal.timeout(BATCH_TIMEOUT_MS),
        })
        if (!res.ok) throw new Error(`OSV querybatch HTTP ${res.status}`)
        const json = (await res.json()) as { results?: Array<{ vulns?: OsvVuln[] } | null> }
        results.push(...(json.results ?? []))
      }
    } catch (err) {
      // Return useful evidence, but mark the pass non-authoritative so the
      // pipeline withholds scores and never resolves earlier vulnerabilities.
      console.warn('[vulnerabilities] OSV lookup skipped:', err instanceof Error ? err.message : err)
      return incompleteAnalyzerOutput([unavailableFinding(limited, err)], {
        detail: `OSV lookup failed: ${err instanceof Error ? err.message.slice(0, 160) : 'unknown error'}`,
        metrics: { packages: limited.length },
      })
    }

    const findings: AnalyzerFinding[] = []
    for (let i = 0; i < limited.length && i < results.length; i++) {
      const vulns = results[i]?.vulns
      if (!vulns || vulns.length === 0) continue
      const q = limited[i]
      const severity = worstSeverity(vulns)
      const lines = vulns.slice(0, 5).map((v) => `- ${v.id}${v.summary ? `: ${v.summary}` : ''}`)
      if (vulns.length > 5) lines.push(`- …and ${vulns.length - 5} more`)
      const fixed = maxFixedVersion(vulns)
      findings.push({
        category: 'DEPENDENCY',
        severity,
        title: `Vulnerable dependency: ${q.name}@${q.version}`,
        description: `${q.name}@${q.version} matches ${vulns.length} known ${vulns.length === 1 ? 'advisory' : 'advisories'} (OSV.dev):\n${lines.join('\n')}`,
        filePath: q.manifest,
        suggestion: fixed
          ? `Upgrade "${q.name}" to ${fixed} or later.`
          : `Review the advisories and upgrade "${q.name}" to a patched release.`,
        impactScore: IMPACT[severity],
        effort: 'low',
        metadata: { ecosystem: q.ecosystem, vulnIds: vulns.map((v) => v.id).slice(0, 10), fixedVersion: fixed },
      })
    }
    const truncated = collected.truncated || queries.length > limited.length || results.length < limited.length
    return truncated
      ? incompleteAnalyzerOutput(findings, {
          truncated: true,
          detail: `Vulnerability analysis covered ${Math.min(results.length, limited.length)} of ${queries.length} package versions.`,
          metrics: {
            packages: queries.length,
            packagesChecked: Math.min(results.length, limited.length),
            packageLimit: BATCH_SIZE * MAX_BATCHES,
          },
        })
      : findings
  },
}

/** One INFO notice instead of silence when OSV.dev is unreachable. */
function unavailableFinding(queries: PackageQuery[], err: unknown): AnalyzerFinding {
  const reason = err instanceof Error ? err.message.slice(0, 120) : 'network error'
  return {
    category: 'DEPENDENCY',
    severity: 'INFO',
    title: 'Dependency vulnerability check unavailable',
    description:
      `The OSV.dev vulnerability database could not be reached (${reason}), so ` +
      `${queries.length} ${queries.length === 1 ? 'dependency was' : 'dependencies were'} not checked ` +
      'against known advisories. The absence of vulnerability findings in this scan is not a clean bill of health.',
    filePath: queries[0]?.manifest,
    suggestion: 'Re-run the scan to retry the OSV.dev lookup, or audit locally (npm audit / pip-audit).',
    impactScore: 10,
    effort: 'low',
    metadata: { uncheckedPackages: queries.length },
  }
}

/** Direct dependencies with exact versions: npm (lockfile → range fallback) + PyPI pins. */
async function collectPackages(index: RepoIndex): Promise<{ queries: PackageQuery[]; truncated: boolean }> {
  // vendored payloads' manifests are not the product's dependencies
  const eligible = index.files.filter((f) => f.kind !== 'vendored')
  const out: PackageQuery[] = []
  const seen = new Set<string>()

  const allPkgPaths = eligible
    .filter((f) => f.path === 'package.json' || f.path.endsWith('/package.json'))
    .map((f) => f.path)
    .sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b))
  const pkgPaths = allPkgPaths.slice(0, MAX_MANIFESTS)
  const lockVersions = await readLockVersions(index.root, eligible)

  for (const path of pkgPaths) {
    let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
    try {
      pkg = JSON.parse(await readFile(join(index.root, path), 'utf8'))
    } catch {
      continue
    }
    for (const deps of [pkg.dependencies, pkg.devDependencies]) {
      for (const [name, range] of Object.entries(deps ?? {})) {
        if (seen.has(`npm:${name}`)) continue
        const version = lockVersions.get(name) ?? exactFromRange(range)
        if (!version) continue
        seen.add(`npm:${name}`)
        out.push({ name, version, ecosystem: 'npm', manifest: path })
      }
    }
  }

  const allReqPaths = eligible
    .filter((f) => f.path === 'requirements.txt' || f.path.endsWith('/requirements.txt'))
    .map((f) => f.path)
  const reqPaths = allReqPaths.slice(0, MAX_MANIFESTS)
  for (const path of reqPaths) {
    let raw: string
    try {
      raw = await readFile(join(index.root, path), 'utf8')
    } catch {
      continue
    }
    for (const line of raw.split('\n')) {
      const m = line.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][\w.!+-]*)/)
      if (!m || seen.has(`pypi:${m[1]}`)) continue
      seen.add(`pypi:${m[1]}`)
      out.push({ name: m[1], version: m[2], ecosystem: 'PyPI', manifest: path })
    }
  }

  return {
    queries: out,
    truncated: allPkgPaths.length > MAX_MANIFESTS || allReqPaths.length > MAX_MANIFESTS,
  }
}

// pnpm-lock.yaml packages/snapshots keys: `  'pkg@1.2.3':` / `  '@scope/pkg@1.2.3(peer@x)':`
const PNPM_PKG_RE = /^ {2}'?((?:@[^\s'/]+\/)?[^\s'@]+)@(\d[^\s'():]*)/gm

async function readLockVersions(
  root: string,
  eligible: Array<{ path: string }>,
): Promise<Map<string, string>> {
  const map = new Map<string, string>()
  const has = (name: string) => eligible.some((f) => f.path === name)

  if (has('package-lock.json')) {
    try {
      const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8')) as {
        packages?: Record<string, { version?: string }>
        dependencies?: Record<string, { version?: string }>
      }
      // v2/v3 format
      for (const [key, val] of Object.entries(lock.packages ?? {})) {
        const m = key.match(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/)
        if (m && typeof val?.version === 'string' && !map.has(m[1])) map.set(m[1], val.version)
      }
      // v1 format
      for (const [name, val] of Object.entries(lock.dependencies ?? {})) {
        if (typeof val?.version === 'string' && !map.has(name)) map.set(name, val.version)
      }
    } catch {
      // unreadable lockfile — fall back to ranges
    }
  }

  if (map.size === 0 && has('pnpm-lock.yaml')) {
    try {
      const raw = await readFile(join(root, 'pnpm-lock.yaml'), 'utf8')
      for (const m of raw.matchAll(PNPM_PKG_RE)) {
        if (!map.has(m[1])) map.set(m[1], m[2])
      }
    } catch {
      // unreadable lockfile — fall back to ranges
    }
  }

  return map
}

/** "^4.17.20" → "4.17.20"; ranges that are not a single version resolve to null. */
function exactFromRange(range: string): string | null {
  if (typeof range !== 'string') return null
  const v = range.replace(/^[\^~=v\s]+/, '')
  return /^\d+\.\d+(\.\d+)?([-+][\w.-]+)?$/.test(v) ? v : null
}

function worstSeverity(vulns: OsvVuln[]): keyof typeof SEVERITY_RANK {
  let worst: keyof typeof SEVERITY_RANK = 'LOW'
  for (const v of vulns) {
    const s = vulnSeverity(v)
    if (SEVERITY_RANK[s] > SEVERITY_RANK[worst]) worst = s
  }
  return worst
}

/** CVSS >= 9 CRITICAL, >= 7 HIGH, >= 4 MEDIUM, else LOW; vector strings computed; label fallback. */
function vulnSeverity(v: OsvVuln): keyof typeof SEVERITY_RANK {
  let best: keyof typeof SEVERITY_RANK | null = null
  for (const s of v.severity ?? []) {
    const numeric = parseFloat(s.score)
    const score = Number.isFinite(numeric) ? numeric : cvss3BaseScore(s.score)
    if (score === null) continue
    const mapped = score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW'
    if (!best || SEVERITY_RANK[mapped] > SEVERITY_RANK[best]) best = mapped
  }
  if (best) return best
  const label = v.database_specific?.severity?.toUpperCase()
  if (label === 'CRITICAL' || label === 'HIGH' || label === 'LOW') return label
  if (label === 'MODERATE' || label === 'MEDIUM') return 'MEDIUM'
  return 'LOW'
}

// CVSS v3.x base-metric weights (spec §7.4). PR weights depend on Scope.
const CVSS3 = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const

/**
 * Base score computed from a CVSS v3.0/3.1 vector string
 * ("CVSS:3.1/AV:N/AC:L/…") with the standard base-score formula;
 * null when the string is not a well-formed base vector.
 */
function cvss3BaseScore(vector: string): number | null {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null
  const metrics = new Map<string, string>()
  for (const part of vector.split('/').slice(1)) {
    const [key, value] = part.split(':')
    if (key && value) metrics.set(key, value)
  }
  const scope = metrics.get('S')
  if (scope !== 'U' && scope !== 'C') return null
  const av = CVSS3.AV[metrics.get('AV') as keyof typeof CVSS3.AV]
  const ac = CVSS3.AC[metrics.get('AC') as keyof typeof CVSS3.AC]
  const pr = CVSS3.PR[scope][metrics.get('PR') as keyof (typeof CVSS3.PR)['U']]
  const ui = CVSS3.UI[metrics.get('UI') as keyof typeof CVSS3.UI]
  const c = CVSS3.CIA[metrics.get('C') as keyof typeof CVSS3.CIA]
  const i = CVSS3.CIA[metrics.get('I') as keyof typeof CVSS3.CIA]
  const a = CVSS3.CIA[metrics.get('A') as keyof typeof CVSS3.CIA]
  if ([av, ac, pr, ui, c, i, a].some((w) => w === undefined)) return null

  const iss = 1 - (1 - c) * (1 - i) * (1 - a)
  const impact = scope === 'C' ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss
  if (impact <= 0) return 0
  const exploitability = 8.22 * av * ac * pr * ui
  const raw = scope === 'C' ? 1.08 * (impact + exploitability) : impact + exploitability
  return roundup(Math.min(raw, 10))
}

/** CVSS v3.1 Roundup (spec appendix A): smallest 1-decimal value >= input, float-safe. */
function roundup(input: number): number {
  const scaled = Math.round(input * 100_000)
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10
}

function maxFixedVersion(vulns: OsvVuln[]): string | null {
  let best: string | null = null
  for (const v of vulns) {
    for (const a of v.affected ?? []) {
      for (const r of a.ranges ?? []) {
        for (const e of r.events ?? []) {
          if (e.fixed && (!best || compareVersions(e.fixed, best) > 0)) best = e.fixed
        }
      }
    }
  }
  return best
}

function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/)
  const pb = b.split(/[.+-]/)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = Number(pa[i] ?? 0)
    const y = Number(pb[i] ?? 0)
    if (Number.isNaN(x) || Number.isNaN(y)) continue
    if (x !== y) return x - y
  }
  return 0
}
