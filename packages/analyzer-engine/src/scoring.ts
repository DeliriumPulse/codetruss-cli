import type { AnalyzerFinding } from './types'
import type { RepoIndex } from './types'
import { analysisCoverage } from './coverage'

export interface Scores {
  health: number
  debt: number
  architecture: number
  security: number
  docs: number
}

/**
 * Per-finding severity weights. CRITICAL is weighted far above the rest on
 * purpose: two committed credentials should roughly halve an axis, while a
 * pile of LOW/MEDIUM findings on a sizable codebase should dent it, not
 * flatten it (the old linear deduction scored a 10k-LOC repo full of LOWs
 * at 5/100).
 */
const SEVERITY_WEIGHT = { CRITICAL: 60, HIGH: 8, MEDIUM: 3, LOW: 1, INFO: 0.25 } as const

/** Compression constant: score = 100 * exp(-weight / K). */
const K = 165
/** LOC baseline for size normalization of non-critical findings. */
const BASELINE_LOC = 10_000

function deduct(findings: AnalyzerFinding[], categories: string[], totalLoc: number): number {
  const relevant = findings.filter((f) => categories.includes(f.category))
  let fixedWeight = 0
  let scaledWeight = 0
  for (const f of relevant) {
    if (f.severity === 'CRITICAL' || f.severity === 'HIGH') fixedWeight += SEVERITY_WEIGHT[f.severity]
    else scaledWeight += SEVERITY_WEIGHT[f.severity]
  }
  // Volume-driven findings (LOW/MEDIUM) are normalized by codebase size:
  // 30 LOWs mean something different at 100k LOC than at 5k. CRITICALs and
  // HIGHs never dilute — a leaked key or vulnerable dependency is just as
  // severe regardless of repo size.
  const sizeFactor = Math.sqrt(Math.max(totalLoc, BASELINE_LOC) / BASELINE_LOC)
  const weight = fixedWeight + scaledWeight / sizeFactor
  // Exponential compression: diminishing returns per extra finding, never
  // collapses to a meaningless floor, spreads scores across the range.
  return Math.round(100 * Math.exp(-weight / K))
}

/**
 * Neutral "we don't know" midpoint. When deep analysis didn't run for most of a
 * repo, the graph-dependent axes decay toward this instead of a confident 100.
 * 50, not 0: withholding an unearned high score is honest; slamming to zero
 * would be dishonest in the other direction.
 */
const NEUTRAL_SCORE = 50

/** Deterministic 0-100 scores derived from findings + repo shape. */
export function computeScores(index: RepoIndex, findings: AnalyzerFinding[]): Scores {
  const loc = index.totalLoc
  const debt = deduct(findings, ['TECH_DEBT', 'DUPLICATION', 'DEAD_CODE'], loc)
  let security = deduct(findings, ['SECURITY_HYGIENE', 'DEPENDENCY'], loc)
  const docs = deduct(findings, ['DOCUMENTATION'], loc)
  let architecture = deduct(findings, ['STRUCTURE', 'ARCHITECTURE', 'TESTING'], loc)

  // Analysis coverage caps each axis to the depth we actually reached, along two
  // independent axes. A cap is a min(): it never RAISES a score, so genuine
  // surface problems still show through — it only withholds a high score we
  // didn't earn. Each ceiling decays to NEUTRAL_SCORE as its coverage → 0.
  //
  //   STRUCTURE (architecture + health): deep for native TS/JS/Python AND for
  //   tree-sitter languages (C#, Go, Java, Rust, PHP, Ruby) — we extract real
  //   symbols, call-graph and complexity. So a well-structured C# repo can score
  //   architecture 85+ on its merits and a messy one scores low; the cap applies
  //   ONLY when the repo is mostly a language with no structural analysis at all.
  //
  //   SECURITY: the SAST engine (rules + taint tracking) runs for the languages
  //   it covers (SAST_COVERED_LANGUAGES). For those the security score is EARNED
  //   and UNCAPPED — real taint findings lower it, genuinely clean code scores
  //   high. Tree-sitter-only languages (C#, Go, …) get structure but only a
  //   regex secrets scan for security, NOT injection/untrusted-input analysis. A
  //   100 there tells a client "this code is secure" when it was never security-
  //   analyzed — the single most dangerous false signal an auditor can emit — so
  //   the security cap remains for the languages the SAST engine does NOT cover.
  //
  // Debt and docs stay unchanged: their checks (finding volume, README/license
  // presence) are genuinely language-agnostic.
  const coverage = analysisCoverage(index)
  const structureCeiling = coverage.structureLimited
    ? Math.round(NEUTRAL_SCORE + (100 - NEUTRAL_SCORE) * coverage.structureRatio)
    : null
  const securityCeiling = coverage.securityLimited
    ? Math.round(NEUTRAL_SCORE + (100 - NEUTRAL_SCORE) * coverage.securityRatio)
    : null
  if (structureCeiling !== null) architecture = Math.min(architecture, structureCeiling)
  if (securityCeiling !== null) security = Math.min(security, securityCeiling)

  // Health = weighted blend, biased toward security & debt. The security cap
  // already flows into health through its 0.3 weight, so health only needs an
  // explicit cap for the structure axis (uncertain structure undermines the
  // whole health picture).
  let health = Math.round(
    security * 0.3 + debt * 0.3 + architecture * 0.25 + docs * 0.15,
  )
  if (structureCeiling !== null) health = Math.min(health, structureCeiling)

  return { health, debt, architecture, security, docs }
}
