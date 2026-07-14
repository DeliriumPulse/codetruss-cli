import type { Analyzer, AnalyzerFinding } from './types'
import type { RepoIndex } from './types'
import { SUPPORTED_TREESITTER_LANGS } from './support'
import { SAST_COVERED_LANGUAGES } from './support'

/**
 * Analysis-coverage signal.
 *
 * CodeTruss analyzes languages at two different depths, and honesty means
 * disclosing which depth applied:
 *
 *  - STRUCTURE (architecture, call-graph, complexity, health): available for
 *    languages with a native TS/JS/Python extractor AND for languages parsed via
 *    tree-sitter AST (C#, Go, Java, Rust, PHP, Ruby). For all of these we extract
 *    real symbols, a call graph and complexity, so architecture/health reflect
 *    genuine structure — a well-built repo can score high on its merits and a
 *    messy one scores low on its merits.
 *
 *  - SECURITY (injection, untrusted-input, deserialization): a real SAST engine
 *    (rules + taint tracking) runs for the languages it covers
 *    (SAST_COVERED_LANGUAGES). For those languages the security axis is EARNED —
 *    real vulns lower it, genuinely clean code scores high. For every other
 *    language we run only regex secret scanning — that is not a security review,
 *    so a clean security axis there means "we didn't look", not "it's safe".
 *
 * Everything outside the structure set is *surface-scanned* — structure regex,
 * secrets, file size, docs — with no architecture, flow, or complexity
 * understanding and a largely empty knowledge graph. When such a language
 * dominates a repo the deep analyzers legitimately find nothing, which naive
 * scoring reads as "excellent". This module measures how much of the codebase we
 * actually understood — separately for structure and for security — so scoring +
 * the report can be upfront about scope instead of rewarding the blind spot.
 *
 * Coverage is derived from the languages map only — the same input every caller
 * (analyzer, scoring, report) already has — so all three stay consistent. In the
 * real indexer `sum(languages) === totalLoc` (both exclude markup/data
 * languages), so the language-LOC fraction is a faithful proxy for "fraction of
 * the codebase we modeled".
 */

/**
 * Languages with a native deep extractor: real import/call graph, routes, data
 * models, symbol/complexity. Keep in sync with src/lib/repo/graph.ts and
 * src/lib/repo/symbols.ts.
 */
export const DEEPLY_SUPPORTED_LANGUAGES = new Set(['TypeScript', 'JavaScript', 'Python'])

/** Tree-sitter AST languages, lowercased. Deep STRUCTURE only — not security. */
const TREESITTER_LANGUAGES = new Set(SUPPORTED_TREESITTER_LANGS.map((l) => l.toLowerCase()))

/**
 * Deep STRUCTURE support: a native extractor OR tree-sitter AST. Architecture,
 * call-graph, complexity and health are trustworthy for these languages, so the
 * architecture/health coverage cap does NOT apply to them.
 */
export function isStructureDeep(language: string): boolean {
  return DEEPLY_SUPPORTED_LANGUAGES.has(language) || TREESITTER_LANGUAGES.has(language.toLowerCase())
}

/**
 * Deep SECURITY support: languages the SAST engine (rules + taint tracking)
 * actually covers. The security coverage cap is LIFTED for these — the security
 * score is earned. Tree-sitter-only languages (C#, Go, …) are NOT in this set:
 * they get structure analysis but only regex secret scanning for security, so
 * the security cap remains for them.
 */
export function isSecurityDeep(language: string): boolean {
  return SAST_COVERED_LANGUAGES.has(language)
}

/** Below this many code LOC a repo is too small to draw coverage conclusions. */
const MIN_ANALYZABLE_LOC = 300
/** At/above this supported fraction the repo reads as well-covered. */
const COVERAGE_OK = 0.5

export interface AnalysisCoverage {
  /** Classified code LOC (sum of the languages map). */
  totalLoc: number
  /** LOC in languages with deep STRUCTURE analysis (native or tree-sitter). */
  structureLoc: number
  /** structureLoc / totalLoc, 0..1. 1 when there is no code to analyze. */
  structureRatio: number
  /** LOC in languages with deep SECURITY analysis (native extractors only). */
  securityLoc: number
  /** securityLoc / totalLoc, 0..1. 1 when there is no code to analyze. */
  securityRatio: number
  primaryLanguage: string | null
  /** Primary language has deep structure analysis (native or tree-sitter). */
  primaryStructureSupported: boolean
  /** Primary language has deep security analysis (native extractor). */
  primarySecuritySupported: boolean
  /** Languages with NO deep structure support (genuinely unsupported), most LOC first. */
  surfaceLanguages: string[]
  /** Languages with structure but not security analysis (tree-sitter), most LOC first. */
  structureOnlyLanguages: string[]
  /** True when architecture/health reflect mostly surface-only analysis. */
  structureLimited: boolean
  /** True when the security axis is mostly regex-only (no real security review). */
  securityLimited: boolean
}

/** Pure coverage computation shared by the analyzer, scoring, and the report. */
export function analysisCoverage(index: RepoIndex): AnalysisCoverage {
  const entries = Object.entries(index.languages)
  const totalLoc = entries.reduce((sum, [, loc]) => sum + loc, 0)

  let structureLoc = 0
  let securityLoc = 0
  const surface: Array<[string, number]> = []
  const structureOnly: Array<[string, number]> = []
  for (const [lang, loc] of entries) {
    const structureDeep = isStructureDeep(lang)
    const securityDeep = isSecurityDeep(lang)
    if (structureDeep) structureLoc += loc
    else surface.push([lang, loc])
    if (securityDeep) securityLoc += loc
    // Deep structure but no security review (tree-sitter languages).
    if (structureDeep && !securityDeep) structureOnly.push([lang, loc])
  }

  const structureRatio = totalLoc > 0 ? structureLoc / totalLoc : 1
  const securityRatio = totalLoc > 0 ? securityLoc / totalLoc : 1
  const primaryLanguage = index.primaryLanguage
  const primaryStructureSupported = primaryLanguage != null && isStructureDeep(primaryLanguage)
  const primarySecuritySupported = primaryLanguage != null && isSecurityDeep(primaryLanguage)
  const byLoc = (a: [string, number], b: [string, number]) => b[1] - a[1]
  const surfaceLanguages = surface.sort(byLoc).map(([lang]) => lang)
  const structureOnlyLanguages = structureOnly.sort(byLoc).map(([lang]) => lang)

  const analyzable = totalLoc >= MIN_ANALYZABLE_LOC
  // Structure is limited when a non-trivial repo is mostly languages we can't
  // parse for architecture/flow. Tree-sitter languages do NOT trip this.
  const structureLimited =
    analyzable && (!primaryStructureSupported || structureRatio < COVERAGE_OK)
  // Security is limited when most of the repo is a language we never security-
  // reviewed (only regex-scanned) — including tree-sitter languages.
  const securityLimited =
    analyzable && (!primarySecuritySupported || securityRatio < COVERAGE_OK)

  return {
    totalLoc,
    structureLoc,
    structureRatio,
    securityLoc,
    securityRatio,
    primaryLanguage,
    primaryStructureSupported,
    primarySecuritySupported,
    surfaceLanguages,
    structureOnlyLanguages,
    structureLimited,
    securityLimited,
  }
}

/**
 * Emits ONE honest disclosure when coverage is limited, matched to the actual
 * depth we reached. This is not a penalty — it tells the reader what the scores
 * do and don't cover:
 *
 *  - Genuinely unsupported language (no extractor, no tree-sitter): the strong
 *    "limited analysis" caveat — architecture/flow/complexity were NOT analyzed.
 *  - Tree-sitter language (structure fully analyzed, security surface-only): the
 *    nuanced caveat — structure is real, security is secret-scanning only.
 */
export const coverageAnalyzer: Analyzer = {
  id: 'coverage',
  name: 'Analysis coverage',
  description:
    'Discloses the depth of analysis per language so a clean report is not misread as a full architecture + security review.',
  async run(index: RepoIndex): Promise<AnalyzerFinding[]> {
    const coverage = analysisCoverage(index)

    if (coverage.structureLimited) {
      const lang = coverage.primaryLanguage ?? coverage.surfaceLanguages[0] ?? 'this language'
      const pct = Math.round(coverage.structureRatio * 100)
      return [
        {
          category: 'ARCHITECTURE',
          severity: 'INFO',
          title: `Limited analysis: ${lang} is not yet deeply supported`,
          description:
            `Only ${pct}% of this codebase (by lines of code) is in a language CodeTruss deeply ` +
            `analyzes for structure (TypeScript, JavaScript, Python, plus C#, Go, Java, Rust, PHP ` +
            `and Ruby via AST parsing). ${lang} is currently surface-scanned only. The scores in ` +
            `this report reflect structure, secrets, file-size and documentation checks — they do ` +
            `NOT include architecture, call-flow, data-flow or complexity analysis for ${lang}, and ` +
            `the knowledge graph is largely empty for this repo. Read the architecture and health ` +
            `scores as provisional for the ${lang} portion of the codebase.`,
          suggestion:
            `Interpret this report as a surface audit of the ${lang} code. Deep ${lang} support ` +
            `(symbol graph, call/data flow) is on the roadmap; until then, no architecture or flow ` +
            `analysis was performed for it.`,
          impactScore: 20,
          effort: 'low',
          metadata: {
            structureRatio: coverage.structureRatio,
            securityRatio: coverage.securityRatio,
            structureLoc: coverage.structureLoc,
            totalLoc: coverage.totalLoc,
            surfaceLanguages: coverage.surfaceLanguages,
          },
        },
      ]
    }

    if (coverage.securityLimited) {
      const lang =
        coverage.primaryLanguage ?? coverage.structureOnlyLanguages[0] ?? 'this language'
      return [
        {
          category: 'SECURITY_HYGIENE',
          severity: 'INFO',
          title: `Security is surface-only for ${lang}`,
          description:
            `Structure and complexity for ${lang} are fully analyzed via AST parsing — the ` +
            `architecture, call-graph and health scores reflect the real code. Security, however, ` +
            `is surface-only: CodeTruss ran secret scanning (regex) over ${lang}, NOT a full ` +
            `security review. CodeTruss's SAST engine (security rules + taint tracking for ` +
            `injection, untrusted-input and deserialization) runs only for TypeScript, JavaScript ` +
            `and Python. Read the security score as "no leaked secrets found", not "this code is ` +
            `secure".`,
          suggestion:
            `Treat the security score as secret-scanning coverage only for ${lang}. A manual ` +
            `security review is still warranted for injection, untrusted input and deserialization.`,
          impactScore: 20,
          effort: 'low',
          metadata: {
            structureRatio: coverage.structureRatio,
            securityRatio: coverage.securityRatio,
            securityLoc: coverage.securityLoc,
            totalLoc: coverage.totalLoc,
            structureOnlyLanguages: coverage.structureOnlyLanguages,
          },
        },
      ]
    }

    return []
  },
}
