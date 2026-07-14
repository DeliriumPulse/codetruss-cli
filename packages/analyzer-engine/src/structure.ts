import type { Analyzer, AnalyzerFinding } from './types'

/**
 * Code-file count above which cross-file views (knowledge graph, duplication)
 * reliably hit their node/entry caps, so the user must be told coverage is a
 * sample. Comfortably below the graph's node cap in file terms.
 */
const LARGE_REPO_CODE_FILES = 1500

/** Project structure & hygiene: missing README, tests, CI, licenses, huge dirs. */
export const structureAnalyzer: Analyzer = {
  id: 'structure',
  name: 'Project Structure',
  description: 'Checks for weak project structure and missing project hygiene files.',
  async run(index) {
    const findings: AnalyzerFinding[] = []
    const paths = index.files.map((f) => f.path)
    const has = (test: (p: string) => boolean) => paths.some(test)

    if (!has((p) => /^readme(\.md|\.rst|\.txt)?$/i.test(p))) {
      findings.push({
        category: 'DOCUMENTATION',
        severity: 'MEDIUM',
        title: 'Missing README',
        description: 'The repository has no root README. New contributors and clients have no entry point to understand the project.',
        suggestion: 'Add a README covering purpose, setup, environment variables, and deployment.',
        impactScore: 60,
        effort: 'low',
      })
    }

    if (!has((p) => p.startsWith('.github/workflows/') || p.includes('.gitlab-ci') || p.includes('.circleci'))) {
      findings.push({
        category: 'STRUCTURE',
        severity: 'MEDIUM',
        title: 'No CI pipeline detected',
        description: 'No GitHub Actions, GitLab CI, or CircleCI configuration found. Changes are not automatically built or tested.',
        suggestion: 'Add a CI workflow that installs dependencies, builds, and runs tests on every pull request.',
        impactScore: 65,
        effort: 'medium',
      })
    }

    const testFiles = index.files.filter((f) => f.kind === 'test')
    const sourceFiles = index.files.filter((f) => f.kind === 'source' || f.kind === 'component' || f.kind === 'route')
    if (sourceFiles.length > 10 && testFiles.length === 0) {
      findings.push({
        category: 'TESTING',
        severity: 'HIGH',
        title: 'No tests detected',
        description: `The project has ${sourceFiles.length} source files and no detectable test files. Regressions will only be caught in production.`,
        suggestion: 'Introduce a test runner (Vitest/Jest/pytest) and start with tests for the most business-critical modules.',
        impactScore: 80,
        effort: 'high',
      })
    } else if (sourceFiles.length > 0 && testFiles.length > 0) {
      const ratio = testFiles.length / sourceFiles.length
      if (ratio < 0.1 && sourceFiles.length > 30) {
        findings.push({
          category: 'TESTING',
          severity: 'MEDIUM',
          title: 'Very low test-to-source ratio',
          description: `Only ${testFiles.length} test files for ${sourceFiles.length} source files (~${Math.round(ratio * 100)}%).`,
          suggestion: 'Prioritize tests for modules with the most churn and business logic.',
          impactScore: 55,
          effort: 'high',
        })
      }
    }

    // Deeply nested directory smell
    const deep = paths.filter((p) => p.split('/').length > 8)
    if (deep.length > 20) {
      findings.push({
        category: 'STRUCTURE',
        severity: 'LOW',
        title: 'Deeply nested directory structure',
        description: `${deep.length} files are nested more than 8 directories deep, which usually signals unclear module boundaries.`,
        filePath: deep[0],
        suggestion: 'Flatten the structure around clear domain modules.',
        impactScore: 30,
        effort: 'medium',
      })
    }

    // Vendored/tooling payloads: one consolidated finding per directory
    // instead of hundreds of noise findings from inside it.
    for (const [dir, count] of Object.entries(index.vendoredDirs)) {
      if (count < 3) continue // one or two config files are not repo bloat
      const severity = count > 200 ? 'HIGH' : count > 50 ? 'MEDIUM' : 'LOW'
      findings.push({
        category: 'STRUCTURE',
        severity,
        title: `Vendored tooling directory committed: ${dir}/ (${count.toLocaleString()} files)`,
        description: `The \`${dir}/\` directory contains ${count.toLocaleString()} files of vendored or agent-tooling content that is not part of this project's source. It bloats the repository, slows clones and CI, and buries real code in noise. CodeTruss excluded it from this analysis.`,
        filePath: dir,
        suggestion: `Remove \`${dir}/\` from the repository and add it to .gitignore. If parts of it are genuinely needed, vendor only those pieces or fetch them at build time.`,
        impactScore: severity === 'LOW' ? 30 : Math.min(85, 50 + Math.floor(count / 50)),
        effort: 'low',
        metadata: { files: count },
      })
    }

    // Committed generated code (excluded from LOC/graph by the indexer):
    // one transparent note instead of per-file "oversized/refactor" findings
    // on machine-written output.
    const generatedFiles = index.generatedFiles ?? {}
    const generatedPaths = Object.keys(generatedFiles)
    const generatedLoc = Object.values(generatedFiles).reduce((a, b) => a + b, 0)
    if (generatedPaths.length > 0 && generatedLoc >= 500) {
      const plural = generatedPaths.length > 1
      findings.push({
        category: 'STRUCTURE',
        severity: 'LOW',
        title: `Generated code excluded from analysis (${generatedPaths.length} file${plural ? 's' : ''}, ~${generatedLoc.toLocaleString()} LOC)`,
        description: `CodeTruss detected ${generatedPaths.length} machine-generated file${plural ? 's' : ''} (~${generatedLoc.toLocaleString()} LOC, e.g. \`${generatedPaths[0]}\`) and excluded ${plural ? 'them' : 'it'} from LOC totals, scores, and the architecture graph so ${plural ? 'they' : 'it'} don't inflate metrics or produce spurious "oversized file" / "duplicated logic" findings.`,
        filePath: generatedPaths[0],
        suggestion: 'Keep generated files out of review scope — regenerate them at build time, or mark them linguist-generated in .gitattributes.',
        impactScore: 20,
        effort: 'low',
        metadata: { files: generatedPaths.length, loc: generatedLoc },
      })
    }

    // Large-repo transparency: the knowledge graph and other cross-file views
    // are capped for performance, so on big codebases they show the
    // most-connected modules and omit the long tail. Say so plainly rather
    // than presenting a truncated graph as the whole picture.
    const codeFiles = index.files.filter(
      (f) => f.kind === 'source' || f.kind === 'component' || f.kind === 'route' || f.kind === 'test',
    )
    if (codeFiles.length >= LARGE_REPO_CODE_FILES) {
      findings.push({
        category: 'STRUCTURE',
        severity: 'LOW',
        title: 'Large repository — architecture graph limited to the most-connected modules',
        description: `This repository has ${codeFiles.length.toLocaleString()} code files. The knowledge graph and other cross-file views are capped for performance, so for a codebase this size they surface the most-connected modules and omit the long tail. Treat graph coverage as a representative sample, not a complete inventory — the file list and per-file findings remain complete.`,
        suggestion: 'Drill into individual modules for areas the graph omits; consider splitting the repository along clear domain boundaries.',
        impactScore: 15,
        effort: 'medium',
        metadata: { codeFiles: codeFiles.length },
      })
    }

    // Only real runtime .env usage warrants an .env.example: test-fixture
    // .env files don't count, and libraries have no deploy environment.
    const runtimeEnvFile = (p: string) =>
      /\.env(\.|$)/.test(p.split('/').pop() ?? '') &&
      !/(^|\/)(tests?|__tests__|__mocks__|fixtures)\//i.test(p)
    if (index.repoType !== 'library' && !has((p) => /^\.env\.example$/.test(p)) && has(runtimeEnvFile)) {
      findings.push({
        category: 'DOCUMENTATION',
        severity: 'LOW',
        title: 'No .env.example template',
        description: 'Environment files are used but there is no .env.example documenting required variables.',
        suggestion: 'Commit a .env.example with every required variable (no real values).',
        impactScore: 40,
        effort: 'low',
      })
    }

    return findings
  },
}
