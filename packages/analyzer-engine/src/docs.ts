import type { Analyzer, AnalyzerFinding } from './types'

/** Documentation coverage: README quality, missing docs for key areas. */
export const docsAnalyzer: Analyzer = {
  id: 'docs',
  name: 'Documentation Coverage',
  description: 'Evaluates README depth and documentation of setup, env vars, and architecture.',
  async run(index) {
    const findings: AnalyzerFinding[] = []
    const readme = index.files.find((f) => /^readme\.md$/i.test(f.path))

    if (readme?.content) {
      const content = readme.content.toLowerCase()
      const words = readme.content.split(/\s+/).length
      if (words < 80) {
        findings.push({
          category: 'DOCUMENTATION',
          severity: 'MEDIUM',
          title: 'README is too thin',
          description: `The README is only ~${words} words. It does not meaningfully explain the project.`,
          filePath: readme.path,
          suggestion: 'Document purpose, quick start, environment variables, scripts, and deployment.',
          impactScore: 50,
          effort: 'low',
        })
      }
      // Libraries are installed, not deployed — demanding env-var and
      // deployment sections in a library README is checklist noise.
      const isLibrary = index.repoType === 'library'
      // Dedicated docs (e.g. docs/deploying/*) count as deployment coverage
      // even when the README itself says nothing about it.
      const hasDeploymentDocs = index.files.some(
        (f) => f.kind === 'doc' && /deploy/i.test(f.path),
      )
      const sections: Array<[string, RegExp, boolean]> = [
        ['setup/installation instructions', /(install|setup|getting started|quick ?start)/, false],
        ['environment variable documentation', /(env|environment variable|\.env)/, isLibrary],
        ['deployment notes', /(deploy|production|hosting)/, isLibrary || hasDeploymentDocs],
      ]
      for (const [what, re, skip] of sections) {
        if (skip) continue
        if (!re.test(content)) {
          findings.push({
            category: 'DOCUMENTATION',
            severity: 'LOW',
            title: `README missing ${what}`,
            description: `The README does not appear to cover ${what}.`,
            filePath: readme.path,
            suggestion: `Add a section covering ${what}.`,
            impactScore: 35,
            effort: 'low',
          })
        }
      }
    }

    // Undocumented API routes
    const routes = index.files.filter((f) => f.kind === 'route')
    const docFiles = index.files.filter((f) => f.kind === 'doc')
    if (routes.length > 8 && docFiles.length <= 1) {
      findings.push({
        category: 'DOCUMENTATION',
        severity: 'MEDIUM',
        title: `${routes.length} routes with almost no docs`,
        description: 'The project exposes many routes/endpoints but has essentially no documentation beyond (at most) a README.',
        suggestion: 'Generate API/route documentation — CodeTruss can produce this from a scan.',
        impactScore: 45,
        effort: 'medium',
      })
    }

    return findings
  },
}
