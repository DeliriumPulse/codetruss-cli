import type { Analyzer, AnalyzerFinding } from './types'

/** Environment variable usage vs. documentation drift. */
export const envVarsAnalyzer: Analyzer = {
  id: 'env-vars',
  name: 'Environment Variables',
  description: 'Cross-references env vars used in code against .env.example documentation.',
  async run(index) {
    const findings: AnalyzerFinding[] = []
    const used = new Set<string>()

    for (const f of index.files) {
      if (!f.content || f.kind === 'doc' || f.kind === 'test') continue
      // Test fixtures reference made-up vars; only production code drives docs drift.
      if (/(^|\/)(tests?|__tests__|__mocks__|fixtures)\//.test(f.path) || /\.(test|spec)\.\w+$/.test(f.path)) continue
      // CI/tooling vars (GITHUB_TOKEN in workflows or .github/ scripts) are
      // provided by the CI platform, not a local .env — not runtime usage.
      if (/(^|\/)\.(github|gitlab|circleci)\//.test(f.path)) continue
      for (const m of f.content.matchAll(/process\.env\.([A-Z][A-Z0-9_]{2,})/g)) {
        // Skip mentions inside string literals (docs, examples, marketing copy)
        const lineStart = f.content.lastIndexOf('\n', m.index) + 1
        const before = f.content.slice(lineStart, m.index)
        const quotes = (before.match(/['"`]/g) ?? []).length
        if (quotes % 2 === 1) continue
        used.add(m[1])
      }
      for (const m of f.content.matchAll(/os\.environ(?:\.get)?\(["']([A-Z][A-Z0-9_]{2,})["']/g)) used.add(m[1])
      for (const m of f.content.matchAll(/ENV\[["']([A-Z][A-Z0-9_]{2,})["']\]/g)) used.add(m[1])
    }
    if (used.size === 0) return findings

    // Env templates go by several conventional names — any of them counts.
    // Content-bearing matches only: a vendored/unreadable duplicate (a stale
    // worktree copy, an oversized file) must not shadow the real template and
    // turn every used var into a false "undocumented" finding.
    const template = index.files.find((f) =>
      f.content &&
      /^(\.env\.(example|sample|template|dist)|\.env\.local\.example|env\.example)$/.test(f.path.split('/').pop() ?? ''),
    )
    const documented = new Set<string>()
    if (template?.content) {
      for (const m of template.content.matchAll(/^([A-Z][A-Z0-9_]{2,})=/gm)) documented.add(m[1])
    }

    // Prose documentation counts too: a var named in the README or docs/ is
    // discoverable without a template file. Whole-token matches only — a
    // README documenting HOSTNAME must not credit HOST.
    const docContents = index.files.filter((f) => f.kind === 'doc' && f.content).map((f) => f.content!)
    const documentedInProse = (v: string) => {
      const token = new RegExp(
        `(?<![A-Za-z0-9_])${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9_])`,
      )
      return docContents.some((c) => token.test(c))
    }

    const BUILTINS = new Set(['NODE_ENV', 'PORT', 'CI', 'HOME', 'PATH', 'VERCEL', 'VERCEL_ENV', 'VERCEL_URL'])
    // GITHUB_* vars are injected by the CI platform (e.g. GITHUB_TOKEN read by
    // maintenance scripts) — they never belong in .env.example.
    const undocumented = [...used].filter(
      (v) =>
        !documented.has(v) &&
        !BUILTINS.has(v) &&
        !v.startsWith('GITHUB_') &&
        !documentedInProse(v),
    )
    if (undocumented.length === 0) return findings

    if (template) {
      // The repo opted into the template convention — report per-var drift.
      const templateName = template.path.split('/').pop()
      findings.push({
        category: 'DOCUMENTATION',
        severity: undocumented.length > 5 ? 'MEDIUM' : 'LOW',
        title: `${undocumented.length} environment variable(s) not documented`,
        description: `Used in code but missing from ${templateName}: ${undocumented.slice(0, 10).join(', ')}${undocumented.length > 10 ? '…' : ''}. New environments will fail in ways only the original author can debug.`,
        suggestion: `Add each variable to ${templateName} with a comment explaining its purpose.`,
        impactScore: 45,
        effort: 'low',
        metadata: { variables: undocumented.slice(0, 50) },
      })
    } else if (index.repoType !== 'library') {
      // No template at all: one LOW nudge, not a per-var wall. Libraries have
      // no deploy environment, so skip them entirely.
      findings.push({
        category: 'DOCUMENTATION',
        severity: 'LOW',
        title: 'No .env.example documenting required environment variables',
        description: `${undocumented.length} environment variable(s) are read in code but no .env.example (or similar template) documents them. New environments will fail in ways only the original author can debug.`,
        suggestion: 'Commit a .env.example listing each required variable with a comment explaining its purpose (no real values).',
        impactScore: 40,
        effort: 'low',
        metadata: { variables: undocumented.slice(0, 50) },
      })
    }

    return findings
  },
}
