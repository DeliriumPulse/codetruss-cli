import { readFile } from 'fs/promises'
import { join } from 'path'
import type { Analyzer, AnalyzerFinding } from './types'

/**
 * Dependency hygiene (defensive): known-risky patterns, missing lockfiles,
 * wildcard versions, deprecated ecosystems. Does not call external services;
 * a CVE feed integration is a clean extension point here.
 */
const RISKY_DEPS: Record<string, string> = {
  request: 'Deprecated since 2020; unpatched. Replace with fetch/undici/axios.',
  'node-sass': 'Deprecated; replace with `sass` (dart-sass).',
  moment: 'In maintenance mode; large bundle. Prefer date-fns, dayjs, or Temporal.',
  'crypto-js': 'Unmaintained; use the platform WebCrypto/node:crypto instead.',
  'event-stream': 'Historically compromised in a supply-chain attack; avoid.',
  colors: 'Had a sabotage incident (v1.4.44+); pin carefully or use picocolors.',
  faker: 'Original package sabotaged; use @faker-js/faker.',
  'left-pad': 'Trivial dependency; inline it.',
}

export const dependencyAnalyzer: Analyzer = {
  id: 'dependencies',
  name: 'Dependency Hygiene',
  description: 'Flags risky, deprecated, or unpinned dependencies and missing lockfiles.',
  async run(index) {
    const findings: AnalyzerFinding[] = []
    const paths = index.files.map((f) => f.path)

    const hasPackageJson = paths.some((p) => p === 'package.json')
    const hasLockfile = ['pnpm-lock.yaml', 'yarn.lock', 'package-lock.json', 'bun.lockb', 'bun.lock'].some((f) =>
      paths.includes(f),
    )
    if (hasPackageJson && !hasLockfile) {
      // A .gitignore that lists lockfiles is deliberate policy (common for
      // published libraries) — flagging it HIGH misreads a healthy repo.
      const gitignore = index.files.find((f) => f.path === '.gitignore')?.content ?? ''
      const lockfilesIgnored = gitignore
        .split('\n')
        .some((l) => /^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|npm-shrinkwrap\.json|\*\.lock)$/.test(l.trim()))
      if (lockfilesIgnored) {
        findings.push({
          category: 'DEPENDENCY',
          severity: 'LOW',
          title: 'Lockfiles intentionally ignored',
          description:
            'The .gitignore explicitly excludes lockfiles — a deliberate policy, typical for published libraries that must resolve against consumers\' dependency trees. Contributor installs are not byte-reproducible; CI should exercise fresh installs.',
          filePath: '.gitignore',
          suggestion: 'No action needed if this is intentional library policy; otherwise remove the lockfile entries from .gitignore and commit one.',
          impactScore: 20,
          effort: 'low',
        })
      } else {
        const isLibrary = index.repoType === 'library'
        findings.push({
          category: 'DEPENDENCY',
          severity: isLibrary ? 'MEDIUM' : 'HIGH',
          title: 'No lockfile committed',
          description: 'package.json exists but no lockfile is committed. Builds are not reproducible and supply-chain drift is invisible.',
          suggestion: 'Commit the lockfile for your package manager and enforce frozen-lockfile installs in CI.',
          impactScore: isLibrary ? 55 : 75,
          effort: 'low',
        })
      }
    }

    for (const [dep, why] of Object.entries(RISKY_DEPS)) {
      if (index.dependencies.has(dep)) {
        findings.push({
          category: 'DEPENDENCY',
          severity: 'MEDIUM',
          title: `Risky dependency: ${dep}`,
          description: why,
          filePath: 'package.json',
          suggestion: `Replace or remove "${dep}".`,
          impactScore: 60,
          effort: 'medium',
        })
      }
    }

    // Wildcard / loose versions in root package.json
    if (hasPackageJson) {
      try {
        const raw = await readFile(join(index.root, 'package.json'), 'utf8')
        const pkg = JSON.parse(raw)
        const loose = Object.entries({ ...pkg.dependencies })
          .filter(([, v]) => typeof v === 'string' && (v === '*' || v === 'latest' || v.startsWith('>')))
          .map(([k]) => k)
        if (loose.length > 0) {
          findings.push({
            category: 'DEPENDENCY',
            severity: 'MEDIUM',
            title: `Unpinned dependency versions: ${loose.slice(0, 5).join(', ')}${loose.length > 5 ? '…' : ''}`,
            description: 'Wildcard or "latest" version ranges let breaking or malicious releases in without review.',
            filePath: 'package.json',
            suggestion: 'Pin to caret or exact ranges and update deliberately.',
            impactScore: 55,
            effort: 'low',
          })
        }
      } catch {
        // ignore
      }
    }

    return findings
  },
}
