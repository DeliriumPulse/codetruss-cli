/** Language, framework, and file-kind detection heuristics. */

const EXT_LANGUAGE: Record<string, string> = {
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript',
  '.js': 'JavaScript',
  '.jsx': 'JavaScript',
  '.mjs': 'JavaScript',
  '.cjs': 'JavaScript',
  '.py': 'Python',
  '.rb': 'Ruby',
  '.go': 'Go',
  '.rs': 'Rust',
  '.java': 'Java',
  '.kt': 'Kotlin',
  '.swift': 'Swift',
  '.cs': 'C#',
  '.php': 'PHP',
  '.c': 'C',
  '.h': 'C',
  '.cpp': 'C++',
  '.hpp': 'C++',
  '.scala': 'Scala',
  '.ex': 'Elixir',
  '.exs': 'Elixir',
  '.vue': 'Vue',
  '.svelte': 'Svelte',
  '.sql': 'SQL',
  '.sh': 'Shell',
  '.css': 'CSS',
  '.scss': 'CSS',
  '.html': 'HTML',
  '.md': 'Markdown',
  '.yml': 'YAML',
  '.yaml': 'YAML',
  '.json': 'JSON',
  '.tf': 'Terraform',
  '.prisma': 'Prisma',
}

export function detectLanguage(path: string): string | null {
  const dot = path.lastIndexOf('.')
  if (dot === -1) return null
  return EXT_LANGUAGE[path.slice(dot).toLowerCase()] ?? null
}

/** Classify what role a file plays in the project. */
export function classifyFile(path: string): string {
  const p = path.toLowerCase()
  const base = p.split('/').pop() ?? p

  if (/\.(test|spec)\.[jt]sx?$/.test(base) || p.includes('__tests__/') || p.startsWith('test/') || p.startsWith('tests/'))
    return 'test'
  if (p.includes('/migrations/') || p.includes('/migrate/')) return 'migration'
  if (base === 'dockerfile' || base === 'package.json' || /\.(ya?ml|toml|ini|env\.example)$/.test(base) || base.startsWith('.env'))
    return 'config'
  if (/\.(md|rst|txt)$/.test(base)) return 'doc'
  if (/\/(app|pages)\/.*(page|route|layout)\.[jt]sx?$/.test(p) || p.includes('/api/')) return 'route'
  if (/\.(tsx|jsx|vue|svelte)$/.test(base)) return 'component'
  if (/\.(json|lock|svg|png|jpe?g|gif|ico)$/.test(base)) return 'asset'
  return 'source'
}

export interface FrameworkSignal {
  name: string
  evidence: string
}

/** Detect frameworks/tools from dependency names + file presence. */
export function detectFrameworks(deps: Set<string>, paths: string[]): FrameworkSignal[] {
  const found: FrameworkSignal[] = []
  const has = (d: string) => deps.has(d)
  const anyPath = (fn: (p: string) => boolean) => paths.some(fn)

  const rules: Array<[string, () => boolean, string]> = [
    ['Next.js', () => has('next'), 'package dependency "next"'],
    ['React', () => has('react'), 'package dependency "react"'],
    ['Vue', () => has('vue'), 'package dependency "vue"'],
    ['Svelte', () => has('svelte'), 'package dependency "svelte"'],
    ['Angular', () => has('@angular/core'), 'package dependency "@angular/core"'],
    ['Express', () => has('express'), 'package dependency "express"'],
    ['Fastify', () => has('fastify'), 'package dependency "fastify"'],
    ['NestJS', () => has('@nestjs/core'), 'package dependency "@nestjs/core"'],
    ['Prisma', () => has('@prisma/client') || anyPath((p) => p.endsWith('schema.prisma')), 'Prisma schema/client'],
    ['Drizzle', () => has('drizzle-orm'), 'package dependency "drizzle-orm"'],
    ['Tailwind CSS', () => has('tailwindcss'), 'package dependency "tailwindcss"'],
    ['tRPC', () => has('@trpc/server'), 'package dependency "@trpc/server"'],
    ['GraphQL', () => has('graphql'), 'package dependency "graphql"'],
    ['Electron', () => has('electron'), 'package dependency "electron"'],
    ['Django', () => anyPath((p) => p.endsWith('manage.py')), 'manage.py present'],
    ['Flask', () => anyPath((p) => p.endsWith('requirements.txt')) && anyPath((p) => /app\.py$/.test(p)), 'Flask layout'],
    ['FastAPI', () => has('fastapi') || (anyPath((p) => p.endsWith('requirements.txt')) && anyPath((p) => /main\.py$/.test(p))), 'dependency "fastapi" or FastAPI layout'],
    ['CrewAI', () => has('crewai'), 'package dependency "crewai"'],
    ['Rails', () => anyPath((p) => p.endsWith('config/routes.rb')), 'config/routes.rb present'],
    ['Go modules', () => anyPath((p) => p.endsWith('go.mod')), 'go.mod present'],
    ['Cargo (Rust)', () => anyPath((p) => p.endsWith('Cargo.toml')), 'Cargo.toml present'],
    // .NET / C#: detectFrameworks only sees paths (csproj <PackageReference>
    // content isn't parsed into `deps`), so the specific stack — BepInEx,
    // Harmony, Steamworks, EF Core — surfaces as DEPENDENCY nodes in the
    // knowledge graph from `using` directives instead. Here we name the
    // ecosystem and the web frameworks that DO leave a path fingerprint, so a
    // C# repo never renders "No frameworks detected."
    ['.NET', () => anyPath((p) => /\.(csproj|sln|fsproj|vbproj)$/.test(p)), '.NET project/solution file'],
    ['ASP.NET Core', () => anyPath((p) => /(^|\/)(Program|Startup)\.cs$/.test(p)) && anyPath((p) => /(^|\/)appsettings(\.\w+)?\.json$/.test(p)), 'ASP.NET Core layout (Program/Startup + appsettings.json)'],
    ['Blazor', () => anyPath((p) => p.endsWith('.razor')), '.razor components present'],
    ['Unity', () => anyPath((p) => p.endsWith('.asmdef') || p.endsWith('.unity')) || anyPath((p) => /(^|\/)ProjectSettings\/ProjectVersion\.txt$/.test(p)), 'Unity project files present'],
    ['Docker', () => anyPath((p) => /(^|\/)dockerfile$/i.test(p)), 'Dockerfile present'],
    ['GitHub Actions', () => anyPath((p) => p.startsWith('.github/workflows/')), '.github/workflows present'],
    ['Vitest', () => has('vitest'), 'package dependency "vitest"'],
    ['Jest', () => has('jest'), 'package dependency "jest"'],
    ['Playwright', () => has('@playwright/test'), 'package dependency "@playwright/test"'],
    ['Stripe', () => has('stripe'), 'package dependency "stripe"'],
  ]

  for (const [name, test, evidence] of rules) {
    if (test()) found.push({ name, evidence })
  }
  return found
}

/** Minimal file shape shared by detection helpers (structural subset of IndexedFile). */
export interface DetectableFile {
  path: string
  content: string | null
}

export function detectPackageManagers(files: DetectableFile[]): string[] {
  const paths = files.map((f) => f.path)
  const managers: string[] = []
  const has = (f: string) => paths.some((p) => p === f || p.endsWith(`/${f}`))
  if (has('pnpm-lock.yaml')) managers.push('pnpm')
  if (has('yarn.lock')) managers.push('yarn')
  if (has('package-lock.json')) managers.push('npm')
  if (has('bun.lockb') || has('bun.lock')) managers.push('bun')
  // package.json with no lockfile still means npm-compatible tooling — say so
  // honestly instead of "None detected" (which contradicts other findings).
  if (managers.length === 0 && has('package.json')) managers.push('npm (no lockfile)')

  // Python: prefer specific lockfile/build-backend evidence over a generic label
  if (has('uv.lock')) managers.push('uv')
  if (has('poetry.lock')) managers.push('poetry')
  if (has('Pipfile.lock')) managers.push('pipenv')
  const pyproject = files.find((f) => f.path === 'pyproject.toml' || f.path.endsWith('/pyproject.toml'))
  const backend = pyproject?.content?.match(/^\s*build-backend\s*=\s*["']([^"']+)/m)?.[1]
  if (backend?.includes('flit')) managers.push('flit')
  else if (backend?.includes('hatch') && !managers.includes('hatch')) managers.push('hatch')
  else if (backend?.includes('poetry') && !managers.includes('poetry')) managers.push('poetry')
  const hasPythonManager = ['uv', 'poetry', 'pipenv', 'flit', 'hatch'].some((m) => managers.includes(m))
  if (!hasPythonManager && (has('requirements.txt') || pyproject)) managers.push('pip')

  if (has('Gemfile.lock')) managers.push('bundler')
  if (has('go.sum')) managers.push('go modules')
  if (has('Cargo.lock')) managers.push('cargo')
  if (has('composer.lock')) managers.push('composer')

  // .NET / NuGet: any project or solution file (or an explicit restore
  // manifest) means NuGet-restored dependencies. Without this a whole C#
  // codebase reports "None detected", contradicting the rest of the audit.
  const anyExt = (ext: string) => paths.some((p) => p.endsWith(ext))
  if (
    anyExt('.csproj') || anyExt('.fsproj') || anyExt('.vbproj') || anyExt('.sln') ||
    has('packages.config') || has('Directory.Packages.props')
  ) {
    managers.push('NuGet')
  }
  return managers
}

/**
 * Dependency names (lowercased) from a requirements.txt — version specifiers,
 * extras, comments, and pip flags (`-r`, `-e`, …) are stripped. PyPI names are
 * case-insensitive, so lowercasing lets detectFrameworks match exactly.
 */
export function parseRequirementsTxt(content: string): string[] {
  const deps: string[] = []
  for (const raw of content.split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#') || line.startsWith('-')) continue
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/)
    if (m) deps.push(m[1].toLowerCase())
  }
  return deps
}

/**
 * Dependency names (lowercased) from a pyproject.toml: PEP 621
 * `dependencies = [...]` arrays and poetry-style `[tool.poetry.dependencies]`
 * tables (the `python` version pin is not a dependency).
 */
export function parsePyprojectDeps(content: string): string[] {
  const deps: string[] = []
  // `(?:[^[\]]|\[[^\]]*\])*` tolerates extras brackets ("crewai[tools]>=…") inside the array
  const list = content.match(/^[ \t]*dependencies[ \t]*=[ \t]*\[((?:[^[\]]|\[[^\]]*\])*)\]/m)
  if (list) {
    for (const m of list[1].matchAll(/["'][ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)/g)) deps.push(m[1].toLowerCase())
  }
  const poetry = content.match(/\[tool\.poetry(?:\.group\.\w+)?\.dependencies\]([\s\S]*?)(?=\n[ \t]*\[|$)/)
  if (poetry) {
    for (const m of poetry[1].matchAll(/^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*=/gm)) {
      const name = m[1].toLowerCase()
      if (name !== 'python') deps.push(name)
    }
  }
  return deps
}

export type RepoType = 'library' | 'application'

/**
 * Library vs. application: published libraries legitimately skip lockfiles,
 * .env.example, deployment docs, etc., so several checks gate on this.
 * Signals: a root package.json with a publish surface (main/exports/files)
 * and no server entrypoint, or a pyproject.toml with a build-backend.
 */
export function detectRepoType(files: DetectableFile[]): RepoType {
  const rootPkg = files.find((f) => f.path === 'package.json')
  if (rootPkg?.content) {
    try {
      const pkg = JSON.parse(rootPkg.content)
      const scripts: Record<string, unknown> = pkg.scripts ?? {}
      const deps = { ...pkg.dependencies, ...pkg.devDependencies }
      const hasServerEntry = Boolean(scripts.start || scripts.dev) || 'next' in deps
      const hasPublishSurface = Boolean(pkg.main || pkg.exports || pkg.module || pkg.files || pkg.bin)
      if (pkg.private !== true && !hasServerEntry && hasPublishSurface) return 'library'
    } catch {
      // unparseable package.json — fall through
    }
  }
  const pyproject = files.find((f) => f.path === 'pyproject.toml')
  if (pyproject?.content && /^\s*build-backend\s*=/m.test(pyproject.content)) return 'library'
  return 'application'
}

/** Generated artifacts declare themselves in the first few lines — don't hand-refactor them. */
export function looksGenerated(content: string): boolean {
  const head = content.split('\n', 5).join('\n')
  return /auto-?generated|@generated|generated by|do not edit/i.test(head)
}

export function detectDatabases(deps: Set<string>, paths: string[]): string[] {
  const dbs: string[] = []
  if (deps.has('pg') || deps.has('postgres')) dbs.push('PostgreSQL')
  if (deps.has('mysql2') || deps.has('mysql')) dbs.push('MySQL')
  if (deps.has('mongodb') || deps.has('mongoose')) dbs.push('MongoDB')
  if (deps.has('better-sqlite3') || deps.has('sqlite3')) dbs.push('SQLite')
  if (deps.has('redis') || deps.has('ioredis')) dbs.push('Redis')
  if (deps.has('@supabase/supabase-js')) dbs.push('Supabase')
  if (paths.some((p) => p.endsWith('schema.prisma'))) {
    if (!dbs.length) dbs.push('SQL (via Prisma)')
  }
  return dbs
}
