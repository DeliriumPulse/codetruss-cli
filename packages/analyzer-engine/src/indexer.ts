import { readdir, readFile, stat } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { createHash } from 'node:crypto'
import type { IndexedFile, RepoIndex } from './types'
import {
  classifyFile,
  detectDatabases,
  detectFrameworks,
  detectLanguage,
  detectPackageManagers,
  detectRepoType,
  looksGenerated,
  parsePyprojectDeps,
  parseRequirementsTxt,
} from './detect'

const IGNORED_DIRS = new Set([
  '.git', 'node_modules', '.next', 'dist', 'build', 'out', 'coverage',
  '.venv', 'venv', '__pycache__', '.pytest_cache', 'vendor', 'target',
  '.turbo', '.cache', '.idea', '.vscode',
])

const DEFAULT_MAX_FILES = 20_000
const DEFAULT_MAX_FILE_BYTES = 1_000_000 // skip reading content over 1MB
const TEXT_KINDS = new Set(['source', 'component', 'route', 'test', 'config', 'doc', 'migration'])
/** Markup/data languages that must never appear in code LOC stats. */
const NON_CODE_LANGUAGES = new Set(['Markdown', 'YAML', 'JSON'])

/**
 * Vendored/tooling directories: third-party or agent-tooling payloads that
 * live inside the repo but are not the product's code. Analyzing them buries
 * real findings under noise — they are excluded from analysis and surfaced
 * as ONE "this should not be committed" finding instead.
 */
const VENDORED_ROOT_RE =
  /^(?:\.agent|\.claude|\.cursor|\.windsurf|\.aider|\.gemini|vendor|vendors|third[-_]?party|external|externals)(?:\/|$)/i

export function vendoredRoot(path: string): string | null {
  const m = path.match(VENDORED_ROOT_RE)
  return m ? m[0].replace(/\/$/, '') : null
}

/**
 * Committed generated code that the directory-based ignores (node_modules,
 * dist, build, …) never see because the generator writes it straight into the
 * source tree. Two content signals, not repo-specific paths, so the rule holds
 * across repos:
 *  - a self-declaring header (`@generated`, "DO NOT EDIT", "auto-generated") —
 *    the convention emitted by protobuf, GraphQL codegen, OpenAPI clients, etc.
 *  - a code generator's unmistakable fingerprint for output that ships no
 *    header, e.g. the Supabase CLI's `gen types typescript` (tens of thousands
 *    of lines of machine-written type declarations).
 * Such files inflate LOC, drag scores with bogus "oversized/duplicated"
 * findings, and blow the knowledge-graph node cap — so they are excluded from
 * analysis and surfaced as one transparent note instead.
 */
export function generatedLabel(content: string): string | null {
  if (looksGenerated(content)) return 'self-declared generated file'
  const head = content.slice(0, 4000)
  // Supabase `supabase gen types typescript` — large, header-less, generated.
  if (/\b__InternalSupabase\b/.test(head) && /\bexport type Database\b/.test(head)) {
    return 'Supabase generated types'
  }
  return null
}

export type { IndexCoverage, IndexedFile, RepoIndex } from './types'

function positiveEnvInt(name: string, fallback: number): number {
  const parsed = Number(process.env[name])
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback
}

async function walk(
  dir: string,
  root: string,
  state: { paths: string[]; maxFiles: number; truncated: boolean },
): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true })
  for (const entry of entries) {
    if (state.paths.length >= state.maxFiles) {
      state.truncated = true
      return
    }
    if (entry.isSymbolicLink()) continue
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue
      await walk(full, root, state)
    } else if (entry.isFile()) {
      state.paths.push(relative(root, full))
    }
  }
}

/** Index a checked-out working tree into a structured RepoIndex. */
export async function indexWorkingTree(root: string): Promise<RepoIndex> {
  const maxFiles = positiveEnvInt('CODETRUSS_MAX_INDEX_FILES', DEFAULT_MAX_FILES)
  const maxFileBytes = positiveEnvInt('CODETRUSS_MAX_INDEX_FILE_BYTES', DEFAULT_MAX_FILE_BYTES)
  const walkState = { paths: [] as string[], maxFiles, truncated: false }
  await walk(root, root, walkState)
  const paths = walkState.paths

  // Parse dependencies from package.json files (root-level first);
  // vendored payloads' manifests would poison framework detection — skip them
  const dependencies = new Set<string>()
  for (const p of paths.filter((p) => p.endsWith('package.json') && !vendoredRoot(p)).slice(0, 20)) {
    try {
      const pkg = JSON.parse(await readFile(join(root, p), 'utf8'))
      for (const dep of Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })) {
        dependencies.add(dep)
      }
    } catch {
      // unparseable package.json — skip
    }
  }
  // Python manifests: requirements.txt and pyproject.toml — package.json alone
  // means Python frameworks (FastAPI, CrewAI, …) could never surface here.
  for (const p of paths.filter((p) => p.endsWith('requirements.txt') && !vendoredRoot(p)).slice(0, 20)) {
    try {
      for (const dep of parseRequirementsTxt(await readFile(join(root, p), 'utf8'))) dependencies.add(dep)
    } catch {
      // unreadable requirements.txt — skip
    }
  }
  for (const p of paths.filter((p) => p.endsWith('pyproject.toml') && !vendoredRoot(p)).slice(0, 20)) {
    try {
      for (const dep of parsePyprojectDeps(await readFile(join(root, p), 'utf8'))) dependencies.add(dep)
    } catch {
      // unreadable pyproject.toml — skip
    }
  }

  const files: IndexedFile[] = []
  const languages: Record<string, number> = {}
  let totalLoc = 0

  const vendoredDirs: Record<string, number> = {}
  const generatedFiles: Record<string, number> = {}
  let textCandidates = 0
  let contentLoaded = 0
  let oversizedTextFiles = 0
  let unreadableTextFiles = 0
  let binaryTextFiles = 0

  for (const path of paths) {
    let size = 0
    try {
      size = (await stat(join(root, path))).size
    } catch {
      continue
    }
    const language = detectLanguage(path)

    // Vendored/tooling payloads: count them, but never read or analyze them
    const vendored = vendoredRoot(path)
    if (vendored) {
      vendoredDirs[vendored] = (vendoredDirs[vendored] ?? 0) + 1
      files.push({ path, language, kind: 'vendored', sizeBytes: size, loc: 0, sha: null, content: null })
      continue
    }

    const kind = classifyFile(path)

    let content: string | null = null
    let loc = 0
    let sha: string | null = null
    if (TEXT_KINDS.has(kind)) textCandidates++
    if (TEXT_KINDS.has(kind) && size > maxFileBytes) oversizedTextFiles++
    if (TEXT_KINDS.has(kind) && size <= maxFileBytes) {
      try {
        content = await readFile(join(root, path), 'utf8')
        if (content.includes('\u0000')) {
          binaryTextFiles++
          content = null // binary masquerading as text
        } else {
          contentLoaded++
          loc = content.split('\n').filter((l) => l.trim().length > 0).length
          sha = createHash('sha1').update(content).digest('hex')
        }
      } catch {
        unreadableTextFiles++
        content = null
      }
    }

    // Committed generated code masquerading as source: exclude it from LOC,
    // language stats, and all content analysis (null content drops it from the
    // knowledge graph too), and record it for one consolidated finding. Only
    // code kinds are eligible — a doc/config with a "do not edit" banner is not
    // machine-written source.
    if (
      content &&
      (kind === 'source' || kind === 'component' || kind === 'route' || kind === 'test') &&
      generatedLabel(content)
    ) {
      generatedFiles[path] = loc
      files.push({ path, language, kind: 'generated', sizeBytes: size, loc, sha, content: null })
      continue
    }

    // Only count code toward language/LOC stats. The kind check misses
    // docs/config nested under test dirs (classified 'test'), so also
    // exclude non-code languages outright — a stray "YAML — 2 LOC" line
    // in the report reads as a false fact.
    if (
      language &&
      loc > 0 &&
      kind !== 'doc' &&
      kind !== 'config' &&
      !NON_CODE_LANGUAGES.has(language)
    ) {
      languages[language] = (languages[language] ?? 0) + loc
      totalLoc += loc
    }

    files.push({ path, language, kind, sizeBytes: size, loc, sha, content })
  }

  const primaryLanguage =
    Object.entries(languages).sort((a, b) => b[1] - a[1])[0]?.[0] ?? null

  return {
    root,
    files,
    languages,
    frameworks: detectFrameworks(dependencies, paths),
    packageManagers: detectPackageManagers(files),
    databases: detectDatabases(dependencies, paths),
    dependencies,
    totalLoc,
    primaryLanguage,
    repoType: detectRepoType(files),
    vendoredDirs,
    generatedFiles,
    coverage: {
      discoveredFiles: paths.length,
      maxFiles,
      truncated: walkState.truncated,
      textCandidates,
      contentLoaded,
      oversizedTextFiles,
      unreadableTextFiles,
      binaryTextFiles,
    },
  }
}
