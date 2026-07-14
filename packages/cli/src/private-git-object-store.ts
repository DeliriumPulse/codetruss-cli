import { randomUUID } from 'node:crypto'
import { chmod, lstat, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { runGitText } from './git-process.js'

export const CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV = 'CODETRUSS_EVIDENCE_OBJECT_DIRECTORY'
const OWNER_FILE = 'codetruss-object-store.json'
const OWNER_KIND = 'codetruss-private-git-object-store'
const REPOSITORY_LOCAL_GIT_ENVIRONMENT = [
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR',
  'GIT_CONFIG',
  'GIT_CONFIG_COUNT',
  'GIT_CONFIG_PARAMETERS',
  'GIT_DIR',
  'GIT_GRAFT_FILE',
  'GIT_IMPLICIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_INTERNAL_SUPER_PREFIX',
  'GIT_NO_REPLACE_OBJECTS',
  'GIT_OBJECT_DIRECTORY',
  'GIT_PREFIX',
  'GIT_QUARANTINE_PATH',
  'GIT_REPLACE_REF_BASE',
  'GIT_SHALLOW_FILE',
  'GIT_WORK_TREE',
] as const

export interface PrivateGitObjectStore {
  /** Private directory that can be removed as a unit after evidence is consumed. */
  directory: string
  /** Git object database beneath directory. This is the only write target. */
  objectDirectory: string
  /** The repository object database, exposed read-only as an alternate while writing. */
  repositoryObjectDirectory: string
  objectFormat: 'sha1' | 'sha256'
  objectIdLength: 40 | 64
  assertObjectId(value: string, label?: string): void
  writeEnvironment(base?: NodeJS.ProcessEnv): NodeJS.ProcessEnv
  readEnvironment(base?: NodeJS.ProcessEnv): NodeJS.ProcessEnv
  cleanup(): Promise<void>
}

function withoutObjectOverrides(base: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const environment = { ...base }
  delete environment.GIT_OBJECT_DIRECTORY
  delete environment.GIT_ALTERNATE_OBJECT_DIRECTORIES
  delete environment[CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV]
  return environment
}

/** Remove parent-repository and private-evidence capabilities before project code. */
export function withoutPrivateGitEvidenceEnvironment(
  base: NodeJS.ProcessEnv = process.env,
  gitCeilingDirectory?: string,
): NodeJS.ProcessEnv {
  const environment = { ...base }
  for (const key of REPOSITORY_LOCAL_GIT_ENVIRONMENT) delete environment[key]
  delete environment.GIT_CEILING_DIRECTORIES
  delete environment.CODETRUSS_INTERNAL_HOOK
  delete environment[CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV]
  for (const key of Object.keys(environment)) {
    if (key.startsWith('CODETRUSS_HOOK_')) delete environment[key]
    if (/^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(key)) delete environment[key]
  }
  if (gitCeilingDirectory) environment.GIT_CEILING_DIRECTORIES = resolve(gitCeilingDirectory)
  return environment
}

function resolveGitPath(repoRoot: string, value: string): string {
  return resolve(isAbsolute(value) ? value : join(repoRoot, value))
}

async function repositoryStorage(repoRoot: string): Promise<{
  commonDirectory: string
  objectDirectory: string
  objectFormat: 'sha1' | 'sha256'
}> {
  if (process.env.GIT_OBJECT_DIRECTORY || process.env.GIT_ALTERNATE_OBJECT_DIRECTORIES) {
    throw new Error('private Git evidence refuses ambient Git object-directory overrides')
  }
  const environment = withoutObjectOverrides(process.env)
  const commonValue = runGitText(repoRoot, ['rev-parse', '--git-common-dir'], { env: environment }).trim()
  const objectsValue = runGitText(repoRoot, ['rev-parse', '--git-path', 'objects'], { env: environment }).trim()
  const objectFormat = runGitText(repoRoot, ['rev-parse', '--show-object-format=storage'], { env: environment }).trim()
  if (objectFormat !== 'sha1' && objectFormat !== 'sha256') {
    throw new Error(`unsupported Git object format ${JSON.stringify(objectFormat)}`)
  }
  return {
    // Git and Node can spell the same directory differently (for example a
    // Windows 8.3 path versus its long form, or macOS /var versus /private/var).
    // Canonicalize the trusted Git directory before applying containment.
    commonDirectory: await realpath(resolveGitPath(repoRoot, commonValue)),
    objectDirectory: await realpath(resolveGitPath(repoRoot, objectsValue)),
    objectFormat,
  }
}

function assertOwnedLeaf(directory: string): void {
  if (basename(directory) !== 'object-store') {
    throw new Error('private Git object-store paths must use the reserved object-store leaf')
  }
}

async function readOwnership(directory: string): Promise<{ version: 1; kind: string; id: string }> {
  let value: unknown
  try {
    value = JSON.parse(await readFile(join(directory, OWNER_FILE), 'utf8'))
  } catch (error) {
    throw new Error(`private Git object store is missing a valid ownership manifest: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('private Git object-store ownership manifest is invalid')
  const manifest = value as Record<string, unknown>
  if (manifest.version !== 1 || manifest.kind !== OWNER_KIND || typeof manifest.id !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(manifest.id)) {
    throw new Error('private Git object-store ownership manifest is invalid')
  }
  return manifest as { version: 1; kind: string; id: string }
}

function relativeWithin(parent: string, candidate: string): string | undefined {
  const value = relative(parent, candidate)
  if (!value || value === '..' || value.startsWith(`..${sep}`) || isAbsolute(value)) return undefined
  return value
}

async function inspectDirectory(path: string): Promise<'missing' | 'directory' | 'symlink' | 'other'> {
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink()) return 'symlink'
    return info.isDirectory() ? 'directory' : 'other'
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return 'missing'
    throw error
  }
}

/**
 * Canonicalize the existing prefix of a path while preserving missing leaf
 * components. This lets containment compare filesystem identity rather than
 * platform-specific aliases without requiring the private store to exist yet.
 */
async function canonicalPotentialDirectory(path: string): Promise<string> {
  const missing: string[] = []
  let current = resolve(path)
  while (true) {
    const kind = await inspectDirectory(current)
    if (kind === 'directory') return join(await realpath(current), ...missing)
    if (kind === 'symlink') throw new Error(`private Git state contains an unsafe symlink at ${JSON.stringify(current)}`)
    if (kind === 'other') throw new Error(`private Git state contains an unsafe filesystem entry at ${JSON.stringify(current)}`)
    const parent = dirname(current)
    if (parent === current) throw new Error(`private Git state has no existing directory ancestor at ${JSON.stringify(path)}`)
    missing.unshift(basename(current))
    current = parent
  }
}

async function canonicalPrivateDirectory(commonDirectory: string, target: string): Promise<string> {
  const candidate = await canonicalPotentialDirectory(target)
  if (!relativeWithin(join(commonDirectory, 'codetruss'), candidate)) {
    throw new Error('private Git object stores must stay under the repository CodeTruss state directory')
  }
  return candidate
}

async function ensurePrivatePath(commonDirectory: string, target: string, create: boolean): Promise<void> {
  const codeTrussRoot = join(commonDirectory, 'codetruss')
  const suffix = relativeWithin(codeTrussRoot, target)
  if (!suffix) throw new Error('private Git object stores must stay under the repository CodeTruss state directory')
  let current = codeTrussRoot
  for (const component of suffix.split(/[\\/]/)) {
    const kind = await inspectDirectory(current)
    if (kind === 'missing' && create) await mkdir(current, { mode: 0o700 })
    else if (kind !== 'directory') throw new Error(`private Git state contains an unsafe ${kind} at ${JSON.stringify(current)}`)
    await chmod(current, 0o700)
    current = join(current, component)
  }
  const kind = await inspectDirectory(current)
  if (kind === 'missing' && create) await mkdir(current, { mode: 0o700 })
  else if (kind !== 'directory') throw new Error(`private Git state contains an unsafe ${kind} at ${JSON.stringify(current)}`)
  await chmod(current, 0o700)
}

function quotedAlternatePath(path: string): string {
  return path.includes(delimiter) || path.includes('\\') || path.startsWith('"') ? JSON.stringify(path) : path
}

function prependAlternate(path: string, existing: string | undefined): string {
  const encoded = quotedAlternatePath(resolve(path))
  return existing ? `${encoded}${delimiter}${existing}` : encoded
}

/** Read private evidence while keeping the user's repository object database primary. */
export function privateGitReadEnvironment(
  objectDirectory: string,
  base: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const environment = { ...base }
  delete environment.GIT_OBJECT_DIRECTORY
  environment.GIT_ALTERNATE_OBJECT_DIRECTORIES = prependAlternate(
    objectDirectory,
    base.GIT_ALTERNATE_OBJECT_DIRECTORIES,
  )
  environment[CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV] = resolve(objectDirectory)
  return environment
}

/** Write private evidence while exposing the user's object database only as an alternate. */
export function privateGitWriteEnvironment(
  objectDirectory: string,
  repositoryObjectDirectory: string,
  base: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  return {
    ...base,
    GIT_OBJECT_DIRECTORY: resolve(objectDirectory),
    GIT_ALTERNATE_OBJECT_DIRECTORIES: prependAlternate(
      repositoryObjectDirectory,
      base.GIT_ALTERNATE_OBJECT_DIRECTORIES,
    ),
    [CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV]: resolve(objectDirectory),
  }
}

async function descriptor(repoRoot: string, directory: string): Promise<PrivateGitObjectStore> {
  const storage = await repositoryStorage(repoRoot)
  const resolvedDirectory = await canonicalPrivateDirectory(storage.commonDirectory, directory)
  assertOwnedLeaf(resolvedDirectory)
  const objectDirectory = join(resolvedDirectory, 'objects')
  return {
    directory: resolvedDirectory,
    objectDirectory,
    repositoryObjectDirectory: storage.objectDirectory,
    objectFormat: storage.objectFormat,
    objectIdLength: storage.objectFormat === 'sha1' ? 40 : 64,
    assertObjectId(value: string, label = 'Git object id') {
      const length = storage.objectFormat === 'sha1' ? 40 : 64
      if (!new RegExp(`^[0-9a-f]{${length}}$`).test(value)) {
        throw new Error(`${label} is not a valid ${storage.objectFormat} object id: ${JSON.stringify(value)}`)
      }
    },
    writeEnvironment(base = process.env) {
      return privateGitWriteEnvironment(objectDirectory, storage.objectDirectory, base)
    },
    readEnvironment(base = process.env) {
      return privateGitReadEnvironment(objectDirectory, base)
    },
    async cleanup() {
      await removePrivateGitObjectStore(repoRoot, resolvedDirectory)
    },
  }
}

/** Reset and initialize a 0700 object store beneath `.git/codetruss/`. */
export async function initializePrivateGitObjectStore(
  repoRoot: string,
  directory: string,
): Promise<PrivateGitObjectStore> {
  const storage = await repositoryStorage(repoRoot)
  const resolvedDirectory = await canonicalPrivateDirectory(storage.commonDirectory, directory)
  assertOwnedLeaf(resolvedDirectory)
  await ensurePrivatePath(storage.commonDirectory, dirname(resolvedDirectory), true)
  const kind = await inspectDirectory(resolvedDirectory)
  if (kind === 'directory') {
    await readOwnership(resolvedDirectory)
    await rm(resolvedDirectory, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
  }
  else if (kind !== 'missing') throw new Error(`private Git object store path is an unsafe ${kind}`)
  await mkdir(resolvedDirectory, { mode: 0o700 })
  try {
    await chmod(resolvedDirectory, 0o700)
    await writeFile(join(resolvedDirectory, OWNER_FILE), `${JSON.stringify({ version: 1, kind: OWNER_KIND, id: randomUUID() })}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    })
    await ensurePrivatePath(storage.commonDirectory, join(resolvedDirectory, 'objects', 'info'), true)
    await ensurePrivatePath(storage.commonDirectory, join(resolvedDirectory, 'objects', 'pack'), true)
    return descriptor(repoRoot, resolvedDirectory)
  } catch (error) {
    try {
      await rm(resolvedDirectory, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
    } catch (cleanupError) {
      throw new Error(`private Git object-store initialization failed and cleanup is pending: ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`, { cause: error })
    }
    throw error
  }
}

/** Reopen an existing private store after a later hook process starts. */
export async function openPrivateGitObjectStore(
  repoRoot: string,
  directory: string,
): Promise<PrivateGitObjectStore> {
  const storage = await repositoryStorage(repoRoot)
  const resolvedDirectory = await canonicalPrivateDirectory(storage.commonDirectory, directory)
  assertOwnedLeaf(resolvedDirectory)
  await ensurePrivatePath(storage.commonDirectory, join(resolvedDirectory, 'objects'), false)
  await readOwnership(resolvedDirectory)
  return descriptor(repoRoot, resolvedDirectory)
}

/** Remove only a validated CodeTruss-owned store; never prune the user's object database. */
export async function removePrivateGitObjectStore(repoRoot: string, directory: string): Promise<void> {
  const storage = await repositoryStorage(repoRoot)
  const resolvedDirectory = await canonicalPrivateDirectory(storage.commonDirectory, directory)
  assertOwnedLeaf(resolvedDirectory)
  if (await inspectDirectory(dirname(resolvedDirectory)) === 'missing') return
  await ensurePrivatePath(storage.commonDirectory, dirname(resolvedDirectory), false)
  const kind = await inspectDirectory(resolvedDirectory)
  if (kind === 'missing') return
  if (kind === 'symlink') throw new Error('refusing to follow a symbolic link while removing a private Git object store')
  if (kind !== 'directory') throw new Error(`refusing to remove an unsafe private Git object store ${JSON.stringify(resolvedDirectory)}`)
  await readOwnership(resolvedDirectory)
  await rm(resolvedDirectory, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
}
