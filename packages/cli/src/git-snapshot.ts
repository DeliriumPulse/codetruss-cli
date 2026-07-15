import { createWriteStream } from 'node:fs'
import { spawn } from 'node:child_process'
import { chmod, copyFile, lstat, mkdir, mkdtemp, readlink, realpath, rm, stat, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { pipeline } from 'node:stream/promises'
import { emptyTree, head } from './git.js'
import { gitCommandArguments, runGit, runGitText } from './git-process.js'

export interface SnapshotOptions {
  /** Optional parent for snapshots that should inherit a repository's node_modules. */
  parentDir?: string
  /** Explicit Git object-read environment for private snapshot commits. */
  gitEnvironment?: NodeJS.ProcessEnv
}

export interface WorkingTreeSnapshotOptions extends SnapshotOptions {
  /** Repository-relative path prefixes to omit in addition to .codetruss. */
  excludePaths?: readonly string[]
  /** Fail closed after this many attempts if files keep changing during capture. */
  maxAttempts?: number
}

export interface MaterializedGitSnapshot {
  /** Filesystem root containing exactly the selected Git tree. */
  root: string
  /** Immutable Git tree object, or null for a byte-for-byte working-tree snapshot. */
  tree: string | null
  source: 'index' | 'tree' | 'working'
  /** Repository-relative prefixes intentionally absent from a working snapshot. */
  excludedPaths?: readonly string[]
  /** Fail closed when the working state captured by this snapshot has since drifted. */
  verifyStillCurrent?(): Promise<void>
  cleanup(): Promise<void>
}

export function indexTree(repoRoot: string, gitEnvironment?: NodeJS.ProcessEnv): string {
  return runGitText(repoRoot, ['write-tree'], { ...(gitEnvironment ? { env: gitEnvironment } : {}) }).trim()
}

export function resolveTree(repoRoot: string, treeish: string, gitEnvironment?: NodeJS.ProcessEnv): string {
  const candidate = treeish === 'HEAD' ? (head(repoRoot) || emptyTree(repoRoot, gitEnvironment)) : (treeish || emptyTree(repoRoot, gitEnvironment))
  return runGitText(repoRoot, ['rev-parse', '--verify', `${candidate}^{tree}`], { ...(gitEnvironment ? { env: gitEnvironment } : {}) }).trim()
}

async function materialize(
  repoRoot: string,
  tree: string,
  source: 'index' | 'tree',
  options: SnapshotOptions,
): Promise<MaterializedGitSnapshot> {
  const parent = options.parentDir ? resolve(options.parentDir) : tmpdir()
  await mkdir(parent, { recursive: true })
  const container = await mkdtemp(join(parent, 'codetruss-git-snapshot-'))
  const snapshotRoot = join(container, 'worktree')
  await mkdir(snapshotRoot, { recursive: true })
  try {
    const records = splitNulUtf8(runGit(repoRoot, ['ls-tree', '-r', '-z', '--full-tree', tree], {
      ...(options.gitEnvironment ? { env: options.gitEnvironment } : {}),
    }).stdout)
    for (const record of records) {
      const tab = record.indexOf('\t')
      if (tab < 0) throw new Error(`unexpected git ls-tree record ${JSON.stringify(record)}`)
      const [mode, type, oid] = record.slice(0, tab).split(' ')
      const path = record.slice(tab + 1)
      if (!mode || !type || !/^[0-9a-f]{40,64}$/.test(oid) || !path || path.includes('\0') || isAbsolute(path) || path === '..' || path.startsWith('../')) {
        throw new Error(`unsafe git ls-tree record ${JSON.stringify(record)}`)
      }
      if (process.platform === 'win32' && path.includes('\\')) throw new Error(`unsafe Windows Git path ${JSON.stringify(path)}`)
      const destination = nativePath(snapshotRoot, path)
      await mkdir(dirname(destination), { recursive: true })
      if (mode === '160000' && type === 'commit') {
        await mkdir(destination, { recursive: true })
      } else if (mode === '120000' && type === 'blob') {
        const target = runGit(repoRoot, ['cat-file', 'blob', oid], {
          ...(options.gitEnvironment ? { env: options.gitEnvironment } : {}),
        }).stdout
        await symlink(target, destination)
      } else if ((mode === '100644' || mode === '100755') && type === 'blob') {
        await streamBlob(repoRoot, oid, destination, options.gitEnvironment)
        await chmod(destination, mode === '100755' ? 0o755 : 0o644)
      } else {
        throw new Error(`unsupported Git tree entry ${JSON.stringify(record)}`)
      }
    }
  } catch (error) {
    await rm(container, { recursive: true, force: true })
    throw error
  }
  let cleaned = false
  return {
    root: snapshotRoot,
    tree,
    source,
    async cleanup() {
      if (cleaned) return
      cleaned = true
      await rm(container, { recursive: true, force: true })
    },
  }
}

async function streamBlob(repoRoot: string, oid: string, destination: string, gitEnvironment?: NodeJS.ProcessEnv): Promise<void> {
  const child = spawn('git', gitCommandArguments(repoRoot, ['cat-file', 'blob', oid]), {
    ...(gitEnvironment ? { env: gitEnvironment } : {}),
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const stderr: Buffer[] = []
  let stderrBytes = 0
  child.stderr.on('data', (value: Buffer | string) => {
    if (stderrBytes >= 64 * 1024) return
    const chunk = Buffer.from(value).subarray(0, 64 * 1024 - stderrBytes)
    stderr.push(chunk)
    stderrBytes += chunk.length
  })
  const exited = new Promise<void>((resolveExit, reject) => {
    child.once('error', reject)
    child.once('close', (code) => {
      if (code === 0) resolveExit()
      else reject(new Error(`git cat-file failed with exit code ${String(code)}: ${Buffer.concat(stderr).toString('utf8').trim()}`))
    })
  })
  try {
    await Promise.all([pipeline(child.stdout, createWriteStream(destination, { flags: 'wx' })), exited])
  } catch (error) {
    child.kill()
    throw error
  }
}

interface SourceIdentity {
  type: 'file' | 'directory' | 'symlink' | 'unsupported'
  mode: string
  size: string
  mtimeNs: string
  ctimeNs: string
  ino: string
  device: string
  target?: Buffer
}

class WorkingTreeChangedError extends Error {
  constructor(path: string) {
    super(`working tree changed while snapshotting ${JSON.stringify(path)}`)
    this.name = 'WorkingTreeChangedError'
  }
}

function splitNulUtf8(output: Buffer): string[] {
  const decoder = new TextDecoder('utf-8', { fatal: true })
  const paths: string[] = []
  let start = 0
  for (let i = 0; i < output.length; i++) {
    if (output[i] !== 0) continue
    if (i > start) paths.push(decoder.decode(output.subarray(start, i)))
    start = i + 1
  }
  if (start < output.length) paths.push(decoder.decode(output.subarray(start)))
  return paths
}

/**
 * Make the repository's already-installed Node toolchain available to a
 * verification snapshot without copying it into the evidence tree. Package
 * managers normally ignore these directories, so an exact Git materialization
 * cannot contain them; `pnpm test`/`npm test` would otherwise fail before the
 * configured verifier starts. Verification commands are explicitly trusted
 * local commands and receive a fresh source tree for every run, while their
 * dependency installation remains the same one the repository would use.
 */
export async function linkInstalledNodeModules(
  repoRoot: string,
  snapshotRoot: string,
): Promise<string[]> {
  const ignored = splitNulUtf8(runGit(repoRoot, [
    'ls-files',
    '--others',
    '--ignored',
    '--exclude-standard',
    '--directory',
    '-z',
  ]).stdout)
  const linked: string[] = []
  for (const rawPath of ignored) {
    // Git appends `/` for ignored directories but not for ignored directory
    // symlinks. Both are valid local dependency installations.
    if (!/(^|\/)node_modules\/?$/.test(rawPath)) continue
    const path = normalizeRepoPath(rawPath)
    const source = nativePath(resolve(repoRoot), path)
    const destination = nativePath(resolve(snapshotRoot), path)
    let target: string
    try {
      target = await realpath(source)
      if (!(await stat(target)).isDirectory()) continue
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue
      throw error
    }
    try {
      await lstat(destination)
      continue
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
    await mkdir(dirname(destination), { recursive: true })
    await symlink(target, destination, process.platform === 'win32' ? 'junction' : 'dir')
    linked.push(path)
  }
  return linked.sort()
}

function normalizeRepoPath(path: string): string {
  const normalized = path.replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/$/, '')
  if (!normalized || normalized.includes('\0') || isAbsolute(normalized) || normalized === '..' || normalized.startsWith('../')) {
    throw new Error(`snapshot exclusion must be a repository-relative path: ${JSON.stringify(path)}`)
  }
  return normalized
}

function nativePath(root: string, path: string): string {
  return join(root, ...path.split('/'))
}

function isExcluded(path: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))
}

function snapshotPaths(repoRoot: string, exclusions: readonly string[]): string[] {
  const output = runGit(repoRoot, ['ls-files', '--cached', '--others', '--exclude-standard', '-z']).stdout
  const paths = [...new Set(splitNulUtf8(output))]
    .filter((path) => !isExcluded(path, exclusions))
    .sort()
  for (const path of paths) {
    if (!path || path.includes('\0') || isAbsolute(path) || path === '..' || path.startsWith('../')) {
      throw new Error(`Git returned an unsafe repository path: ${JSON.stringify(path)}`)
    }
  }
  return paths
}

async function sourceIdentity(path: string): Promise<SourceIdentity | null> {
  let info
  try {
    info = await lstat(path, { bigint: true })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
  const type = info.isFile() ? 'file' : info.isDirectory() ? 'directory' : info.isSymbolicLink() ? 'symlink' : 'unsupported'
  return {
    type,
    mode: info.mode.toString(),
    size: info.size.toString(),
    mtimeNs: info.mtimeNs.toString(),
    ctimeNs: info.ctimeNs.toString(),
    ino: info.ino.toString(),
    device: info.dev.toString(),
    ...(type === 'symlink' ? { target: await readlink(path, { encoding: 'buffer' }) } : {}),
  }
}

function identitiesMatch(left: SourceIdentity | null, right: SourceIdentity | null): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

async function copySnapshotPath(source: string, destination: string, identity: SourceIdentity): Promise<void> {
  await mkdir(dirname(destination), { recursive: true })
  if (identity.type === 'file') {
    await copyFile(source, destination)
    await chmod(destination, Number(identity.mode) & 0o777)
    return
  }
  if (identity.type === 'symlink') {
    await symlink(identity.target!, destination)
    return
  }
  if (identity.type === 'directory') {
    // Git only tracks directories as gitlinks. Their nested repository is out of scope.
    await mkdir(destination, { recursive: true })
    return
  }
  throw new Error(`cannot snapshot unsupported filesystem entry ${JSON.stringify(source)}`)
}

function relativeRepoPath(repoRoot: string, path: string): string | undefined {
  const candidate = relative(repoRoot, path).replaceAll('\\', '/')
  if (!candidate || candidate === '..' || candidate.startsWith('../') || isAbsolute(candidate)) return undefined
  return normalizeRepoPath(candidate)
}

/**
 * Materialize the exact Git-visible working state: tracked files at their current
 * bytes (including staged and unstaged edits) plus non-ignored untracked files.
 * CodeTruss evidence is always excluded. Capture retries on concurrent mutation
 * and fails closed if the working tree does not become stable.
 */
export async function materializeWorkingTreeSnapshot(
  repoRoot: string,
  options: WorkingTreeSnapshotOptions = {},
): Promise<MaterializedGitSnapshot> {
  const root = resolve(repoRoot)
  const parent = options.parentDir ? resolve(options.parentDir) : tmpdir()
  const maxAttempts = options.maxAttempts ?? 3
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10) {
    throw new Error('maxAttempts must be an integer between 1 and 10')
  }
  const configuredExclusions = ['.codetruss', ...(options.excludePaths ?? []).map(normalizeRepoPath)]
  await mkdir(parent, { recursive: true })
  let lastMutation: WorkingTreeChangedError | undefined

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const container = await mkdtemp(join(parent, 'codetruss-working-snapshot-'))
    const snapshotRoot = join(container, 'worktree')
    const containerPath = relativeRepoPath(root, container)
    const exclusions = [...new Set([...configuredExclusions, ...(containerPath ? [containerPath] : [])])].sort()
    await mkdir(snapshotRoot, { recursive: true })
    try {
      const pathsBefore = snapshotPaths(root, exclusions)
      const identities = new Map<string, SourceIdentity | null>()
      for (const path of pathsBefore) {
        const source = nativePath(root, path)
        const destination = nativePath(snapshotRoot, path)
        const before = await sourceIdentity(source)
        identities.set(path, before)
        if (before) await copySnapshotPath(source, destination, before)
        if (!identitiesMatch(before, await sourceIdentity(source))) throw new WorkingTreeChangedError(path)
      }
      const pathsAfter = snapshotPaths(root, exclusions)
      if (JSON.stringify(pathsBefore) !== JSON.stringify(pathsAfter)) throw new WorkingTreeChangedError('file list')
      for (const [path, before] of identities) {
        if (!identitiesMatch(before, await sourceIdentity(nativePath(root, path)))) throw new WorkingTreeChangedError(path)
      }
      const verifyStillCurrent = async (): Promise<void> => {
        const currentPaths = snapshotPaths(root, exclusions)
        if (JSON.stringify(pathsBefore) !== JSON.stringify(currentPaths)) throw new WorkingTreeChangedError('file list')
        for (const [path, before] of identities) {
          if (!identitiesMatch(before, await sourceIdentity(nativePath(root, path)))) throw new WorkingTreeChangedError(path)
        }
      }
      let cleaned = false
      return {
        root: snapshotRoot,
        tree: null,
        source: 'working',
        excludedPaths: exclusions,
        verifyStillCurrent,
        async cleanup() {
          if (cleaned) return
          cleaned = true
          await rm(container, { recursive: true, force: true })
        },
      }
    } catch (error) {
      await rm(container, { recursive: true, force: true })
      const mutation = error instanceof WorkingTreeChangedError
        || (error instanceof Error && ['ENOENT', 'ESTALE', 'EBUSY'].includes((error as NodeJS.ErrnoException).code ?? ''))
      if (!mutation) throw error
      lastMutation = error instanceof WorkingTreeChangedError ? error : new WorkingTreeChangedError('filesystem')
    }
  }
  throw new Error(`unable to capture a stable working tree after ${maxAttempts} attempts`, { cause: lastMutation })
}

/** Materialize the exact staged/index tree without changing the user's index. */
export async function materializeIndexSnapshot(
  repoRoot: string,
  options: SnapshotOptions = {},
): Promise<MaterializedGitSnapshot> {
  return materialize(repoRoot, indexTree(repoRoot, options.gitEnvironment), 'index', options)
}

/** Materialize HEAD, the empty tree, or any explicit commit/tree object. */
export async function materializeTreeSnapshot(
  repoRoot: string,
  treeish: string,
  options: SnapshotOptions = {},
): Promise<MaterializedGitSnapshot> {
  return materialize(repoRoot, resolveTree(repoRoot, treeish, options.gitEnvironment), 'tree', options)
}

export async function withMaterializedIndexSnapshot<T>(
  repoRoot: string,
  fn: (snapshot: MaterializedGitSnapshot) => Promise<T>,
  options: SnapshotOptions = {},
): Promise<T> {
  const snapshot = await materializeIndexSnapshot(repoRoot, options)
  try {
    return await fn(snapshot)
  } finally {
    await snapshot.cleanup()
  }
}

export async function withMaterializedWorkingTreeSnapshot<T>(
  repoRoot: string,
  fn: (snapshot: MaterializedGitSnapshot) => Promise<T>,
  options: WorkingTreeSnapshotOptions = {},
): Promise<T> {
  const snapshot = await materializeWorkingTreeSnapshot(repoRoot, options)
  try {
    return await fn(snapshot)
  } finally {
    await snapshot.cleanup()
  }
}
