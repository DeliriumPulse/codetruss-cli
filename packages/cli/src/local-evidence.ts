import { randomUUID } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { lstat, mkdir, open, realpath, unlink } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { runGit, runGitText } from './git-process.js'

export const LOCAL_EVIDENCE_DIRECTORY = '.codetruss'
export const LOCAL_EVIDENCE_EXCLUDE_PATTERN = '/.codetruss/'
const EXCLUDE_COMMENT = '# CodeTruss local evidence; never add receipts or patches to Git'
const EXCLUDE_APPEND_BYTES = Buffer.from(`${EXCLUDE_COMMENT}\n${LOCAL_EVIDENCE_EXCLUDE_PATTERN}\n`, 'ascii')
const PRIVATE_EVIDENCE_SUBDIRECTORIES = ['receipts', 'snapshots', 'hooks'] as const

export interface LocalEvidenceProtection {
  excludePath: string
  changed: boolean
}

function splitNul(value: Buffer): string[] {
  return value.toString('utf8').split('\0').filter(Boolean)
}

function trackedLocalEvidence(root: string): string[] {
  return splitNul(runGit(root, ['ls-files', '-z', '--', LOCAL_EVIDENCE_DIRECTORY]).stdout)
}

function resolvedGitPath(root: string, argument: '--git-common-dir' | 'info/exclude'): string {
  const raw = argument === '--git-common-dir'
    ? runGitText(root, ['rev-parse', argument]).trim()
    : runGitText(root, ['rev-parse', '--git-path', argument]).trim()
  if (!raw) throw new Error(`Git did not return ${argument}`)
  return resolve(isAbsolute(raw) ? raw : join(root, raw))
}

function isContainedPath(parent: string, child: string): boolean {
  const path = relative(parent, child)
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path))
}

async function effectiveExcludePath(root: string): Promise<string> {
  const path = resolvedGitPath(root, 'info/exclude')
  const common = resolvedGitPath(root, '--git-common-dir')
  if (!isContainedPath(common, path)) {
    throw new Error(`Git exclude file is outside the repository common directory: ${path}`)
  }

  const parent = dirname(path)
  await mkdir(parent, { recursive: true, mode: 0o700 })
  const [commonReal, parentReal] = await Promise.all([realpath(common), realpath(parent)])
  if (!isContainedPath(commonReal, parentReal)) {
    throw new Error(`refusing Git exclude directory outside the repository common directory: ${parent}`)
  }
  return path
}

async function assertRegularFileOrMissing(path: string, label: string): Promise<void> {
  try {
    const metadata = await lstat(path)
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`refusing non-regular ${label} ${path}`)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
}

function hasEvidenceExclude(contents: Buffer): boolean {
  const line = Buffer.from(LOCAL_EVIDENCE_EXCLUDE_PATTERN, 'ascii')
  for (let start = 0; start <= contents.length;) {
    const newline = contents.indexOf(0x0a, start)
    const end = newline === -1 ? contents.length : newline
    const lineEnd = end > start && contents[end - 1] === 0x0d ? end - 1 : end
    if (lineEnd - start === line.length && contents.subarray(start, lineEnd).equals(line)) return true
    if (newline === -1) break
    start = newline + 1
  }
  return false
}

function appendBytes(contents: Buffer): Buffer {
  const prefix = contents.length > 0 && contents[contents.length - 1] !== 0x0a ? Buffer.from('\n', 'ascii') : Buffer.alloc(0)
  return Buffer.concat([prefix, EXCLUDE_APPEND_BYTES])
}

async function safelyEnsureExclude(path: string): Promise<boolean> {
  const lockPath = `${path}.codetruss.lock`
  await assertRegularFileOrMissing(path, 'Git exclude file')
  let lock
  try {
    lock = await open(lockPath, 'wx', 0o600)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new Error(`another CodeTruss process is updating ${path}; retry after it finishes (remove ${lockPath} only if no process is active)`)
    }
    throw error
  }

  try {
    await lock.writeFile(`${process.pid}\n`, 'ascii')
    await lock.sync()
    await assertRegularFileOrMissing(path, 'Git exclude file')
    const noFollow = typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0
    const handle = await open(
      path,
      fsConstants.O_CREAT | fsConstants.O_APPEND | fsConstants.O_RDWR | noFollow,
      0o600,
    )
    try {
      const metadata = await handle.stat()
      if (!metadata.isFile()) throw new Error(`refusing non-regular Git exclude file ${path}`)
      const contents = await handle.readFile()
      if (hasEvidenceExclude(contents)) return false
      await handle.write(appendBytes(contents))
      await handle.sync()
      return true
    } finally {
      await handle.close()
    }
  } finally {
    await lock.close()
    await unlink(lockPath).catch(() => undefined)
  }
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  try {
    const metadata = await lstat(path)
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error(`refusing non-directory local evidence path ${path}`)
    }
    return
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  await mkdir(path, { mode: 0o700 })
  const metadata = await lstat(path)
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`refusing non-directory local evidence path ${path}`)
  }
}

async function ensureEvidenceDirectories(root: string): Promise<string> {
  const path = join(root, LOCAL_EVIDENCE_DIRECTORY)
  await ensurePrivateDirectory(path)
  for (const directory of PRIVATE_EVIDENCE_SUBDIRECTORIES) {
    await ensurePrivateDirectory(join(path, directory))
  }
  return path
}

function localEvidencePath(root: string, requested: string): string {
  const repoRoot = resolve(root)
  const absolute = resolve(repoRoot, requested)
  const path = relative(repoRoot, absolute).replaceAll('\\', '/')
  if (path !== LOCAL_EVIDENCE_DIRECTORY && !path.startsWith(`${LOCAL_EVIDENCE_DIRECTORY}/`)) {
    throw new Error(`local evidence protection only accepts paths under ${LOCAL_EVIDENCE_DIRECTORY}/`)
  }
  return path
}

export function assertLocalEvidencePathsIgnored(root: string, requestedPaths: string[]): void {
  for (const requested of requestedPaths) {
    const path = localEvidencePath(root, requested)
    const result = runGit(root, ['check-ignore', '--no-index', '--quiet', '--', path], {
      allowedExitCodes: [0, 1],
    })
    if (result.status !== 0) {
      throw new Error(
        `${path} is not excluded from Git; add ${LOCAL_EVIDENCE_EXCLUDE_PATTERN} after any .codetruss negations in the repository .gitignore`,
      )
    }
  }
}

function privacyProbePaths(root: string): string[] {
  const id = `privacy-probe-${randomUUID()}`
  return [
    join(root, LOCAL_EVIDENCE_DIRECTORY),
    `${LOCAL_EVIDENCE_DIRECTORY}/receipts/${id}.json`,
    `${LOCAL_EVIDENCE_DIRECTORY}/receipts/${id}.md`,
    `${LOCAL_EVIDENCE_DIRECTORY}/receipts/${id}.patch`,
    `${LOCAL_EVIDENCE_DIRECTORY}/receipts/${id}.sig`,
    `${LOCAL_EVIDENCE_DIRECTORY}/receipts/${id}.patch.${process.pid}.${Date.now()}.tmp`,
    `${LOCAL_EVIDENCE_DIRECTORY}/hooks/agent.cjs`,
    `${LOCAL_EVIDENCE_DIRECTORY}/snapshots/${id}`,
  ]
}

/**
 * Keep receipt JSON, Markdown, signatures, raw patches, temporary files, and
 * generated hook runtime files out of Git without changing the repository's
 * committed `.gitignore`. Existing tracked files are a hard stop because
 * ignore rules do not protect paths already present in the index.
 */
export async function ensureLocalEvidenceProtected(root: string): Promise<LocalEvidenceProtection> {
  const tracked = trackedLocalEvidence(root)
  if (tracked.length) {
    throw new Error(
      `${LOCAL_EVIDENCE_DIRECTORY}/ already contains ${tracked.length} Git-tracked file${tracked.length === 1 ? '' : 's'}; `
      + `inspect them, then run git rm -r --cached ${LOCAL_EVIDENCE_DIRECTORY} before CodeTruss can write local evidence`,
    )
  }

  const excludePath = await effectiveExcludePath(root)
  const changed = await safelyEnsureExclude(excludePath)
  await ensureEvidenceDirectories(root)
  assertLocalEvidencePathsIgnored(root, privacyProbePaths(root))
  return { excludePath, changed }
}
