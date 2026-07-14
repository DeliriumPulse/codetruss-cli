import { createReadStream } from 'node:fs'
import { lstat, readdir, readlink } from 'node:fs/promises'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { dirtyFiles, head } from './git.js'
import { materializeWorkingTreeSnapshot } from './git-snapshot.js'
import { runGit, runGitText } from './git-process.js'
import type { PrivateGitObjectStore } from './private-git-object-store.js'

interface TreeEntry {
  mode: '100644' | '100755' | '120000' | '160000' | '040000'
  type: 'blob' | 'commit' | 'tree'
  oid: string
  name: string
}

export interface ExactSnapshotCommit {
  commit: string
  tree: string
  head: string
  dirtyFiles: string[]
}

export type ExactHookBaseline = ExactSnapshotCommit

function encodeTree(entries: TreeEntry[]): Buffer {
  const chunks: Buffer[] = []
  const gitTreeOrder = (left: TreeEntry, right: TreeEntry): number => {
    const leftName = Buffer.from(left.name)
    const rightName = Buffer.from(right.name)
    const length = Math.min(leftName.length, rightName.length)
    for (let index = 0; index < length; index++) {
      if (leftName[index] !== rightName[index]) return leftName[index] - rightName[index]
    }
    const leftTerminator = leftName.length === length ? (left.type === 'tree' ? 47 : 0) : leftName[length]
    const rightTerminator = rightName.length === length ? (right.type === 'tree' ? 47 : 0) : rightName[length]
    return leftTerminator - rightTerminator
  }
  for (const entry of entries.sort(gitTreeOrder)) {
    if (!entry.name || entry.name.includes('\0') || entry.name.includes('/')) {
      throw new Error(`cannot store unsafe Git tree entry ${JSON.stringify(entry.name)}`)
    }
    chunks.push(Buffer.from(`${entry.mode} ${entry.type} ${entry.oid}\t${entry.name}\0`))
  }
  return Buffer.concat(chunks)
}

async function hashFile(
  repoRoot: string,
  path: string,
  environment: NodeJS.ProcessEnv,
  assertObjectId: (value: string, label?: string) => void,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn('git', ['-C', repoRoot, 'hash-object', '-w', '--stdin'], {
      env: environment,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    const source = createReadStream(path)
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    let stderrBytes = 0
    let settled = false
    const fail = (error: Error) => {
      if (settled) return
      settled = true
      child.kill()
      reject(error)
    }
    source.once('error', fail)
    child.once('error', fail)
    child.stdout.on('data', (chunk: Buffer | string) => stdout.push(Buffer.from(chunk)))
    child.stderr.on('data', (chunk: Buffer | string) => {
      if (stderrBytes >= 64 * 1024) return
      const bytes = Buffer.from(chunk).subarray(0, 64 * 1024 - stderrBytes)
      stderr.push(bytes)
      stderrBytes += bytes.length
    })
    child.once('close', (code) => {
      if (settled) return
      settled = true
      if (code !== 0) {
        reject(new Error(`git hash-object failed with exit code ${String(code)}: ${Buffer.concat(stderr).toString('utf8').slice(0, 64 * 1024).trim()}`))
        return
      }
      const oid = Buffer.concat(stdout).toString('utf8').trim()
      try { assertObjectId(oid, 'git hash-object result') } catch (error) { reject(error); return }
      resolve(oid)
    })
    source.pipe(child.stdin)
  })
}

function indexedGitlinks(repoRoot: string): Map<string, string> {
  const output = runGit(repoRoot, ['ls-files', '--stage', '-z']).stdout
  const result = new Map<string, string>()
  let start = 0
  for (let index = 0; index <= output.length; index++) {
    if (index !== output.length && output[index] !== 0) continue
    if (index === start) { start = index + 1; continue }
    const record = output.subarray(start, index).toString('utf8')
    start = index + 1
    const tab = record.indexOf('\t')
    if (tab < 0) throw new Error(`unexpected git ls-files record ${JSON.stringify(record)}`)
    const [mode, oid, stage] = record.slice(0, tab).split(' ')
    const path = record.slice(tab + 1)
    if (mode === '160000' && stage === '0') result.set(path, oid)
  }
  return result
}

function currentGitlink(repoRoot: string, path: string, indexedOid: string): string {
  try {
    const oid = runGitText(join(repoRoot, ...path.split('/')), ['rev-parse', '--verify', 'HEAD^{commit}']).trim()
    return /^[0-9a-f]{40,64}$/.test(oid) ? oid : indexedOid
  } catch {
    return indexedOid
  }
}

function resolvedGitlinks(repoRoot: string): Map<string, string> {
  return new Map(
    [...indexedGitlinks(repoRoot)].map(([path, indexedOid]) => [path, currentGitlink(repoRoot, path, indexedOid)]),
  )
}

function mapsEqual(left: Map<string, string>, right: Map<string, string>): boolean {
  if (left.size !== right.size) return false
  for (const [path, oid] of left) {
    if (right.get(path) !== oid) return false
  }
  return true
}

function assertGitCaptureState(
  repoRoot: string,
  expectedHead: string,
  expectedDirtyFiles: readonly string[],
  expectedGitlinks: Map<string, string>,
): void {
  if (head(repoRoot) !== expectedHead) throw new Error('HEAD changed while the hook baseline was being captured')
  if (JSON.stringify(dirtyFiles(repoRoot)) !== JSON.stringify(expectedDirtyFiles)) {
    throw new Error('Git status changed while the hook baseline was being captured')
  }
  if (!mapsEqual(resolvedGitlinks(repoRoot), expectedGitlinks)) {
    throw new Error('Gitlink state changed while the hook baseline was being captured')
  }
}

async function buildTree(
  repoRoot: string,
  directory: string,
  relativeDirectory: string,
  gitlinks: Map<string, string>,
  environment: NodeJS.ProcessEnv,
  assertObjectId: (value: string, label?: string) => void,
): Promise<string | null> {
  const entries: TreeEntry[] = []
  const items = await readdir(directory, { withFileTypes: true }).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return []
    throw error
  })
  const seen = new Set<string>()
  for (const item of items) {
    seen.add(item.name)
    const relativePath = relativeDirectory ? `${relativeDirectory}/${item.name}` : item.name
    const sourcePath = join(directory, item.name)
    const gitlink = gitlinks.get(relativePath)
    if (gitlink) {
      assertObjectId(gitlink, `gitlink ${relativePath}`)
      entries.push({ mode: '160000', type: 'commit', oid: gitlink, name: item.name })
      continue
    }
    if (item.isDirectory()) {
      const oid = await buildTree(repoRoot, sourcePath, relativePath, gitlinks, environment, assertObjectId)
      if (oid) entries.push({ mode: '040000', type: 'tree', oid, name: item.name })
      continue
    }
    if (item.isSymbolicLink()) {
      const target = await readlink(sourcePath, { encoding: 'buffer' })
      const oid = runGitText(repoRoot, ['hash-object', '-w', '--stdin'], { env: environment, input: target }).trim()
      assertObjectId(oid, `symlink blob ${relativePath}`)
      entries.push({ mode: '120000', type: 'blob', oid, name: item.name })
      continue
    }
    if (item.isFile()) {
      const info = await lstat(sourcePath)
      entries.push({
        mode: (info.mode & 0o111) === 0 ? '100644' : '100755',
        type: 'blob',
        oid: await hashFile(repoRoot, sourcePath, environment, assertObjectId),
        name: item.name,
      })
      continue
    }
    throw new Error(`cannot store unsupported baseline entry ${JSON.stringify(relativePath)}`)
  }
  const prefix = relativeDirectory ? `${relativeDirectory}/` : ''
  const virtualDirectories = new Set<string>()
  for (const [path, oid] of gitlinks) {
    if (!path.startsWith(prefix)) continue
    const remainder = path.slice(prefix.length)
    if (!remainder || seen.has(remainder.split('/', 1)[0])) continue
    const slash = remainder.indexOf('/')
    if (slash < 0) {
      assertObjectId(oid, `gitlink ${path}`)
      entries.push({ mode: '160000', type: 'commit', oid, name: remainder })
    } else {
      virtualDirectories.add(remainder.slice(0, slash))
    }
  }
  for (const name of virtualDirectories) {
    const relativePath = relativeDirectory ? `${relativeDirectory}/${name}` : name
    const oid = await buildTree(repoRoot, join(directory, name), relativePath, gitlinks, environment, assertObjectId)
    if (oid) entries.push({ mode: '040000', type: 'tree', oid, name })
  }
  if (entries.length === 0 && relativeDirectory) return null
  const tree = runGitText(repoRoot, ['mktree', '-z', '--missing'], { env: environment, input: encodeTree(entries) }).trim()
  assertObjectId(tree, `tree ${relativeDirectory || '/'}`)
  return tree
}

/**
 * Capture the exact Git-visible working state and persist it as an immutable
 * synthetic commit in a caller-owned private object database. Blob creation
 * deliberately bypasses clean/smudge filters. Neither HEAD, the user's index,
 * refs, nor the user's object database is changed.
 */
export async function createExactSnapshotCommit(
  repoRoot: string,
  snapshotParent: string,
  objectStore: PrivateGitObjectStore,
): Promise<ExactSnapshotCommit> {
  const startHead = head(repoRoot)
  const startDirtyFiles = dirtyFiles(repoRoot)
  const startGitlinks = resolvedGitlinks(repoRoot)
  const objectEnvironment = objectStore.writeEnvironment()
  const snapshot = await materializeWorkingTreeSnapshot(repoRoot, { parentDir: snapshotParent })
  try {
    assertGitCaptureState(repoRoot, startHead, startDirtyFiles, startGitlinks)
    const tree = await buildTree(
      repoRoot,
      snapshot.root,
      '',
      startGitlinks,
      objectEnvironment,
      objectStore.assertObjectId.bind(objectStore),
    )
    if (!tree) throw new Error('could not create the baseline tree')
    await snapshot.verifyStillCurrent?.()
    assertGitCaptureState(repoRoot, startHead, startDirtyFiles, startGitlinks)
    const now = new Date().toISOString()
    const env = {
      ...objectEnvironment,
      GIT_AUTHOR_NAME: 'CodeTruss',
      GIT_AUTHOR_EMAIL: 'local@codetruss.invalid',
      GIT_COMMITTER_NAME: 'CodeTruss',
      GIT_COMMITTER_EMAIL: 'local@codetruss.invalid',
      GIT_AUTHOR_DATE: now,
      GIT_COMMITTER_DATE: now,
    }
    const commit = runGitText(
      repoRoot,
      ['commit-tree', tree, ...(startHead ? ['-p', startHead] : [])],
      { env, input: 'CodeTruss agent turn baseline\n' },
    ).trim()
    objectStore.assertObjectId(commit, 'snapshot commit')
    return { commit, tree, head: startHead, dirtyFiles: startDirtyFiles }
  } finally {
    await snapshot.cleanup()
  }
}

/** Backwards-compatible name for hook callers; no repository ref is created. */
export const createExactHookBaseline = createExactSnapshotCommit

/** Remove refs left by prerelease clients so Git can eventually collect them. */
export function deleteLegacyHookBaseline(repoRoot: string, ref: string): void {
  if (!/^refs\/codetruss\/hooks\/[0-9a-f/]+$/.test(ref)) return
  runGit(repoRoot, ['update-ref', '-d', ref], { allowedExitCodes: [0, 1] })
}
