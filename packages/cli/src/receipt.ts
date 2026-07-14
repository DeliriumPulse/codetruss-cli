import { chmod, mkdir, readFile, readdir, rename, unlink, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import {
  loadSigningKey,
  normalizePublicKey,
  publicKeyFingerprint,
  sha256,
  signBytes,
  verifyBytes,
} from './signing.js'
import type { Receipt, SyncEnvelope, Verdict } from './types.js'

const SYNC_REDACTION = '[redacted unrelated path]'

function pathRelatedToChanges(path: string | undefined, changedPaths: string[]): boolean {
  if (!path) return false
  const normalized = path.replaceAll('\\', '/').replace(/^\.\//, '')
  return changedPaths.some((changedPath) => (
    normalized === changedPath
    || normalized.startsWith(`${changedPath}/`)
    || changedPath.startsWith(`${normalized}/`)
  ))
}

function collectPotentialPaths(value: unknown, output: string[]): void {
  if (typeof value === 'string') {
    if (value.includes('/') || value.includes('\\') || /^[^\s]+\.[A-Za-z0-9]{1,12}$/.test(value)) output.push(value)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) collectPotentialPaths(item, output)
    return
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) collectPotentialPaths(item, output)
  }
}

function pathVariants(path: string): string[] {
  const normalized = path.replaceAll('\\', '/').replace(/^\.\//, '')
  const parts = normalized.split('/').filter(Boolean)
  return [...new Set([
    path,
    normalized,
    parts.length > 1 ? parts.slice(-2).join('/') : normalized,
  ].filter(Boolean))]
}

function redactKnownPaths(value: string, privatePaths: string[]): string {
  let redacted = value
  for (const path of privatePaths) redacted = redacted.replaceAll(path, SYNC_REDACTION)
  return redacted
}

export function newSessionId(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.(\d{3})Z$/, '$1Z')
  return `${stamp}-${sha256(`${process.pid}:${Math.random()}:${now.getTime()}`).slice(0, 6)}`
}

/**
 * One immutable hook attempt owns one receipt path, even if the hook or CLI
 * process crashes after writing receipt files but before committing its result.
 */
export function hookSessionId(now: Date, attemptId: string): string {
  if (!/^[0-9a-f]{64}$/.test(attemptId)) throw new Error('hook receipt attempt id is invalid')
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.(\d{3})Z$/, '$1Z')
  return `${stamp}-hook-${attemptId}`
}

export function exitCode(verdict: Verdict): number {
  return verdict === 'PASS' ? 0 : verdict === 'REVIEW_REQUIRED' ? 1 : 2
}

function legacyScoreLines(receipt: Receipt): string[] {
  if ('analysisProfile' in receipt.analyzers || !receipt.analyzers.scores) return []
  return [
    `Final scores: health ${receipt.analyzers.scores.health}, debt ${receipt.analyzers.scores.debt}, architecture ${receipt.analyzers.scores.architecture}, security ${receipt.analyzers.scores.security}, docs ${receipt.analyzers.scores.docs}.`,
    ...(receipt.analyzers.baselineScores ? [
      `Baseline scores: health ${receipt.analyzers.baselineScores.health}, debt ${receipt.analyzers.baselineScores.debt}, architecture ${receipt.analyzers.baselineScores.architecture}, security ${receipt.analyzers.baselineScores.security}, docs ${receipt.analyzers.baselineScores.docs}.`,
    ] : []),
  ]
}

function analysisProfileLines(receipt: Receipt): string[] {
  const current = 'analysisProfile' in receipt.analyzers && receipt.analyzers.analysisProfile
  return [
    '## Analysis profile',
    '',
    ...(current ? [
      `Profile: \`${current.id}\`.`,
      '',
      'The 13 deterministic registry analyzers ran locally. Hosted graph and SAST passes were omitted.',
    ] : [
      'Legacy local receipt. Earlier CLI versions emitted numeric scores without hosted graph and SAST; those values are suppressed.',
    ]),
    '',
    'Hosted Health scores: **N/A**. Local receipts do not calculate hosted scores without the graph and SAST passes.',
    '',
    '[Run a hosted full audit](https://codetruss.com/dashboard/repos/new?source=cli-receipt).',
  ]
}

function renderMarkdownInternal(receipt: Receipt, preserveLegacyScores: boolean): string {
  const lines = [
    `# CodeTruss receipt — ${receipt.verdict}`,
    '',
    `- **Session:** \`${receipt.sessionId}\``,
    `- **Task:** ${receipt.task.replaceAll('\n', ' ')}`,
    `- **Repository:** \`${receipt.repoRoot}\``,
    `- **Starting commit:** \`${receipt.startCommit || '(unborn)'}\``,
    ...(receipt.git ? [`- **Evidence trees:** \`${receipt.git.baselineTree}\` → \`${receipt.git.finalTree}\``] : []),
    ...(receipt.policy ? [`- **Policy SHA-256:** \`${receipt.policy.sha256}\``] : []),
    `- **Mode:** ${receipt.mode}`,
    '',
    `## Verdict: ${receipt.verdict}`,
    '',
    ...receipt.reasons.map((reason) => `- ${reason}`),
    '',
    `Diff evidence: ${receipt.diff.bytes}/${receipt.diff.totalBytes ?? receipt.diff.bytes} bytes captured${receipt.diff.truncated ? ' (truncated; PASS prohibited)' : ' (complete)'}, SHA-256 \`${receipt.diff.sha256.slice(0, 16)}…\`.`,
    '',
    `## Changed files (${receipt.files.length})`,
    '',
    '| Path | Change | Scope | Sensitive | Lines |',
    '|---|---|---|---|---:|',
    ...receipt.files.map((file) => `| \`${file.path.replaceAll('|', '\\|')}\` | ${file.change} | ${file.classification} | ${file.sensitive ?? (file.dependency ? 'dependency' : '—')} | +${file.additions}/−${file.deletions} |`),
    '',
    `## Introduced or worsened analyzer findings (${receipt.analyzers.findings.length})`,
    '',
    '| Severity | Analyzer | Location | Finding |',
    '|---|---|---|---|',
    ...receipt.analyzers.findings.slice(0, 100).map((finding) => `| ${finding.severity} | ${finding.analyzerId ?? 'unknown'} | ${finding.filePath ? `\`${finding.filePath}${finding.line ? `:${finding.line}` : ''}\`` : 'repository'} | ${finding.title.replaceAll('|', '\\|')} |`),
    '',
    ...(preserveLegacyScores ? legacyScoreLines(receipt) : analysisProfileLines(receipt)),
    ...(receipt.analyzers.delta ? [
      `Finding delta: ${receipt.analyzers.delta.introduced} introduced, ${receipt.analyzers.delta.worsened} worsened, ${receipt.analyzers.delta.recurring} recurring, ${receipt.analyzers.delta.resolved} resolved.`,
    ] : []),
    '',
    '## Verification',
    '',
    ...(receipt.verifications.length ? receipt.verifications.map((item) => `- \`${item.command}\` — exit ${item.exitCode} in ${item.durationMs}ms${item.truncated ? ' (output truncated)' : ''}`) : ['- No verification commands configured.']),
  ]
  if (receipt.llm) {
    const coverage = receipt.llm.diffCoverage
    lines.push(
      '',
      '## Optional LLM review',
      '',
      coverage
        ? `Provider: ${receipt.llm.provider}. Sent ${receipt.llm.transmittedBytes} bytes directly to that provider. Reviewed ${coverage.reviewedBytes}/${coverage.totalBytes} diff bytes${coverage.truncated ? ' (truncated; PASS prohibited)' : ' (complete)'}.`
        : `Provider: ${receipt.llm.provider}. Sent ${receipt.llm.transmittedBytes} bytes directly to that provider.`,
      '',
      receipt.llm.summary,
      ...receipt.llm.findings.map((item) => `- ${item}`),
    )
  }
  lines.push('', '## Coverage and privacy', '', ...receipt.coverageNotes.map((note) => `- ${note}`), '', '_The signature proves these receipt bytes have not changed since signing. It does not prove trusted execution or that every analysis conclusion is correct._', '')
  return lines.join('\n')
}

/** Render the current honest local profile, including when displaying a legacy receipt. */
export function renderMarkdown(receipt: Receipt): string {
  return renderMarkdownInternal(receipt, false)
}

/** Byte-compatible renderer used only to verify Markdown written by older receipt-v1 clients. */
export function renderLegacyMarkdown(receipt: Receipt): string {
  return renderMarkdownInternal(receipt, true)
}

async function writePrivateAtomic(path: string, value: string | Buffer): Promise<void> {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`
  try {
    await writeFile(temporary, value, { mode: 0o600, flag: 'wx' })
    await rename(temporary, path)
    await chmod(path, 0o600)
  } catch (error) {
    try { await unlink(temporary) } catch {}
    throw error
  }
}

export async function writeReceipt(dir: string, receipt: Receipt, patch: string | Buffer): Promise<{ json: string; markdown: string; signature: string }> {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  await chmod(dir, 0o700)
  const patchName = `${receipt.sessionId}.patch`
  const patchPath = join(dir, patchName)
  await writePrivateAtomic(patchPath, patch)
  receipt.evidence.patchFile = patchName
  receipt.evidence.patchSha256 = sha256(patch)
  const markdown = renderMarkdown(receipt)
  receipt.evidence.markdownSha256 = sha256(markdown)
  const key = await loadSigningKey(true)
  receipt.evidence.signatureFile = `${receipt.sessionId}.sig`
  receipt.evidence.publicKey = key.publicKey
  receipt.evidence.keyFingerprint = key.fingerprint
  const jsonText = `${JSON.stringify(receipt, null, 2)}\n`
  const signature = signBytes(jsonText, key.privateKey)
  const jsonPath = join(dir, `${receipt.sessionId}.json`)
  const markdownPath = join(dir, `${receipt.sessionId}.md`)
  const signaturePath = join(dir, `${receipt.sessionId}.sig`)
  await writePrivateAtomic(jsonPath, jsonText)
  await writePrivateAtomic(markdownPath, markdown)
  await writePrivateAtomic(signaturePath, `${signature}\n`)
  return { json: jsonPath, markdown: markdownPath, signature: signaturePath }
}

export async function receiptIds(dir: string): Promise<string[]> {
  try { return (await readdir(dir)).filter((name) => name.endsWith('.json')).map((name) => basename(name, '.json')).sort().reverse() } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error }
}

export async function resolveReceipt(dir: string, id = 'latest'): Promise<{ receipt: Receipt; jsonPath: string }> {
  const ids = await receiptIds(dir)
  const resolved = id === 'latest' ? ids[0] : id
  if (!resolved || !ids.includes(resolved)) throw new Error(`receipt ${id} not found`)
  const jsonPath = join(dir, `${resolved}.json`)
  return { receipt: JSON.parse(await readFile(jsonPath, 'utf8')) as Receipt, jsonPath }
}

export async function verifyReceipt(dir: string, id = 'latest', pinnedPublicKey?: string): Promise<Receipt> {
  const { receipt, jsonPath } = await resolveReceipt(dir, id)
  if (receipt.git && ![receipt.git.baselineTree, receipt.git.finalTree].every((oid) => /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(oid))) {
    throw new Error('receipt evidence tree object id is invalid')
  }
  if (receipt.policy && !/^[0-9a-f]{64}$/.test(receipt.policy.sha256)) {
    throw new Error('receipt policy SHA-256 is invalid')
  }
  if (!receipt.evidence.publicKey || !receipt.evidence.signatureFile) throw new Error('receipt is unsigned')
  const trustedPublicKey = pinnedPublicKey ? normalizePublicKey(pinnedPublicKey) : (await loadSigningKey()).publicKey
  const embeddedPublicKey = normalizePublicKey(receipt.evidence.publicKey)
  const embeddedFingerprint = publicKeyFingerprint(embeddedPublicKey)
  const trustedFingerprint = publicKeyFingerprint(trustedPublicKey)
  if (receipt.evidence.keyFingerprint !== embeddedFingerprint) throw new Error('receipt signing fingerprint does not match its public key')
  if (embeddedFingerprint !== trustedFingerprint) {
    throw new Error(`receipt signer ${embeddedFingerprint} does not match trusted key ${trustedFingerprint}`)
  }
  const jsonBytes = await readFile(jsonPath)
  const signature = (await readFile(join(dir, receipt.evidence.signatureFile), 'utf8')).trim()
  if (!verifyBytes(jsonBytes, trustedPublicKey, signature)) throw new Error('receipt signature does not match')
  const markdown = await readFile(join(dir, `${receipt.sessionId}.md`), 'utf8')
  const currentMarkdown = renderMarkdown(receipt)
  const legacyMarkdown = !('analysisProfile' in receipt.analyzers) ? renderLegacyMarkdown(receipt) : null
  if (markdown !== currentMarkdown && markdown !== legacyMarkdown) throw new Error('Markdown receipt does not match the signed JSON')
  if (sha256(markdown) !== receipt.evidence.markdownSha256) throw new Error('Markdown receipt hash does not match')
  if (receipt.evidence.patchFile) {
    const patch = await readFile(join(dir, receipt.evidence.patchFile))
    if (sha256(patch) !== receipt.evidence.patchSha256) throw new Error('captured patch hash does not match')
    if (sha256(patch) !== receipt.diff.sha256) throw new Error('captured patch does not match the signed diff hash')
    if (patch.length !== receipt.diff.bytes) throw new Error('captured patch byte count does not match the signed receipt')
    const totalBytes = receipt.diff.totalBytes ?? receipt.diff.bytes
    if (totalBytes < receipt.diff.bytes || receipt.diff.truncated !== (totalBytes > receipt.diff.bytes)) {
      throw new Error('captured patch truncation metadata is inconsistent')
    }
  }
  return receipt
}

/** Create a signed, privacy-minimized copy for an explicit hosted sync. */
export async function createSyncEnvelope(receipt: Receipt): Promise<SyncEnvelope> {
  const key = await loadSigningKey()
  const synced = structuredClone(receipt)
  const changedPaths = [...new Set(receipt.files.flatMap((file) => [file.path, file.oldPath])
    .filter((path): path is string => Boolean(path))
    .map((path) => path.replaceAll('\\', '/').replace(/^\.\//, '')))]
  const possiblePrivatePaths = [
    receipt.repoRoot,
    ...receipt.startDirtyFiles.filter((path) => !pathRelatedToChanges(path, changedPaths)),
    ...receipt.analyzers.findings
      .map((finding) => finding.filePath)
      .filter((path): path is string => Boolean(path) && !pathRelatedToChanges(path, changedPaths)),
    ...receipt.analyzers.passes.flatMap((pass) => pass.result.findings
      .map((finding) => finding.filePath)
      .filter((path): path is string => Boolean(path) && !pathRelatedToChanges(path, changedPaths))),
  ]
  for (const finding of receipt.analyzers.findings) collectPotentialPaths(finding.metadata, possiblePrivatePaths)
  for (const pass of receipt.analyzers.passes) {
    for (const finding of pass.result.findings) collectPotentialPaths(finding.metadata, possiblePrivatePaths)
  }
  const privatePaths = [...new Set(possiblePrivatePaths
    .filter((path) => !pathRelatedToChanges(path, changedPaths))
    .flatMap(pathVariants))]
    .sort((left, right) => right.length - left.length)

  synced.repoRoot = basename(receipt.repoRoot)
  synced.startDirtyFiles = synced.startDirtyFiles.filter((path) => pathRelatedToChanges(path, changedPaths))
  if (synced.agent) {
    synced.agent.command = synced.agent.command.length ? [basename(synced.agent.command[0])] : []
    delete synced.agent.startError
  }
  // Analyzer passes contain a second, whole-repository copy of every finding.
  // Sync only pass completion status and the separately filtered changed-file findings.
  synced.analyzers.passes = synced.analyzers.passes.map((pass) => {
    const result: Receipt['analyzers']['passes'][number]['result'] = {
      findings: [],
      complete: pass.result.complete,
    }
    if (pass.result.truncated !== undefined) result.truncated = pass.result.truncated
    return { id: pass.id, result }
  })
  synced.analyzers.findings = synced.analyzers.findings
    .filter((finding) => !finding.filePath || pathRelatedToChanges(finding.filePath, changedPaths))
    .map((finding) => {
      const sanitized = {
        ...finding,
        title: redactKnownPaths(finding.title, privatePaths),
        description: redactKnownPaths(finding.description, privatePaths),
      }
      if (finding.suggestion !== undefined) sanitized.suggestion = redactKnownPaths(finding.suggestion, privatePaths)
      delete sanitized.metadata
      return sanitized
    })
  synced.verifications = synced.verifications.map((item) => ({ ...item, command: '[redacted for sync]', output: '' }))
  synced.evidence = {
    patchSha256: receipt.evidence.patchSha256,
    publicKey: key.publicKey,
    keyFingerprint: key.fingerprint,
  }
  synced.coverageNotes = [
    ...synced.coverageNotes,
    'Hosted sync copy redacted the absolute repository path, unrelated dirty paths, agent arguments/start error, verification commands/output, duplicate whole-repository analyzer finding bodies, unrelated analyzer paths/metadata, and local evidence filenames.',
  ]
  const signedReceipt = `${JSON.stringify(synced, null, 2)}\n`
  return { signedReceipt, signature: signBytes(signedReceipt, key.privateKey) }
}
