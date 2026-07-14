import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createSyncEnvelope, hookSessionId, newSessionId, renderLegacyMarkdown, renderMarkdown, verifyReceipt, writeReceipt } from '../src/receipt.js'
import { loadSigningKey, sha256, signBytes, verifyBytes } from '../src/signing.js'
import { LOCAL_ANALYSIS_PROFILE, type Receipt } from '../src/types.js'

const originalKey = process.env.CODETRUSS_SIGNING_KEY
afterEach(() => { if (originalKey === undefined) delete process.env.CODETRUSS_SIGNING_KEY; else process.env.CODETRUSS_SIGNING_KEY = originalKey })

function fixture(root: string, patch = 'diff evidence'): Receipt {
  const now = new Date('2026-07-12T21:00:00.123Z')
  return {
    receiptVersion: 1, sessionId: newSessionId(now), createdAt: now.toISOString(), finishedAt: now.toISOString(), durationMs: 0,
    mode: 'review', task: 'test receipt', repoRoot: root, startCommit: 'abc', endCommit: 'abc',
    git: { baselineTree: 'a'.repeat(40), finalTree: 'b'.repeat(40) }, policy: { sha256: 'c'.repeat(64) }, startDirty: false, startDirtyFiles: [],
    scope: { allow: ['src/**'], deny: [] }, files: [], diff: {
      sha256: createHash('sha256').update(patch).digest('hex'),
      bytes: Buffer.byteLength(patch),
      totalBytes: Buffer.byteLength(patch),
      truncated: false,
    },
    analyzers: { passes: [], findings: [], analysisProfile: LOCAL_ANALYSIS_PROFILE, index: { totalLoc: 0, languages: {}, primaryLanguage: null } },
    verifications: [], coverageNotes: ['local'], verdict: 'PASS', reasons: ['no changes'], evidence: {},
  }
}

function legacyFixture(root: string, patch = 'diff evidence'): Receipt {
  const receipt = fixture(root, patch)
  return {
    ...receipt,
    analyzers: {
      passes: receipt.analyzers.passes,
      findings: receipt.analyzers.findings,
      scores: { health: 100, debt: 100, architecture: 100, security: 100, docs: 100 },
      index: receipt.analyzers.index,
    },
  }
}

describe('signed receipts', () => {
  it('binds internal hook retries to one deterministic receipt path', () => {
    const now = new Date('2026-07-14T12:34:56.789Z')
    const attemptId = 'a'.repeat(64)
    expect(hookSessionId(now, attemptId)).toBe(`20260714T123456789Z-hook-${attemptId}`)
    expect(hookSessionId(now, attemptId)).toBe(hookSessionId(now, attemptId))
    expect(() => hookSessionId(now, 'A'.repeat(64))).toThrow(/attempt id is invalid/)
  })

  it('verifies JSON signature and Markdown/patch hashes and detects tampering', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-receipt-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = fixture(root)
    const paths = await writeReceipt(dir, receipt, 'diff evidence')
    await expect(verifyReceipt(dir, receipt.sessionId)).resolves.toMatchObject({ verdict: 'PASS' })
    const markdown = await readFile(paths.markdown, 'utf8')
    expect(markdown).toContain('Policy SHA-256')
    expect(markdown).toContain('Profile: `local-registry-v1`')
    expect(markdown).toContain('Hosted Health scores: **N/A**')
    expect(markdown).toContain('Hosted graph and SAST passes were omitted')
    expect(markdown).not.toContain('Final scores:')
    await writeFile(paths.markdown, `${await readFile(paths.markdown, 'utf8')}tampered`)
    await expect(verifyReceipt(dir, receipt.sessionId)).rejects.toThrow('Markdown receipt does not match')
  })

  it('verifies old score-bearing Markdown but suppresses those legacy scores when reporting it now', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-legacy-receipt-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = legacyFixture(root)
    const paths = await writeReceipt(dir, receipt, 'diff evidence')
    const oldMarkdown = renderLegacyMarkdown(receipt)
    receipt.evidence.markdownSha256 = sha256(oldMarkdown)
    const jsonText = `${JSON.stringify(receipt, null, 2)}\n`
    const key = await loadSigningKey()
    await writeFile(paths.json, jsonText)
    await writeFile(paths.markdown, oldMarkdown)
    await writeFile(paths.signature, `${signBytes(jsonText, key.privateKey)}\n`)

    const verified = await verifyReceipt(dir, receipt.sessionId)
    expect(oldMarkdown).toContain('Final scores: health 100')
    expect(renderMarkdown(verified)).toContain('Legacy local receipt')
    expect(renderMarkdown(verified)).toContain('Hosted Health scores: **N/A**')
    expect(renderMarkdown(verified)).not.toContain('security 100')
  })

  it('renders explicit optional LLM diff coverage', () => {
    const receipt = fixture('/tmp/repo')
    receipt.llm = {
      provider: 'openai', model: 'gpt-5.6-terra', transmittedBytes: 1_200,
      diffCoverage: { reviewedBytes: 200_000, totalBytes: 240_000, truncated: true },
      verdict: 'clean', summary: 'Reviewed the available prefix.', findings: [],
    }
    expect(renderMarkdown(receipt)).toContain('Reviewed 200000/240000 diff bytes (truncated; PASS prohibited).')
  })

  it('rejects a forged receipt signed by a substituted embedded key', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-receipt-forgery-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'trusted-signing.pem')
    const receipt = fixture(root)
    const paths = await writeReceipt(dir, receipt, 'diff evidence')
    const forged = JSON.parse(await readFile(paths.json, 'utf8')) as Receipt
    const attacker = generateKeyPairSync('ed25519')
    const attackerPublicKey = attacker.publicKey.export({ type: 'spki', format: 'pem' }).toString()
    forged.verdict = 'FAILED'
    forged.reasons = ['forged result']
    forged.evidence.publicKey = attackerPublicKey
    forged.evidence.keyFingerprint = createHash('sha256')
      .update(attacker.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex')
      .slice(0, 16)
    const forgedJson = `${JSON.stringify(forged, null, 2)}\n`
    await writeFile(paths.json, forgedJson)
    await writeFile(paths.signature, `${sign(null, Buffer.from(forgedJson), attacker.privateKey).toString('base64')}\n`)
    await expect(verifyReceipt(dir, receipt.sessionId)).rejects.toThrow('does not match trusted key')
  })

  it('signs a privacy-minimized sync copy', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-receipt-sync-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = fixture(root, 'private patch')
    receipt.startDirty = true
    receipt.startDirtyFiles = ['src/changed.ts', 'notes/private-plan.md']
    receipt.files = [{
      path: 'src/changed.ts', change: 'modified', classification: 'allowed', dependency: false, additions: 2, deletions: 1,
    }]
    receipt.agent = { command: ['codex', 'secret prompt'], exitCode: 0, durationMs: 1 }
    receipt.verifications = [{ command: 'test', exitCode: 0, durationMs: 1, output: 'sensitive output', truncated: false }]
    const relevantFinding = {
      analyzerId: 'duplication', category: 'DUPLICATION' as const, severity: 'MEDIUM' as const,
      title: 'Duplicated logic: private/unrelated.ts and src/changed.ts',
      description: 'A block appears in both private/unrelated.ts and src/changed.ts.',
      suggestion: 'Extract private/unrelated.ts and src/changed.ts into one module.',
      filePath: 'src/changed.ts', line: 3, impactScore: 55, effort: 'medium' as const,
      metadata: { otherFile: 'private/unrelated.ts', otherLine: 7 },
    }
    const unrelatedFinding = {
      analyzerId: 'size', category: 'TECH_DEBT' as const, severity: 'LOW' as const,
      title: 'Private whole-repo finding', description: 'whole-repo body must not sync',
      filePath: 'private/unrelated.ts', line: 7, impactScore: 10,
    }
    receipt.analyzers.findings = [relevantFinding, unrelatedFinding]
    receipt.analyzers.passes = [{
      id: 'duplication',
      result: {
        findings: [relevantFinding, unrelatedFinding], complete: false, truncated: true,
        detail: 'failed while reading private/unrelated.ts', metrics: { privatePath: 'private/unrelated.ts' },
      },
      error: 'private analyzer error at private/unrelated.ts',
    }]
    await writeReceipt(dir, receipt, 'private patch')
    const envelope = await createSyncEnvelope(receipt)
    const synced = JSON.parse(envelope.signedReceipt) as Receipt
    expect(synced.repoRoot).toBe(basename(root))
    expect(synced.startDirtyFiles).toEqual(['src/changed.ts'])
    expect(synced.policy).toEqual({ sha256: 'c'.repeat(64) })
    expect(synced.agent?.command).toEqual(['codex'])
    expect(synced.verifications[0].command).toBe('[redacted for sync]')
    expect(synced.verifications[0].output).toBe('')
    expect(synced.analyzers.passes).toEqual([{
      id: 'duplication', result: { findings: [], complete: false, truncated: true },
    }])
    expect(synced.analyzers.findings).toEqual([{
      analyzerId: 'duplication', category: 'DUPLICATION', severity: 'MEDIUM',
      title: 'Duplicated logic: [redacted unrelated path] and src/changed.ts',
      description: 'A block appears in both [redacted unrelated path] and src/changed.ts.',
      suggestion: 'Extract [redacted unrelated path] and src/changed.ts into one module.',
      filePath: 'src/changed.ts', line: 3, impactScore: 55, effort: 'medium',
    }])
    expect(Object.keys(synced.evidence).sort()).toEqual(['keyFingerprint', 'patchSha256', 'publicKey'])
    expect(verifyBytes(envelope.signedReceipt, synced.evidence.publicKey!, envelope.signature)).toBe(true)
    expect(envelope.signedReceipt).not.toContain('secret prompt')
    expect(envelope.signedReceipt).not.toContain('sensitive output')
    expect(envelope.signedReceipt).not.toContain('"command": "test"')
    expect(envelope.signedReceipt).not.toContain('private patch')
    expect(envelope.signedReceipt).not.toContain('notes/private-plan.md')
    expect(envelope.signedReceipt).not.toContain('private/unrelated.ts')
    expect(envelope.signedReceipt).not.toContain('whole-repo body must not sync')
    expect(envelope.signedReceipt).not.toContain('private analyzer error')
  })
})
