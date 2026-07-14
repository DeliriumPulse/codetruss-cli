import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { computeScores } from '@codetruss/analyzer-engine'
import { afterEach, describe, expect, it } from 'vitest'
import { analyzeRepository, analyzerReceipt } from '../src/analysis.js'
import { LOCAL_ANALYSIS_PROFILE } from '../src/types.js'

const cleanup: string[] = []

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

describe('honest local analysis profile', () => {
  it('does not emit a perfect security score when graph and SAST never ran', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-analysis-profile-'))
    cleanup.push(root)
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'users.ts'), [
      'export function findUser(',
      '  req: { query: { id: string } },',
      '  db: { query(sql: string): unknown },',
      ') {',
      '  return db.query("SELECT * FROM users WHERE id = " + req.query.id)',
      '}',
      '',
    ].join('\n'))

    const analysis = await analyzeRepository(root)
    expect(analysis.passes).toHaveLength(13)

    // This is the exact misleading value earlier CLI versions inferred from
    // registry-only findings even though the synthetic SQL injection was never
    // examined by the hosted SAST pass.
    expect(computeScores(analysis.index, analysis.findings).security).toBe(100)

    const evidence = analyzerReceipt(analysis)
    expect(evidence.analysisProfile).toEqual(LOCAL_ANALYSIS_PROFILE)
    expect(evidence).not.toHaveProperty('scores')
    expect(evidence).not.toHaveProperty('baselineScores')
    expect(JSON.stringify(evidence)).not.toContain('"security"')
  })
})
