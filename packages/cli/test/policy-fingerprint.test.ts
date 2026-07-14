import { describe, expect, it } from 'vitest'
import { policyFingerprint } from '../src/policy-fingerprint.js'
import type { CliConfig, ReviewOptions } from '../src/types.js'

const config: CliConfig = {
  version: 1,
  allow: [],
  deny: [],
  verify: [],
  receipts: { dir: '.codetruss/receipts' },
  llm: { provider: 'claude', model: 'default', maxDiffBytes: 100_000 },
  signing: {},
  sync: { url: 'https://codetruss.com' },
}

const options: ReviewOptions = {
  mode: 'review',
  task: 'Fix auth',
  allow: ['src/**', 'tests/**'],
  deny: ['infra/**'],
  verify: ['pnpm test', 'pnpm lint'],
  llm: true,
  staged: false,
}

describe('policy fingerprint', () => {
  it('is stable across semantically irrelevant set ordering and task changes', () => {
    const first = policyFingerprint(options, config)
    const reordered = policyFingerprint({
      ...options,
      task: 'A different task does not change policy',
      allow: ['tests/**', 'src/**', 'src/**'],
      verify: ['pnpm lint', 'pnpm test'],
    }, config)
    expect(first).toMatch(/^[0-9a-f]{64}$/)
    expect(reordered).toBe(first)
  })

  it('changes for every material policy surface without exposing commands', () => {
    const baseline = policyFingerprint(options, config)
    expect(policyFingerprint({ ...options, deny: ['infra/**', 'migrations/**'] }, config)).not.toBe(baseline)
    expect(policyFingerprint({ ...options, verify: ['pnpm test --filter auth'] }, config)).not.toBe(baseline)
    expect(policyFingerprint({ ...options, llm: false }, config)).not.toBe(baseline)
    expect(JSON.stringify({ policy: { sha256: baseline } })).not.toContain('pnpm')
  })
})
