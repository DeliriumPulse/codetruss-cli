import { createHash } from 'node:crypto'
import type { CliConfig, ReviewOptions } from './types.js'

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function canonicalSet(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right))
}

/**
 * Stable semantic fingerprint for the effective review policy. Verification
 * commands influence the digest but are never copied into synced receipts.
 */
export function policyFingerprint(options: ReviewOptions, config: CliConfig): string {
  const document = {
    version: 1,
    scope: {
      allow: canonicalSet(options.allow),
      deny: canonicalSet(options.deny),
    },
    verification: {
      commandDigests: canonicalSet(options.verify.map(sha256)),
    },
    llm: {
      enabled: options.llm,
      provider: options.provider ?? config.llm.provider ?? null,
      model: config.llm.model ?? null,
      maxDiffBytes: config.llm.maxDiffBytes,
    },
  }
  return sha256(JSON.stringify(document))
}
