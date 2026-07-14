import { describe, expect, it } from 'vitest'
import { parseSyncSuccess, syncedReceiptUrl } from '../src/sync-response.js'

const expected = { sessionId: '20260714T120000Z-demo', verdict: 'REVIEW_REQUIRED' as const }

describe('hosted sync response binding', () => {
  it('returns only an exact verified receipt confirmation and a local dashboard URL', () => {
    const result = parseSyncSuccess(JSON.stringify({
      receipt: { id: 'cm123_example', sessionId: expected.sessionId, verdict: expected.verdict },
      idempotent: false,
      verification: { status: 'VERIFIED', sha256: 'a'.repeat(64) },
    }), expected)
    expect(result).toEqual({ receiptId: 'cm123_example', idempotent: false })
    expect(syncedReceiptUrl('https://codetruss.com', result.receiptId))
      .toBe('https://codetruss.com/dashboard/receipts/cm123_example')
  })

  it('rejects malformed, mismatched, unverified, and oversized confirmations', () => {
    expect(() => parseSyncSuccess('{', expected)).toThrow(/invalid JSON/)
    for (const mutation of [
      { sessionId: 'other', verdict: expected.verdict, status: 'VERIFIED', id: 'cm123' },
      { sessionId: expected.sessionId, verdict: 'PASS', status: 'VERIFIED', id: 'cm123' },
      { sessionId: expected.sessionId, verdict: expected.verdict, status: 'UNVERIFIED', id: 'cm123' },
      { sessionId: expected.sessionId, verdict: expected.verdict, status: 'VERIFIED', id: '../escape' },
    ]) {
      expect(() => parseSyncSuccess(JSON.stringify({
        receipt: { id: mutation.id, sessionId: mutation.sessionId, verdict: mutation.verdict },
        idempotent: false,
        verification: { status: mutation.status },
      }), expected)).toThrow(/exact verified receipt/)
    }
    expect(() => parseSyncSuccess(`{"padding":"${'x'.repeat(70_000)}"}`, expected)).toThrow(/exceeded/)
  })
})
