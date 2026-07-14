const MAX_SYNC_RESPONSE_BYTES = 64 * 1024
const RECEIPT_ID = /^[A-Za-z0-9_-]{1,128}$/

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`CodeTruss sync returned an invalid ${label}`)
  }
  return value as Record<string, unknown>
}

export function parseSyncSuccess(
  text: string,
  expected: { sessionId: string; verdict: 'PASS' | 'REVIEW_REQUIRED' | 'FAILED' },
): { receiptId: string; idempotent: boolean } {
  if (Buffer.byteLength(text) > MAX_SYNC_RESPONSE_BYTES) {
    throw new Error(`CodeTruss sync response exceeded ${MAX_SYNC_RESPONSE_BYTES} bytes`)
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error('CodeTruss sync returned invalid JSON')
  }
  const response = object(parsed, 'response')
  const receipt = object(response.receipt, 'receipt')
  const verification = object(response.verification, 'verification result')
  if (
    typeof receipt.id !== 'string'
    || !RECEIPT_ID.test(receipt.id)
    || receipt.sessionId !== expected.sessionId
    || receipt.verdict !== expected.verdict
    || verification.status !== 'VERIFIED'
    || typeof response.idempotent !== 'boolean'
  ) {
    throw new Error('CodeTruss sync response did not confirm the exact verified receipt')
  }
  return { receiptId: receipt.id, idempotent: response.idempotent }
}

export function syncedReceiptUrl(origin: string, receiptId: string): string {
  if (!RECEIPT_ID.test(receiptId)) throw new Error('CodeTruss receipt id is invalid')
  return new URL(`/dashboard/receipts/${encodeURIComponent(receiptId)}`, origin).toString()
}
