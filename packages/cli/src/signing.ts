import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto'
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

export interface SigningKey {
  privateKey: KeyObject
  publicKey: string
  fingerprint: string
}

export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex')
}

export function signingKeyPath(): string {
  return process.env.CODETRUSS_SIGNING_KEY ?? join(homedir(), '.config', 'codetruss', 'signing-private.pem')
}

export function normalizePublicKey(publicKey: string): string {
  return createPublicKey(publicKey).export({ type: 'spki', format: 'pem' }).toString()
}

export function publicKeyFingerprint(publicKey: string): string {
  const der = createPublicKey(publicKey).export({ type: 'spki', format: 'der' })
  return sha256(der).slice(0, 16)
}

export async function loadSigningKey(create = false): Promise<SigningKey> {
  const path = signingKeyPath()
  let pem: Buffer
  try {
    pem = await readFile(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    if (!create) {
      throw new Error(`trusted signing key not found at ${path}; run codetruss init or set CODETRUSS_SIGNING_KEY`)
    }
    const pair = generateKeyPairSync('ed25519')
    pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) as Buffer
    await mkdir(dirname(path), { recursive: true })
    await writeFile(path, pem, { mode: 0o600 })
    await chmod(path, 0o600)
  }
  const privateKey = createPrivateKey(pem)
  const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString()
  return { privateKey, publicKey, fingerprint: publicKeyFingerprint(publicKey) }
}

export async function requireTrustedSigningKey(pinnedPublicKey?: string): Promise<SigningKey> {
  const key = await loadSigningKey(true)
  if (pinnedPublicKey) {
    const pinnedFingerprint = publicKeyFingerprint(pinnedPublicKey)
    if (pinnedFingerprint !== key.fingerprint) {
      throw new Error(
        `local signing key ${key.fingerprint} does not match repository pin ${pinnedFingerprint}; set CODETRUSS_SIGNING_KEY to the trusted private key`,
      )
    }
  }
  return key
}

export function signBytes(bytes: Buffer | string, privateKey: KeyObject): string {
  return sign(null, Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes), privateKey).toString('base64')
}

export function verifyBytes(bytes: Buffer | string, publicKey: string, signature: string): boolean {
  return verify(
    null,
    Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes),
    createPublicKey(publicKey),
    Buffer.from(signature, 'base64'),
  )
}
