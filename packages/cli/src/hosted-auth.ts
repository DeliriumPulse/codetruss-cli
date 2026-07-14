import { spawn } from 'node:child_process'
import { hostname, platform } from 'node:os'
import {
  clearCliAuth,
  loadCliAuth,
  saveCliAuth,
  type CliAuthCredential,
} from './auth-storage.js'
import { resolveSyncOrigin } from './config.js'

const CLIENT_ID = 'codetruss-cli'
const DEVICE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'
const REQUEST_TIMEOUT_MS = 15_000

type Fetch = typeof fetch

export interface HostedAuthOptions {
  origin?: string
  authFile?: string
  fetch?: Fetch
  openBrowser?: (url: string) => Promise<boolean>
  sleep?: (milliseconds: number) => Promise<void>
  now?: () => number
  stdout?: Pick<NodeJS.WriteStream, 'write'>
  stderr?: Pick<NodeJS.WriteStream, 'write'>
  clientName?: string
}

interface DeviceResponse {
  device_code: string
  user_code: string
  verification_uri: string
  verification_uri_complete: string
  expires_in: number
  interval: number
}

interface TokenSuccess {
  access_token: string
  token_type: 'Bearer'
  expires_in: number
  scope: string
  key_prefix: string
  org: { id: string; name: string; slug: string }
}

function form(values: Record<string, string>): URLSearchParams {
  return new URLSearchParams(values)
}

function hostedOrigin(value: string | undefined): string {
  if (value === undefined) return resolveSyncOrigin()
  if (value === 'https://codetruss.com') return value
  return resolveSyncOrigin(value)
}

async function fetchWithTimeout(
  fetchImpl: Fetch,
  input: string,
  init: RequestInit,
): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    return await fetchImpl(input, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

async function responseJson(response: Response): Promise<Record<string, unknown>> {
  const parsed = await response.json().catch(() => null)
  return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {}
}

function deviceResponse(value: Record<string, unknown>): DeviceResponse {
  if (
    typeof value.device_code !== 'string'
    || value.device_code.length < 32
    || value.device_code.length > 256
    || typeof value.user_code !== 'string'
    || !/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/.test(value.user_code)
    || typeof value.verification_uri !== 'string'
    || typeof value.verification_uri_complete !== 'string'
    || typeof value.expires_in !== 'number'
    || !Number.isInteger(value.expires_in)
    || value.expires_in < 60
    || value.expires_in > 1_800
    || typeof value.interval !== 'number'
    || !Number.isInteger(value.interval)
    || value.interval < 5
    || value.interval > 60
  ) {
    throw new Error('CodeTruss returned an invalid device authorization response')
  }
  return value as unknown as DeviceResponse
}

function validateVerificationUrls(authorization: DeviceResponse, origin: string): void {
  let verification: URL
  let complete: URL
  try {
    verification = new URL(authorization.verification_uri)
    complete = new URL(authorization.verification_uri_complete)
  } catch {
    throw new Error('CodeTruss returned an invalid verification URL')
  }
  if (
    verification.origin !== origin
    || verification.pathname !== '/cli/authorize'
    || verification.search
    || verification.hash
    || complete.origin !== origin
    || complete.pathname !== '/cli/authorize'
    || complete.hash
    || complete.searchParams.get('user_code') !== authorization.user_code
  ) {
    throw new Error('CodeTruss returned a verification URL outside the authenticated origin')
  }
}

function tokenSuccess(value: Record<string, unknown>): TokenSuccess {
  if (
    typeof value.access_token !== 'string'
    || !/^ct_cli_[0-9A-Za-z]{32}$/.test(value.access_token)
    || value.token_type !== 'Bearer'
    || typeof value.expires_in !== 'number'
    || !Number.isInteger(value.expires_in)
    || value.expires_in < 60
    || value.expires_in > 366 * 24 * 60 * 60
    || typeof value.scope !== 'string'
    || value.scope.split(/\s+/).sort().join(' ') !== 'receipts:read receipts:write'
    || typeof value.key_prefix !== 'string'
    || !value.access_token.startsWith(value.key_prefix)
    || !value.org
    || typeof value.org !== 'object'
  ) {
    throw new Error('CodeTruss returned an invalid CLI credential')
  }
  const org = value.org as Record<string, unknown>
  if (typeof org.id !== 'string' || typeof org.name !== 'string' || typeof org.slug !== 'string') {
    throw new Error('CodeTruss returned an invalid organization')
  }
  return value as unknown as TokenSuccess
}

export async function openHostedAuthBrowser(url: string): Promise<boolean> {
  const target = new URL(url)
  if (target.protocol !== 'https:' && target.hostname !== 'localhost' && target.hostname !== '127.0.0.1') {
    return false
  }
  const command = process.platform === 'darwin'
    ? { executable: 'open', args: [url] }
    : process.platform === 'win32'
      ? { executable: 'rundll32', args: ['url.dll,FileProtocolHandler', url] }
      : { executable: 'xdg-open', args: [url] }
  return new Promise((resolve) => {
    const child = spawn(command.executable, command.args, {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    })
    let settled = false
    child.once('error', () => {
      if (!settled) resolve(false)
      settled = true
    })
    child.once('spawn', () => {
      child.unref()
      if (!settled) resolve(true)
      settled = true
    })
  })
}

export async function loginHosted(options: HostedAuthOptions = {}): Promise<CliAuthCredential> {
  const origin = hostedOrigin(options.origin)
  const fetchImpl = options.fetch ?? fetch
  const sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)))
  const now = options.now ?? Date.now
  const stdout = options.stdout ?? process.stdout
  const stderr = options.stderr ?? process.stderr
  const openBrowser = options.openBrowser ?? openHostedAuthBrowser
  const clientName = options.clientName ?? `${hostname()} (${platform()})`

  const deviceRequest = await fetchWithTimeout(
    fetchImpl,
    `${origin}/api/v1/cli/auth/device`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form({
        client_id: CLIENT_ID,
        scope: 'receipts:read receipts:write',
        client_name: clientName,
      }),
    },
  )
  const deviceBody = await responseJson(deviceRequest)
  if (!deviceRequest.ok) {
    throw new Error(`CodeTruss login could not start (HTTP ${deviceRequest.status})`)
  }
  const authorization = deviceResponse(deviceBody)
  validateVerificationUrls(authorization, origin)
  stdout.write(`Open ${authorization.verification_uri}\nEnter code: ${authorization.user_code}\n`)
  if (!(await openBrowser(authorization.verification_uri_complete))) {
    stderr.write('codetruss: could not open a browser; use the URL and code above\n')
  }

  const deadline = now() + authorization.expires_in * 1000
  let interval = Math.max(5, authorization.interval)
  while (now() < deadline) {
    await sleep(interval * 1000)
    let response: Response
    try {
      response = await fetchWithTimeout(
        fetchImpl,
        `${origin}/api/v1/cli/auth/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: form({
            grant_type: DEVICE_GRANT_TYPE,
            device_code: authorization.device_code,
            client_id: CLIENT_ID,
          }),
        },
      )
    } catch {
      interval = Math.min(60, interval * 2)
      stderr.write(`codetruss: login poll timed out; retrying in ${interval}s\n`)
      continue
    }

    const body = await responseJson(response)
    if (response.ok) {
      const token = tokenSuccess(body)
      const authenticatedAt = new Date(now()).toISOString()
      const credential: CliAuthCredential = {
        version: 1,
        origin,
        accessToken: token.access_token,
        keyPrefix: token.key_prefix,
        org: token.org,
        scopes: token.scope.split(/\s+/).filter(Boolean),
        expiresAt: new Date(Date.parse(authenticatedAt) + token.expires_in * 1000).toISOString(),
        authenticatedAt,
      }
      await saveCliAuth(credential, options.authFile)
      stdout.write(`Signed in to ${credential.org.name} (${credential.org.slug}).\n`)
      return credential
    }

    const error = typeof body.error === 'string' ? body.error : 'unknown_error'
    if (error === 'authorization_pending') {
      if (typeof body.interval === 'number') interval = Math.max(interval, body.interval)
      continue
    }
    if (error === 'slow_down') {
      interval = Math.max(interval + 5, typeof body.interval === 'number' ? body.interval : 0)
      continue
    }
    if (error === 'access_denied') throw new Error('CodeTruss CLI authorization was denied')
    if (error === 'expired_token') throw new Error('CodeTruss CLI authorization expired; run auth login again')
    throw new Error(`CodeTruss login failed (${error})`)
  }
  throw new Error('CodeTruss CLI authorization expired; run auth login again')
}

export type HostedAuthStatus =
  | { state: 'signed_out' }
  | { state: 'authenticated'; credential: CliAuthCredential }
  | { state: 'invalid'; credential: CliAuthCredential }
  | { state: 'unverified'; credential: CliAuthCredential; reason: string }

export async function hostedAuthStatus(options: HostedAuthOptions = {}): Promise<HostedAuthStatus> {
  const credential = await loadCliAuth(options.authFile)
  if (!credential) return { state: 'signed_out' }
  const fetchImpl = options.fetch ?? fetch
  try {
    const response = await fetchWithTimeout(
      fetchImpl,
      `${credential.origin}/api/v1/cli/auth/session`,
      { headers: { authorization: `Bearer ${credential.accessToken}` } },
    )
    if (response.status === 401) return { state: 'invalid', credential }
    if (!response.ok) return { state: 'unverified', credential, reason: `HTTP ${response.status}` }
    const body = await responseJson(response)
    return body.authenticated === true
      ? { state: 'authenticated', credential }
      : { state: 'invalid', credential }
  } catch (error) {
    return {
      state: 'unverified',
      credential,
      reason: error instanceof Error ? error.message : 'network error',
    }
  }
}

export async function logoutHosted(options: HostedAuthOptions = {}): Promise<boolean> {
  const credential = await loadCliAuth(options.authFile)
  if (!credential) return false
  const fetchImpl = options.fetch ?? fetch
  const response = await fetchWithTimeout(
    fetchImpl,
    `${credential.origin}/api/v1/cli/auth/session`,
    { method: 'DELETE', headers: { authorization: `Bearer ${credential.accessToken}` } },
  )
  if (!response.ok && response.status !== 401) {
    throw new Error(`CodeTruss logout failed with HTTP ${response.status}; local credential retained for retry`)
  }
  await clearCliAuth(options.authFile)
  return true
}
