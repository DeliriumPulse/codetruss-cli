import { access, lstat } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline/promises'
import type { Readable, Writable } from 'node:stream'
import { CONFIG_FILE, initialize, loadConfig } from './config.js'
import { inspectHookDoctor, installHooks } from './hooks.js'
import { ensureLocalEvidenceProtected } from './local-evidence.js'
import { trustVerifyCommands, verifyCommandTrustStatus } from './verify-trust.js'

const SUGGESTED_SCOPE_DIRECTORIES = [
  'src',
  'app',
  'apps',
  'packages',
  'lib',
  'components',
  'server',
  'client',
  'public',
  'test',
  'tests',
  'e2e',
  'spec',
  'docs',
] as const

const HOOK_TARGETS = ['all', 'pre-commit', 'claude', 'codex', 'none'] as const
type SetupHookTarget = typeof HOOK_TARGETS[number]

export interface GuidedSetupOptions {
  allow?: string[]
  deny?: string[]
  hooks?: string
  trustVerify?: boolean
  yes?: boolean
  input?: Readable
  output?: Writable
  ask?: (question: string) => Promise<string>
}

function normalizeGlobs(values: string[] | undefined, label: string): string[] | undefined {
  if (values === undefined) return undefined
  const normalized = values.map((value) => value.trim())
  if (normalized.some((value) => !value)) throw new Error(`setup ${label} globs must be non-empty strings`)
  return normalized
}

function parsePromptGlobs(value: string): string[] {
  return value.split(',').map((glob) => glob.trim()).filter(Boolean)
}

function repositoryWide(glob: string): boolean {
  return new Set(['*', '**', '**/*', './**', './**/*']).has(glob.trim())
}

function hookTarget(value: string | undefined): SetupHookTarget | undefined {
  if (value === undefined) return undefined
  if (!HOOK_TARGETS.includes(value as SetupHookTarget)) {
    throw new Error(`unknown setup hook target ${value}; expected ${HOOK_TARGETS.join(', ')}`)
  }
  return value as SetupHookTarget
}

async function exists(path: string): Promise<boolean> {
  return access(path).then(() => true, () => false)
}

export async function suggestedAllowGlobs(root: string): Promise<string[]> {
  const suggestions: string[] = []
  for (const directory of SUGGESTED_SCOPE_DIRECTORIES) {
    try {
      const metadata = await lstat(join(root, directory))
      if (metadata.isDirectory() && !metadata.isSymbolicLink()) suggestions.push(`${directory}/**`)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
  }
  return suggestions
}

async function resolveAllowGlobs(
  root: string,
  explicit: string[] | undefined,
  yes: boolean,
  ask: (question: string) => Promise<string>,
  write: (value: string) => void,
): Promise<string[]> {
  if (explicit?.length) return explicit
  const suggestions = await suggestedAllowGlobs(root)
  if (yes) {
    throw new Error('non-interactive setup requires at least one explicit --allow "src/**" value')
  }

  if (suggestions.length) {
    write(`Suggested allowed change roots: ${suggestions.join(', ')}\n`)
  } else {
    write('No conventional source directories were found. Choose the paths agents are normally allowed to change.\n')
  }
  const answer = await ask(
    suggestions.length
      ? `Allowed roots (comma-separated) [${suggestions.join(', ')}]: `
      : 'Allowed roots (comma-separated, for example src/**, tests/**): ',
  )
  const selected = answer.trim() ? parsePromptGlobs(answer) : suggestions
  if (!selected.length) throw new Error('setup requires at least one allowed change root')
  if (selected.some(repositoryWide)) {
    write('Warning: a repository-wide allow glob weakens scope-drift detection.\n')
    const confirmation = await ask('Type "broad" to keep this repository-wide scope: ')
    if (confirmation.trim().toLowerCase() !== 'broad') throw new Error('repository-wide scope was not confirmed')
  }
  return selected
}

async function resolveHookTarget(
  requested: SetupHookTarget | undefined,
  yes: boolean,
  ask: (question: string) => Promise<string>,
): Promise<SetupHookTarget> {
  if (requested) return requested
  if (yes) return 'all'
  const answer = (await ask('Automatic checks [all] (all, pre-commit, claude, codex, none): ')).trim()
  return hookTarget(answer || 'all')!
}

/**
 * One guided, resumable setup path. Repository verification commands are
 * displayed before their exact path-bound fingerprint is trusted. `--yes`
 * deliberately does not imply command trust.
 */
export async function guidedSetup(root: string, options: GuidedSetupOptions = {}): Promise<number> {
  const input = options.input ?? process.stdin
  const output = options.output ?? process.stdout
  const write = (value: string) => { output.write(value) }
  const allow = normalizeGlobs(options.allow, 'allow')
  const deny = normalizeGlobs(options.deny, 'deny')
  const requestedHooks = hookTarget(options.hooks)
  const yes = options.yes === true
  let readline: ReturnType<typeof createInterface> | undefined
  let answers: AsyncIterableIterator<string> | undefined
  const ask = options.ask ?? (async (question: string) => {
    if (!readline) {
      readline = createInterface({ input, output })
      answers = readline[Symbol.asyncIterator]()
    }
    output.write(question)
    const answer = await answers!.next()
    if (answer.done) throw new Error('setup input ended before every required confirmation')
    return answer.value
  })

  try {
    write('CodeTruss guided setup — local only; nothing is uploaded.\n')
    await ensureLocalEvidenceProtected(root)
    const configPath = join(root, CONFIG_FILE)
    const hasConfig = await exists(configPath)
    if (hasConfig) {
      const existing = await loadConfig(root)
      const allowChanged = allow !== undefined && JSON.stringify(allow) !== JSON.stringify(existing.allow)
      const denyChanged = deny !== undefined && JSON.stringify(deny) !== JSON.stringify(existing.deny)
      if (allowChanged || denyChanged) {
        throw new Error(`${CONFIG_FILE} already exists with a different ${allowChanged ? 'allow' : 'deny'} policy; edit and review it directly, then rerun setup`)
      }
      write(`${allow !== undefined || deny !== undefined ? 'Requested policy matches' : 'Using existing'} ${CONFIG_FILE}.\n`)
    } else {
      const selectedAllow = await resolveAllowGlobs(root, allow, yes, ask, write)
      const selectedDeny = deny ?? []
      const path = await initialize(root, false, {
        allow: selectedAllow,
        deny: selectedDeny,
      })
      write(`Saved policy: ${path}\n`)
    }

    const config = await loadConfig(root)
    if (!config.allow.length) {
      throw new Error(`${CONFIG_FILE} has no allowed change roots; define at least one allow glob and rerun codetruss setup`)
    }
    write(`Allowed: ${config.allow.join(', ')}\n`)
    write(`Denied: ${config.deny.length ? config.deny.join(', ') : '(none; sensitive surfaces still require review)'}\n`)

    if (config.verify.length) {
      write('Detected repository verification commands:\n')
      for (const command of config.verify) write(`  - ${command}\n`)
      write('These commands execute repository code, each in its own isolated snapshot.\n')
    } else {
      write('No repository verification commands were detected; add trusted checks to verify: in .codetruss.yml when ready.\n')
    }

    const selectedHooks = await resolveHookTarget(requestedHooks, yes, ask)
    if (config.verify.length && (selectedHooks !== 'none' || options.trustVerify)) {
      const currentTrust = await verifyCommandTrustStatus(root, config.verify)
      write(`Verification fingerprint: ${currentTrust.hash}\n`)
      if (currentTrust.trusted) {
        write('Verification commands are already trusted for this repository path.\n')
      } else {
        if (options.trustVerify) {
          await trustVerifyCommands(root, config.verify)
          write('Trusted the exact verification command list shown above.\n')
        } else if (yes) {
          throw new Error('automatic setup will not trust repository commands via --yes; inspect the commands above and rerun with --trust-verify')
        } else {
          const approval = await ask('Type "trust" to approve this exact command list for automatic checks: ')
          if (approval.trim().toLowerCase() !== 'trust') {
            write('Setup paused before hook installation. The policy is saved, but repository commands remain untrusted.\n')
            write('After inspection: codetruss verify-policy trust && codetruss setup\n')
            return 3
          }
          await trustVerifyCommands(root, config.verify)
          write('Trusted the exact verification command list shown above.\n')
        }
      }
    }

    if (selectedHooks === 'none') {
      write('Policy ready. Automatic hooks were not installed. Run codetruss hooks install all when ready.\n')
      write('Receipts stay on this machine unless you explicitly run codetruss sync.\n')
      return 0
    }

    await installHooks(root, selectedHooks)
    const doctor = await inspectHookDoctor(root, selectedHooks)
    const errors = doctor.checks.filter((check) => check.level === 'error')
    const warnings = doctor.checks.filter((check) => check.level === 'warning' && check.target !== 'codex')
    for (const check of [...errors, ...warnings]) {
      write(`${check.level.toUpperCase()} ${check.target}: ${check.message}${check.path ? ` (${check.path})` : ''}\n`)
    }
    if (errors.length) throw new Error(`hook health check found ${errors.length} error(s); run codetruss hooks doctor ${selectedHooks}`)

    const codexSelected = selectedHooks === 'all' || selectedHooks === 'codex'
    if (selectedHooks === 'codex') write('INSTALLED: Codex automatic checks are configured but are not active until project-hook approval.\n')
    else write(`READY: ${selectedHooks === 'all' ? 'pre-commit and Claude' : selectedHooks} automatic checks are active.\n`)
    if (warnings.length) write(`Hook health has ${warnings.length} warning(s); run codetruss hooks doctor ${selectedHooks} for detail.\n`)
    if (codexSelected) {
      write('ACTION REQUIRED FOR CODEX: open /hooks once and trust this exact project hook. Changed hook definitions require review again.\n')
    }
    if (selectedHooks === 'codex') write('After that approval, use Codex normally; no per-change CodeTruss command is required.\n')
    else if (selectedHooks === 'all') write('Use Claude Code or your normal commit flow now; after the Codex approval above, use Codex normally too. No per-change CodeTruss command is required.\n')
    else if (selectedHooks === 'claude') write('Use Claude Code normally; no per-change CodeTruss command is required.\n')
    else write('Use your normal commit flow; no per-change CodeTruss command is required.\n')
    write(`Undo automatic checks: codetruss hooks uninstall ${selectedHooks}\n`)
    write('Receipts stay on this machine unless you explicitly run codetruss sync.\n')
    return 0
  } finally {
    readline?.close()
  }
}
