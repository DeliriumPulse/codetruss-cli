#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto'
import { realpath, rmdir } from 'node:fs/promises'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { analyzeRepository, analysisEvidenceIssues, analyzerReceipt, computeVerdict, diffFindings } from './analysis.js'
import { loadSyncAuthentication } from './auth-storage.js'
import { initialize, loadConfig, receiptDir } from './config.js'
import {
  allocatedVerificationTimeout,
  captureDiffEvidence,
  changedFiles,
  findRepoRoot,
  head,
  INTERNAL_HOOK_WORK_BUDGET_MS,
  runAgent,
  runVerification,
  VERIFICATION_TIMEOUT_MS,
} from './git.js'
import { createExactSnapshotCommit } from './hook-baseline.js'
import { indexTree, linkInstalledNodeModules, materializeTreeSnapshot, type MaterializedGitSnapshot } from './git-snapshot.js'
import {
  CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV,
  CODETRUSS_HOOK_CONTEXT_PATH_ENV,
  CODETRUSS_HOOK_CONTEXT_SHA256_ENV,
  dispatchAgentHook,
  readHookTurnContext,
  type AgentHookSurface,
} from './hook-runtime.js'
import { doctorHooks, hookStatus, installHooks, uninstallHooks } from './hooks.js'
import { hostedAuthStatus, loginHosted, logoutHosted } from './hosted-auth.js'
import { parseInternalHookResultRequest, writeInternalHookResult } from './hook-result.js'
import { reviewWithLlm } from './llm.js'
import { classifyPath, isDependencyFile, sensitiveCategory } from './policy.js'
import { policyFingerprint } from './policy-fingerprint.js'
import {
  CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV,
  initializePrivateGitObjectStore,
  openPrivateGitObjectStore,
  withoutPrivateGitEvidenceEnvironment,
  type PrivateGitObjectStore,
} from './private-git-object-store.js'
import { createSyncEnvelope, exitCode, hookSessionId, newSessionId, receiptIds, renderMarkdown, resolveReceipt, verifyReceipt, writeReceipt } from './receipt.js'
import { requireTrustedSigningKey } from './signing.js'
import { parseSyncSuccess, syncedReceiptUrl } from './sync-response.js'
import { runGitText } from './git-process.js'
import { LLM_PROVIDERS, type CliConfig, type Receipt, type ReviewOptions } from './types.js'
import { revokeVerifyCommands, trustVerifyCommands, verifyCommandTrustStatus } from './verify-trust.js'
import { CLI_VERSION } from './version.js'

interface Parsed { command: string; positionals: string[]; values: Map<string, string[]>; booleans: Set<string>; agent: string[] }

interface EvidenceTarget {
  baselineTreeish: string
  finalTreeish: string
  startCommit: string
  endCommit: string
  startDirtyFiles: string[]
  gitEnvironment?: NodeJS.ProcessEnv
}

interface HookEvidence {
  config: CliConfig
  task: string
  startedAt: Date
  contextPath: string
  target: EvidenceTarget
  objectStore: PrivateGitObjectStore
}

const MAX_RECEIPT_DURATION_MS = 7 * 24 * 60 * 60 * 1_000

function parse(argv: string[]): Parsed {
  const separator = argv.indexOf('--')
  const before = separator === -1 ? argv : argv.slice(0, separator)
  const agent = separator === -1 ? [] : argv.slice(separator + 1)
  const command = before.shift() ?? 'help'
  const positionals: string[] = []
  const values = new Map<string, string[]>()
  const booleans = new Set<string>()
  const booleanNames = new Set(['llm', 'staged', 'json', 'force', 'help', 'no-verify', 'dry-run'])
  for (let i = 0; i < before.length; i++) {
    const item = before[i]
    if (!item.startsWith('--')) { positionals.push(item); continue }
    const [name, inline] = item.slice(2).split('=', 2)
    if (booleanNames.has(name)) { booleans.add(name); continue }
    const value = inline ?? before[++i]
    if (value === undefined || value.startsWith('--')) throw new Error(`--${name} requires a value`)
    values.set(name, [...(values.get(name) ?? []), value])
  }
  return { command, positionals, values, booleans, agent }
}

function one(parsed: Parsed, name: string): string | undefined { return parsed.values.get(name)?.at(-1) }
function many(parsed: Parsed, name: string, fallback: string[]): string[] { return parsed.values.has(name) ? parsed.values.get(name)! : fallback }

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex')
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`CodeTruss hook evidence is missing ${name}`)
  return value
}

function assertCommitObject(root: string, objectStore: PrivateGitObjectStore, value: string, label: string): void {
  objectStore.assertObjectId(value, label)
  const resolved = runGitText(root, ['rev-parse', '--verify', `${value}^{commit}`], { env: objectStore.writeEnvironment() }).trim()
  if (resolved !== value) throw new Error(`${label} did not resolve to its exact commit object`)
}

function assertSnapshotParent(
  root: string,
  objectStore: PrivateGitObjectStore,
  snapshot: string,
  expectedParent: string,
  label: string,
): void {
  const parents = runGitText(root, ['show', '-s', '--format=%P', snapshot], { env: objectStore.writeEnvironment() })
    .trim()
    .split(/\s+/)
    .filter(Boolean)
  const expected = expectedParent ? [expectedParent] : []
  if (JSON.stringify(parents) !== JSON.stringify(expected)) {
    throw new Error(`${label} is not linked to the recorded repository commit`)
  }
}

function validatedHookStartedAt(): Date {
  const value = requiredEnvironment('CODETRUSS_HOOK_STARTED_AT')
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error('CodeTruss hook start time is not a canonical ISO timestamp')
  }
  const age = Date.now() - timestamp
  if (age < -5 * 60 * 1_000) throw new Error('CodeTruss hook start time is in the future')
  if (age > MAX_RECEIPT_DURATION_MS) throw new Error('CodeTruss hook evidence is older than the maximum receipt duration')
  return new Date(timestamp)
}

async function loadHookEvidence(root: string, baseline: string, final: string): Promise<HookEvidence> {
  const objectDirectory = await realpath(resolve(requiredEnvironment(CODETRUSS_EVIDENCE_OBJECT_DIRECTORY_ENV)))
  const objectStore = await openPrivateGitObjectStore(root, dirname(objectDirectory))
  if (await realpath(objectStore.objectDirectory) !== objectDirectory) {
    throw new Error('CodeTruss hook object-directory evidence does not match its private store')
  }
  objectStore.assertObjectId(baseline, 'baseline snapshot commit')
  objectStore.assertObjectId(final, 'final snapshot commit')
  assertCommitObject(root, objectStore, baseline, 'baseline snapshot commit')
  assertCommitObject(root, objectStore, final, 'final snapshot commit')

  const contextPath = await realpath(resolve(requiredEnvironment(CODETRUSS_HOOK_CONTEXT_PATH_ENV)))
  const expectedContextPath = await realpath(resolve(dirname(objectStore.directory), 'turn-context.json'))
  if (contextPath !== expectedContextPath) throw new Error('CodeTruss hook context is outside its private turn state')
  const context = await readHookTurnContext(contextPath, requiredEnvironment(CODETRUSS_HOOK_CONTEXT_SHA256_ENV))
  const expectedDirtyHash = requiredEnvironment(CODETRUSS_HOOK_BASELINE_DIRTY_FILES_SHA256_ENV)
  if (!/^[0-9a-f]{64}$/.test(expectedDirtyHash)
    || sha256(JSON.stringify(context.baselineDirtyFiles)) !== expectedDirtyHash) {
    throw new Error('CodeTruss hook baseline dirty-file evidence does not match prompt-time context')
  }

  const startCommit = process.env.CODETRUSS_HOOK_START_COMMIT
  const endCommit = process.env.CODETRUSS_HOOK_END_COMMIT
  if (startCommit === undefined || endCommit === undefined) {
    throw new Error('CodeTruss hook commit evidence is incomplete')
  }
  if (startCommit) assertCommitObject(root, objectStore, startCommit, 'hook starting commit')
  if (endCommit) assertCommitObject(root, objectStore, endCommit, 'hook final commit')
  assertSnapshotParent(root, objectStore, baseline, startCommit, 'baseline snapshot commit')
  assertSnapshotParent(root, objectStore, final, endCommit, 'final snapshot commit')

  return {
    config: context.config,
    task: context.task,
    startedAt: validatedHookStartedAt(),
    contextPath,
    objectStore,
    target: {
      baselineTreeish: baseline,
      finalTreeish: final,
      startCommit,
      endCommit,
      startDirtyFiles: [...context.baselineDirtyFiles],
      gitEnvironment: objectStore.writeEnvironment(),
    },
  }
}

async function initializeCommandObjectStore(root: string): Promise<{ objectStore: PrivateGitObjectStore; parent: string }> {
  const rawCommonDirectory = runGitText(root, ['rev-parse', '--git-common-dir']).trim()
  const commonDirectory = resolve(isAbsolute(rawCommonDirectory) ? rawCommonDirectory : join(root, rawCommonDirectory))
  const parent = join(commonDirectory, 'codetruss', 'commands', 'v1', randomUUID())
  const objectStore = await initializePrivateGitObjectStore(root, join(parent, 'object-store'))
  return { objectStore, parent }
}

function privateEmptyTree(root: string, objectStore: PrivateGitObjectStore): string {
  const tree = runGitText(root, ['mktree'], { env: objectStore.writeEnvironment(), input: Buffer.alloc(0) }).trim()
  objectStore.assertObjectId(tree, 'empty tree')
  return tree
}

function captureStagedTarget(root: string, objectStore: PrivateGitObjectStore): EvidenceTarget {
  const environment = objectStore.writeEnvironment()
  for (let attempt = 0; attempt < 3; attempt++) {
    const startCommit = head(root)
    const finalTreeish = indexTree(root, environment)
    objectStore.assertObjectId(finalTreeish, 'staged index tree')
    if (head(root) !== startCommit) continue
    return {
      baselineTreeish: startCommit || privateEmptyTree(root, objectStore),
      finalTreeish,
      startCommit,
      endCommit: startCommit,
      startDirtyFiles: [],
      gitEnvironment: environment,
    }
  }
  throw new Error('HEAD changed while capturing the staged evidence target')
}

async function cleanupCommandObjectStore(objectStore: PrivateGitObjectStore, parent: string): Promise<void> {
  try {
    await objectStore.cleanup()
  } finally {
    await rmdir(parent).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT' && error.code !== 'ENOTEMPTY') throw error
    })
  }
}

function help(): string {
  return `CodeTruss CLI — local guardrails and receipts for coding agents

Usage:
  codetruss run --task "..." [--allow GLOB] [--deny GLOB] [--verify CMD] [--llm] [--provider anthropic|openai|claude] -- <agent-cmd>
  codetruss review [--staged] --task "..." [--allow GLOB] [--deny GLOB] [--verify CMD] [--no-verify] [--llm] [--provider anthropic|openai|claude]
  codetruss report [id|latest] [--json]
  codetruss list [--json]
  codetruss init [--allow GLOB] [--deny GLOB] [--force]
  codetruss verify [id|latest]
  codetruss sync [id|latest] [--dry-run]
  codetruss auth login|status|logout
  codetruss verify-policy [status|trust|revoke]
  codetruss hooks install|status|doctor|uninstall [pre-commit|claude|codex|all]

Exit codes: PASS=0, REVIEW_REQUIRED=1, FAILED=2, usage/environment=3.`
}

async function executeReview(parsed: Parsed, root: string, liveConfig: CliConfig): Promise<number> {
  const mode = parsed.command as 'run' | 'review'
  const hookBase = one(parsed, 'base')
  const hookFinal = one(parsed, 'final')
  const hookResultRequest = parseInternalHookResultRequest()
  if (hookResultRequest && (!hookBase || !hookFinal)) {
    throw new Error('CodeTruss hook result output requires an exact internal hook baseline and final snapshot')
  }
  if (hookBase || hookFinal) {
    if (mode !== 'review' || parsed.booleans.has('staged') || process.env.CODETRUSS_INTERNAL_HOOK !== '1') {
      throw new Error('--base and --final are reserved for an active CodeTruss agent hook review')
    }
    if (!hookBase || !hookFinal) throw new Error('CodeTruss hook review requires both exact baseline and final object ids')
    const hookValueNames = new Set(['task', 'base', 'final'])
    const overrides = [...parsed.values.keys()].filter((name) => !hookValueNames.has(name))
    if (overrides.length || parsed.booleans.size) {
      throw new Error('CodeTruss hook reviews use only the prompt-time frozen policy; command-line overrides are not accepted')
    }
  }
  const requestedTask = one(parsed, 'task')?.trim()
  if (!requestedTask) throw new Error(`${mode} requires --task`)
  if (mode === 'run' && parsed.agent.length === 0) throw new Error('run requires an agent command after --')
  if (mode === 'run' && parsed.booleans.has('staged')) throw new Error('run does not accept --staged; use review --staged for index-only evidence')
  if (mode === 'review' && parsed.agent.length) throw new Error('review does not accept a command after --')
  const requestedProvider = one(parsed, 'provider')
  if (requestedProvider && !parsed.booleans.has('llm')) throw new Error('--provider requires --llm')
  if (requestedProvider && !LLM_PROVIDERS.includes(requestedProvider as typeof LLM_PROVIDERS[number])) {
    throw new Error(`unsupported LLM provider ${requestedProvider}; expected ${LLM_PROVIDERS.join(', ')}`)
  }
  const hookEvidence = hookBase && hookFinal ? await loadHookEvidence(root, hookBase, hookFinal) : undefined
  const internalHookDeadline = hookEvidence ? performance.now() + INTERNAL_HOOK_WORK_BUDGET_MS : undefined
  if (hookEvidence && hookEvidence.task !== requestedTask) {
    throw new Error('CodeTruss hook task does not match the authenticated prompt-time task')
  }
  const task = hookEvidence?.task ?? requestedTask
  const config = hookEvidence?.config ?? liveConfig
  if (requestedProvider && config.llm.model && config.llm.provider && config.llm.provider !== requestedProvider) {
    throw new Error(`--provider ${requestedProvider} conflicts with model ${config.llm.model} configured for ${config.llm.provider}`)
  }
  await requireTrustedSigningKey(config.signing.publicKey)
  const options: ReviewOptions = {
    mode, task,
    allow: many(parsed, 'allow', config.allow),
    deny: many(parsed, 'deny', config.deny),
    verify: parsed.booleans.has('no-verify') ? [] : many(parsed, 'verify', config.verify),
    llm: hookEvidence ? false : parsed.booleans.has('llm'),
    provider: hookEvidence ? config.llm.provider : requestedProvider,
    staged: parsed.booleans.has('staged'),
    agentCommand: mode === 'run' ? parsed.agent : undefined,
  }
  const repositoryVerifyCommands = options.verify.length > 0
    && !parsed.booleans.has('no-verify')
    && !parsed.values.has('verify')
  if (repositoryVerifyCommands) {
    const trust = await verifyCommandTrustStatus(root, options.verify)
    if (!trust.trusted) {
      throw new Error(
        `repository verification commands are not trusted (${trust.hash.slice(0, 12)}); inspect ${config.verify.join(', ')} and run codetruss verify-policy trust`,
      )
    }
  }

  const startedAt = hookEvidence?.startedAt ?? new Date()
  const snapshotParent = join(root, '.codetruss', 'snapshots')
  let baselineSnapshot: MaterializedGitSnapshot | undefined
  let finalSnapshot: MaterializedGitSnapshot | undefined
  let agent: Receipt['agent']
  let target = hookEvidence?.target
  let objectStore = hookEvidence?.objectStore
  let objectStoreParent: string | undefined
  let objectStoreOwned = false

  try {
    if (!target) {
      const commandStore = await initializeCommandObjectStore(root)
      objectStore = commandStore.objectStore
      objectStoreParent = commandStore.parent
      objectStoreOwned = true
      if (mode === 'run') {
        const baseline = await createExactSnapshotCommit(root, snapshotParent, objectStore)
        process.stderr.write(`codetruss: starting at ${baseline.head || '(unborn branch)'}\n`)
        const result = await runAgent(options.agentCommand!, root)
        agent = { command: options.agentCommand!, ...result }
        const final = await createExactSnapshotCommit(root, snapshotParent, objectStore)
        target = {
          baselineTreeish: baseline.commit,
          finalTreeish: final.commit,
          startCommit: baseline.head,
          endCommit: final.head,
          startDirtyFiles: [...baseline.dirtyFiles],
          gitEnvironment: objectStore.writeEnvironment(),
        }
      } else if (options.staged) {
        target = captureStagedTarget(root, objectStore)
      } else {
        const final = await createExactSnapshotCommit(root, snapshotParent, objectStore)
        target = {
          baselineTreeish: final.head || privateEmptyTree(root, objectStore),
          finalTreeish: final.commit,
          startCommit: final.head,
          endCommit: final.head,
          startDirtyFiles: [],
          gitEnvironment: objectStore.writeEnvironment(),
        }
      }
    }
    const immutableTarget = target
    baselineSnapshot = await materializeTreeSnapshot(root, immutableTarget.baselineTreeish, {
      parentDir: snapshotParent,
      gitEnvironment: immutableTarget.gitEnvironment,
    })
    finalSnapshot = await materializeTreeSnapshot(root, immutableTarget.finalTreeish, {
      parentDir: snapshotParent,
      gitEnvironment: immutableTarget.gitEnvironment,
    })

    const files = await changedFiles(
      root, immutableTarget.baselineTreeish, false,
      (path, oldPath) => classifyPath(path, oldPath, options.allow, options.deny),
      sensitiveCategory, isDependencyFile,
      immutableTarget.finalTreeish,
      { env: immutableTarget.gitEnvironment },
    )
    const diff = await captureDiffEvidence(root, immutableTarget.baselineTreeish, false, files, {
      targetTreeish: immutableTarget.finalTreeish,
      env: immutableTarget.gitEnvironment,
    })
    if (!baselineSnapshot.tree || !finalSnapshot.tree) {
      throw new Error('CodeTruss immutable evidence snapshots did not resolve to Git trees')
    }

    const baselineAnalysis = await analyzeRepository(baselineSnapshot.root)
    const analysis = await analyzeRepository(finalSnapshot.root)
    const findingDelta = diffFindings(baselineAnalysis.findings, analysis.findings, files)
    const relevantFindings = [...findingDelta.introduced, ...findingDelta.worsened]
    const baselineEvidenceIssues = analysisEvidenceIssues(baselineAnalysis.passes, baselineAnalysis.index.coverage)
    const finalEvidenceIssues = analysisEvidenceIssues(analysis.passes, analysis.index.coverage)
    const evidenceIssues = [
      ...finalEvidenceIssues.map((issue) => `final ${issue}`),
      ...(diff.truncated ? [`diff capture retained ${diff.capturedBytes} of ${diff.totalBytes} bytes`] : []),
    ]

    const verifications = []
    for (const [commandIndex, command] of options.verify.entries()) {
      process.stderr.write(`codetruss: verifying ${command}\n`)
      const remainingHookBudget = internalHookDeadline === undefined
        ? VERIFICATION_TIMEOUT_MS
        : allocatedVerificationTimeout(
            internalHookDeadline,
            performance.now(),
            options.verify.length - commandIndex,
          )
      if (remainingHookBudget <= 0) {
        verifications.push({
          command,
          exitCode: 124,
          durationMs: 0,
          output: `CodeTruss internal hook work budget was exhausted before this verification command started.`,
          truncated: false,
        })
        continue
      }
      const verificationSnapshot = await materializeTreeSnapshot(root, immutableTarget.finalTreeish, {
        gitEnvironment: immutableTarget.gitEnvironment,
      })
      try {
        await linkInstalledNodeModules(root, verificationSnapshot.root)
        const runtimeTimeout = internalHookDeadline === undefined
          ? VERIFICATION_TIMEOUT_MS
          : allocatedVerificationTimeout(
              internalHookDeadline,
              performance.now(),
              options.verify.length - commandIndex,
            )
        if (runtimeTimeout <= 0) {
          verifications.push({
            command,
            exitCode: 124,
            durationMs: 0,
            output: 'CodeTruss internal hook work budget was exhausted before this verification command started.',
            truncated: false,
          })
          continue
        }
        verifications.push(await runVerification(
          command,
          verificationSnapshot.root,
          16_384,
          withoutPrivateGitEvidenceEnvironment(process.env, verificationSnapshot.root),
          runtimeTimeout,
          !hookEvidence,
        ))
      } finally {
        await verificationSnapshot.cleanup()
      }
    }
    let llm: Receipt['llm']
    let llmFailure: string | undefined
    if (options.llm) {
      try { llm = await reviewWithLlm(task, diff.patch.toString('utf8'), config, options.provider, undefined, diff.totalBytes) }
      catch (error) { llmFailure = error instanceof Error ? error.message : String(error) }
    }
    const recordsStartState = mode === 'run' || Boolean(hookEvidence)
    const startDirtyFiles = recordsStartState ? immutableTarget.startDirtyFiles : []
    const startDirty = startDirtyFiles.length > 0
    const outcome = computeVerdict({
      agentExitCode: agent?.exitCode,
      verifications,
      files,
      // Hook receipts retain the factual prompt-time dirty state, but their
      // exact prompt snapshot still gives trustworthy turn attribution.
      startDirty: mode === 'run' && startDirty,
      findings: relevantFindings,
      llm,
      evidenceIssues,
      baselineEvidenceIssues: finalEvidenceIssues.length === 0 ? baselineEvidenceIssues : [],
    })
    if (llmFailure) { outcome.verdict = 'FAILED'; outcome.reasons.unshift(`requested LLM review failed: ${llmFailure}`) }
    const finishedAt = new Date()
    const durationMs = finishedAt.getTime() - startedAt.getTime()
    if (durationMs < 0 || durationMs > MAX_RECEIPT_DURATION_MS) {
      throw new Error('CodeTruss receipt duration is outside the accepted evidence window')
    }
    const sessionId = hookResultRequest
      ? hookSessionId(startedAt, hookResultRequest.attemptId)
      : newSessionId(startedAt)
    const receipt: Receipt = {
      receiptVersion: 1, sessionId, createdAt: startedAt.toISOString(), finishedAt: finishedAt.toISOString(), durationMs,
      mode, task, repoRoot: root, startCommit: immutableTarget.startCommit, endCommit: immutableTarget.endCommit,
      git: { baselineTree: baselineSnapshot.tree, finalTree: finalSnapshot.tree },
      policy: { sha256: policyFingerprint(options, config) },
      startDirty, startDirtyFiles, agent,
      scope: { allow: options.allow, deny: options.deny }, files,
      diff: {
        sha256: sha256(diff.patch),
        bytes: diff.capturedBytes,
        totalBytes: diff.totalBytes,
        truncated: diff.truncated,
      },
      analyzers: analyzerReceipt(analysis, baselineAnalysis, findingDelta),
      verifications, llm,
      coverageNotes: [
        hookEvidence
          ? 'Deterministic analyzers, scope evidence, and verification commands compare the prompt-time and Stop-time immutable private Git trees, including non-ignored untracked files.'
          : options.staged
            ? 'Deterministic analyzers and scope evidence compare HEAD with one frozen staged Git index tree; unstaged bytes were excluded.'
            : mode === 'run'
              ? 'Deterministic analyzers and scope evidence compare exact immutable pre-agent and post-agent Git-visible trees, including non-ignored untracked files.'
              : 'Deterministic analyzers and scope evidence compare HEAD with one immutable capture of the Git-visible working state, including non-ignored untracked files.',
        `Analyzer deltas compare exact baseline and final snapshots: ${findingDelta.introduced.length} introduced, ${findingDelta.worsened.length} worsened, ${findingDelta.recurring.length} recurring, ${findingDelta.resolved.length} resolved. Only introduced and worsened findings affect the verdict.`,
        diff.truncated
          ? `Diff evidence was truncated after ${diff.capturedBytes} of ${diff.totalBytes} bytes, so the receipt cannot PASS.`
          : `Diff evidence captured all ${diff.totalBytes} bytes.`,
        'Git inventory covers committed, staged, unstaged, renamed, deleted, and non-ignored untracked files; ignored files are not inspected.',
        'The local OSV vulnerability lookup is advisory and intentionally offline; use a trusted local package-audit command when vulnerability evidence is required.',
        llm
          ? `CodeTruss supplied the bounded task, ${llm.diffCoverage?.reviewedBytes ?? diff.capturedBytes} of ${llm.diffCoverage?.totalBytes ?? diff.totalBytes} observed diff bytes, fixed review instructions, and a response schema directly to ${llm.provider} using developer-owned credentials; the provider client may add its own runtime instructions and metadata.${llm.diffCoverage?.truncated ? ' LLM coverage was truncated, so the receipt cannot PASS.' : ''}`
          : options.llm
            ? 'The requested optional LLM review did not produce accepted evidence; the failure is recorded in the verdict reasons.'
            : 'No source code or diff left the machine.',
        'Every verification command ran outside the live repository on a fresh materialization of the same immutable final Git tree, so source-tree mutations could not affect later checks. Trusted commands reused the repository\'s ignored installed Node dependencies when present.',
      ],
      verdict: outcome.verdict, reasons: outcome.reasons, evidence: {},
    }
    const outputDirectory = receiptDir(root, config)
    const showFirstReceiptNextSteps = !hookEvidence && files.length > 0 && (await receiptIds(outputDirectory)).length === 0
    const paths = await writeReceipt(outputDirectory, receipt, diff.patch)
    if (hookResultRequest) {
      await writeInternalHookResult(
        hookResultRequest,
        hookEvidence!.contextPath,
        {
          verdict: receipt.verdict,
          receiptPath: resolve(paths.markdown),
          reasons: receipt.reasons,
        },
      )
    }
    process.stdout.write(`${receipt.verdict} ${receipt.sessionId}\n${paths.markdown}\n`)
    for (const reason of receipt.reasons) process.stdout.write(`- ${reason}\n`)
    if (showFirstReceiptNextSteps) {
      process.stdout.write([
        '',
        'First signed receipt created. REVIEW_REQUIRED exits 1 by design and is still valid evidence.',
        'Next: codetruss verify latest',
        'Then: codetruss init --allow "<your-change-root>/**"',
        'After policy: codetruss hooks install all',
        'Optional design-partner cohort: https://codetruss.com/cli#design-partner',
        '',
      ].join('\n'))
    }
    return exitCode(receipt.verdict)
  } finally {
    const cleanupErrors: unknown[] = []
    const cleanups: Array<() => Promise<void>> = []
    if (finalSnapshot) cleanups.push(finalSnapshot.cleanup.bind(finalSnapshot))
    if (baselineSnapshot) cleanups.push(baselineSnapshot.cleanup.bind(baselineSnapshot))
    if (objectStoreOwned && objectStore && objectStoreParent) {
      const ownedStore = objectStore
      const ownedStoreParent = objectStoreParent
      cleanups.push(() => cleanupCommandObjectStore(ownedStore, ownedStoreParent))
    }
    for (const cleanup of cleanups) {
      try { await cleanup() }
      catch (error) { cleanupErrors.push(error) }
    }
    if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'CodeTruss could not completely clean up private evidence')
  }
}

async function main(argv = process.argv.slice(2)): Promise<number> {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') { process.stdout.write(`${help()}\n`); return 0 }
  if (argv[0] === '--version' || argv[0] === '-v') { process.stdout.write(`codetruss ${CLI_VERSION}\n`); return 0 }
  const parsed = parse(argv)
  if (parsed.command === 'help' || parsed.booleans.has('help')) { process.stdout.write(`${help()}\n`); return 0 }
  if (parsed.command === 'version') { process.stdout.write(`codetruss ${CLI_VERSION}\n`); return 0 }
  if (parsed.command === 'auth') {
    const action = parsed.positionals[0] ?? 'status'
    if (action === 'login') { await loginHosted(); return 0 }
    if (action === 'status') {
      const status = await hostedAuthStatus()
      if (status.state === 'signed_out') {
        process.stdout.write('Not signed in. Run codetruss auth login.\n')
        return 1
      }
      if (status.state === 'invalid') {
        process.stdout.write(`Saved login for ${status.credential.org.name} is expired or revoked. Run codetruss auth login.\n`)
        return 1
      }
      if (status.state === 'unverified') {
        process.stdout.write(`Saved login for ${status.credential.org.name} could not be verified (${status.reason}).\n`)
        return 1
      }
      process.stdout.write(
        `Signed in to ${status.credential.org.name} (${status.credential.org.slug}).\n`
        + `Credential ${status.credential.keyPrefix}… expires ${status.credential.expiresAt}.\n`
        + `Scopes: ${status.credential.scopes.join(' ')}\n`,
      )
      return 0
    }
    if (action === 'logout') {
      const revoked = await logoutHosted()
      process.stdout.write(revoked ? 'Signed out and revoked the CLI credential.\n' : 'Already signed out.\n')
      return 0
    }
    throw new Error('auth requires login, status, or logout')
  }
  const root = findRepoRoot()
  const config = await loadConfig(root)
  const dir = receiptDir(root, config)
  if (parsed.command === 'run' || parsed.command === 'review') return executeReview(parsed, root, config)
  if (parsed.command === 'init') {
    const allow = many(parsed, 'allow', [])
    const deny = many(parsed, 'deny', [])
    const path = await initialize(root, parsed.booleans.has('force'), { allow, deny })
    process.stdout.write(`${path}\n`)
    if (allow.length === 0) {
      process.stdout.write(
        'No allow globs configured: changed paths remain unexpected, and agent hooks cannot be installed until .codetruss.yml defines at least one allow glob.\n'
        + 'Rerun with --force --allow "src/**" (repeat --allow as needed), or edit the policy before installing hooks.\n',
      )
    }
    return 0
  }
  if (parsed.command === 'report') {
    const receipt = await verifyReceipt(dir, parsed.positionals[0] ?? 'latest', config.signing.publicKey)
    process.stdout.write(parsed.booleans.has('json') ? `${JSON.stringify(receipt, null, 2)}\n` : renderMarkdown(receipt))
    return 0
  }
  if (parsed.command === 'list') {
    const ids = await receiptIds(dir)
    const rows = await Promise.all(ids.map(async (id) => (await resolveReceipt(dir, id)).receipt))
    if (parsed.booleans.has('json')) process.stdout.write(`${JSON.stringify(rows.map((r) => ({ sessionId: r.sessionId, verdict: r.verdict, task: r.task, createdAt: r.createdAt })), null, 2)}\n`)
    else { process.stdout.write('VERDICT\tSESSION\tTASK\n'); for (const row of rows) process.stdout.write(`${row.verdict}\t${row.sessionId}\t${row.task.replaceAll('\n', ' ')}\n`) }
    return 0
  }
  if (parsed.command === 'verify') { const receipt = await verifyReceipt(dir, parsed.positionals[0] ?? 'latest', config.signing.publicKey); process.stdout.write(`verified ${receipt.sessionId} (${receipt.verdict})\n`); return 0 }
  if (parsed.command === 'verify-policy') {
    const action = parsed.positionals[0] ?? 'status'
    if (!config.verify.length) { process.stdout.write('No repository verification commands are configured.\n'); return 0 }
    if (action === 'status') {
      const trust = await verifyCommandTrustStatus(root, config.verify)
      process.stdout.write(`${trust.trusted ? 'trusted' : 'untrusted'} ${trust.hash}\n${config.verify.map((command) => `- ${command}`).join('\n')}\n`)
      return trust.trusted ? 0 : 1
    }
    if (action === 'trust') {
      const trust = await trustVerifyCommands(root, config.verify)
      process.stdout.write(`trusted ${trust.hash}\n${config.verify.map((command) => `- ${command}`).join('\n')}\n`)
      return 0
    }
    if (action === 'revoke') {
      const trust = await revokeVerifyCommands(root, config.verify)
      process.stdout.write(`revoked ${trust.hash}\n`)
      return 0
    }
    throw new Error(`unknown verify-policy action ${action}; expected status, trust, or revoke`)
  }
  if (parsed.command === 'sync') {
    const receipt = await verifyReceipt(dir, parsed.positionals[0] ?? 'latest', config.signing.publicKey)
    const envelope = await createSyncEnvelope(receipt)
    if (parsed.booleans.has('dry-run')) { process.stdout.write(`${JSON.stringify(envelope, null, 2)}\n`); return 0 }
    const authentication = await loadSyncAuthentication()
    if (!authentication) throw new Error('sync requires codetruss auth login or CODETRUSS_API_KEY')
    if (
      authentication.source === 'saved-login'
      && authentication.credential
      && Date.parse(authentication.credential.expiresAt) <= Date.now()
    ) {
      throw new Error('saved CodeTruss login expired; run codetruss auth login again')
    }
    const url = `${authentication.origin}/api/v1/cli/receipts`
    const response = await fetch(url, { method: 'POST', headers: { authorization: `Bearer ${authentication.bearer}`, 'content-type': 'application/json' }, body: JSON.stringify(envelope) })
    const responseText = await response.text()
    if (!response.ok) throw new Error(`sync failed with HTTP ${response.status}: ${responseText.slice(0, 300)}`)
    const synced = parseSyncSuccess(responseText, { sessionId: receipt.sessionId, verdict: receipt.verdict })
    const dashboardUrl = syncedReceiptUrl(authentication.origin, synced.receiptId)
    process.stdout.write(`${synced.idempotent ? 'already synced' : 'synced'} ${receipt.sessionId}\nView: ${dashboardUrl}\n`); return 0
  }
  if (parsed.command === 'hooks') {
    const action = parsed.positionals[0]
    const target = parsed.positionals[1] ?? 'all'
    if (action === 'install') { await installHooks(root, target); return 0 }
    if (action === 'status') { await hookStatus(root, target); return 0 }
    if (action === 'doctor') return (await doctorHooks(root, target)).ok ? 0 : 1
    if (action === 'uninstall') { await uninstallHooks(root, target); return 0 }
    if (action === 'dispatch') {
      if (target !== 'claude' && target !== 'codex') throw new Error('hook dispatch requires claude or codex')
      return dispatchAgentHook(root, target as AgentHookSurface, config)
    }
    throw new Error('hooks requires install, status, doctor, or uninstall')
  }
  throw new Error(`unknown command ${parsed.command}\n\n${help()}`)
}

main().then((code) => { process.exitCode = code }).catch((error) => { process.stderr.write(`codetruss: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 3 })
