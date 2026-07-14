# Changelog

CodeTruss CLI follows semantic versioning. Release artifacts and their SHA-256
checksums are published at <https://codetruss.com/downloads/codetruss-cli-latest.json>.

## 0.2.13 — 2026-07-14

- Enable Git for Windows long-path support command-locally for every
  CodeTruss-owned Git process and generated hook entry point. Exact private
  evidence now remains usable in deep checkouts without changing the user's
  repository or global Git configuration.
- Preserve the complete v0.2.12 SBOM, authentication-network-contract, hook,
  verifier-isolation, and local-evidence hardening in a new immutable release
  after the Windows compatibility matrix rejected the prior candidate.

## 0.2.12 — 2026-07-14 (unpublished)

- Preserve the complete v0.2.11 hook, Windows, verifier, and exact-evidence
  hardening without replacing that candidate's immutable versioned bytes.
- Emit canonical Package URLs for scoped npm components in the deterministic
  CycloneDX SBOM so registry and vulnerability tooling can match them.
- Correct the authentication network contract: `auth status` verifies the
  saved credential with CodeTruss, while `auth logout` revokes it before
  deleting the local copy; neither command sends repository data or receipts.
- Release review retained this candidate without publication after the Windows
  matrix exposed a remaining Git `MAX_PATH` failure in deep private-evidence
  directories. v0.2.13 carries the command-local long-path fix.

## 0.2.11 — 2026-07-14 (unpublished)

- Make agent hooks fail closed when exact baseline evidence, state locks, the
  installed runner, or the local review process fails. A failed first Stop asks
  for one repair turn; an already-active Stop reports the result without
  creating an infinite continuation loop.
- Preserve retryability before final evidence is frozen and durably replay a
  completed exact result after post-review transport failures, so a transient
  crash cannot poison state or silently rerun a completed review.
- Bound the full hook pipeline inside its host deadline, terminate timed-out
  verifier process trees, fairly allocate the remaining command budget, and
  retain bounded head/tail output when a trusted verifier is noisy.
- Normalize Windows Git evidence against its native `NUL` sentinel, canonicalize
  filesystem aliases before private-object-store containment checks, keep hook
  state below native path limits, and keep the verifier deadline armed while
  descendant-held output pipes remain open.
- Keep hosted analyzer indexing historically identical while enabling explicit
  binary-aware local CLI indexing for archives, fonts, and WebAssembly assets.
- Include the hook-state migration and deterministic release-policy hardening
  from the unpublished 0.2.6 through 0.2.10 candidates.
- Release review rejected this candidate before publication because its SBOM
  encoded scoped npm package slashes noncanonically. The immutable artifact was
  retained; v0.2.12 carries the corrected metadata.

## 0.2.10 — 2026-07-14 (unpublished)

- Freeze the hook-state migration only after its full-key precedence, candidate
  collision cleanup, and empty legacy-root removal regressions passed. This
  prevents the release artifact from racing the final privacy hardening.
- Include the migration and independent package-policy enforcement from the
  unpublished 0.2.9 candidate.
- Independent release review rejected this candidate before publication after
  finding that some Stop-hook operational failures did not block and that
  verifier timeouts did not yet terminate the complete descendant process tree.

## 0.2.9 — 2026-07-14 (unpublished)

- Move compact hook state to a new versioned layout and explicitly retire the
  legacy 64-character state tree, including owned private Git object stores, so
  an upgrade cannot orphan captured task text or source evidence.
- Enforce a release-package policy independently from byte reproducibility:
  fixed package identity and source links, no runtime dependency declarations,
  no install lifecycle scripts, and matching CycloneDX component identity.
- Include the Windows path, cross-platform reproducibility, and strict release
  verifier hardening from the unpublished 0.2.8 candidate.

## 0.2.8 — 2026-07-14 (unpublished)

- Byte-compare the complete packaged manifest, including lifecycle scripts and
  dependency metadata, and require canonical release metadata and checksum
  sidecars so a refreshed-but-tampered release cannot pass local verification.
- Bound private agent-hook state components to 96-bit hashed path keys and use
  compact snapshot directories so exact evidence remains reliable under
  Windows path limits; run CLI subprocess coverage through Node on every OS.
- Force LF source checkout across platforms, reject non-regular release inputs
  even where symlink creation is unavailable, and include all deterministic
  packaging and verifier hardening from the unpublished 0.2.7 candidate.

## 0.2.7 — 2026-07-14 (unpublished)

- Strictly verify the custom release envelope independently from the writer:
  gzip framing, stored blocks, CRC32, ISIZE, USTAR magic, checksums, ownership,
  modes, ordering, padding, terminators, exact entries, and `package.json.files`.
- Add boundary and corruption regressions, reject symbolic/non-regular package
  inputs, enforce a 1 MB archive budget, and require every operating-system and
  Node compatibility job to rebuild and match the immutable website archive.
- Keep engine enforcement strict on Node 22/24 while using a dev-dependency-only
  override on Node 20.9; installed release archives receive no engine override.
- Include the deterministic packaging change from the unpublished 0.2.6
  candidate.

## 0.2.6 — 2026-07-14 (unpublished)

- Replace `npm pack` release construction with a deterministic USTAR writer and
  platform-independent stored-gzip encoder over the exact eight published
  files. Website, GitHub Actions, provenance, and npm now verify one byte-for-byte
  archive regardless of npm version, zlib build, or operating system.
- Separate Node.js 20.9 runtime smoke coverage from source-test coverage now that
  modern Vitest requires a newer Node release. Node 20.9 still builds, installs,
  verifies, and exercises the packaged CLI; Node 22 and 24 run the full source
  suite.
- Include the verifier-isolation, baseline-repair, and lint-race hardening from
  the unpublished 0.2.5 candidate.
- Public release review held this candidate before publication until the custom
  format had an independent strict verifier and cross-platform SHA coverage.

## 0.2.5 — 2026-07-14 (unpublished)

- Keep final analysis, diff, and verifier evidence fail-closed while allowing a
  repair to advance when an incomplete baseline becomes complete in the final
  tree. The resolved historical limitation is explicit and forces
  `REVIEW_REQUIRED`; it can never produce `PASS`.
- Include the external verifier isolation and binary-evidence hardening from the
  unpublished 0.2.4 candidate.
- Dogfood and public CI rejected this candidate before release after finding a
  transient lint race and platform-specific `npm pack` archive metadata.

## 0.2.4 — 2026-07-14 (unpublished)

- Run each trusted verification command from a fresh immutable source tree
  outside the live repository, strip repository-local Git hook variables, and
  stop Git discovery at the snapshot boundary. Verifiers cannot accidentally
  read or mutate the parent checkout or inherit CodeTruss private-object access.
- Reuse ignored installed Node dependencies through an explicit link while
  keeping verifier source writes isolated, with an end-to-end regression that
  proves exact staged bytes, dependency availability, Git-environment cleanup,
  and live-repository isolation.
- Classify common archives and binary assets without treating them as incomplete
  source evidence, and replace a raw NUL byte in existing TypeScript source with
  its equivalent escaped representation.
- Include the reproducible public-source release workflow from the unpublished
  0.2.2 and 0.2.3 candidates.
- Dogfood rejected this candidate because a repaired baseline-only binary-text
  limitation was still treated as an unresolvable final-evidence failure.

## 0.2.3 — 2026-07-14 (unpublished)

- Make the repository's ignored installed Node toolchain available inside each
  fresh, immutable verification source snapshot, so trusted project commands
  such as `pnpm test` run against exact evidence without sharing source writes
  between verifiers.
- Treat release archives and common binary assets as assets during indexing,
  preventing packaged CLI artifacts from creating false incomplete-evidence
  failures.
- Include the reproducible public-source release workflow from the unpublished
  0.2.2 candidate. Dogfood rejected this candidate after exposing inherited Git
  hook state inside verification commands.

## 0.2.2 — 2026-07-14 (unpublished)

- Rebuild the distributable from the clean, locked workspace dependency graph
  and require the public-source release workflow to reproduce the exact website
  archive before attestation.
- Include the hook protocol and doctor hardening from the unpublished 0.2.1
  release candidate.

## 0.2.1 — 2026-07-14 (unpublished)

- Align Claude Code and Codex hook responses with each host's current hook
  protocol: invalid prompt capture blocks explicitly, edit feedback reaches the
  agent as model context, and a failed stop check requests one repair turn.
- Prevent stop-hook retry loops by degrading an already-active failed stop check
  to visible feedback instead of requesting another continuation.
- Make `hooks doctor` verify the installed runner and policy while clearly
  surfacing Codex's required one-time, hash-specific `/hooks` trust review.

## 0.2.0 — 2026-07-14

- Build every new receipt from one immutable baseline-to-final Git evidence pair,
  including exact pre-agent dirty and untracked bytes, stable start/end commits,
  and the two evidence-tree object IDs. Synthetic evidence stays in a disposable
  private object database instead of the repository object database.
- Freeze staged and working-tree review targets before analysis. Each verification
  command now receives a fresh materialization of the same final tree, so one
  verifier cannot mutate the evidence observed by the next; private Git and hook
  capabilities are stripped before repository commands run.
- Harden optional local LLM review. Claude and Codex receive the bounded task and
  diff through standard input only, run without tools or persistent sessions, and
  are bounded by time, output, and descendant-process cleanup. Diff content still
  goes directly to the developer-selected provider and never to CodeTruss.
- Add prompt-frozen Claude Code and Codex turn hooks with exact private snapshots,
  authenticated task and policy context, fast edit-time scope feedback, and one
  full receipt at Stop. Hook installation is transactional, `hooks doctor` reports
  actionable configuration/runtime failures, and pre-commit distinguishes review
  findings from blocking failures.
- Add a signed policy SHA-256 covering effective scope, verification-command
  digests, and LLM settings without copying raw verification commands into synced
  receipts. Evidence truncation or incomplete analyzer coverage still fails closed.
- Add browser-approved, receipt-only `auth login`, `status`, and `logout`; explicit
  `sync` remains the only upload path. Synced History receipts retain signer
  credential lifecycle status and support append-only reviewer annotations.
- Harden staged, working-tree, unborn-repository, large-diff, linked-worktree,
  SHA-256 repository, symlink, gitlink, and verification evidence paths.
- Ship a deterministic CycloneDX SBOM with the package and versioned download, plus
  checksums and release metadata for GitHub artifact-attestation/provenance
  verification. Publication and attestation remain explicit release operations.

## 0.1.1 — 2026-07-13

- Initial local-first CLI preview.
- Scope allow/deny policy and sensitive-surface classification.
- Shared deterministic analyzer registry and project verification commands.
- Markdown and integrity-signed JSON receipts with explicit verdict reasons.
- Explicit privacy-minimized receipt sync and optional direct-provider LLM review.
