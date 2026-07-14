# Changelog

CodeTruss CLI follows semantic versioning. Release artifacts and their SHA-256
checksums are published at <https://codetruss.com/downloads/codetruss-cli-latest.json>.

## 0.2.5 — 2026-07-14

- Keep final analysis, diff, and verifier evidence fail-closed while allowing a
  repair to advance when an incomplete baseline becomes complete in the final
  tree. The resolved historical limitation is explicit and forces
  `REVIEW_REQUIRED`; it can never produce `PASS`.
- Include the external verifier isolation and binary-evidence hardening from the
  unpublished 0.2.4 candidate.

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
