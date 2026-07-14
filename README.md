# CodeTruss CLI

Review tools ask whether code looks wrong. CodeTruss proves whether the agent
stayed inside its task contract and whether the exact final Git state passed
your checks.

CodeTruss is a local-first guardrail for coding agents. It captures an exact
before/after Git evidence pair, checks task scope and sensitive surfaces, runs
the shared CodeTruss analyzers and repository verification commands, then writes
a signed `PASS`, `REVIEW_REQUIRED`, or `FAILED` receipt before a pull request.

## Quickstart

```bash
curl -fsSL https://codetruss.com/install.sh | sh
codetruss review --task "Review my current agent changes"
codetruss verify latest
```

The first receipt needs no account or configuration. With no allow policy,
changed files are deliberately classified as unexpected, so the review exits
`1` with `REVIEW_REQUIRED` and still writes a signed receipt. Then make the
scope contract explicit and automate it:

```bash
codetruss init --allow "src/**" --allow "tests/**" --deny "infra/production/**"
codetruss hooks install all
codetruss run --task "Fix auth" --allow "src/auth/**" --verify "pnpm test" -- codex exec "Fix auth"
```

Use `codetruss hooks install claude`, `codex`, `pre-commit`, or `all` to run the
guard automatically. `codetruss hooks doctor all` verifies the installed hook
commands, permissions, policy, and CLI resolution.

## Fail-closed policy

`codetruss init` intentionally starts with an empty `allow` list. Until the
approved scope is explicit, every changed file is unexpected and the session
cannot receive `PASS`. Deny rules win over allow rules, and sensitive surfaces
such as CI, infrastructure, migrations, secrets, dependencies, and lockfiles
are flagged independently of scope.

```yaml
# .codetruss.yml
version: 1
allow:
  - src/auth/**
  - test/auth/**
deny:
  - infra/**
  - .github/workflows/**
verify:
  - pnpm lint
  - pnpm test
receipts:
  dir: .codetruss/receipts
llm:
  maxDiffBytes: 200000
```

Command-line `--allow`, `--deny`, and `--verify` values can supply the policy for
one run. Repository configuration cannot redirect authenticated sync traffic;
production sync is fixed to `https://codetruss.com`.

## Verdicts and exit codes

| Verdict | Exit | Meaning |
|---|---:|---|
| `PASS` | 0 | No blocking or review signal was found; any configured verification commands passed. |
| `REVIEW_REQUIRED` | 1 | Scope drift, a denied or sensitive surface, dependency changes, uncertain attribution, a medium-or-higher finding, or optional local LLM review needs human judgment. |
| `FAILED` | 2 | The agent or a verification command failed, evidence is incomplete, or a high/critical security or dependency finding blocks the result. |

Usage and environment errors exit `3`. A receipt records every explicit reason;
the verdict is not a confidence score.

## Illustrative receipt

The shortened IDs and hashes below are illustrative sample data, not a customer
result or validation claim.

```markdown
# CodeTruss receipt — REVIEW_REQUIRED

- Task: Fix auth callback validation
- Evidence trees: `a1b2c3…` → `d4e5f6…`
- Policy SHA-256: `91f0ab…`

## Verdict: REVIEW_REQUIRED

- 1 file changed outside approved scope: infra/main.tf
- sensitive surfaces changed: infra/main.tf (iac)

## Verification

- `pnpm test` — exit 0

Diff evidence: complete, SHA-256 `7bc21e…`.
```

Receipts are written as Markdown and JSON alongside the hashed patch evidence
and can be checked later with `codetruss verify latest`.

## Privacy

Deterministic `run`, `review`, `report`, `list`, `init`, `verify`, and hook
checks run locally without contacting CodeTruss. Installation fetches release
metadata and package bytes from CodeTruss. Optional `--llm --provider
anthropic|openai|claude` review sends the bounded task and diff directly to the
selected provider using the developer's API key or authenticated local Claude
Code. CodeTruss receives no receipt unless the developer explicitly runs
`codetruss sync`; there is no background telemetry or synchronization.

`codetruss auth login` contacts CodeTruss device/session endpoints but uploads
no source, patch, or receipt. `auth status` contacts the session endpoint to
verify the saved credential. `auth logout` revokes the server-side credential
before deleting the local copy; if revocation fails, the local copy is retained
for retry. Neither command sends source, patches, or receipts. Local receipts
identify the 13-pass `local-registry-v1` analyzer profile and report hosted
Health scores as N/A; graph and SAST analysis remain part of the hosted full
audit.

Agent-turn evidence is held in a private per-turn Git object store under Git
metadata, is unavailable to ordinary repository Git commands, and is removed
after the receipt is complete. Synced receipts omit the patch, absolute local
path, agent command, raw verification commands/output, and signing secrets.

## Source and development

This repository contains the CLI and its DB-free analyzer engine. The published
npm package is a single bundled executable with no runtime npm dependencies.

```bash
corepack enable
corepack prepare pnpm@10.28.2 --activate
pnpm install --frozen-lockfile
pnpm validate
```

`pnpm validate` typechecks, builds the deterministic release, runs the source
and adversarial release tests, verifies the exact website reference, and
exercises a clean global install.

Release output is written to `release/`. Verify a GitHub release attestation
with:

```bash
gh attestation verify codetruss-cli-VERSION.tgz --repo DeliriumPulse/codetruss-cli
```

Tag-driven GitHub releases and attestations do not depend on npm credentials.
npm publication is a separate, explicitly confirmed workflow that publishes
the already-attested release bytes. Maintainers should follow
[docs/RELEASE.md](docs/RELEASE.md) for repository setup and first-publish
requirements.

## License and support

CodeTruss-authored source is source-visible proprietary software, not open
source. See [LICENSE](LICENSE) before using or copying it. Bundled dependencies
retain the licenses in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating. Report security
problems privately under [SECURITY.md](SECURITY.md). Product documentation and
downloads are at [codetruss.com/cli](https://codetruss.com/cli).
