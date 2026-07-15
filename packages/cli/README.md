# `@codetruss/cli`

Local-first scope, analyzer, verification, and signed-receipt guardrails for coding agents.

```bash
curl -fsSL https://codetruss.com/install.sh | sh
codetruss review --task "Review my current agent changes"
codetruss verify latest
```

This first receipt needs no account, `.codetruss.yml`, or sync. Run it after
an agent makes a real change. With no allow policy, changed files are deliberately
`unexpected`: `REVIEW_REQUIRED` exits 1 but still writes a valid receipt.

Then configure repeat runs, automatic hooks, and a wrapped agent command:

```bash
codetruss setup
codetruss run --task "Fix auth" --allow "src/auth/**" --verify "pnpm test" -- codex exec "Fix auth"
```

`codetruss setup` proposes conventional source roots, shows every detected
verification command and its exact fingerprint before trust, installs the
pre-commit plus Claude/Codex hooks, and runs a health check. It never defaults
to a repository-wide allow rule, never treats `--yes` as command trust, and
never uploads anything. Codex asks for one final project-hook approval in
`/hooks`.
Non-interactive `--yes` setup requires explicit `--allow` values and still
requires `--trust-verify` before it can trust detected repository commands.

A 14-day local-only design-partner cohort is open without repository access,
an account, or receipt sync. The consent request is:

> I am testing whether CodeTruss catches meaningful AI-agent scope or quality problems before a PR. The 14-day design-partner test is local-first. You can participate without giving us repository access or syncing a receipt. May I record your product-use outcomes and contact you up to twice about this test? Receipt sharing, quotes, and case-study publication are separate opt-ins.

[Email your opt-in to zack@codetruss.com](mailto:zack@codetruss.com?subject=CodeTruss%20design%20partner%20opt-in).
Enrollment starts only after a dated affirmative email response; install, click,
and sync events are not consent.

Cross-platform direct install:

```bash
npm install --global https://codetruss.com/downloads/codetruss-cli-latest.tgz
```

The release tarball contains one bundled executable and has no runtime npm
dependencies. The shell installers resolve a versioned artifact and verify its
published SHA-256 digest before installation. Every release also includes a
deterministic CycloneDX SBOM, changelog, and security policy.

Deterministic `run`, `review`, `report`, `list`, `metrics`, `init`, `verify`, and hook
checks run on-machine without contacting CodeTruss. Installation fetches release
metadata and package bytes from CodeTruss. `auth login` contacts CodeTruss
device/session endpoints but uploads no source, patch, or receipt. `auth status`
contacts the session endpoint to verify the saved credential, and `auth logout`
contacts it to revoke the credential before deleting the local copy; neither
sends source, patches, or receipts. `--llm --provider anthropic|openai|claude`
opts into provider review using your API key or authenticated local Claude Code.
Local receipts identify the 13-pass `local-registry-v1` profile and show hosted
Health scores as N/A. Graph and SAST run only in the hosted full audit, so the
CLI never infers a complete score from its smaller local pass set.
CodeTruss supplies a bounded task, reviewed diff prefix, and fixed review schema;
the provider client may add its own runtime instructions or metadata. The receipt
discloses reviewed versus total diff bytes, and truncation prevents `PASS`.
Provider review never crosses CodeTruss servers. `sync` is the only command that
uploads to CodeTruss, and it sends a redacted receipt without the patch, absolute
repository path, agent arguments/start errors, or verification commands/output.
There is no background usage telemetry, receipt upload, or synchronization.
`codetruss metrics --json` verifies the local signed receipts and emits only
aggregate first/last UTC dates, active UTC day count, verdict, invocation,
agent-surface, D7 receipt-pattern, and hook-health fields.
It includes no repository, task, file, finding, verification command, diff, or
signing-key data and makes no network request. Receipts from older releases are
counted under `legacy_unknown` invocation provenance.
The `pre_commit` label is explicitly `self_attested`; it is useful for local
breakdowns but is not counted as authenticated agent-hook evidence. Claude and
Codex Stop receipts bind `agent_hook` plus `hook_context` provenance to the
private prompt-time hook context.

`codetruss auth login` opens a short-lived browser confirmation, lets you
choose the destination organization, and saves a 90-day `receipts:read` +
`receipts:write` credential in private user config. It cannot read repositories
or start hosted scans. `auth status` verifies the saved credential against the
CodeTruss session endpoint. `auth logout` revokes the server-side credential and
then deletes the local copy; if revocation fails, the local copy is retained for
retry. Authentication never enables background sync; every
receipt upload still requires an explicit `sync`.

The CLI is proprietary software distributed under the included [CodeTruss CLI Proprietary License](LICENSE) and the [CodeTruss Terms of Service](https://codetruss.com/terms). Bundled third-party components retain the licenses listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Uninstall a global installation with `npm uninstall --global @codetruss/cli`.
This does not remove repository-owned `.codetruss.yml`, receipts, or hooks; run
`codetruss hooks uninstall all` before uninstalling when automatic hooks are
installed. Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md).

See the [full CLI guide](https://codetruss.com/cli) for configuration, verdicts, hooks, privacy, checksums, and receipt examples.
