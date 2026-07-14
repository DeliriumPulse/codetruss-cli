# CodeTruss CLI

CodeTruss is a local-first guardrail for coding agents. It captures an exact
before/after Git evidence pair, checks task scope and sensitive surfaces, runs
the shared CodeTruss analyzers and repository verification commands, then writes
a signed `PASS`, `REVIEW_REQUIRED`, or `FAILED` receipt before a pull request.

```bash
curl -fsSL https://codetruss.com/install.sh | sh
codetruss init
codetruss run --task "Fix auth" --allow "src/auth/**" --verify "pnpm test" -- codex exec "Fix auth"
```

Use `codetruss hooks install claude`, `codex`, `pre-commit`, or `all` to run the
guard automatically. `codetruss hooks doctor all` verifies the installed hook
commands, permissions, policy, and CLI resolution.

## Privacy

Deterministic analysis runs locally. Optional `--llm` review sends only the
bounded task and diff directly to the developer-selected provider using that
developer's key or authenticated Claude/Codex CLI. CodeTruss receives nothing
unless the developer explicitly runs `codetruss sync`.

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
pnpm typecheck
pnpm test
pnpm release:artifact
pnpm release:verify
pnpm test:install
```

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

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue. Report security
problems privately under [SECURITY.md](SECURITY.md). Product documentation and
downloads are at [codetruss.com/cli](https://codetruss.com/cli).
