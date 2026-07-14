# `@codetruss/cli`

Local-first scope, analyzer, verification, and signed-receipt guardrails for coding agents.

```bash
curl -fsSL https://codetruss.com/install.sh | sh
codetruss init
codetruss run --task "Fix auth" --allow "src/auth/**" --verify "pnpm test" -- codex exec "Fix auth"
codetruss auth login
codetruss sync latest
```

Cross-platform direct install:

```bash
npm install --global https://codetruss.com/downloads/codetruss-cli-latest.tgz
```

The release tarball contains one bundled executable and has no runtime npm
dependencies. The shell installers resolve a versioned artifact and verify its
published SHA-256 digest before installation. Every release also includes a
deterministic CycloneDX SBOM, changelog, and security policy.

Deterministic checks run on-machine. `--llm` sends the bounded task and diff directly to a developer-selected provider using a developer-owned key or authenticated local Claude/Codex CLI; it does not cross CodeTruss servers. `sync` is the only command that uploads to CodeTruss, and it sends a redacted receipt without the patch, absolute repository path, agent arguments/start errors, or verification commands/output.

`codetruss auth login` opens a short-lived browser confirmation, lets you
choose the destination organization, and saves a 90-day `receipts:read` +
`receipts:write` credential in private user config. It cannot read repositories
or start hosted scans. `auth logout` revokes the credential on CodeTruss before
removing the local copy. Authentication never enables background sync; every
receipt upload still requires an explicit `sync`.

The CLI is proprietary software distributed under the included [CodeTruss CLI Proprietary License](LICENSE) and the [CodeTruss Terms of Service](https://codetruss.com/terms). Bundled third-party components retain the licenses listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Uninstall a global installation with `npm uninstall --global @codetruss/cli`.
This does not remove repository-owned `.codetruss.yml`, receipts, or hooks; run
`codetruss hooks uninstall all` before uninstalling when automatic hooks are
installed. Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md).

See the [full CLI guide](https://codetruss.com/cli) for configuration, verdicts, hooks, privacy, checksums, and receipt examples.
