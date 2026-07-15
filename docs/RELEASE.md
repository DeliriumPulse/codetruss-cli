# Release process

CodeTruss builds, tests, and attests immutable GitHub release assets before
publishing those exact bytes to npm. The release workflow therefore needs no npm
account, npm token, package access, or npm environment approval.

## GitHub release

1. Confirm CI is green on `main` and the package version and changelog are final.
   Update `release-reference.json` from the immutable website candidate. The
   verifier rejects any archive, SBOM, or executable digest that differs from
   that checked-in reference.
2. Create and push the matching annotated tag, for example `v0.2.24` for package
   version `0.2.24`.
3. `.github/workflows/release.yml` installs the locked dependency graph, runs
   typechecking and tests, builds the package, verifies a clean global install,
   creates GitHub build-provenance and SBOM attestations, and finally creates the
   GitHub release.
4. Verify the downloaded archive independently:

   ```bash
   gh attestation verify codetruss-cli-0.2.24.tgz --repo DeliriumPulse/codetruss-cli
   shasum -a 256 -c codetruss-cli-0.2.24.tgz.sha256
   ```

The release workflow intentionally has no npm environment, npm credentials, or
`npm publish` step. Its release job has only the permissions required to create
the GitHub release and its attestations.

## npm trusted publishing

npm publishing is a manual operation in `.github/workflows/publish-npm.yml`.
The public package is [`@codetruss/cli`][npm-package],
and its one-time authenticated bootstrap publication is complete. Before each
publication:

1. Confirm the `npm` GitHub environment still requires maintainer review and
   permits only protected branches. The workflow itself also requires a
   `refs/heads/main` dispatch.
2. Confirm npm package settings name the GitHub Actions trusted publisher with:
   organization or user `DeliriumPulse`, repository `codetruss-cli`, workflow
   filename `publish-npm.yml`, environment `npm`, and allowed action
   `npm publish`. Publishing access must remain `mfa=publish`, which requires
   2FA and disallows conventional publish tokens while permitting the trusted
   OIDC publisher.
3. Run **Publish npm**, enter an existing GitHub release tag, and explicitly
   select **Publish the verified release archive to npm**.

The manual workflow first verifies the selected tag and release in a job with no
OIDC publishing permission. It requires a public, non-prerelease, immutable
release; binds the attestation to the release workflow, exact tag, tag commit,
and GitHub-hosted runner; verifies the manifest, checksums, package contents,
and install behavior; then hands off the single verified tarball by immutable
artifact ID and SHA-256 digest.

A separate, environment-gated publish job receives `id-token: write`. It does
not check out or execute selected-tag code. It downloads only that immutable
artifact, rechecks the filename, SHA-256 digest, and package identity, then
publishes the exact bytes through npm OIDC with provenance. The workflow
contains no npm token fallback.

## Repository controls

Keep `main` protected, restrict tag creation to maintainers, require CI, review
the `npm` environment approvers, and limit GitHub Actions to the SHA-pinned
actions in this repository. If a release asset changes, bump the package
version; do not replace an existing version's bytes.

[npm-package]: https://www.npmjs.com/package/@codetruss/cli
