# Release process

CodeTruss separates the public GitHub release from npm publication. A tag can
therefore build, test, attest, and publish immutable release assets without an
npm account, npm token, pre-existing npm package, or npm environment approval.

## GitHub release

1. Confirm CI is green on `main` and the package version and changelog are final.
   Update `release-reference.json` from the immutable website candidate. The
   verifier rejects any archive, SBOM, or executable digest that differs from
   that checked-in reference.
2. Create and push the matching annotated tag, for example `v0.2.20` for package
   version `0.2.20`.
3. `.github/workflows/release.yml` installs the locked dependency graph, runs
   typechecking and tests, builds the package, verifies a clean global install,
   creates GitHub build-provenance and SBOM attestations, and finally creates the
   GitHub release.
4. Verify the downloaded archive independently:

   ```bash
   gh attestation verify codetruss-cli-0.2.20.tgz --repo DeliriumPulse/codetruss-cli
   shasum -a 256 -c codetruss-cli-0.2.20.tgz.sha256
   ```

The release workflow intentionally has no npm environment, npm credentials, or
`npm publish` step. Its release job has only the permissions required to create
the GitHub release and its attestations.

## npm trusted publishing

npm publishing is a separate, manual operation in
`.github/workflows/publish-npm.yml`. Before enabling it:

1. Create an `npm` GitHub environment with required maintainer review.
2. Ensure the public `@codetruss/cli` package exists. npm currently requires a
   one-time authenticated bootstrap publish before a trusted publisher can be
   configured for a new package.
3. In npm package settings, configure the GitHub Actions trusted publisher with:
   organization or user `DeliriumPulse`, repository `codetruss-cli`, workflow
   filename `publish-npm.yml`, environment `npm`, and allowed action
   `npm publish`.
4. Run **Publish npm**, enter an existing GitHub release tag, and explicitly
   select **Publish the verified release archive to npm**.

The manual workflow checks out that tag, downloads rather than rebuilds the
GitHub release assets, verifies the manifest, checksums, package contents,
install behavior, and GitHub attestation, then publishes those exact bytes with
npm's OIDC trusted publishing and provenance. It contains no npm token fallback.

## Repository controls

Before the first public tag, protect `main`, restrict tag creation to
maintainers, require CI, review the `npm` environment approvers, and limit
GitHub Actions to the SHA-pinned actions in this repository. If a release asset
changes, bump the package version; do not replace an existing version's bytes.
