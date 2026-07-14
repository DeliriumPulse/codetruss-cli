import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { assertReleasePackagePolicy } from './release-package-policy.mjs'
import { cycloneDxSerialNumber } from './generate-sbom.mjs'
import { verifyDeterministicPackageArchive } from './verify-deterministic-package.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const defaultPackageDir = resolve(dirname(scriptPath), '..')
const defaultRepoRoot = resolve(defaultPackageDir, '../..')
const defaultReleaseDir = join(defaultRepoRoot, 'release')
const defaultReferencePath = join(defaultRepoRoot, 'release-reference.json')
const digest = (value) => createHash('sha256').update(value).digest('hex')

export async function verifyRelease({
  packageDir = defaultPackageDir,
  releaseDir = defaultReleaseDir,
  referencePath = defaultReferencePath,
} = {}) {
  const pkgBytes = await readFile(join(packageDir, 'package.json'))
  const pkg = JSON.parse(pkgBytes.toString('utf8'))
  assertReleasePackagePolicy(pkg)
  const archiveName = `codetruss-cli-${pkg.version}.tgz`
  const sbomName = `codetruss-cli-${pkg.version}.sbom.cdx.json`
  const archive = await readFile(join(releaseDir, archiveName))
  const sbom = await readFile(join(releaseDir, sbomName))
  const archiveSha256 = digest(archive)
  const sbomSha256 = digest(sbom)
  const entries = verifyDeterministicPackageArchive(archive)
  const bundle = entries.get('package/dist/cli.cjs')
  if (!bundle) throw new Error('release archive does not contain the CLI executable')
  const bundleSha256 = digest(bundle)

  const expectedReference = {
    schemaVersion: 1,
    version: pkg.version,
    websiteArchive: `https://codetruss.com/downloads/${archiveName}`,
    archiveSha256,
    sbomSha256,
    bundleSha256,
  }
  const referenceBytes = await readFile(referencePath)
  const expectedReferenceBytes = Buffer.from(`${JSON.stringify(expectedReference, null, 2)}\n`, 'utf8')
  if (!referenceBytes.equals(expectedReferenceBytes)) {
    throw new Error(`release reference is not the canonical website metadata for ${pkg.version}`)
  }

  const expectedManifest = {
    schemaVersion: 1,
    package: pkg.name,
    version: pkg.version,
    tag: `v${pkg.version}`,
    repository: 'https://github.com/DeliriumPulse/codetruss-cli',
    node: pkg.engines.node,
    artifacts: [
      { name: archiveName, mediaType: 'application/gzip', sha256: archiveSha256 },
      { name: sbomName, mediaType: 'application/vnd.cyclonedx+json', sha256: sbomSha256 },
    ],
  }
  const manifestBytes = await readFile(join(releaseDir, 'release-manifest.json'))
  const expectedManifestBytes = Buffer.from(`${JSON.stringify(expectedManifest, null, 2)}\n`, 'utf8')
  if (!manifestBytes.equals(expectedManifestBytes)) {
    throw new Error(`release manifest is not canonical for ${archiveName}`)
  }

  const sidecar = await readFile(join(releaseDir, `${archiveName}.sha256`), 'utf8')
  if (sidecar !== `${archiveSha256}  ${archiveName}\n`) {
    throw new Error(`${archiveName}.sha256 is not the canonical checksum for ${archiveName}`)
  }

  // A checksum can prove that a hosted tarball is immutable without proving
  // that it contains the source being released. Compare every package byte,
  // including package.json lifecycle scripts and dependency metadata.
  for (const name of [
    'CHANGELOG.md',
    'LICENSE',
    'README.md',
    'SBOM.cdx.json',
    'SECURITY.md',
    'THIRD_PARTY_NOTICES.md',
    'dist/cli.cjs',
    'package.json',
  ]) {
    const local = name === 'package.json' ? pkgBytes : await readFile(join(packageDir, name))
    const packed = entries.get(`package/${name}`)
    if (!packed || !local.equals(packed)) {
      throw new Error(`${archiveName} does not contain the current ${name}`)
    }
  }
  if (!entries.get('package/SBOM.cdx.json').equals(sbom)) {
    throw new Error(`${sbomName} does not describe the SBOM included in ${archiveName}`)
  }
  const packagedSbom = JSON.parse(sbom.toString('utf8'))
  if (packagedSbom.metadata?.component?.name !== pkg.name || packagedSbom.metadata?.component?.version !== pkg.version) {
    throw new Error(`${sbomName} does not identify ${pkg.name}@${pkg.version}`)
  }
  const expectedSerialNumber = cycloneDxSerialNumber(pkg.name, pkg.version)
  if (packagedSbom.bomFormat !== 'CycloneDX'
    || packagedSbom.specVersion !== '1.6'
    || packagedSbom.serialNumber !== expectedSerialNumber) {
    throw new Error(`${sbomName} does not have the canonical CycloneDX identity ${expectedSerialNumber}`)
  }

  return { version: pkg.version, sha256: archiveSha256 }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : undefined
if (invokedPath === import.meta.url) {
  const result = await verifyRelease()
  process.stdout.write(`Verified ${result.version} release (${result.sha256})\n`)
}
