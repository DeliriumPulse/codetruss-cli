import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildDeterministicPackageArchive, PACKAGE_ARCHIVE_FILES } from './deterministic-package.mjs'
import { verifyDeterministicPackageArchive } from './verify-deterministic-package.mjs'
import { verifyRelease } from './verify-release.mjs'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const scratch = await mkdtemp(join(tmpdir(), 'codetruss-public-release-verifier-'))
const releaseDir = join(scratch, 'release')
const referencePath = join(scratch, 'release-reference.json')
const tamperedPackageDir = join(scratch, 'tampered-package')
const digest = (value) => createHash('sha256').update(value).digest('hex')

async function writeRelease(archivePackageDir = packageDir) {
  await rm(releaseDir, { recursive: true, force: true })
  await mkdir(releaseDir, { recursive: true })
  const pkg = JSON.parse(await readFile(join(archivePackageDir, 'package.json'), 'utf8'))
  const archiveName = `codetruss-cli-${pkg.version}.tgz`
  const sbomName = `codetruss-cli-${pkg.version}.sbom.cdx.json`
  const archive = await buildDeterministicPackageArchive(archivePackageDir, join(releaseDir, archiveName))
  const entries = verifyDeterministicPackageArchive(archive)
  const bundle = entries.get('package/dist/cli.cjs')
  if (!bundle) throw new Error('fixture archive does not contain the CLI executable')
  const sbom = await readFile(join(packageDir, 'SBOM.cdx.json'))
  const archiveSha256 = digest(archive)
  const sbomSha256 = digest(sbom)
  await writeFile(join(releaseDir, sbomName), sbom)
  await writeFile(join(releaseDir, `${archiveName}.sha256`), `${archiveSha256}  ${archiveName}\n`)
  await writeFile(join(releaseDir, 'release-manifest.json'), `${JSON.stringify({
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
  }, null, 2)}\n`)
  await writeFile(referencePath, `${JSON.stringify({
    schemaVersion: 1,
    version: pkg.version,
    websiteArchive: `https://codetruss.com/downloads/${archiveName}`,
    archiveSha256,
    sbomSha256,
    bundleSha256: digest(bundle),
  }, null, 2)}\n`)
}

async function verify(packagePath = packageDir) {
  return verifyRelease({ packageDir: packagePath, releaseDir, referencePath })
}

try {
  await writeRelease()
  await verify()

  for (const file of PACKAGE_ARCHIVE_FILES) {
    const target = join(tamperedPackageDir, file.source)
    await mkdir(dirname(target), { recursive: true })
    await copyFile(join(packageDir, file.source), target)
  }
  const maliciousManifest = JSON.parse(await readFile(join(tamperedPackageDir, 'package.json'), 'utf8'))
  maliciousManifest.scripts = { ...maliciousManifest.scripts, postinstall: 'node -e "process.exit(99)"' }
  await writeFile(join(tamperedPackageDir, 'package.json'), `${JSON.stringify(maliciousManifest, null, 2)}\n`)
  await writeRelease(tamperedPackageDir)
  await assert.rejects(() => verify(), /does not contain the current package\.json/)
  await assert.rejects(() => verify(tamperedPackageDir), /postinstall install lifecycle script/)

  delete maliciousManifest.scripts.postinstall
  maliciousManifest.dependencies = { 'runtime-surprise': '1.0.0' }
  await writeFile(join(tamperedPackageDir, 'package.json'), `${JSON.stringify(maliciousManifest, null, 2)}\n`)
  await writeRelease(tamperedPackageDir)
  await assert.rejects(() => verify(tamperedPackageDir), /must not declare dependencies/)

  delete maliciousManifest.dependencies
  for (const [field, value] of [
    ['registry', 'https://packages.example.invalid'],
    ['tag', 'preview'],
  ]) {
    maliciousManifest.publishConfig = { access: 'public', [field]: value }
    await writeFile(join(tamperedPackageDir, 'package.json'), `${JSON.stringify(maliciousManifest, null, 2)}\n`)
    await writeRelease(tamperedPackageDir)
    await assert.rejects(() => verify(tamperedPackageDir), /package access or supported Node policy is invalid/)
  }

  await writeRelease()
  const reference = JSON.parse(await readFile(referencePath, 'utf8'))
  await writeFile(referencePath, `${JSON.stringify({ ...reference, unexpected: true }, null, 2)}\n`)
  await assert.rejects(() => verify(), /reference is not the canonical website metadata/)

  await writeRelease()
  const manifestPath = join(releaseDir, 'release-manifest.json')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  await writeFile(manifestPath, `${JSON.stringify({ ...manifest, unexpected: true }, null, 2)}\n`)
  await assert.rejects(() => verify(), /release manifest is not canonical/)

  await writeRelease()
  const pkg = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'))
  const sidecarPath = join(releaseDir, `codetruss-cli-${pkg.version}.tgz.sha256`)
  await writeFile(sidecarPath, `${await readFile(sidecarPath, 'utf8')}untrusted trailing bytes\n`)
  await assert.rejects(() => verify(), /not the canonical checksum/)
} finally {
  await rm(scratch, { recursive: true, force: true })
}

process.stdout.write('Public release integrity verifier tests passed.\n')
