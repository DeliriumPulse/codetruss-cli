import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gunzipSync } from 'node:zlib'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(packageDir, '../..')
const releaseDir = join(repoRoot, 'release')
const pkg = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'))
const archiveName = `codetruss-cli-${pkg.version}.tgz`
const sbomName = `codetruss-cli-${pkg.version}.sbom.cdx.json`
const archive = await readFile(join(releaseDir, archiveName))
const sbom = await readFile(join(releaseDir, sbomName))
const manifest = JSON.parse(await readFile(join(releaseDir, 'release-manifest.json'), 'utf8'))
const reference = JSON.parse(await readFile(join(repoRoot, 'release-reference.json'), 'utf8'))

function digest(value) {
  return createHash('sha256').update(value).digest('hex')
}

function tarEntries(archiveBytes) {
  const tar = gunzipSync(archiveBytes)
  const entries = new Map()
  let offset = 0
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512)
    if (header.every((byte) => byte === 0)) break
    const text = (start, end) => header.subarray(start, end).toString('utf8').replace(/\0.*$/s, '')
    const name = text(0, 100)
    const prefix = text(345, 500)
    const path = prefix ? `${prefix}/${name}` : name
    const size = Number.parseInt(text(124, 136).trim() || '0', 8)
    if (!Number.isSafeInteger(size) || size < 0) throw new Error(`invalid tar entry size for ${path}`)
    const contentStart = offset + 512
    const contentEnd = contentStart + size
    if (contentEnd > tar.length) throw new Error(`truncated tar entry ${path}`)
    entries.set(path, tar.subarray(contentStart, contentEnd))
    offset = contentStart + Math.ceil(size / 512) * 512
  }
  return entries
}

const archiveSha256 = digest(archive)
if (
  reference.schemaVersion !== 1
  || reference.version !== pkg.version
  || reference.websiteArchive !== `https://codetruss.com/downloads/${archiveName}`
  || reference.archiveSha256 !== archiveSha256
  || reference.sbomSha256 !== digest(sbom)
) {
  throw new Error(`release bytes do not match the immutable website reference for ${pkg.version}`)
}
const expectedManifest = {
  package: pkg.name,
  version: pkg.version,
  tag: `v${pkg.version}`,
  repository: 'https://github.com/DeliriumPulse/codetruss-cli',
}
for (const [key, value] of Object.entries(expectedManifest)) {
  if (manifest[key] !== value) throw new Error(`release manifest ${key} does not match ${value}`)
}
const artifactDigests = new Map(manifest.artifacts?.map((artifact) => [artifact.name, artifact.sha256]))
if (artifactDigests.get(archiveName) !== archiveSha256 || artifactDigests.get(sbomName) !== digest(sbom)) {
  throw new Error('release manifest artifact digests do not match release bytes')
}
if (await readFile(join(releaseDir, `${archiveName}.sha256`), 'utf8') !== `${archiveSha256}  ${archiveName}\n`) {
  throw new Error('release checksum sidecar does not match the package archive')
}

const entries = tarEntries(archive)
const expectedEntries = new Set([
  'package/CHANGELOG.md',
  'package/LICENSE',
  'package/README.md',
  'package/SBOM.cdx.json',
  'package/SECURITY.md',
  'package/THIRD_PARTY_NOTICES.md',
  'package/dist/cli.cjs',
  'package/package.json',
])
const actualEntries = [...entries.keys()].filter((name) => name.startsWith('package/'))
if (actualEntries.some((name) => !expectedEntries.has(name)) || [...expectedEntries].some((name) => !entries.has(name))) {
  throw new Error(`release archive file manifest is not exact: ${actualEntries.join(', ')}`)
}
for (const name of ['CHANGELOG.md', 'LICENSE', 'README.md', 'SBOM.cdx.json', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md', 'dist/cli.cjs']) {
  if (digest(await readFile(join(packageDir, name))) !== digest(entries.get(`package/${name}`))) {
    throw new Error(`${archiveName} does not contain the current ${name}`)
  }
}
if (reference.bundleSha256 !== digest(entries.get('package/dist/cli.cjs'))) {
  throw new Error(`release executable does not match the website reference for ${pkg.version}`)
}
const packedPackage = JSON.parse(entries.get('package/package.json').toString('utf8'))
if (packedPackage.name !== pkg.name || packedPackage.version !== pkg.version || packedPackage.bin?.codetruss !== pkg.bin.codetruss) {
  throw new Error('packed package identity differs from source package.json')
}
for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
  if (packedPackage[field] && Object.keys(packedPackage[field]).length) {
    throw new Error(`published CLI must not have ${field}`)
  }
}
if (
  packedPackage.repository?.url !== 'git+https://github.com/DeliriumPulse/codetruss-cli.git'
  || packedPackage.homepage !== 'https://codetruss.com/cli'
) {
  throw new Error('packed package does not identify the public source and product pages')
}
const packagedSbom = JSON.parse(entries.get('package/SBOM.cdx.json').toString('utf8'))
if (packagedSbom.metadata?.component?.name !== pkg.name || packagedSbom.metadata?.component?.version !== pkg.version) {
  throw new Error('packaged SBOM does not identify this CLI release')
}
if (digest(entries.get('package/SBOM.cdx.json')) !== digest(sbom)) {
  throw new Error('standalone SBOM differs from the SBOM included in the package')
}
process.stdout.write(`Verified ${archiveName} (${archiveSha256})\n`)
