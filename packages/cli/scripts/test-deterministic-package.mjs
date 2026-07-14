import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, symlink, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildDeterministicPackageArchive, deterministicGzip, PACKAGE_ARCHIVE_FILES } from './deterministic-package.mjs'
import { npmPurl } from './generate-sbom.mjs'
import { decodeDeterministicGzip, verifyDeterministicPackageArchive } from './verify-deterministic-package.mjs'

function rejects(fn, pattern) {
  assert.throws(fn, pattern)
}

// Release builds must not depend on package-manager shim resolution: Windows
// exposes those shims as `.cmd` files, which Node cannot spawn without a shell.
const releaseBuilder = await readFile(new URL('./build-release.mjs', import.meta.url), 'utf8')
assert.doesNotMatch(releaseBuilder, /\brun\(['"](?:npm|pnpm|yarn)['"]/, 'release build must not spawn a package-manager shim')
assert.match(releaseBuilder, /run\(process\.execPath, \[join\(scriptDir, 'build\.mjs'\)\]\)/)

// The install smoke invokes npm and generated command shims through cmd.exe on
// Windows, but native executables such as Git and PowerShell must receive their
// argument arrays directly. Blanket shell execution loses argument boundaries
// and Node 22.15+ rejects the unsafe shell-plus-args pattern (DEP0190).
const installSmoke = await readFile(new URL('./test-install.mjs', import.meta.url), 'utf8')
assert.doesNotMatch(installSmoke, /shell:\s*process\.platform\s*===\s*['"]win32['"]/, 'install smoke must not shell every Windows command')
assert.match(installSmoke, /process\.env\.ComSpec \|\| 'cmd\.exe'/)
assert.match(installSmoke, /\['\/d', '\/s', '\/c'/)

assert.equal(npmPurl('@codetruss/cli', '1.2.3'), 'pkg:npm/%40codetruss/cli@1.2.3')
assert.equal(
  npmPurl('@codetruss/analyzer-engine', '0.1.0'),
  'pkg:npm/%40codetruss/analyzer-engine@0.1.0',
)
assert.equal(npmPurl('yaml', '2.8.1'), 'pkg:npm/yaml@2.8.1')

for (const size of [0, 65_535, 65_536, 131_070]) {
  const input = Buffer.alloc(size, size & 0xff)
  assert.deepEqual(decodeDeterministicGzip(deterministicGzip(input)), input)
}

const sample = deterministicGzip(Buffer.from('deterministic gzip fixture'))
for (const [index, pattern] of [[0, /gzip header/], [15, /CRC32/], [sample.length - 8, /CRC32/], [sample.length - 4, /ISIZE/]]) {
  const corrupt = Buffer.from(sample)
  corrupt[index] ^= 0x01
  rejects(() => decodeDeterministicGzip(corrupt), pattern)
}

const noncanonicalBlocks = Buffer.from(deterministicGzip(Buffer.alloc(65_536, 0x61)))
noncanonicalBlocks.writeUInt16LE(65_534, 11)
noncanonicalBlocks.writeUInt16LE((~65_534) & 0xffff, 13)
rejects(() => decodeDeterministicGzip(noncanonicalBlocks), /noncanonical/)

const root = await mkdtemp(join(tmpdir(), 'codetruss-package-format-'))
try {
  for (const file of PACKAGE_ARCHIVE_FILES) {
    const path = join(root, file.source)
    await mkdir(join(path, '..'), { recursive: true })
    const content = file.source === 'package.json'
      ? `${JSON.stringify({ name: '@codetruss/fixture', version: '1.0.0', files: ['dist', 'CHANGELOG.md', 'LICENSE', 'README.md', 'SBOM.cdx.json', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md'] }, null, 2)}\n`
      : `${file.source} fixture\n`
    await writeFile(path, content)
    await utimes(path, new Date('2001-01-01T00:00:00Z'), new Date('2030-01-01T00:00:00Z'))
  }
  const firstPath = join(root, 'first.tgz')
  const secondPath = join(root, 'second.tgz')
  const first = await buildDeterministicPackageArchive(root, firstPath)
  const second = await buildDeterministicPackageArchive(root, secondPath)
  assert.equal(createHash('sha256').update(first).digest('hex'), createHash('sha256').update(second).digest('hex'))
  assert.deepEqual([...verifyDeterministicPackageArchive(first).keys()], PACKAGE_ARCHIVE_FILES.map((file) => file.archive))

  const tar = decodeDeterministicGzip(first)
  for (const [offset, pattern] of [[257, /USTAR magic/], [156, /regular file/], [148, /checksum/]]) {
    const corrupt = Buffer.from(tar)
    corrupt[offset] ^= 0x01
    rejects(() => verifyDeterministicPackageArchive(deterministicGzip(corrupt)), pattern)
  }
  for (const [offset, pattern] of [[329, /device metadata/], [500, /header extension/]]) {
    const corrupt = Buffer.from(tar)
    corrupt[offset] ^= 0x01
    const checksum = corrupt.subarray(0, 512).reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 0x20 : byte), 0)
    Buffer.from(`${checksum.toString(8).padStart(6, '0')}\0 `, 'ascii').copy(corrupt, 148)
    rejects(() => verifyDeterministicPackageArchive(deterministicGzip(corrupt)), pattern)
  }
  const padding = Buffer.from(tar)
  padding[512 + Buffer.byteLength('CHANGELOG.md fixture\n')] = 0x01
  rejects(() => verifyDeterministicPackageArchive(deterministicGzip(padding)), /padding/)
  rejects(() => verifyDeterministicPackageArchive(deterministicGzip(tar.subarray(0, -512))), /two zero blocks|terminators/)

  await rm(join(root, 'LICENSE'))
  await mkdir(join(root, 'LICENSE'))
  await assert.rejects(() => buildDeterministicPackageArchive(root, join(root, 'directory.tgz')), /regular file/)
  await rm(join(root, 'LICENSE'), { recursive: true })
  let symlinkCreated = false
  try {
    await symlink(join(root, 'README.md'), join(root, 'LICENSE'))
    symlinkCreated = true
  } catch (error) {
    if (!['EPERM', 'EACCES'].includes(error.code)) throw error
  }
  if (symlinkCreated) {
    await assert.rejects(() => buildDeterministicPackageArchive(root, join(root, 'symlink.tgz')), /regular file/)
  }
  assert.deepEqual(await readFile(firstPath), first)
} finally {
  await rm(root, { recursive: true, force: true })
}

process.stdout.write('Deterministic package format tests passed.\n')
