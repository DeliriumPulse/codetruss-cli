import { lstat, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const TAR_BLOCK_BYTES = 512
const DEFLATE_STORED_BLOCK_BYTES = 65_535
export const MAX_PACKAGE_ARCHIVE_BYTES = 1_000_000

export const PACKAGE_ARCHIVE_FILES = [
  { source: 'CHANGELOG.md', archive: 'package/CHANGELOG.md', mode: 0o644 },
  { source: 'LICENSE', archive: 'package/LICENSE', mode: 0o644 },
  { source: 'README.md', archive: 'package/README.md', mode: 0o644 },
  { source: 'SBOM.cdx.json', archive: 'package/SBOM.cdx.json', mode: 0o644 },
  { source: 'SECURITY.md', archive: 'package/SECURITY.md', mode: 0o644 },
  { source: 'THIRD_PARTY_NOTICES.md', archive: 'package/THIRD_PARTY_NOTICES.md', mode: 0o644 },
  { source: 'dist/cli.cjs', archive: 'package/dist/cli.cjs', mode: 0o755 },
  { source: 'package.json', archive: 'package/package.json', mode: 0o644 },
]

function writeText(target, offset, length, value) {
  const bytes = Buffer.from(value, 'utf8')
  if (bytes.length > length) throw new Error(`tar field exceeds ${length} bytes: ${value}`)
  bytes.copy(target, offset)
}

function writeOctal(target, offset, length, value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`invalid tar number ${value}`)
  const text = value.toString(8).padStart(length - 1, '0')
  if (text.length !== length - 1) throw new Error(`tar number ${value} exceeds ${length} bytes`)
  writeText(target, offset, length, `${text}\0`)
}

function tarHeader(path, size, mode) {
  const header = Buffer.alloc(TAR_BLOCK_BYTES)
  writeText(header, 0, 100, path)
  writeOctal(header, 100, 8, mode)
  writeOctal(header, 108, 8, 0)
  writeOctal(header, 116, 8, 0)
  writeOctal(header, 124, 12, size)
  writeOctal(header, 136, 12, 0)
  header.fill(0x20, 148, 156)
  header[156] = 0x30
  writeText(header, 257, 6, 'ustar\0')
  writeText(header, 263, 2, '00')
  writeText(header, 265, 32, 'root')
  writeText(header, 297, 32, 'root')
  writeOctal(header, 329, 8, 0)
  writeOctal(header, 337, 8, 0)
  const checksum = header.reduce((sum, byte) => sum + byte, 0)
  writeText(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `)
  return header
}

function tarFile(path, content, mode) {
  const padding = (TAR_BLOCK_BYTES - (content.length % TAR_BLOCK_BYTES)) % TAR_BLOCK_BYTES
  return [tarHeader(path, content.length, mode), content, Buffer.alloc(padding)]
}

const CRC32_TABLE = Array.from({ length: 256 }, (_, value) => {
  let crc = value
  for (let bit = 0; bit < 8; bit++) crc = (crc & 1) === 1 ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1)
  return crc >>> 0
})

function crc32(input) {
  let crc = 0xffffffff
  for (const byte of input) crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

/** Encode gzip with uncompressed DEFLATE blocks for byte identity across zlib and operating systems. */
export function deterministicGzip(input) {
  const chunks = [Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff])]
  if (input.length === 0) chunks.push(Buffer.from([0x01, 0x00, 0x00, 0xff, 0xff]))
  for (let offset = 0; offset < input.length;) {
    const length = Math.min(DEFLATE_STORED_BLOCK_BYTES, input.length - offset)
    const final = offset + length === input.length
    const header = Buffer.alloc(5)
    header[0] = final ? 0x01 : 0x00
    header.writeUInt16LE(length, 1)
    header.writeUInt16LE((~length) & 0xffff, 3)
    chunks.push(header, input.subarray(offset, offset + length))
    offset += length
  }
  const trailer = Buffer.alloc(8)
  trailer.writeUInt32LE(crc32(input), 0)
  trailer.writeUInt32LE(input.length >>> 0, 4)
  chunks.push(trailer)
  return Buffer.concat(chunks)
}

export async function buildDeterministicPackageArchive(packageDir, outputPath) {
  const chunks = []
  for (const file of PACKAGE_ARCHIVE_FILES) {
    const path = join(packageDir, file.source)
    const metadata = await lstat(path)
    if (!metadata.isFile()) throw new Error(`package source must be a regular file: ${file.source}`)
    const content = await readFile(path)
    chunks.push(...tarFile(file.archive, content, file.mode))
  }
  chunks.push(Buffer.alloc(TAR_BLOCK_BYTES * 2))
  const archive = deterministicGzip(Buffer.concat(chunks))
  if (archive.length > MAX_PACKAGE_ARCHIVE_BYTES) {
    throw new Error(`package archive exceeds the ${MAX_PACKAGE_ARCHIVE_BYTES}-byte release budget`)
  }
  await writeFile(outputPath, archive)
  return archive
}
