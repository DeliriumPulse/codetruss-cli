const TAR_BLOCK_BYTES = 512
const DEFLATE_STORED_BLOCK_BYTES = 65_535
const EXPECTED_ENTRIES = [
  ['package/CHANGELOG.md', 0o644],
  ['package/LICENSE', 0o644],
  ['package/README.md', 0o644],
  ['package/SBOM.cdx.json', 0o644],
  ['package/SECURITY.md', 0o644],
  ['package/THIRD_PARTY_NOTICES.md', 0o644],
  ['package/dist/cli.cjs', 0o755],
  ['package/package.json', 0o644],
]
const EXPECTED_PACKAGE_FILES = [
  'CHANGELOG.md',
  'LICENSE',
  'README.md',
  'SBOM.cdx.json',
  'SECURITY.md',
  'THIRD_PARTY_NOTICES.md',
  'dist',
].sort()
const EXPECTED_GZIP_HEADER = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff])
const MAX_ARCHIVE_BYTES = 1_000_000

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

function requireBytes(actual, expected, label) {
  if (!actual.equals(expected)) throw new Error(`invalid deterministic package ${label}`)
}

/** Independently decode the exact stored-block gzip profile emitted for releases. */
export function decodeDeterministicGzip(archive) {
  if (!Buffer.isBuffer(archive) || archive.length < 23 || archive.length > MAX_ARCHIVE_BYTES) {
    throw new Error('invalid deterministic package gzip size')
  }
  requireBytes(archive.subarray(0, 10), EXPECTED_GZIP_HEADER, 'gzip header')
  const payloadEnd = archive.length - 8
  const chunks = []
  let cursor = 10
  let final = false
  let blocks = 0
  while (!final) {
    if (cursor + 5 > payloadEnd) throw new Error('truncated deterministic package DEFLATE block')
    const flags = archive[cursor]
    if (flags !== 0x00 && flags !== 0x01) throw new Error('release gzip must use byte-aligned stored DEFLATE blocks')
    final = flags === 0x01
    const length = archive.readUInt16LE(cursor + 1)
    const invertedLength = archive.readUInt16LE(cursor + 3)
    if (((~length) & 0xffff) !== invertedLength) throw new Error('invalid deterministic package DEFLATE length')
    if ((!final && length !== DEFLATE_STORED_BLOCK_BYTES) || (final && length === 0 && blocks > 0)) {
      throw new Error('deterministic package gzip uses noncanonical DEFLATE block sizing')
    }
    cursor += 5
    if (cursor + length > payloadEnd) throw new Error('truncated deterministic package DEFLATE payload')
    chunks.push(archive.subarray(cursor, cursor + length))
    cursor += length
    blocks++
  }
  if (blocks === 0 || cursor !== payloadEnd) throw new Error('deterministic package gzip has trailing DEFLATE bytes')
  const payload = Buffer.concat(chunks)
  if (archive.readUInt32LE(payloadEnd) !== crc32(payload)) throw new Error('deterministic package gzip CRC32 mismatch')
  if (archive.readUInt32LE(payloadEnd + 4) !== (payload.length >>> 0)) throw new Error('deterministic package gzip ISIZE mismatch')
  return payload
}

function zeroBlock(block) {
  return block.length === TAR_BLOCK_BYTES && block.every((byte) => byte === 0)
}

function readString(field, label) {
  const end = field.indexOf(0)
  if (end < 0 || !field.subarray(end).every((byte) => byte === 0)) throw new Error(`invalid USTAR ${label}`)
  return field.subarray(0, end).toString('utf8')
}

function readOctal(field, label) {
  if (field.at(-1) !== 0) throw new Error(`invalid USTAR ${label} terminator`)
  const value = field.subarray(0, -1).toString('ascii')
  if (!/^[0-7]+$/.test(value)) throw new Error(`invalid USTAR ${label}`)
  const parsed = Number.parseInt(value, 8)
  if (!Number.isSafeInteger(parsed)) throw new Error(`invalid USTAR ${label}`)
  return parsed
}

function checksum(header) {
  let value = 0
  for (let index = 0; index < header.length; index++) value += index >= 148 && index < 156 ? 0x20 : header[index]
  return value
}

/** Strictly parse the release USTAR profile and reject ambiguous or extra entries. */
export function parseDeterministicPackageTar(tar) {
  if (!Buffer.isBuffer(tar) || tar.length % TAR_BLOCK_BYTES !== 0) throw new Error('invalid deterministic package USTAR size')
  const entries = new Map()
  let offset = 0
  let expectedIndex = 0
  while (offset + TAR_BLOCK_BYTES <= tar.length) {
    const header = tar.subarray(offset, offset + TAR_BLOCK_BYTES)
    if (zeroBlock(header)) {
      const second = tar.subarray(offset + TAR_BLOCK_BYTES, offset + TAR_BLOCK_BYTES * 2)
      if (!zeroBlock(second) || offset + TAR_BLOCK_BYTES * 2 !== tar.length) {
        throw new Error('deterministic package USTAR must end with exactly two zero blocks')
      }
      break
    }
    const expected = EXPECTED_ENTRIES[expectedIndex]
    if (!expected) throw new Error('deterministic package USTAR contains an extra entry')
    requireBytes(header.subarray(257, 263), Buffer.from('ustar\0'), 'USTAR magic')
    requireBytes(header.subarray(263, 265), Buffer.from('00'), 'USTAR version')
    if (header[156] !== 0x30) throw new Error('deterministic package USTAR entry is not a regular file')
    const checksumField = header.subarray(148, 156)
    if (!/^[0-7]{6}\0 $/.test(checksumField.toString('latin1'))) throw new Error('invalid USTAR checksum field')
    if (Number.parseInt(checksumField.subarray(0, 6).toString('ascii'), 8) !== checksum(header)) {
      throw new Error('deterministic package USTAR checksum mismatch')
    }
    const name = readString(header.subarray(0, 100), 'name')
    const prefix = readString(header.subarray(345, 500), 'prefix')
    const path = prefix ? `${prefix}/${name}` : name
    if (path !== expected[0] || entries.has(path)) throw new Error(`unexpected deterministic package USTAR entry ${path}`)
    if (readOctal(header.subarray(100, 108), 'mode') !== expected[1]) throw new Error(`unexpected USTAR mode for ${path}`)
    if (readOctal(header.subarray(108, 116), 'uid') !== 0 || readOctal(header.subarray(116, 124), 'gid') !== 0) {
      throw new Error(`unexpected USTAR ownership for ${path}`)
    }
    if (readOctal(header.subarray(136, 148), 'mtime') !== 0) throw new Error(`unexpected USTAR mtime for ${path}`)
    if (!header.subarray(157, 257).every((byte) => byte === 0)) throw new Error(`unexpected USTAR link target for ${path}`)
    if (readString(header.subarray(265, 297), 'owner') !== 'root' || readString(header.subarray(297, 329), 'group') !== 'root') {
      throw new Error(`unexpected USTAR owner label for ${path}`)
    }
    if (readOctal(header.subarray(329, 337), 'device major') !== 0 || readOctal(header.subarray(337, 345), 'device minor') !== 0) {
      throw new Error(`unexpected USTAR device metadata for ${path}`)
    }
    if (!header.subarray(500, TAR_BLOCK_BYTES).every((byte) => byte === 0)) {
      throw new Error(`unexpected USTAR header extension for ${path}`)
    }
    const size = readOctal(header.subarray(124, 136), 'size')
    const contentStart = offset + TAR_BLOCK_BYTES
    const contentEnd = contentStart + size
    const paddedEnd = contentStart + Math.ceil(size / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES
    if (paddedEnd > tar.length) throw new Error(`truncated deterministic package USTAR entry ${path}`)
    if (!tar.subarray(contentEnd, paddedEnd).every((byte) => byte === 0)) throw new Error(`nonzero USTAR padding for ${path}`)
    entries.set(path, tar.subarray(contentStart, contentEnd))
    offset = paddedEnd
    expectedIndex++
  }
  if (expectedIndex !== EXPECTED_ENTRIES.length || offset + TAR_BLOCK_BYTES * 2 !== tar.length) {
    throw new Error('deterministic package USTAR is missing required entries or terminators')
  }
  const packageJson = JSON.parse(entries.get('package/package.json').toString('utf8'))
  const declaredFiles = Array.isArray(packageJson.files) ? [...packageJson.files].sort() : []
  if (JSON.stringify(declaredFiles) !== JSON.stringify(EXPECTED_PACKAGE_FILES)) {
    throw new Error('package.json files does not match the deterministic release manifest')
  }
  return entries
}

export function verifyDeterministicPackageArchive(archive) {
  return parseDeterministicPackageTar(decodeDeterministicGzip(archive))
}
