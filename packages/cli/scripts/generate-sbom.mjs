import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { readFile, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = resolve(scriptDir, '..')
const require = createRequire(import.meta.url)
const UUID_URL_NAMESPACE = Buffer.from('6ba7b8119dad11d180b400c04fd430c8', 'hex')

export function npmPurl(name, version) {
  const scoped = /^(@[^/]+)\/([^/]+)$/.exec(name)
  const packagePath = scoped
    ? `${encodeURIComponent(scoped[1])}/${encodeURIComponent(scoped[2])}`
    : encodeURIComponent(name)
  return `pkg:npm/${packagePath}@${encodeURIComponent(version)}`
}

export function cycloneDxSerialNumber(name, version) {
  const uuid = createHash('sha1')
    .update(UUID_URL_NAMESPACE)
    .update(`${name}@${version}`, 'utf8')
    .digest()
    .subarray(0, 16)
  uuid[6] = (uuid[6] & 0x0f) | 0x50
  uuid[8] = (uuid[8] & 0x3f) | 0x80
  const hex = uuid.toString('hex')
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

function licenseEntry(value) {
  return value
    ? [{ license: /^[A-Za-z0-9-.+]+$/.test(value) ? { id: value } : { name: value } }]
    : undefined
}

async function packageJson(path) {
  return JSON.parse(await readFile(path, 'utf8'))
}

export async function generateSbom() {
  const cli = await packageJson(join(packageDir, 'package.json'))
  const engine = await packageJson(join(packageDir, '..', 'analyzer-engine', 'package.json'))
  const minimatchPath = require.resolve('minimatch/package.json')
  const braceExpansionPath = createRequire(minimatchPath).resolve('brace-expansion/package.json')
  const balancedMatchPath = createRequire(braceExpansionPath).resolve('balanced-match/package.json')
  const bundled = await Promise.all([
    packageJson(balancedMatchPath),
    packageJson(braceExpansionPath),
    packageJson(minimatchPath),
    packageJson(require.resolve('yaml/package.json')),
  ])

  const rootRef = npmPurl(cli.name, cli.version)
  const engineRef = npmPurl(engine.name, engine.version)
  const refs = new Map(bundled.map((pkg) => [pkg.name, npmPurl(pkg.name, pkg.version)]))
  const components = [
    {
      type: 'library',
      'bom-ref': engineRef,
      name: engine.name,
      version: engine.version,
      licenses: licenseEntry('CodeTruss CLI Proprietary License'),
      purl: engineRef,
      properties: [{ name: 'codetruss:bundled', value: 'true' }],
    },
    ...bundled
      .map((pkg) => {
        const ref = refs.get(pkg.name)
        return {
          type: 'library',
          'bom-ref': ref,
          name: pkg.name,
          version: pkg.version,
          licenses: licenseEntry(pkg.license),
          purl: ref,
          properties: [{ name: 'codetruss:bundled', value: 'true' }],
        }
      })
      .sort((left, right) => left.name.localeCompare(right.name)),
  ]

  const dependencyRefs = (names) => names.map((name) => refs.get(name)).filter(Boolean).sort()
  const dependencies = [
    { ref: rootRef, dependsOn: [engineRef, ...dependencyRefs(['minimatch', 'yaml'])].sort() },
    { ref: engineRef, dependsOn: [] },
    { ref: refs.get('minimatch'), dependsOn: dependencyRefs(['brace-expansion']) },
    { ref: refs.get('brace-expansion'), dependsOn: dependencyRefs(['balanced-match']) },
    { ref: refs.get('balanced-match'), dependsOn: [] },
    { ref: refs.get('yaml'), dependsOn: [] },
  ].sort((left, right) => left.ref.localeCompare(right.ref))

  const bom = {
    $schema: 'https://cyclonedx.org/schema/bom-1.6.schema.json',
    bomFormat: 'CycloneDX',
    serialNumber: cycloneDxSerialNumber(cli.name, cli.version),
    specVersion: '1.6',
    version: 1,
    metadata: {
      component: {
        type: 'application',
        'bom-ref': rootRef,
        name: cli.name,
        version: cli.version,
        description: cli.description,
        licenses: licenseEntry('CodeTruss CLI Proprietary License'),
        purl: rootRef,
      },
      properties: [
        { name: 'codetruss:distribution', value: 'single-file JavaScript bundle' },
        { name: 'codetruss:runtimeDependencies', value: '0' },
      ],
    },
    components,
    dependencies,
  }

  const output = join(packageDir, 'SBOM.cdx.json')
  await writeFile(output, `${JSON.stringify(bom, null, 2)}\n`, 'utf8')
  return output
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const output = await generateSbom()
  process.stdout.write(`${output}\n`)
}
