import { createHash } from 'node:crypto'
import { copyFile, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(packageDir, '../..')
const releaseDir = join(repoRoot, 'release')

function run(command, args, cwd = packageDir) {
  const env = command === 'npm'
    ? Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.toLowerCase().startsWith('npm_config_')))
    : process.env
  const result = spawnSync(command, args, { cwd, env, encoding: 'utf8', stdio: 'inherit' })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} exited with ${result.status}`)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

const pkg = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'))
const archiveName = `codetruss-cli-${pkg.version}.tgz`
const sbomName = `codetruss-cli-${pkg.version}.sbom.cdx.json`

await rm(releaseDir, { recursive: true, force: true })
await mkdir(releaseDir, { recursive: true })
run('pnpm', ['build'])

const version = spawnSync(process.execPath, [join(packageDir, 'dist', 'cli.cjs'), '--version'], {
  cwd: packageDir,
  encoding: 'utf8',
})
if (version.status !== 0 || version.stdout.trim() !== `codetruss ${pkg.version}`) {
  throw new Error(`built CLI version does not match package ${pkg.version}`)
}

run('npm', ['pack', '--ignore-scripts', '--pack-destination', releaseDir])
const archives = (await readdir(releaseDir)).filter((name) => name.endsWith('.tgz'))
if (archives.length !== 1 || archives[0] !== archiveName) {
  throw new Error(`expected exactly ${archiveName}, received ${archives.join(', ') || '(none)'}`)
}

const archive = await readFile(join(releaseDir, archiveName))
const archiveSha256 = sha256(archive)
await writeFile(join(releaseDir, `${archiveName}.sha256`), `${archiveSha256}  ${archiveName}\n`, 'utf8')
await copyFile(join(packageDir, 'SBOM.cdx.json'), join(releaseDir, sbomName))
const sbom = await readFile(join(releaseDir, sbomName))

const manifest = {
  schemaVersion: 1,
  package: pkg.name,
  version: pkg.version,
  tag: `v${pkg.version}`,
  repository: 'https://github.com/DeliriumPulse/codetruss-cli',
  node: pkg.engines.node,
  artifacts: [
    { name: archiveName, mediaType: 'application/gzip', sha256: archiveSha256 },
    { name: sbomName, mediaType: 'application/vnd.cyclonedx+json', sha256: sha256(sbom) },
  ],
}
await writeFile(join(releaseDir, 'release-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
process.stdout.write(`Built ${archiveName} (${archiveSha256})\n`)
