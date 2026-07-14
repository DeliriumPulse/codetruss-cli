import { chmod, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { delimiter, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(packageDir, '../..')
const pkg = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'))
const archive = join(repoRoot, 'release', `codetruss-cli-${pkg.version}.tgz`)
const scratch = await mkdtemp(join(tmpdir(), 'codetruss-public-install-'))
const prefix = join(scratch, 'prefix')
const repo = join(scratch, 'repo')
const home = join(scratch, 'home')
const binDir = process.platform === 'win32' ? prefix : join(prefix, 'bin')
const executable = process.platform === 'win32' ? join(prefix, 'codetruss.cmd') : join(binDir, 'codetruss')
const environment = {
  ...process.env,
  HOME: home,
  USERPROFILE: home,
  NPM_CONFIG_PREFIX: prefix,
  PATH: `${binDir}${delimiter}${process.env.PATH ?? ''}`,
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: environment,
    encoding: 'utf8',
  })
  if (result.error) throw result.error
  if (result.status !== (options.exitCode ?? 0)) {
    throw new Error(`${command} ${args.join(' ')} exited with ${result.status}\n${result.stdout ?? ''}${result.stderr ?? ''}`)
  }
  return `${result.stdout ?? ''}${result.stderr ?? ''}`
}

try {
  run('npm', ['install', '--global', '--ignore-scripts', '--no-audit', '--no-fund', archive])
  if (run(executable, ['--version']).trim() !== `codetruss ${pkg.version}`) {
    throw new Error('installed executable version does not match the release package')
  }
  const installedPackage = join(prefix, 'lib', 'node_modules', '@codetruss', 'cli')
  const installedFiles = (await readdir(installedPackage)).sort()
  for (const forbidden of ['src', 'test', 'scripts', '.env']) {
    if (installedFiles.includes(forbidden)) throw new Error(`published install unexpectedly contains ${forbidden}`)
  }

  run('git', ['init', '--quiet', repo])
  run('git', ['-C', repo, 'config', 'user.name', 'CodeTruss Release Test'])
  run('git', ['-C', repo, 'config', 'user.email', 'release-test@codetruss.local'])
  run(executable, ['init'], { cwd: repo })
  const configPath = join(repo, '.codetruss.yml')
  const initialConfig = await readFile(configPath, 'utf8')
  const configured = initialConfig.replace(/^allow:\s*\[\]\s*$/m, 'allow:\n  - "src/**"')
  if (configured === initialConfig) throw new Error('init did not create a fail-closed empty allow list')
  await writeFile(configPath, configured, 'utf8')
  run(executable, ['hooks', 'install', 'all'], { cwd: repo })
  const doctor = run(executable, ['hooks', 'doctor', 'all'], { cwd: repo })
  if (!doctor.includes('doctor\thealthy\t0 error(s)')) throw new Error(`hook doctor was not healthy:\n${doctor}`)
  const preCommit = join(repo, '.git', 'hooks', 'pre-commit')
  if (process.platform !== 'win32') {
    if (((await stat(preCommit)).mode & 0o111) === 0) throw new Error('installed pre-commit hook is not executable')
    await chmod(preCommit, 0o755)
    run(preCommit, [], { cwd: repo })
  }
  process.stdout.write(`Installed and exercised codetruss ${pkg.version} from the release archive.\n`)
} finally {
  await rm(scratch, { recursive: true, force: true })
}
