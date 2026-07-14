import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn, spawnSync } from 'node:child_process'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = resolve(scriptDir, '..')
const repoRoot = resolve(packageDir, '../..')
const packageVersion = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8')).version
const expectedVersion = `codetruss ${packageVersion}`
const archive = join(repoRoot, 'public', 'downloads', 'codetruss-cli-latest.tgz')
const scratch = await mkdtemp(join(tmpdir(), 'codetruss-cli-install-'))
const prefix = join(scratch, 'prefix')
const normalNpmPrefix = join(scratch, 'normal-npm-prefix')
const repo = join(scratch, 'repo')
let releaseServer
let releasePort

function run(command, args, options = {}) {
  const windowsBatchCommand = process.platform === 'win32'
    && (command.toLowerCase() === 'npm' || /\.(?:bat|cmd)$/i.test(command))
  const executable = windowsBatchCommand ? (process.env.ComSpec || 'cmd.exe') : command
  const executableArgs = windowsBatchCommand
    ? ['/d', '/s', '/c', command.toLowerCase() === 'npm' ? 'npm.cmd' : command, ...args]
    : args
  const result = spawnSync(executable, executableArgs, {
    cwd: options.cwd ?? repoRoot,
    encoding: 'utf8',
    env: { ...process.env, ...options.env },
    windowsHide: true,
  })
  if (result.error) throw result.error
  if (result.status !== (options.exitCode ?? 0)) {
    throw new Error(
      `${command} ${args.join(' ')} exited with ${result.status}\n${result.stdout ?? ''}${result.stderr ?? ''}`,
    )
  }
  return `${result.stdout ?? ''}${result.stderr ?? ''}`
}

try {
  await readFile(archive)
  // The product installer deliberately disables lifecycle scripts as a
  // defense-in-depth control. Also exercise ordinary npm behavior so the
  // release remains compatible for developers who install the tarball
  // directly without that hardening flag.
  run('npm', ['install', '--global', '--no-audit', '--no-fund', archive], {
    env: { NPM_CONFIG_PREFIX: normalNpmPrefix },
  })
  const normalNpmExecutable = process.platform === 'win32'
    ? join(normalNpmPrefix, 'codetruss.cmd')
    : join(normalNpmPrefix, 'bin', 'codetruss')
  const normalNpmVersion = run(normalNpmExecutable, ['--version']).trim()
  if (normalNpmVersion !== expectedVersion) {
    throw new Error(`unexpected normal npm install version output: expected ${expectedVersion}, received ${normalNpmVersion}`)
  }

  releaseServer = spawn(
    process.execPath,
    [join(scriptDir, 'test-release-server.mjs'), join(repoRoot, 'public')],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] },
  )
  releasePort = await new Promise((resolvePort, reject) => {
    releaseServer.once('error', reject)
    releaseServer.once('exit', (code) => reject(new Error(`release fixture server exited with ${code}`)))
    releaseServer.stdout.setEncoding('utf8')
    releaseServer.stdout.once('data', (value) => resolvePort(String(value).trim()))
  })
  if (process.platform === 'win32') {
    run('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(repoRoot, 'public', 'install.ps1')], {
      env: {
        CODETRUSS_INSTALL_METADATA_URL: `http://127.0.0.1:${releasePort}/downloads/codetruss-cli-latest.json`,
        NPM_CONFIG_PREFIX: prefix,
      },
    })
  } else {
    run('sh', [join(repoRoot, 'public', 'install.sh')], {
      env: {
        CODETRUSS_INSTALL_METADATA_URL: `http://127.0.0.1:${releasePort}/downloads/codetruss-cli-latest.json`,
        NPM_CONFIG_PREFIX: prefix,
      },
    })
  }
  const executable = process.platform === 'win32'
    ? join(prefix, 'codetruss.cmd')
    : join(prefix, 'bin', 'codetruss')
  const version = run(executable, ['--version']).trim()
  if (version !== expectedVersion) throw new Error(`unexpected version output: expected ${expectedVersion}, received ${version}`)

  const shellInstaller = await readFile(join(repoRoot, 'public', 'install.sh'), 'utf8')
  const powershellInstaller = await readFile(join(repoRoot, 'public', 'install.ps1'), 'utf8')
  const hardenedInstall = 'npm install --global --ignore-scripts --no-audit --no-fund'
  if (!shellInstaller.includes(hardenedInstall) || !powershellInstaller.includes(hardenedInstall)) {
    throw new Error('installers must disable package lifecycle scripts, audit requests, and funding prompts')
  }
  if (
    !powershellInstaller.includes('[System.Security.Cryptography.SHA256]::Create()')
    || /^\s*\$ActualSha256\s*=\s*\(Get-FileHash\b/m.test(powershellInstaller)
  ) {
    throw new Error('Windows installer must hash releases without relying on PowerShell module autoloading')
  }

  run('git', ['init', '--quiet', repo])
  run('git', ['-C', repo, 'config', 'user.name', 'CodeTruss Install Test'])
  run('git', ['-C', repo, 'config', 'user.email', 'install-test@codetruss.local'])
  run(executable, ['init', '--allow', 'src/**'], { cwd: repo })
  const configPath = join(repo, '.codetruss.yml')
  const initializedConfig = await readFile(configPath, 'utf8')
  if (!/allow:\s*\n\s+- src\/\*\*/m.test(initializedConfig)) {
    throw new Error('init did not persist the explicit allow policy required by agent hooks')
  }
  run(executable, ['hooks', 'install', 'all'], { cwd: repo })
  const preCommit = await readFile(join(repo, '.git', 'hooks', 'pre-commit'), 'utf8')
  const claude = await readFile(join(repo, '.claude', 'settings.json'), 'utf8')
  const codex = await readFile(join(repo, '.codex', 'hooks.json'), 'utf8')
  if (!preCommit.includes('node_modules/.bin/codetruss') || !preCommit.includes('codetruss review --staged')) {
    throw new Error('pre-commit hook does not support both local and global CLI installs')
  }
  if (!claude.includes('.codetruss/hooks/agent.cjs') || !codex.includes('.codetruss/hooks/agent.cjs')) {
    throw new Error('agent hooks do not invoke the installed CLI')
  }
  await readFile(join(repo, '.codetruss', 'hooks', 'agent.cjs'), 'utf8')
  if (process.platform !== 'win32' && ((await stat(join(repo, '.git', 'hooks', 'pre-commit'))).mode & 0o111) === 0) {
    throw new Error('pre-commit hook is not executable')
  }
  if (process.platform !== 'win32') {
    run(join(repo, '.git', 'hooks', 'pre-commit'), [], {
      cwd: repo,
      env: { PATH: `${join(prefix, 'bin')}:${process.env.PATH ?? ''}` },
    })
    run('sh', [join(repoRoot, 'public', 'install.sh')], {
      exitCode: 1,
      env: {
        CODETRUSS_INSTALL_URL: `file://${archive}`,
        CODETRUSS_INSTALL_SHA256: '0'.repeat(64),
        NPM_CONFIG_PREFIX: join(scratch, 'rejected-prefix'),
      },
    })
  } else {
    const rejectedInstall = run('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(repoRoot, 'public', 'install.ps1')], {
      exitCode: 1,
      env: {
        CODETRUSS_INSTALL_URL: `http://127.0.0.1:${releasePort}/downloads/codetruss-cli-latest.tgz`,
        CODETRUSS_INSTALL_SHA256: '0'.repeat(64),
        NPM_CONFIG_PREFIX: join(scratch, 'rejected-prefix'),
      },
    })
    if (!rejectedInstall.includes('CodeTruss release checksum mismatch')) {
      throw new Error(`Windows installer failed for the wrong reason:\n${rejectedInstall}`)
    }
  }
  process.stdout.write(`Installed ${version} from ${archive}, initialized a clean repository, and exercised all hook installers.\n`)
} finally {
  releaseServer?.kill('SIGTERM')
  await rm(scratch, { recursive: true, force: true })
}
