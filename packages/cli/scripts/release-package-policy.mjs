function hasEntries(value) {
  if (value === undefined || value === null) return false
  if (Array.isArray(value)) return value.length > 0
  if (typeof value === 'object') return Object.keys(value).length > 0
  return true
}

/** Supply-chain invariants that must hold even when source and archive agree. */
export function assertReleasePackagePolicy(pkg) {
  const binEntries = Object.entries(pkg.bin ?? {})
  if (pkg.name !== '@codetruss/cli'
    || binEntries.length !== 1
    || binEntries[0]?.[0] !== 'codetruss'
    || binEntries[0]?.[1] !== 'dist/cli.cjs') {
    throw new Error('published CLI package identity or executable mapping is invalid')
  }
  if (
    pkg.repository?.url !== 'git+https://github.com/DeliriumPulse/codetruss-cli.git'
    || pkg.homepage !== 'https://codetruss.com/cli'
    || pkg.bugs?.url !== 'https://github.com/DeliriumPulse/codetruss-cli/issues'
  ) {
    throw new Error('published CLI package does not identify the canonical source, product, and support pages')
  }
  const publishConfigEntries = Object.entries(pkg.publishConfig ?? {})
  if (pkg.private === true
    || publishConfigEntries.length !== 1
    || publishConfigEntries[0]?.[0] !== 'access'
    || publishConfigEntries[0]?.[1] !== 'public'
    || pkg.engines?.node !== '>=20.9.0') {
    throw new Error('published CLI package access or supported Node policy is invalid')
  }
  for (const field of [
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
    'bundledDependencies',
    'bundleDependencies',
  ]) {
    if (hasEntries(pkg[field])) throw new Error(`published CLI must not declare ${field}`)
  }
  for (const name of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (typeof pkg.scripts?.[name] === 'string') {
      throw new Error(`published CLI must not declare the ${name} install lifecycle script`)
    }
  }
}
