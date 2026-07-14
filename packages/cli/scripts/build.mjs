import { chmod, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { generateSbom } from './generate-sbom.mjs'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outDir = join(packageDir, 'dist')
const outfile = join(outDir, 'cli.cjs')

await rm(outDir, { recursive: true, force: true })
await build({
  entryPoints: [join(packageDir, 'src', 'cli.ts')],
  bundle: true,
  platform: 'node',
  target: 'node20.9',
  format: 'cjs',
  legalComments: 'eof',
  outfile,
})

// esbuild includes resolved source labels in its otherwise deterministic output.
// pnpm may place these ESM-only glob dependencies at the workspace root or the
// package root depending on unrelated workspace dependencies. Normalize their
// comment labels without changing executable code or stack-bearing CommonJS
// module names, so the release bytes do not depend on hoisting collisions.
const bundle = await readFile(outfile, 'utf8')
const normalizedBundle = bundle.replace(
  /^(\/\/ )(?:(?:\.\.\/)+)?node_modules\/(?:\.pnpm\/[^/]+\/node_modules\/)?((?:balanced-match|brace-expansion|minimatch)\/)/gm,
  '$1node_modules/$2',
)
await writeFile(outfile, normalizedBundle, 'utf8')
await chmod(outfile, 0o755)
await generateSbom()
