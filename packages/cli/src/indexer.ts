import { indexWorkingTree } from '@codetruss/analyzer-engine/indexer'

/** Keep hosted historical classification stable while making local evidence binary-aware. */
export function indexRepository(root: string) {
  return indexWorkingTree(root, { assetMode: 'binary-aware' })
}
