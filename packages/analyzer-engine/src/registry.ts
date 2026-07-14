import type { Analyzer } from './types'
import { structureAnalyzer } from './structure'
import { sizeAnalyzer } from './size'
import { duplicationAnalyzer } from './duplication'
import { secretsAnalyzer } from './secrets'
import { deadCodeAnalyzer } from './dead-code'
import { removedRoutesAnalyzer } from './removed-routes'
import { dependencyAnalyzer } from './dependencies'
import { docsAnalyzer } from './docs'
import { envVarsAnalyzer } from './env-vars'
import { complexityAnalyzer } from './complexity'
import { todosAnalyzer } from './todos'
import { vulnerabilityAnalyzer } from './vulnerabilities'
import { coverageAnalyzer } from './coverage'

/**
 * Analyzer registry — the plugin surface. Adding an analyzer means writing
 * one module implementing Analyzer and registering it here.
 */
export const ANALYZERS: Analyzer[] = [
  structureAnalyzer,
  sizeAnalyzer,
  duplicationAnalyzer,
  secretsAnalyzer,
  deadCodeAnalyzer,
  removedRoutesAnalyzer,
  dependencyAnalyzer,
  docsAnalyzer,
  envVarsAnalyzer,
  complexityAnalyzer,
  todosAnalyzer,
  vulnerabilityAnalyzer,
  coverageAnalyzer,
]

export function getAnalyzers(): Analyzer[] {
  return ANALYZERS
}
