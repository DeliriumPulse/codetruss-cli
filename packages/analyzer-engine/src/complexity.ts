import {
  annotatedAnalyzerOutput,
  incompleteAnalyzerOutput,
  type Analyzer,
  type AnalyzerFinding,
} from './types'
import { looksGenerated } from './support'

const MAX_NESTING = 5
const LONG_FUNCTION_LINES = 120
const WRAPPER_HEAD_LINES = 10
const WRAPPER_MIN_COVERAGE = 0.9

/**
 * A `{` opens a CONTROL block (not an object/array literal) when the code
 * segment before it on the line ends a control-flow header or a function:
 * `if (…) {`, `} else {`, `try {`, `function f() {`, `=> {`, `for … {` (Go).
 */
const CONTROL_SEGMENT_RE =
  /(\b(if|else|for|while|switch|match|try|catch|finally|do|loop|function|fn|func|def)\b[^;{}]*$)|=>\s*\(?\s*$|\)\s*$/

/**
 * Complexity heuristics without a parser: deep nesting depth and very long
 * function bodies. Language-agnostic for brace languages. Only control-flow
 * and function braces count toward nesting — object/array literals (JSON
 * schemas, config objects) are data, not logic. Generated files and
 * file-spanning module-wrapper IIFEs are excluded.
 */
export const complexityAnalyzer: Analyzer = {
  id: 'complexity',
  name: 'Code Complexity',
  description: 'Flags deeply nested logic and very long functions.',
  async run(index) {
    const findings: AnalyzerFinding[] = []

    const candidates = index.files.filter(
      (f) =>
        f.content &&
        (f.kind === 'source' || f.kind === 'component' || f.kind === 'route') &&
        /\.(ts|tsx|js|jsx|java|go|rs|cs|c|cpp|php|swift|kt)$/.test(f.path),
    )

    const candidateLimit = 2000
    for (const file of candidates.slice(0, candidateLimit)) {
      if (looksGenerated(file.content!)) continue // machines don't need refactoring advice

      const lines = file.content!.split('\n')
      let depth = 0
      let controlDepth = 0
      const controlStack: boolean[] = []
      let maxDepth = 0
      let maxDepthLine = 0
      let funcStart = -1
      let funcStartDepth = 0
      // long-function findings held per file so a module-wrapper IIFE can be dropped
      const longFunctions: Array<{ start: number; span: number }> = []
      // top-level block accounting for wrapper-IIFE detection
      let topLevelBlocks = 0
      let firstTopOpenLine = -1
      let firstTopIsIife = false
      let lastTopCloseLine = -1

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        // strip strings & comments crudely to avoid counting braces in them
        const code = line.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '""').replace(/\/\/.*$/, '')

        const isFuncDecl = /\b(function\b|=>\s*{|def |func |fn )/.test(code)
        if (isFuncDecl && funcStart === -1) {
          funcStart = i
          funcStartDepth = depth
        }

        let segStart = 0
        for (let j = 0; j < code.length; j++) {
          const ch = code[j]
          if (ch === '{') {
            const isControl = CONTROL_SEGMENT_RE.test(code.slice(segStart, j))
            segStart = j + 1
            if (depth === 0) {
              topLevelBlocks++
              if (firstTopOpenLine === -1) {
                firstTopOpenLine = i + 1
                // `(function () {` / `;(async () => {` — an invoked wrapper,
                // not a plain declaration (which IS a reportable function)
                firstTopIsIife = /^\s*[;!]?\s*\(\s*(async\s+)?(function\b|\()/.test(code)
              }
            }
            depth++
            controlStack.push(isControl)
            if (isControl) {
              controlDepth++
              if (controlDepth > maxDepth) {
                maxDepth = controlDepth
                maxDepthLine = i + 1
              }
            }
          } else if (ch === '}') {
            segStart = j + 1
            if (controlStack.pop()) controlDepth = Math.max(0, controlDepth - 1)
            depth = Math.max(0, depth - 1)
            if (depth === 0) lastTopCloseLine = i + 1
            if (funcStart !== -1 && depth <= funcStartDepth) {
              if (i - funcStart > LONG_FUNCTION_LINES) {
                longFunctions.push({ start: funcStart, span: i - funcStart })
              }
              funcStart = -1
            }
          }
        }
      }

      // A single file-spanning IIFE is a module wrapper, not a "long function":
      // drop its finding and discount the one level of nesting it adds.
      const isWrapper =
        topLevelBlocks === 1 &&
        firstTopIsIife &&
        firstTopOpenLine <= WRAPPER_HEAD_LINES &&
        lastTopCloseLine >= lines.length * WRAPPER_MIN_COVERAGE
      if (isWrapper) maxDepth = Math.max(0, maxDepth - 1)

      const reportable = longFunctions.filter(
        (fn) => !(isWrapper && fn.start < WRAPPER_HEAD_LINES && fn.span >= lines.length * WRAPPER_MIN_COVERAGE),
      )
      const fn = reportable[0] // one long-function finding per file, as before
      if (fn) {
        findings.push({
          category: 'TECH_DEBT',
          severity: 'MEDIUM',
          title: `Very long function in ${file.path.split('/').pop()} (~${fn.span} lines)`,
          description: `A function starting near line ${fn.start + 1} of ${file.path} spans ~${fn.span} lines. Long functions hide bugs and resist testing.`,
          filePath: file.path,
          line: fn.start + 1,
          suggestion: 'Extract cohesive steps into named helper functions.',
          impactScore: 45,
          effort: 'medium',
        })
      }

      if (maxDepth > MAX_NESTING) {
        findings.push({
          category: 'TECH_DEBT',
          severity: maxDepth > MAX_NESTING + 2 ? 'MEDIUM' : 'LOW',
          title: `Deep nesting in ${file.path.split('/').pop()} (depth ${maxDepth})`,
          description: `${file.path} reaches a control-flow nesting depth of ${maxDepth} around line ${maxDepthLine}. Deeply nested logic is a common source of bugs.`,
          filePath: file.path,
          line: maxDepthLine,
          suggestion: 'Use early returns, extract functions, or invert conditions to flatten the logic.',
          impactScore: 40,
          effort: 'medium',
        })
      }
    }

    const findingLimit = 20
    const output = findings.slice(0, findingLimit)
    // Only the candidate-file cap loses coverage. The finding cap bounds the
    // persisted/displayed output after every candidate was analyzed, so it must
    // not make otherwise authoritative scores disappear.
    if (candidates.length > candidateLimit) {
      return incompleteAnalyzerOutput(output, {
        truncated: true,
        detail: `Complexity analysis hit a candidate bound (${candidates.length} candidate files, ${findings.length} matches).`,
        metrics: { candidates: candidates.length, candidateLimit, matches: findings.length, findingLimit },
      })
    }
    if (findings.length > findingLimit) {
      return annotatedAnalyzerOutput(output, {
        detail: `Complexity output capped at ${findingLimit} of ${findings.length} matches.`,
        metrics: { candidates: candidates.length, candidateLimit, matches: findings.length, findingLimit },
      })
    }
    return output
  },
}
