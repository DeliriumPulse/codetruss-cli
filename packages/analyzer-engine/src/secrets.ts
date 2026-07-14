import { incompleteAnalyzerOutput, type Analyzer, type AnalyzerFinding } from './types'

/**
 * Defensive secret-exposure detection: flags credentials that appear to be
 * committed so the owner can rotate them. Values are NEVER included in
 * findings — only the location and the credential type.
 *
 * Length floors are tuned to real credential formats so short test strings
 * (e.g. "sk-ant-abc123-...") do not masquerade as production keys.
 */
const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'Stripe live secret key', re: /\bsk_live_[A-Za-z0-9]{24,}\b/ },
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{80,}\b/ },
  { name: 'OpenAI API key', re: /\bsk-(?!ant-)[A-Za-z0-9_-]{40,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'Generic password assignment', re: /(?:password|passwd|secret)\s*[:=]\s*['"][^'"]{8,}['"]/i },
  { name: 'Database URL with credentials', re: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/([^\s'":@/]+):([^\s'"@]+)@([^\s'"/]+)/ },
]

const SKIP_FILES = /(\.env\.example|\.md|\.lock|package-lock\.json|pnpm-lock\.yaml)$/i
const PLACEHOLDER = /(example|placeholder|your[-_]|xxx|changeme|dummy|<[^>]+>|\$\{)/i
/** Placeholder shapes inside the matched value itself. */
const PLACEHOLDER_VALUE = /(example|sample|dummy|fake|placeholder|changeme|your[-_]?(key|token|secret)|abc123|xxx+)/i

/** Dev/CI dummy hosts — credentials pointing here are not real secrets. */
const DUMMY_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', 'host.docker.internal'])

/** Test/fixture locations: findings here are downgraded, not silenced. */
const TEST_PATH_RE = /(^|\/)(tests?|__tests__|__mocks__|fixtures)\/|\.(test|spec)\./

/**
 * Only the fuzzy generic-password pattern is eligible for the test-fixture
 * downgrade: every other pattern matches an unambiguous production credential
 * format, which is a real leak even when pasted into a test file.
 */
const TEST_DOWNGRADEABLE = new Set(['Generic password assignment'])

export const secretsAnalyzer: Analyzer = {
  id: 'secrets',
  name: 'Exposed Secrets',
  description: 'Detects credentials committed to the repository (defensive; values are never reported).',
  async run(index) {
    const findings: AnalyzerFinding[] = []
    const findingLimit = 50

    for (const file of index.files) {
      if (!file.content || SKIP_FILES.test(file.path)) continue
      const isTestContext = TEST_PATH_RE.test(file.path)
      const lines = file.content.split('\n')
      for (let i = 0; i < lines.length && findings.length < findingLimit; i++) {
        const line = lines[i]
        if (PLACEHOLDER.test(line)) continue
        for (const { name, re } of SECRET_PATTERNS) {
          const match = line.match(re)
          if (!match) continue
          if (PLACEHOLDER_VALUE.test(match[0])) continue
          if (name === 'Database URL with credentials') {
            const hostPort = match[3]
            const host = hostPort.replace(/:\d+$/, '').replace(/^\[|\]$/g, '')
            // localhost/CI dummy hosts are not leaks; default credentials
            // (postgres:postgres, admin:admin) on a real host still are.
            if (DUMMY_HOSTS.has(host)) continue
          }
          const isEnvFile = /(^|\/)\.env/.test(file.path)
          // Committed .env files always escalate, even under tests/.
          if (isTestContext && TEST_DOWNGRADEABLE.has(name) && !isEnvFile) {
            findings.push({
              category: 'SECURITY_HYGIENE',
              severity: 'LOW',
              title: `Test fixture resembling a secret: ${name} in ${file.path.split('/').pop()}`,
              description: `Line ${i + 1} of ${file.path} contains a value shaped like a ${name}. It sits in test/fixture code and does not match a production key format, so it is most likely a fixture — but confirm no real credential was pasted.`,
              filePath: file.path,
              line: i + 1,
              suggestion: 'Use an obviously fake placeholder (e.g. "test-not-a-real-key") so scanners and reviewers can dismiss it at a glance.',
              impactScore: 25,
              effort: 'low',
              metadata: { credentialType: name, testContext: true },
            })
          } else {
            findings.push({
              category: 'SECURITY_HYGIENE',
              severity: isEnvFile ? 'CRITICAL' : 'HIGH',
              title: `Possible ${name} committed in ${file.path.split('/').pop()}`,
              description: `Line ${i + 1} of ${file.path} appears to contain a ${name}. Committed credentials should be treated as compromised.`,
              filePath: file.path,
              line: i + 1,
              suggestion: 'Rotate this credential immediately, move it to environment configuration, and add the file to .gitignore. Consider a pre-commit secret scanner.',
              impactScore: 95,
              effort: 'low',
              metadata: { credentialType: name },
            })
          }
          break // one finding per line
        }
      }
    }
    return findings.length >= findingLimit
      ? incompleteAnalyzerOutput(findings, {
          truncated: true,
          detail: `Secret scanning stopped after ${findingLimit} matches.`,
          metrics: { matches: findings.length, findingLimit },
        })
      : findings
  },
}
