import type { AuditReport } from '../../../types/report.js';
import type { SecurityFinding } from '../../../types/finding.js';

/** A finding with every optional field populated, so reporters are exercised fully. */
export function sampleFinding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: 'RNSEC-SECRET-001-9f2c1a8b4d3e',
    ruleId: 'RNSEC-SECRET-001',
    title: 'AWS access key id committed to source',
    description:
      'A value matching the published format of an AWS access key id appears in this file.',
    severity: 'critical',
    confidence: 'very-high',
    categories: ['secrets'],
    location: { path: 'src/api/client.ts', line: 12, column: 21 },
    codeSnippet: 'const accessKeyId = "AKIA****************";',
    evidence: [
      {
        kind: 'matched-pattern',
        description: 'Matched the AWS access key id format',
        snippet: 'AKIA****',
        line: 12,
      },
    ],
    cwe: [{ id: 'CWE-798', title: 'Use of Hard-coded Credentials', mappingConfidence: 'high' }],
    maswe: [
      {
        id: 'MASWE-0004',
        title: 'Sensitive Data Hardcoded in the App Package',
        mappingConfidence: 'high',
      },
    ],
    masvs: [
      {
        id: 'MASVS-STORAGE-1',
        title: 'The app securely stores sensitive data.',
        mappingConfidence: 'high',
      },
    ],
    impact:
      'Anything shipped in an application binary is readable by anyone who has the application.',
    exploitability:
      'No privileges are needed; extracting strings from a distributed APK is one command.',
    remediation: 'Move the credential to a server and rotate the exposed one.',
    sources: ['deterministic'],
    fingerprint: '9f2c1a8b4d3e5f60718293a4b5c6d7e8',
    ...overrides,
  };
}

/** A complete report, with suppressions, errors and a second finding at another severity. */
export function sampleReport(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    startedAt: '2026-08-19T09:00:00.000Z',
    durationMs: 412,
    root: '/Users/example/work/app',
    findings: [
      sampleFinding(),
      sampleFinding({
        id: 'RNSEC-LOG-001-1122334455',
        ruleId: 'RNSEC-LOG-001',
        title: 'accessToken is written to the log',
        description: '"accessToken" names an authentication token and is passed to console.log.',
        severity: 'medium',
        confidence: 'high',
        categories: ['logging', 'privacy'],
        location: { path: 'src/auth/session.ts', line: 40 },
        fingerprint: '1122334455667788990011223344556677',
        severityAdjustment: { from: 'high', to: 'medium', reason: 'file is test code' },
      }),
    ],
    suppressed: [
      {
        finding: sampleFinding({
          id: 'RNSEC-SECRET-001-aabbccdd',
          location: { path: 'docs/rules/RNSEC-SECRET-001.md', line: 31 },
          fingerprint: 'aabbccddeeff00112233445566778899',
        }),
        kind: 'inline',
        reason: 'illustration in rule documentation, not a live key',
      },
    ],
    skipped: [{ path: 'assets/logo.png', reason: 'binary', detail: 'binary file extension' }],
    ruleErrors: [],
    suppressionErrors: [],
    stats: {
      filesDiscovered: 316,
      filesAnalysed: 315,
      filesParsed: 210,
      bytesRead: 1_204_338,
      rulesRun: 14,
      findingsBeforeDeduplication: 4,
      findingsSuppressed: 1,
      findingsBelowThreshold: 2,
      excludedByConfig: 9,
      notIncludedByConfig: 0,
    },
    truncated: false,
    timedOut: false,
    failOn: 'high',
    exceedsFailOn: true,
    aiUsed: false,
    ...overrides,
  };
}

/**
 * A report whose text is actively hostile.
 *
 * Every string here comes from a repository the auditor does not trust, and each
 * value is a real injection attempt against a specific output format.
 */
export function hostileReport(): AuditReport {
  return sampleReport({
    findings: [
      sampleFinding({
        title: '<script>alert(document.cookie)</script>',
        description: 'Closing an attribute: " onmouseover="alert(1)',
        location: { path: 'src/<img src=x onerror=alert(1)>.ts', line: 1 },
        codeSnippet: '</code></pre><script>alert(2)</script>',
        evidence: [{ kind: 'matched-pattern', description: 'a | pipe | and ```fences```' }],
        remediation: 'Table | breaking | pipes and **markdown** _emphasis_',
      }),
    ],
  });
}
