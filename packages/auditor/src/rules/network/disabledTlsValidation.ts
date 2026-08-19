import { buildFinding, evidence } from '../../analysis/findings.js';
import type { RawFinding } from '../../types/finding.js';
import type { RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-NETWORK-002 — certificate or hostname validation switched off.
 *
 * This is the highest-severity network finding the auditor produces, because it
 * converts HTTPS into HTTP with extra steps. A trust manager that accepts every
 * certificate, or a hostname verifier that returns `true`, means any on-path
 * attacker with a self-signed certificate reads and rewrites the session.
 *
 * It is almost always introduced deliberately — to make a development proxy or a
 * staging certificate work — and then survives into release. That is exactly why
 * it is worth a rule: nobody sets out to ship it.
 */

interface TlsPattern {
  readonly id: string;
  readonly pattern: RegExp;
  readonly title: string;
  readonly detail: string;
  readonly confidence: RawFinding['confidence'];
  readonly languages?: readonly string[];
}

const PATTERNS: readonly TlsPattern[] = [
  {
    id: 'reject-unauthorized-false',
    pattern: /rejectUnauthorized\s*:\s*false/,
    title: 'TLS certificate validation disabled',
    detail:
      '`rejectUnauthorized: false` accepts any certificate, including one an attacker minted.',
    confidence: 'very-high',
  },
  {
    id: 'node-tls-env',
    pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0/,
    title: 'TLS verification disabled through the environment',
    detail:
      'Setting NODE_TLS_REJECT_UNAUTHORIZED to 0 disables certificate verification process-wide.',
    confidence: 'very-high',
  },
  {
    id: 'trust-all-hostname-verifier',
    // Kotlin's trailing-lambda form uses braces rather than parentheses, so
    // both bracket styles have to match.
    pattern:
      /ALLOW_ALL_HOSTNAME_VERIFIER|(?:set)?[Hh]ostnameVerifier\s*[({][^}\n]*(?:->|=>)\s*true|new\s+HostnameVerifier/,
    title: 'Hostname verification disabled',
    detail:
      'A hostname verifier that returns true accepts a valid certificate issued for any other ' +
      'domain, which defeats the purpose of verification.',
    confidence: 'high',
    languages: ['kotlin', 'java'],
  },
  {
    id: 'trust-all-manager',
    pattern:
      /(?:object\s*:\s*X509TrustManager|implements\s+X509TrustManager|new\s+X509TrustManager|TrustAllCerts|trustAllCerts)/,
    title: 'Custom trust manager in use',
    detail:
      'A hand-written X509TrustManager usually exists to accept certificates the platform ' +
      'rejected. Verify that it validates the chain; an empty `checkServerTrusted` accepts ' +
      'everything.',
    // A custom trust manager can be legitimate — certificate pinning is
    // implemented this way — so this is an indicator to review, not a verdict.
    confidence: 'medium',
    languages: ['kotlin', 'java'],
  },
  {
    id: 'ios-trust-all',
    pattern: /URLCredential\s*\(\s*trust\s*:/,
    title: 'Server trust accepted without validation',
    detail:
      'Creating a URLCredential directly from the server trust in an authentication challenge ' +
      'accepts the certificate the server presented, whatever it is.',
    confidence: 'medium',
    languages: ['swift', 'objective-c', 'objective-cpp'],
  },
  {
    id: 'okhttp-trust-all-socket-factory',
    pattern: /sslSocketFactory\s*\([^)]*trustAll/i,
    title: 'HTTP client configured with a permissive socket factory',
    detail: 'The client is given a socket factory built from a trust-all trust manager.',
    confidence: 'high',
    languages: ['kotlin', 'java'],
  },
];

const KNOWLEDGE = {
  cwe: ['CWE-295', 'CWE-297'],
  masvs: ['MASVS-NETWORK-1'],
  maswe: ['MASWE-0027'],
  mappingConfidence: 'high',
} as const;

export const disabledTlsValidationRule: SecurityRule = {
  id: 'RNSEC-NETWORK-002',
  name: 'TLS validation disabled or weakened',
  description:
    'Certificate or hostname validation is turned off, so an on-path attacker can present any ' +
    'certificate and intercept the connection.',
  severity: 'critical',
  categories: ['network'],
  languages: [],
  fileKinds: [],
  // A code example in prose is not a defect.
  excludeFileKinds: ['documentation'],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    const findings: RawFinding[] = [];
    const reported = new Set<string>();

    context.lines.forEach((text, index) => {
      const trimmed = text.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) {
        return;
      }

      for (const candidate of PATTERNS) {
        if (
          candidate.languages !== undefined &&
          !candidate.languages.includes(context.file.language)
        ) {
          continue;
        }
        if (!candidate.pattern.test(text) || reported.has(candidate.id)) {
          continue;
        }
        reported.add(candidate.id);

        const line = index + 1;
        findings.push(
          buildFinding({
            ruleId: 'RNSEC-NETWORK-002',
            title: candidate.title,
            description: candidate.detail,
            severity: candidate.confidence === 'medium' ? 'high' : 'critical',
            confidence: candidate.confidence,
            categories: ['network'],
            path: context.file.path,
            line,
            evidence: [
              evidence('matched-pattern', candidate.title, {
                line,
                snippet: text.trim().slice(0, 200),
              }),
            ],
            impact:
              'An attacker on the network path can present their own certificate, decrypt the ' +
              'session, read credentials and personal data, and modify responses the application ' +
              'trusts.',
            exploitability:
              'Requires only a network position and a self-signed certificate. Off-the-shelf proxies ' +
              'do the rest.',
            remediation:
              'Remove the override and let the platform validate the chain. If a development ' +
              'certificate is the reason, install its CA on the test device or scope the exception ' +
              'to debug builds through a Network Security Config or an ATS exception, never in ' +
              'shared code. For extra assurance use certificate pinning with backup pins and a ' +
              'rotation plan — not a disabled check.',
            structuralContext: candidate.id,
            knowledge: KNOWLEDGE,
          })
        );
      }
    });

    return findings;
  },
};
