import { buildFinding, evidence } from '../../analysis/findings.js';
import { scanPlist } from '../../analysis/xml.js';
import type { RawFinding } from '../../types/finding.js';
import type { KnowledgeRefs, RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-IOS-PLIST-001 — App Transport Security weakened in `Info.plist`.
 *
 * ATS is on by default and requires HTTPS with TLS 1.2 or better. Every finding
 * here is something a developer had to add deliberately, usually to make one
 * endpoint work, and which then applies far more broadly than intended.
 *
 * The gradation matters. `NSAllowsArbitraryLoads` disables ATS for the whole
 * application; a per-domain exception disables it for one host. Reporting them
 * at the same severity would be wrong, and would push people towards the blunt
 * fix.
 *
 * One caveat is stated in the findings rather than left implicit: React Native's
 * debug build enables `localhost` exceptions so Metro can serve the bundle over
 * HTTP. That is expected, and the rule does not report it.
 */

const KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-319'],
  masvs: ['MASVS-NETWORK-1'],
  maswe: ['MASWE-0026'],
  mappingConfidence: 'high',
};

const IMPACT =
  'Traffic to the affected hosts may travel in cleartext or over an outdated TLS version, where ' +
  'anything on the network path can read and modify it.';

const EXPLOITABILITY =
  'A network position is sufficient — a shared access point, a hostile operator, or an on-path ' +
  'device. No access to the phone is needed.';

/** Hosts where a cleartext exception is expected and not a finding. */
const DEVELOPMENT_HOSTS: readonly string[] = ['localhost', '127.0.0.1', '::1', 'local'];

export const appTransportSecurityRule: SecurityRule = {
  id: 'RNSEC-IOS-PLIST-001',
  name: 'App Transport Security weakened',
  description:
    'Info.plist disables App Transport Security globally, for web content, or for specific ' +
    'domains, or permits a TLS version below 1.2.',
  severity: 'high',
  categories: ['ios', 'network', 'configuration'],
  languages: ['plist', 'xml'],
  fileKinds: ['ios-plist'],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    const entries = scanPlist(context.text);
    const findings: RawFinding[] = [];

    for (const entry of entries) {
      const key = entry.keyPath;
      const isTrue = entry.type === 'true';

      if (key.endsWith('NSAllowsArbitraryLoads') && isTrue) {
        // The exception dictionary wins over the global flag on modern iOS, but
        // relying on that ordering is fragile and the flag still applies where
        // no exception matches.
        findings.push(
          finding(context, {
            line: entry.line,
            title: 'App Transport Security disabled for the whole application',
            description:
              '`NSAllowsArbitraryLoads` turns ATS off application-wide, so every connection may use ' +
              'cleartext HTTP or an outdated TLS version.',
            severity: 'high',
            confidence: 'high',
            structural: 'NSAllowsArbitraryLoads',
            remediation:
              'Remove the key and serve every endpoint over HTTPS with TLS 1.2 or better. If a ' +
              'single third-party host is the obstacle, add a scoped exception for that host under ' +
              '`NSExceptionDomains` instead of disabling ATS everywhere. App Review also asks for a ' +
              'justification for this key.',
          })
        );
        continue;
      }

      if (key.endsWith('NSAllowsArbitraryLoadsInWebContent') && isTrue) {
        findings.push(
          finding(context, {
            line: entry.line,
            title: 'App Transport Security disabled for web content',
            description:
              '`NSAllowsArbitraryLoadsInWebContent` lets WebViews load cleartext content, so a page ' +
              'the application displays can be modified in transit.',
            severity: 'medium',
            confidence: 'high',
            structural: 'NSAllowsArbitraryLoadsInWebContent',
            remediation:
              'Remove the key and serve web content over HTTPS. If the WebView shows third-party ' +
              'pages, treat their content as untrusted regardless.',
          })
        );
        continue;
      }

      if (key.endsWith('NSExceptionAllowsInsecureHTTPLoads') && isTrue) {
        const domain = domainOf(key);
        if (
          domain !== undefined &&
          DEVELOPMENT_HOSTS.some((host) => domain === host || domain.endsWith(`.${host}`))
        ) {
          // React Native's debug configuration adds exactly this for Metro.
          continue;
        }
        findings.push(
          finding(context, {
            line: entry.line,
            title: `Cleartext HTTP permitted for ${domain ?? 'a domain'}`,
            description: `\`NSExceptionAllowsInsecureHTTPLoads\` permits cleartext HTTP to ${domain ?? 'this domain'}.`,
            severity: 'medium',
            confidence: 'high',
            structural: key,
            remediation:
              'Serve the endpoint over HTTPS and remove the exception. Where a third party is ' +
              'genuinely HTTP-only, keep the exception scoped to that domain and treat the data as ' +
              'public.',
          })
        );
        continue;
      }

      if (key.endsWith('NSExceptionMinimumTLSVersion') && isBelowTls12(entry.value)) {
        findings.push(
          finding(context, {
            line: entry.line,
            title: `TLS ${entry.value} permitted for ${domainOf(key) ?? 'a domain'}`,
            description:
              `\`NSExceptionMinimumTLSVersion\` lowers the minimum to ${entry.value}. TLS below 1.2 ` +
              'has known weaknesses and is deprecated by the IETF.',
            severity: 'medium',
            confidence: 'high',
            structural: key,
            remediation:
              'Require TLS 1.2 or better, and remove the exception once the server supports it.',
          })
        );
        continue;
      }

      if (key.endsWith('NSExceptionRequiresForwardSecrecy') && entry.type === 'false') {
        findings.push(
          finding(context, {
            line: entry.line,
            title: `Forward secrecy not required for ${domainOf(key) ?? 'a domain'}`,
            description:
              'Disabling `NSExceptionRequiresForwardSecrecy` permits cipher suites where recorded ' +
              'traffic can be decrypted later if the server key is compromised.',
            severity: 'low',
            confidence: 'high',
            structural: key,
            remediation: 'Configure the server for ECDHE cipher suites and remove the exception.',
          })
        );
      }
    }

    return findings;
  },
};

interface AtsFinding {
  readonly line: number;
  readonly title: string;
  readonly description: string;
  readonly severity: RawFinding['severity'];
  readonly confidence: RawFinding['confidence'];
  readonly structural: string;
  readonly remediation: string;
}

function finding(context: RuleContext, input: AtsFinding): RawFinding {
  return buildFinding({
    ruleId: 'RNSEC-IOS-PLIST-001',
    title: input.title,
    description: input.description,
    severity: input.severity,
    confidence: input.confidence,
    categories: ['ios', 'network', 'configuration'],
    path: context.file.path,
    line: input.line,
    evidence: [evidence('plist-key', input.title, { line: input.line })],
    impact: IMPACT,
    exploitability: EXPLOITABILITY,
    remediation: input.remediation,
    structuralContext: input.structural,
    knowledge: KNOWLEDGE,
  });
}

/** The domain an exception key belongs to, from its dotted key path. */
function domainOf(keyPath: string): string | undefined {
  const parts = keyPath.split('.');
  const index = parts.indexOf('NSExceptionDomains');
  if (index === -1 || parts.length <= index + 1) {
    return undefined;
  }
  // A domain contains dots, which the key path also uses as a separator; the
  // trailing key name is the only fixed point.
  return parts.slice(index + 1, parts.length - 1).join('.');
}

function isBelowTls12(value: string): boolean {
  return value === 'TLSv1.0' || value === 'TLSv1.1' || value === '1.0' || value === '1.1';
}
