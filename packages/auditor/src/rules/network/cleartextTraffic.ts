import { buildFinding, evidence } from '../../analysis/findings.js';
import type { RawFinding } from '../../types/finding.js';
import type { RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-NETWORK-001 — an endpoint reached over plain HTTP.
 *
 * Everything on an HTTP connection is readable and modifiable by anything on the
 * path: the coffee-shop access point, the mobile operator, a compromised router.
 * For a mobile application that includes the session token in the request
 * header.
 *
 * The interesting work in this rule is **not** finding `http://`; it is not
 * reporting the many `http://` strings that are not endpoints. XML namespaces,
 * DTD identifiers, licence URLs and schema references all use `http://` by
 * specification and always will — `http://schemas.android.com/apk/res/android`
 * is in every AndroidManifest.xml ever written. Reporting those would bury the
 * one URL that matters.
 */

/** Hosts and URL prefixes that are not endpoints, or are local by definition. */
const NON_ENDPOINT_PREFIXES: readonly string[] = [
  'http://schemas.android.com/',
  'http://schemas.microsoft.com/',
  'http://www.w3.org/',
  'http://www.apple.com/DTDs/',
  'http://json-schema.org/',
  'http://maven.apache.org/',
  'http://java.sun.com/',
  'http://xmlns.jcp.org/',
  'http://purl.org/',
  'http://ns.adobe.com/',
  'http://www.opengis.net/',
  'http://tempuri.org/',
];

/** Local addresses, where cleartext is normal and often unavoidable. */
const LOCAL_HOSTS: readonly RegExp[] = [
  /^https?:\/\/localhost(?::\d+)?(?:[/?#]|$)/i,
  /^https?:\/\/127\.0\.0\.1(?::\d+)?(?:[/?#]|$)/i,
  /^https?:\/\/\[::1\](?::\d+)?(?:[/?#]|$)/i,
  // The Android emulator's alias for the host machine.
  /^https?:\/\/10\.0\.2\.2(?::\d+)?(?:[/?#]|$)/i,
  /^https?:\/\/0\.0\.0\.0(?::\d+)?(?:[/?#]|$)/i,
  // Private ranges: a developer's machine on a LAN, not a shipped endpoint.
  /^https?:\/\/192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?(?:[/?#]|$)/i,
  /^https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:[/?#]|$)/i,
  // Documentation domains reserved by RFC 2606.
  /^https?:\/\/(?:[\w-]+\.)*example\.(?:com|org|net)(?::\d+)?(?:[/?#]|$)/i,
];

const URL_PATTERN = /http:\/\/[^\s"'`<>)\\]+/g;

const KNOWLEDGE = {
  cwe: ['CWE-319'],
  masvs: ['MASVS-NETWORK-1'],
  maswe: ['MASWE-0026'],
  mappingConfidence: 'high',
} as const;

export const cleartextTrafficRule: SecurityRule = {
  id: 'RNSEC-NETWORK-001',
  name: 'Endpoint reached over cleartext HTTP',
  description: 'A remote endpoint is addressed with `http://`, so its traffic is unprotected.',
  severity: 'high',
  categories: ['network'],
  languages: [],
  // Documentation is excluded: a link in a README is not a request.
  fileKinds: [
    'source',
    'android-manifest',
    'android-network-security-config',
    'gradle-build',
    'ios-plist',
    'package-manifest',
    'metro-config',
    'expo-config',
    'env-file',
    'other',
  ],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    const findings: RawFinding[] = [];
    const reportedHosts = new Set<string>();

    // Block-comment state has to be carried across lines: an Apache licence
    // header puts its URL on a line of its own, several lines into the comment.
    let inBlockComment = false;

    context.lines.forEach((rawText, index) => {
      // A URL in a comment is a citation — a licence header, a link to
      // documentation, a note about where a value came from — not an endpoint
      // the application talks to. Scanning comments reports the Apache licence
      // URL in every generated XML file in an Android project.
      const { code, stillInComment } = withoutComments(rawText, inBlockComment);
      inBlockComment = stillInComment;

      const text = code;
      URL_PATTERN.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = URL_PATTERN.exec(text)) !== null) {
        const url = match[0];
        if (isNotAnEndpoint(url)) {
          continue;
        }

        const host = hostOf(url);
        // One finding per host per file: a base URL repeated across ten calls is
        // one decision to fix, not ten.
        if (reportedHosts.has(host)) {
          continue;
        }
        reportedHosts.add(host);

        const line = index + 1;
        findings.push(
          buildFinding({
            ruleId: 'RNSEC-NETWORK-001',
            title: `Cleartext HTTP endpoint: ${host}`,
            description:
              `Traffic to ${host} is sent over HTTP, so it can be read and modified by anything on ` +
              'the network path.',
            severity: 'high',
            confidence: 'high',
            categories: ['network'],
            path: context.file.path,
            line,
            column: match.index + 1,
            evidence: [
              evidence('cleartext-url', `The URL uses the http scheme`, {
                line,
                snippet: url.slice(0, 200),
              }),
            ],
            impact:
              'Anything on the network path can read the request and the response, and can modify ' +
              'either. Session tokens and personal data sent this way should be treated as public.',
            exploitability:
              'A network position is all that is required — a shared access point, a hostile ' +
              'operator, or an on-path device. Tooling for this is commodity.',
            remediation:
              'Serve the endpoint over HTTPS and address it as `https://`. Keep the platform ' +
              'cleartext protections on: `android:usesCleartextTraffic="false"` with a Network ' +
              'Security Config, and App Transport Security left at its defaults on iOS.',
            structuralContext: host,
            knowledge: KNOWLEDGE,
          })
        );
      }
    });

    return findings;
  },
};

/**
 * Removes comment text from a line, carrying block-comment state across lines.
 *
 * Deliberately simple: it recognises `//`, `#`, `/* … *\/` and `<!-- … -->`,
 * which covers every file type the auditor reads, and it does not attempt to
 * understand strings. A URL inside a string that also contains a `#` will be
 * truncated — an acceptable trade for not reporting every licence header.
 */
function withoutComments(
  text: string,
  inBlockComment: boolean
): { code: string; stillInComment: boolean } {
  let rest = text;
  let code = '';
  let inComment = inBlockComment;

  while (rest.length > 0) {
    if (inComment) {
      const end = rest.search(/\*\/|-->/);
      if (end === -1) {
        return { code, stillInComment: true };
      }
      rest = rest.slice(end + (rest.startsWith('-->', end) ? 3 : 2));
      inComment = false;
      continue;
    }

    const lineComment = rest.search(/(?:^|\s)(?:\/\/|#)/);
    const blockStart = rest.search(/\/\*|<!--/);

    if (blockStart !== -1 && (lineComment === -1 || blockStart < lineComment)) {
      code += rest.slice(0, blockStart);
      rest = rest.slice(blockStart + (rest.startsWith('<!--', blockStart) ? 4 : 2));
      inComment = true;
      continue;
    }

    if (lineComment !== -1) {
      code += rest.slice(0, lineComment);
      return { code, stillInComment: false };
    }

    code += rest;
    rest = '';
  }

  return { code, stillInComment: inComment };
}

function isNotAnEndpoint(url: string): boolean {
  if (NON_ENDPOINT_PREFIXES.some((prefix) => url.startsWith(prefix))) {
    return true;
  }
  return LOCAL_HOSTS.some((pattern) => pattern.test(url));
}

function hostOf(url: string): string {
  const withoutScheme = url.slice('http://'.length);
  const end = withoutScheme.search(/[/?#]/);
  return end === -1 ? withoutScheme : withoutScheme.slice(0, end);
}
