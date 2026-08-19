import { calleeName, enclosingContext, memberName, walk } from '../../analysis/ast.js';
import { buildFinding, evidence, nodeLocation, snippetOf } from '../../analysis/findings.js';
import { elementsNamed, scanXml } from '../../analysis/xml.js';
import type * as t from '@babel/types';

import type { RawFinding } from '../../types/finding.js';
import type { RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-DEEPLINK-001 — a deep link that is trusted more than it should be.
 *
 * A deep link is **remote input**. Anything can send one: a web page, another
 * application, an SMS. Two shapes of mistake follow from forgetting that, and
 * both are checked here.
 *
 * **Unvalidated navigation.** A URL taken from a link and handed to
 * `Linking.openURL` or a WebView is an open redirect: an attacker chooses where
 * the application goes, and the destination inherits whatever trust the
 * application places in its own navigation.
 *
 * **Unverified app links (Android).** An `http`/`https` intent filter without
 * `android:autoVerify="true"` can be claimed by any other installed application,
 * which then receives the link — including any token in it. Verification is what
 * ties the filter to a domain you demonstrably control.
 */

const KNOWLEDGE = {
  cwe: ['CWE-939'],
  masvs: ['MASVS-PLATFORM-1'],
  maswe: ['MASWE-0029'],
  mappingConfidence: 'high',
} as const;

const IMPACT =
  'An attacker chooses what the application opens or navigates to. Depending on the sink that ' +
  'means phishing inside a trusted shell, an authorization code delivered to the wrong party, or ' +
  'a WebView loading a page that can talk to the native bridge.';

const EXPLOITABILITY =
  'Sending a deep link requires no privileges: a link on a web page, in a message, or from another ' +
  'installed application is enough.';

/** Expressions that read a value out of a link. */
const LINK_SOURCES: readonly RegExp[] = [
  /\bLinking\.getInitialURL\b/,
  /\bLinking\.addEventListener\b/,
  /\buseURL\b/,
  /\broute\.params\b/,
  /\bsearchParams\.get\b/,
  /\bparse\(\s*url/i,
];

/** Sinks that act on a URL. */
const NAVIGATION_SINKS: readonly string[] = [
  'Linking.openURL',
  'Linking.canOpenURL',
  'WebBrowser.openBrowserAsync',
  'InAppBrowser.open',
];

export const unvalidatedDeepLinkRule: SecurityRule = {
  id: 'RNSEC-DEEPLINK-001',
  name: 'Deep link handled without validation',
  description:
    'A URL that arrived through a deep link is opened or navigated to without being checked, or an ' +
    'Android app link is declared without domain verification.',
  severity: 'high',
  categories: ['deep-links'],
  languages: [],
  fileKinds: [],
  // A code example in prose is not a defect.
  excludeFileKinds: ['documentation'],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    if (context.file.kind === 'android-manifest') {
      return detectUnverifiedAppLinks(context);
    }
    return detectUnvalidatedNavigation(context);
  },
};

/**
 * A URL derived from a link, passed to a navigation sink.
 *
 * The check is intentionally narrow: the file must both *read* a link and *act*
 * on a non-literal URL. A hardcoded `Linking.openURL('https://example.com/help')`
 * is not a finding, and neither is a file that merely imports `Linking`.
 */
function detectUnvalidatedNavigation(context: RuleContext): RawFinding[] {
  const readsLink = LINK_SOURCES.some((pattern) => pattern.test(context.text));
  if (!readsLink) {
    return [];
  }

  const findings: RawFinding[] = [];

  walk(context.parsed, ({ node, ancestors }) => {
    if (node.type !== 'CallExpression') {
      return;
    }
    const callee = calleeName(node);
    if (callee === undefined || !NAVIGATION_SINKS.includes(callee)) {
      return;
    }

    const argument = node.arguments[0] as t.Node | undefined;
    if (argument === undefined) {
      return;
    }
    // A literal destination is chosen by the developer, not the caller.
    if (argument.type === 'StringLiteral') {
      return;
    }
    if (argument.type === 'TemplateLiteral' && argument.expressions.length === 0) {
      return;
    }

    const location = nodeLocation(node);
    const snippet = snippetOf(context.lines, location.line);
    const structural = enclosingContext(ancestors);
    const name =
      argument.type === 'Identifier' ? argument.name : (memberName(argument) ?? 'a computed value');

    findings.push(
      buildFinding({
        ruleId: 'RNSEC-DEEPLINK-001',
        title: `${callee} is called with a URL from a deep link`,
        description:
          `This file reads a URL from a deep link and passes ${name} to ${callee} without a visible ` +
          'check that the destination is one the application intended.',
        severity: 'high',
        // Whether validation happens elsewhere cannot be established without
        // data-flow analysis, so this is an indicator to review.
        confidence: 'low',
        categories: ['deep-links'],
        path: context.file.path,
        ...location,
        evidence: [
          evidence('deep-link-source', 'This file reads a URL from a deep link'),
          evidence('navigation-sink', `The URL is passed to ${callee}`, {
            ...location,
            ...(snippet === undefined ? {} : { snippet }),
          }),
        ],
        impact: IMPACT,
        exploitability: EXPLOITABILITY,
        remediation:
          'Validate before acting: parse the URL, require an expected scheme and an allow-listed ' +
          'host, and map the path to a known route rather than following it. Treat every parameter ' +
          'as untrusted, and never let a link alone authorise anything.',
        ...(snippet === undefined ? {} : { codeSnippet: snippet }),
        ...(structural === undefined ? {} : { structuralContext: structural }),
        knowledge: KNOWLEDGE,
      })
    );
  });

  return findings;
}

/** An Android `http`/`https` intent filter without `android:autoVerify="true"`. */
function detectUnverifiedAppLinks(context: RuleContext): RawFinding[] {
  const elements = scanXml(context.text);
  const findings: RawFinding[] = [];

  const filters = elementsNamed(elements, 'intent-filter');

  for (let index = 0; index < filters.length; index += 1) {
    const filter = filters[index];
    if (filter === undefined || filter.attributes['android:autoVerify'] === 'true') {
      continue;
    }

    // `<data>` elements belonging to *this* filter: after it, and before the
    // next one begins. Without the upper bound, a filter inherits the schemes of
    // every filter below it — which reports the launcher activity for a deep
    // link declared elsewhere in the file.
    const nextFilterLine = filters[index + 1]?.line ?? Number.MAX_SAFE_INTEGER;
    const schemes = elements
      .filter(
        (element) =>
          element.name === 'data' && element.line > filter.line && element.line < nextFilterLine
      )
      .map((element) => element.attributes['android:scheme'])
      .filter((scheme): scheme is string => scheme !== undefined);

    const webSchemes = schemes.filter((scheme) => scheme === 'http' || scheme === 'https');
    if (webSchemes.length === 0) {
      continue;
    }

    findings.push(
      buildFinding({
        ruleId: 'RNSEC-DEEPLINK-001',
        title: 'Web intent filter without domain verification',
        description:
          'An intent filter accepts http/https links but does not set `android:autoVerify="true"`. ' +
          'Any other installed application can register the same filter and receive these links.',
        severity: 'medium',
        confidence: 'high',
        categories: ['deep-links', 'android'],
        path: context.file.path,
        line: filter.line,
        evidence: [
          evidence('manifest-attribute', 'The intent-filter accepts http/https links', {
            line: filter.line,
          }),
          evidence('manifest-attribute', 'android:autoVerify is not set to true', {
            line: filter.line,
          }),
        ],
        impact:
          'A competing application can claim the link and receive whatever it carries — including ' +
          'an authorization code in an OAuth redirect.',
        exploitability:
          'Requires the user to install an application that declares the same filter, and the ' +
          'attacker to control neither the domain nor the device.',
        remediation:
          'Set `android:autoVerify="true"` on the filter and publish an `assetlinks.json` for the ' +
          'domain, so only your application can claim it. Do not deliver secrets through a link ' +
          'that a competing filter can capture.',
        structuralContext: 'intent-filter-autoverify',
        knowledge: KNOWLEDGE,
      })
    );
  }

  return findings;
}
