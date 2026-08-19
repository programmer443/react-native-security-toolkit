import {
  jsxAttributeName,
  jsxBooleanAttribute,
  jsxElementName,
  staticString,
  walk,
} from '../../analysis/ast.js';
import { buildFinding, evidence, nodeLocation, snippetOf } from '../../analysis/findings.js';
import type * as t from '@babel/types';

import type { RawFinding } from '../../types/finding.js';
import type { KnowledgeRefs, RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-WEBVIEW-001 — a WebView configured to trust content it should not.
 *
 * A WebView is a browser inside the application, with the application's
 * identity. The dangerous combinations are well known and are all *opt-in*, so
 * finding them is a matter of reading configuration rather than guessing:
 *
 * - `originWhitelist={['*']}` — any page the WebView navigates to, including one
 *   an attacker redirects it to, runs with the WebView's privileges.
 * - File access combined with JavaScript — a page can read the application's own
 *   files, which on Android has historically meant reading the WebView cookie
 *   store and shared preferences.
 * - `addJavascriptInterface` — exposes a native object to page JavaScript. Any
 *   page that ends up loaded gets to call it.
 * - `mixedContentMode="always"` — an HTTPS page may load HTTP subresources, so
 *   an attacker rewrites the script the page executes.
 *
 * None of these is a defect in isolation in every application; each is reported
 * with what makes it dangerous so the reader can judge.
 */

const PLATFORM_KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-749', 'CWE-79'],
  masvs: ['MASVS-PLATFORM-2'],
  maswe: ['MASWE-0034'],
  mappingConfidence: 'high',
};

const BRIDGE_KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-749', 'CWE-94'],
  masvs: ['MASVS-PLATFORM-2'],
  maswe: ['MASWE-0033'],
  mappingConfidence: 'high',
};

const UNTRUSTED_CONTENT_KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-79'],
  masvs: ['MASVS-PLATFORM-2'],
  maswe: ['MASWE-0035'],
  mappingConfidence: 'high',
};

const IMPACT =
  "Content loaded in the WebView runs with the application's privileges: it can reach whatever the " +
  'WebView is allowed to reach — local files, native bridges, the session the WebView holds.';

const EXPLOITABILITY =
  'Requires getting the WebView to load attacker-influenced content: a deep link carrying a URL, ' +
  'an open redirect on a trusted domain, or a cleartext subresource on a network the attacker sits on.';

export const unsafeWebViewRule: SecurityRule = {
  id: 'RNSEC-WEBVIEW-001',
  name: 'Unsafe WebView configuration',
  description:
    'A WebView is configured to allow any origin, expose native functionality, reach local files, ' +
    'or load mixed content.',
  severity: 'high',
  categories: ['webview'],
  languages: [],
  fileKinds: [],
  // A code example in prose is not a defect.
  excludeFileKinds: ['documentation'],
  knowledge: {
    cwe: ['CWE-749', 'CWE-79', 'CWE-94'],
    masvs: ['MASVS-PLATFORM-2'],
    maswe: ['MASWE-0033', 'MASWE-0034', 'MASWE-0035'],
    mappingConfidence: 'high',
  },

  detect(context: RuleContext): readonly RawFinding[] {
    return [...detectJsx(context), ...detectNative(context)];
  },
};

interface JsxIssue {
  readonly id: string;
  readonly title: string;
  readonly detail: string;
  readonly severity: RawFinding['severity'];
  readonly confidence: RawFinding['confidence'];
  readonly remediation: string;
  readonly knowledge: KnowledgeRefs;
}

function detectJsx(context: RuleContext): RawFinding[] {
  const findings: RawFinding[] = [];

  walk(context.parsed, ({ node }) => {
    if (node.type !== 'JSXOpeningElement') {
      return;
    }
    const element = jsxElementName(node);
    if (element === undefined || !/webview$/i.test(element)) {
      return;
    }

    const attributes = new Map<string, t.JSXAttribute>();
    for (const attribute of node.attributes) {
      const name = jsxAttributeName(attribute as t.Node);
      if (name !== undefined && attribute.type === 'JSXAttribute') {
        attributes.set(name, attribute);
      }
    }

    const issues: JsxIssue[] = [];

    const originWhitelist = attributes.get('originWhitelist');
    if (originWhitelist !== undefined && containsWildcardOrigin(originWhitelist)) {
      issues.push({
        id: 'origin-whitelist-wildcard',
        title: 'WebView accepts navigation to any origin',
        detail:
          "`originWhitelist={['*']}` lets the WebView navigate anywhere, so a redirect carries the " +
          "WebView's privileges to a site the application does not control.",
        severity: 'high',
        confidence: 'high',
        remediation:
          'List the origins the WebView is allowed to reach, and handle everything else in the ' +
          'system browser through `onShouldStartLoadWithRequest`.',
        knowledge: UNTRUSTED_CONTENT_KNOWLEDGE,
      });
    }

    const javaScriptEnabled = attributes.get('javaScriptEnabled');
    const javaScriptOn =
      javaScriptEnabled === undefined ? false : jsxBooleanAttribute(javaScriptEnabled) === true;

    for (const fileAttribute of [
      'allowFileAccess',
      'allowFileAccessFromFileURLs',
      'allowUniversalAccessFromFileURLs',
    ]) {
      const attribute = attributes.get(fileAttribute);
      if (attribute !== undefined && jsxBooleanAttribute(attribute) === true) {
        issues.push({
          id: fileAttribute,
          title: `WebView grants ${fileAttribute}`,
          detail:
            `\`${fileAttribute}\` lets loaded content reach the file system` +
            (javaScriptOn ? ', and JavaScript is enabled to make use of it.' : '.'),
          severity: javaScriptOn ? 'high' : 'medium',
          confidence: 'high',
          remediation:
            'Leave file access off. If local content must be rendered, bundle it and load it from ' +
            'a dedicated origin rather than opening the file system to remote content.',
          knowledge: PLATFORM_KNOWLEDGE,
        });
      }
    }

    const mixedContent = attributes.get('mixedContentMode');
    if (mixedContent !== undefined && attributeString(mixedContent) === 'always') {
      issues.push({
        id: 'mixed-content-always',
        title: 'WebView allows mixed content',
        detail:
          '`mixedContentMode="always"` lets an HTTPS page load HTTP subresources, so an on-path ' +
          'attacker can replace the scripts the page runs.',
        severity: 'high',
        confidence: 'high',
        remediation: 'Use the default (`never`), and serve every subresource over HTTPS.',
        knowledge: UNTRUSTED_CONTENT_KNOWLEDGE,
      });
    }

    const injected =
      attributes.get('injectedJavaScript') ??
      attributes.get('injectedJavaScriptBeforeContentLoaded');
    if (injected !== undefined && javaScriptOn && attributes.get('originWhitelist') === undefined) {
      issues.push({
        id: 'injected-javascript-any-origin',
        title: 'JavaScript is injected into pages from unrestricted origins',
        detail:
          'Injected script runs in whatever page the WebView has loaded. Without an origin ' +
          'restriction, that may be a page the application did not choose.',
        severity: 'medium',
        confidence: 'medium',
        remediation:
          'Restrict `originWhitelist` to the origins you control, and treat every message received ' +
          'from the page as untrusted input.',
        knowledge: BRIDGE_KNOWLEDGE,
      });
    }

    if (issues.length === 0) {
      return;
    }

    const location = nodeLocation(node);
    const snippet = snippetOf(context.lines, location.line);

    for (const issue of issues) {
      findings.push(
        buildFinding({
          ruleId: 'RNSEC-WEBVIEW-001',
          title: issue.title,
          description: issue.detail,
          severity: issue.severity,
          confidence: issue.confidence,
          categories: ['webview'],
          path: context.file.path,
          ...location,
          evidence: [
            evidence('webview-configuration', issue.title, {
              ...location,
              ...(snippet === undefined ? {} : { snippet }),
            }),
          ],
          impact: IMPACT,
          exploitability: EXPLOITABILITY,
          remediation: issue.remediation,
          ...(snippet === undefined ? {} : { codeSnippet: snippet }),
          structuralContext: `${element}:${issue.id}`,
          knowledge: issue.knowledge,
        })
      );
    }
  });

  return findings;
}

function containsWildcardOrigin(attribute: t.JSXAttribute): boolean {
  const value = attribute.value;
  if (value === null || value === undefined || value.type !== 'JSXExpressionContainer') {
    return false;
  }
  const expression = value.expression;
  if (expression.type !== 'ArrayExpression') {
    return false;
  }
  return expression.elements.some((element) => {
    if (element === null || element.type === 'SpreadElement') {
      return false;
    }
    const text = staticString(element as t.Node);
    return text === '*' || text === 'http://*' || text === 'https://*';
  });
}

function attributeString(attribute: t.JSXAttribute): string | undefined {
  const value = attribute.value;
  if (value === null || value === undefined) {
    return undefined;
  }
  if (value.type === 'StringLiteral') {
    return value.value;
  }
  if (value.type === 'JSXExpressionContainer') {
    return staticString(value.expression as t.Node);
  }
  return undefined;
}

/** Native WebView settings, matched textually. */
const NATIVE_PATTERNS: readonly {
  id: string;
  pattern: RegExp;
  title: string;
  detail: string;
  severity: RawFinding['severity'];
  remediation: string;
  knowledge: KnowledgeRefs;
  languages: readonly string[];
}[] = [
  {
    id: 'add-javascript-interface',
    pattern: /addJavascriptInterface\s*\(/,
    title: 'Native object exposed to WebView JavaScript',
    detail:
      '`addJavascriptInterface` exposes a native object to page script. Whatever page is loaded — ' +
      'including one reached by redirect — can call its annotated methods.',
    severity: 'high',
    remediation:
      'Prefer `WebViewCompat.postWebMessage` with an explicit origin, expose the narrowest possible ' +
      'surface, and validate every argument as untrusted input.',
    knowledge: BRIDGE_KNOWLEDGE,
    languages: ['kotlin', 'java'],
  },
  {
    id: 'universal-file-access',
    pattern:
      /setAllow(?:Universal|File)AccessFromFileURLs\s*\(\s*true|allowUniversalAccessFromFileURLs\s*=\s*true|allowFileAccessFromFileURLs\s*=\s*true/,
    title: 'WebView allows file URLs to reach other origins',
    detail:
      'A page loaded from a `file://` URL can read other local files and, with universal access, ' +
      'issue requests to any origin with the results readable by the page.',
    severity: 'high',
    remediation:
      'Leave these settings at their defaults (false) and serve local content from a bundled origin.',
    knowledge: PLATFORM_KNOWLEDGE,
    languages: ['kotlin', 'java', 'swift', 'objective-c', 'objective-cpp'],
  },
  {
    id: 'mixed-content-always-allow',
    pattern: /MIXED_CONTENT_ALWAYS_ALLOW/,
    title: 'WebView allows mixed content',
    detail: 'An HTTPS page may load HTTP subresources, which an on-path attacker can replace.',
    severity: 'high',
    remediation: 'Use `MIXED_CONTENT_NEVER_ALLOW` and serve every subresource over HTTPS.',
    knowledge: UNTRUSTED_CONTENT_KNOWLEDGE,
    languages: ['kotlin', 'java'],
  },
];

function detectNative(context: RuleContext): RawFinding[] {
  const findings: RawFinding[] = [];
  const reported = new Set<string>();

  context.lines.forEach((text, index) => {
    const trimmed = text.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) {
      return;
    }

    for (const candidate of NATIVE_PATTERNS) {
      if (!candidate.languages.includes(context.file.language)) {
        continue;
      }
      if (!candidate.pattern.test(text) || reported.has(candidate.id)) {
        continue;
      }
      reported.add(candidate.id);

      const line = index + 1;
      findings.push(
        buildFinding({
          ruleId: 'RNSEC-WEBVIEW-001',
          title: candidate.title,
          description: candidate.detail,
          severity: candidate.severity,
          confidence: 'high',
          categories: ['webview'],
          path: context.file.path,
          line,
          evidence: [
            evidence('webview-configuration', candidate.title, {
              line,
              snippet: text.trim().slice(0, 200),
            }),
          ],
          impact: IMPACT,
          exploitability: EXPLOITABILITY,
          remediation: candidate.remediation,
          structuralContext: candidate.id,
          knowledge: candidate.knowledge,
        })
      );
    }
  });

  return findings;
}
