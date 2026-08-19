import { enclosingContext, propertyName, staticString, walk } from '../../analysis/ast.js';
import { hasBenignShape, looksHighEntropy } from '../../analysis/entropy.js';
import { buildFinding, evidence, nodeLocation, snippetOf } from '../../analysis/findings.js';
import {
  isSensitiveName,
  maskSecret,
  sensitiveKindOf,
  describeSensitiveKind,
} from '../../analysis/sensitivity.js';
import type { RawFinding } from '../../types/finding.js';
import type { RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-SECRET-001 — a credential embedded in the application.
 *
 * The defining constraint of a secrets rule is stated in §34: *do not flag every
 * random-looking string*. A scanner that reports every base64 blob and every
 * UUID gets switched off within a day, and then it detects nothing at all.
 *
 * So detection runs at two confidences, and never on entropy alone:
 *
 * 1. **Provider patterns** — an AWS key id, a Stripe live key, a PEM private key
 *    block. These identify themselves, so they are `very-high` confidence and
 *    fire wherever they appear, in any language.
 * 2. **A sensitive name assigned a secret-shaped literal** — `const apiKey =
 *    "wJalrXUtn..."`. Neither half is sufficient: the name alone catches
 *    `apiKey = process.env.API_KEY`, which is correct code, and the shape alone
 *    catches every hash in the repository.
 *
 * Values are **masked** in the report. A findings file travels into pull
 * requests, CI logs and issue trackers — much further than the source file it
 * came from.
 */

interface ProviderPattern {
  readonly id: string;
  readonly label: string;
  readonly pattern: RegExp;
}

/**
 * Credentials whose format identifies the issuer.
 *
 * Every entry is a documented, published prefix. Nothing here is a guess about
 * what a token "usually looks like" — that is how a secrets rule starts matching
 * commit hashes.
 */
const PROVIDER_PATTERNS: readonly ProviderPattern[] = [
  {
    id: 'aws-access-key-id',
    label: 'AWS access key id',
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  },
  { id: 'google-api-key', label: 'Google API key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  {
    id: 'stripe-secret-key',
    label: 'Stripe secret key',
    pattern: /\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b/g,
  },
  { id: 'github-token', label: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { id: 'slack-token', label: 'Slack token', pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { id: 'npm-token', label: 'npm access token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'twilio-api-key', label: 'Twilio API key', pattern: /\bSK[0-9a-fA-F]{32}\b/g },
  {
    id: 'sendgrid-api-key',
    label: 'SendGrid API key',
    pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
  },
  {
    id: 'private-key-block',
    label: 'PEM private key block',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    id: 'json-web-token',
    label: 'JSON Web Token',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
];

const KNOWLEDGE = {
  cwe: ['CWE-798', 'CWE-312'],
  masvs: ['MASVS-STORAGE-1'],
  maswe: ['MASWE-0004'],
  mappingConfidence: 'high',
} as const;

const IMPACT =
  'Anything shipped in an application binary is readable by anyone who has the application. ' +
  'A credential embedded here should be treated as public, and as compromised the moment it ships.';

const EXPLOITABILITY =
  'No privileges are needed. Extracting strings from a distributed IPA or APK is a single command, ' +
  'and public tooling scans stores for exactly these patterns.';

const REMEDIATION =
  'Move the credential to a server you control and have the application request what it needs at ' +
  'runtime, authenticated as the user. If a value genuinely must reach the device, treat it as ' +
  'public and scope it accordingly. Then rotate the exposed credential: removing it from source ' +
  'does not un-ship it.';

export const hardcodedSecretRule: SecurityRule = {
  id: 'RNSEC-SECRET-001',
  name: 'Hardcoded credential',
  description:
    'A credential, API key or private key appears to be embedded in the application source rather ' +
    'than supplied at runtime.',
  severity: 'critical',
  categories: ['secrets'],
  // Any language: a credential in a Gradle file or a plist is no less shipped
  // than one in TypeScript.
  languages: [],
  fileKinds: [],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    const findings: RawFinding[] = [];
    const reportedLines = new Set<number>();

    findings.push(...detectProviderPatterns(context, reportedLines));
    findings.push(...detectSensitiveAssignments(context, reportedLines));
    return findings;
  },
};

/** Pass one: credentials whose format names their issuer. */
function detectProviderPatterns(context: RuleContext, reportedLines: Set<number>): RawFinding[] {
  const findings: RawFinding[] = [];

  context.lines.forEach((text, index) => {
    for (const provider of PROVIDER_PATTERNS) {
      // Patterns are global; reset so state does not leak between lines.
      provider.pattern.lastIndex = 0;
      const match = provider.pattern.exec(text);
      if (match === null) {
        continue;
      }

      const line = index + 1;
      reportedLines.add(line);
      findings.push(
        buildFinding({
          ruleId: 'RNSEC-SECRET-001',
          title: `${provider.label} committed to source`,
          description:
            `A value matching the published format of ${provider.label.toLowerCase()} appears in ` +
            `this file. Credentials in source are shipped inside the application binary.`,
          severity: 'critical',
          confidence: 'very-high',
          categories: ['secrets'],
          path: context.file.path,
          line,
          column: match.index + 1,
          evidence: [
            evidence('matched-pattern', `Matched the ${provider.label} format`, {
              // Masked: the point is to locate it, not to reproduce it.
              snippet: maskSecret(match[0]),
              line,
            }),
          ],
          impact: IMPACT,
          exploitability: EXPLOITABILITY,
          remediation: REMEDIATION,
          structuralContext: provider.id,
          knowledge: KNOWLEDGE,
        })
      );
    }
  });

  return findings;
}

/**
 * Pass two: a sensitively named binding assigned a secret-shaped literal.
 *
 * JavaScript-family only, because it needs to know that the value is a *static*
 * string. `const apiKey = process.env.API_KEY` is the correct pattern and must
 * never be reported, and only a parse can tell the two apart reliably.
 */
function detectSensitiveAssignments(
  context: RuleContext,
  reportedLines: Set<number>
): RawFinding[] {
  const findings: RawFinding[] = [];
  const seen = new Set<string>();

  walk(context.parsed, ({ node, ancestors }) => {
    let name: string | undefined;
    let valueNode: typeof node | null | undefined;

    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') {
      name = node.id.name;
      valueNode = node.init;
    } else if (node.type === 'ObjectProperty') {
      name = propertyName(node);
      valueNode = node.value;
    } else if (
      node.type === 'AssignmentExpression' &&
      node.left.type === 'MemberExpression' &&
      !node.left.computed &&
      node.left.property.type === 'Identifier'
    ) {
      name = node.left.property.name;
      valueNode = node.right;
    } else if (node.type === 'ClassProperty' && node.key.type === 'Identifier') {
      name = node.key.name;
      valueNode = node.value;
    }

    if (name === undefined || valueNode == null || !isSensitiveName(name)) {
      return;
    }

    const value = staticString(valueNode);
    if (value === undefined || value === '') {
      // A non-literal initialiser is the *correct* pattern: environment
      // variables, keychain reads, values fetched at runtime.
      return;
    }

    if (hasBenignShape(value) || !looksHighEntropy(value, 12)) {
      return;
    }

    const location = nodeLocation(node);
    if (location.line !== undefined && reportedLines.has(location.line)) {
      // Already reported by a provider pattern, at higher confidence.
      return;
    }

    const key = `${name}:${location.line ?? 0}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);

    const kind = sensitiveKindOf(name);
    findings.push(
      buildFinding({
        ruleId: 'RNSEC-SECRET-001',
        title: `Hardcoded value assigned to "${name}"`,
        description:
          `"${name}" is assigned a literal string that looks like ${kind === undefined ? 'credential material' : describeSensitiveKind(kind)}. ` +
          'Values supplied at build time are shipped inside the application binary.',
        severity: 'high',
        // The name is a strong hint and the shape corroborates it, but neither
        // proves the value is live rather than a sample.
        confidence: 'medium',
        categories: ['secrets'],
        path: context.file.path,
        ...location,
        evidence: [
          evidence('sensitive-name', `The binding "${name}" names sensitive data`, location),
          evidence(
            'value-shape',
            'The assigned literal is high-entropy and not a recognisable benign format',
            {
              snippet: maskSecret(value),
              ...location,
            }
          ),
        ],
        impact: IMPACT,
        exploitability: EXPLOITABILITY,
        remediation: REMEDIATION,
        ...(snippetOf(context.lines, location.line) === undefined
          ? {}
          : { codeSnippet: snippetOf(context.lines, location.line) }),
        ...(enclosingContext(ancestors) === undefined
          ? {}
          : { structuralContext: enclosingContext(ancestors) }),
        knowledge: KNOWLEDGE,
      })
    );
  });

  return findings;
}
