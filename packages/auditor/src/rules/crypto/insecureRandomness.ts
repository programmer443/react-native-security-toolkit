import { calleeName, enclosingContext, walk } from '../../analysis/ast.js';
import { buildFinding, evidence, nodeLocation, snippetOf } from '../../analysis/findings.js';
import { splitWords } from '../../analysis/sensitivity.js';
import type { RawFinding } from '../../types/finding.js';
import type { RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-CRYPTO-002 — a non-cryptographic random source used for a security value.
 *
 * `Math.random()` is not a defect. It is the right tool for a shuffle, an
 * animation jitter or a cache-busting suffix, and a rule that flags every call
 * is one people disable — taking the real findings with it.
 *
 * What makes it a defect is *what the value becomes*: a token, a nonce, an IV,
 * a salt, a password-reset code, a session identifier. `Math.random()` is
 * seeded from and predictable within a JavaScript engine; an attacker who
 * observes a few outputs can predict the rest.
 *
 * So the rule fires only when the surrounding name — the variable being
 * assigned, or the function being defined — says the value is security-relevant.
 */

/** Words that make a random value security-relevant. */
const SECURITY_WORDS: readonly string[] = [
  'token',
  'nonce',
  'iv',
  'salt',
  'key',
  'secret',
  'password',
  'passcode',
  'otp',
  'pin',
  'session',
  'csrf',
  'challenge',
  'verifier',
  'uuid',
  'guid',
  'id',
  'identifier',
  'code',
  'seed',
];

/** Words that make it clear the value is *not* security-relevant. */
const BENIGN_WORDS: readonly string[] = [
  'jitter',
  'delay',
  'animation',
  'shuffle',
  'sample',
  'colour',
  'color',
  'placeholder',
  'mock',
  'demo',
  'cachebust',
  'index',
];

const KNOWLEDGE = {
  cwe: ['CWE-338', 'CWE-330'],
  masvs: ['MASVS-CRYPTO-1'],
  maswe: ['MASWE-0012'],
  mappingConfidence: 'high',
} as const;

const IMPACT =
  'A value an attacker can predict is a value an attacker can produce. For a token or a one-time ' +
  'code that means impersonation; for an IV or a nonce it can break the confidentiality of the ' +
  'ciphertext it protects.';

const EXPLOITABILITY =
  'Predicting a JavaScript engine PRNG from a handful of observed outputs is published work with ' +
  'public implementations. No privileged access is needed — the attacker only needs to see some ' +
  'values the application generated.';

const REMEDIATION =
  'Use a cryptographically secure source: `crypto.getRandomValues` where available, ' +
  '`SecureRandom` on Android, `SecRandomCopyBytes` on iOS, or a vetted React Native module that ' +
  'wraps them. Never seed a security value from a timestamp.';

/** JavaScript random sources that are not cryptographically secure. */
const JS_SOURCES: readonly string[] = ['Math.random', 'Date.now'];

/** Native sources, matched textually. */
const NATIVE_SOURCES: readonly { pattern: RegExp; label: string }[] = [
  { pattern: /\bnew\s+(?:java\.util\.)?Random\s*\(/, label: 'java.util.Random' },
  { pattern: /\bRandom\(\)\.next/, label: 'kotlin.random.Random' },
  { pattern: /\bMath\.random\s*\(/, label: 'Math.random' },
  { pattern: /\barc4random_uniform\s*\(/, label: 'arc4random_uniform' },
];

export const insecureRandomnessRule: SecurityRule = {
  id: 'RNSEC-CRYPTO-002',
  name: 'Predictable randomness used for a security value',
  description:
    'A non-cryptographic random source produces a value whose name indicates it is used as a ' +
    'token, key, nonce, salt or similar.',
  severity: 'high',
  categories: ['cryptography'],
  languages: [],
  fileKinds: [],
  // A code example in prose is not a defect.
  excludeFileKinds: ['documentation'],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    return [...detectJavaScript(context), ...detectNative(context)];
  },
};

function isSecurityRelevant(name: string | undefined): boolean {
  if (name === undefined) {
    return false;
  }
  const words = splitWords(name);
  if (words.some((word) => BENIGN_WORDS.includes(word))) {
    return false;
  }
  return words.some((word) => SECURITY_WORDS.includes(word));
}

function detectJavaScript(context: RuleContext): RawFinding[] {
  const findings: RawFinding[] = [];

  walk(context.parsed, ({ node, ancestors }) => {
    if (node.type !== 'CallExpression') {
      return;
    }
    const callee = calleeName(node);
    if (callee === undefined || !JS_SOURCES.includes(callee)) {
      return;
    }

    const structural = enclosingContext(ancestors);
    if (!isSecurityRelevant(structural)) {
      // A random number that does not become a security value is fine, and
      // saying otherwise is how a rule gets switched off.
      return;
    }

    const location = nodeLocation(node);
    const snippet = snippetOf(context.lines, location.line);

    findings.push(
      buildFinding({
        ruleId: 'RNSEC-CRYPTO-002',
        title: `${callee} used to produce "${structural}"`,
        description:
          `${callee} is not a cryptographically secure source, and "${structural}" names a value ` +
          'that must be unpredictable.',
        severity: 'high',
        confidence: 'high',
        categories: ['cryptography'],
        path: context.file.path,
        ...location,
        evidence: [
          evidence('insecure-random-source', `${callee} is not cryptographically secure`, {
            ...location,
            ...(snippet === undefined ? {} : { snippet }),
          }),
          evidence('security-relevant-name', `The result is used for "${structural}"`, location),
        ],
        impact: IMPACT,
        exploitability: EXPLOITABILITY,
        remediation: REMEDIATION,
        ...(snippet === undefined ? {} : { codeSnippet: snippet }),
        structuralContext: structural,
        knowledge: KNOWLEDGE,
      })
    );
  });

  return findings;
}

function detectNative(context: RuleContext): RawFinding[] {
  const language = context.file.language;
  if (language !== 'kotlin' && language !== 'java') {
    return [];
  }

  const findings: RawFinding[] = [];

  context.lines.forEach((text, index) => {
    const source = NATIVE_SOURCES.find((candidate) => candidate.pattern.test(text));
    if (source === undefined) {
      return;
    }

    // The same requirement as the parsed case: the line has to say what the
    // value is for.
    const names = text.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
    const relevant = names.find((name) => isSecurityRelevant(name));
    if (relevant === undefined) {
      return;
    }

    const line = index + 1;
    findings.push(
      buildFinding({
        ruleId: 'RNSEC-CRYPTO-002',
        title: `${source.label} used to produce "${relevant}"`,
        description:
          `${source.label} is not a cryptographically secure source, and "${relevant}" names a ` +
          'value that must be unpredictable.',
        severity: 'high',
        confidence: 'medium',
        categories: ['cryptography'],
        path: context.file.path,
        line,
        evidence: [
          evidence('insecure-random-source', `${source.label} is not cryptographically secure`, {
            line,
            snippet: text.trim().slice(0, 200),
          }),
          evidence('security-relevant-name', `The result is used for "${relevant}"`, { line }),
        ],
        impact: IMPACT,
        exploitability: EXPLOITABILITY,
        remediation: REMEDIATION,
        structuralContext: relevant,
        knowledge: KNOWLEDGE,
      })
    );
  });

  return findings;
}
