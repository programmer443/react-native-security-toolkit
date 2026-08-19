import {
  calleeName,
  enclosingContext,
  memberName,
  staticString,
  walk,
} from '../../analysis/ast.js';
import { buildFinding, evidence, nodeLocation, snippetOf } from '../../analysis/findings.js';
import { describeSensitiveKind, sensitiveKindOf } from '../../analysis/sensitivity.js';
import type * as t from '@babel/types';

import type { RawFinding } from '../../types/finding.js';
import type { RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-LOG-001 — sensitive data written to a log.
 *
 * §34 is explicit: *do not flag every logging statement*. Logging is how people
 * debug, and a rule that objects to `console.log('mounted')` is noise. What
 * matters is the **argument**: a token, a password, an authorization header or a
 * document number reaching a log sink.
 *
 * Device logs are not private. On Android any app held `READ_LOGS` historically,
 * crash reporters and analytics SDKs commonly forward them off-device, and iOS
 * unified logging persists to the system log. A token in a log line is a token
 * in a place the application no longer controls.
 */

/** JavaScript log sinks. */
const JS_SINKS: readonly string[] = [
  'console.log',
  'console.info',
  'console.warn',
  'console.error',
  'console.debug',
  'console.trace',
  'console.table',
  'console.dir',
];

/** Native log sinks, matched textually because those languages are not parsed. */
const NATIVE_SINKS: readonly { pattern: RegExp; label: string }[] = [
  { pattern: /\bLog\.[vdiwe]\s*\(/, label: 'android.util.Log' },
  { pattern: /\bLogger\.[a-z]+\s*\(/, label: 'Logger' },
  { pattern: /\bSystem\.out\.print(?:ln)?\s*\(/, label: 'System.out' },
  { pattern: /\bprintln\s*\(/, label: 'println' },
  { pattern: /\bNSLog\s*\(/, label: 'NSLog' },
  { pattern: /\bos_log[a-z_]*\s*\(/, label: 'os_log' },
  { pattern: /(?:^|[^.\w])print\s*\(/, label: 'print' },
];

const KNOWLEDGE = {
  cwe: ['CWE-532', 'CWE-359'],
  masvs: ['MASVS-STORAGE-2'],
  maswe: ['MASWE-0005'],
  mappingConfidence: 'high',
} as const;

const IMPACT =
  'Log output leaves the application boundary: it is readable over a debug bridge, is commonly ' +
  'collected by crash reporters and analytics SDKs, and persists in system logs. Anything logged ' +
  'should be assumed to reach systems the application does not control.';

const EXPLOITABILITY =
  'Requires access to device logs — a connected debugger, a diagnostics export, or whichever ' +
  'third-party SDK is already forwarding them.';

const REMEDIATION =
  'Log an identifier or a redacted form instead of the value. Where a value is genuinely needed ' +
  'while debugging, gate the statement behind a development-only flag and strip it from release ' +
  'builds — on Android, a ProGuard rule that removes log calls; on iOS, a wrapper that compiles ' +
  'away outside DEBUG.';

export const sensitiveLoggingRule: SecurityRule = {
  id: 'RNSEC-LOG-001',
  name: 'Sensitive data written to a log',
  description:
    'A value whose name indicates a credential, token or personal data is passed to a logging ' +
    'function.',
  severity: 'medium',
  categories: ['logging', 'privacy'],
  languages: [],
  fileKinds: [],
  // A code example in prose is not a defect.
  excludeFileKinds: ['documentation'],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    return [...detectJavaScript(context), ...detectNative(context)];
  },
};

function detectJavaScript(context: RuleContext): RawFinding[] {
  const findings: RawFinding[] = [];

  walk(context.parsed, ({ node, ancestors }) => {
    if (node.type !== 'CallExpression') {
      return;
    }
    const callee = calleeName(node);
    if (callee === undefined || !JS_SINKS.includes(callee)) {
      return;
    }

    for (const argument of node.arguments) {
      const match = sensitiveArgument(argument as t.Node);
      if (match === undefined) {
        continue;
      }

      const location = nodeLocation(node);
      const snippet = snippetOf(context.lines, location.line);
      const structural = enclosingContext(ancestors);

      findings.push(
        buildFinding({
          ruleId: 'RNSEC-LOG-001',
          title: `${match.name} is written to the log`,
          description:
            `"${match.name}" names ${describeSensitiveKind(match.kind)} and is passed to ${callee}. ` +
            'Log output is readable outside the application.',
          severity: 'medium',
          confidence: match.confidence,
          categories: ['logging', 'privacy'],
          path: context.file.path,
          ...location,
          evidence: [
            evidence('log-sink', `Passed to ${callee}`, {
              ...location,
              ...(snippet === undefined ? {} : { snippet }),
            }),
            evidence(
              'sensitive-name',
              `"${match.name}" names ${describeSensitiveKind(match.kind)}`,
              location
            ),
          ],
          impact: IMPACT,
          exploitability: EXPLOITABILITY,
          remediation: REMEDIATION,
          ...(snippet === undefined ? {} : { codeSnippet: snippet }),
          ...(structural === undefined ? {} : { structuralContext: structural }),
          knowledge: KNOWLEDGE,
        })
      );
      // One finding per call: the second sensitive argument to the same
      // statement is the same problem.
      break;
    }
  });

  return findings;
}

interface SensitiveMatch {
  readonly name: string;
  readonly kind: ReturnType<typeof sensitiveKindOf> & string;
  readonly confidence: RawFinding['confidence'];
}

/**
 * Whether a logged argument names something sensitive.
 *
 * Identifiers and member expressions are read by name. A template literal is
 * read through its interpolations, which is how `` `token=${accessToken}` ``
 * gets caught. A plain string literal is never a finding on its own — it is a
 * message, not data.
 */
function sensitiveArgument(node: t.Node): SensitiveMatch | undefined {
  if (node.type === 'Identifier') {
    const kind = sensitiveKindOf(node.name);
    return kind === undefined ? undefined : { name: node.name, kind, confidence: 'high' };
  }

  if (node.type === 'MemberExpression') {
    const name = memberName(node);
    if (name === undefined) {
      return undefined;
    }
    const property = node.property.type === 'Identifier' ? node.property.name : name;
    const kind = sensitiveKindOf(property) ?? sensitiveKindOf(name);
    return kind === undefined ? undefined : { name, kind, confidence: 'high' };
  }

  if (node.type === 'TemplateLiteral') {
    for (const expression of node.expressions) {
      const nested = sensitiveArgument(expression as t.Node);
      if (nested !== undefined) {
        return { ...nested, confidence: 'high' };
      }
    }
    // A template with no interpolation is just a message.
    return undefined;
  }

  if (node.type === 'ObjectExpression') {
    for (const property of node.properties) {
      if (property.type !== 'ObjectProperty' || property.computed) {
        continue;
      }
      const key =
        property.key.type === 'Identifier' ? property.key.name : staticString(property.key);
      if (key === undefined) {
        continue;
      }
      const kind = sensitiveKindOf(key);
      if (kind !== undefined) {
        // Logging `{ token }` is logging the token.
        return { name: key, kind, confidence: 'high' };
      }
    }
    return undefined;
  }

  if (node.type === 'CallExpression') {
    // `JSON.stringify(user)` hides nothing: inspect what is being serialised.
    const callee = calleeName(node);
    if (callee === 'JSON.stringify') {
      for (const argument of node.arguments) {
        const nested = sensitiveArgument(argument as t.Node);
        if (nested !== undefined) {
          return { ...nested, confidence: 'medium' };
        }
      }
    }
    return undefined;
  }

  return undefined;
}

/**
 * Everything on a line except the contents of string literals, plus whatever
 * those literals interpolate.
 *
 * Kotlin's `"$token"` and Swift's `\(token)` are values, not prose, so their
 * interpolations are kept while the surrounding message text is dropped.
 */
function valueExpressions(text: string): string {
  const interpolations: string[] = [];
  const withoutStrings = text.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, (literal) => {
    const inner = /\$\{([^}]*)\}|\$([A-Za-z_][A-Za-z0-9_.]*)|\\\(([^)]*)\)/g;
    let match: RegExpExecArray | null;
    while ((match = inner.exec(literal)) !== null) {
      interpolations.push(match[1] ?? match[2] ?? match[3] ?? '');
    }
    return ' ';
  });
  return `${withoutStrings} ${interpolations.join(' ')}`;
}

/**
 * Native log sinks, matched line by line.
 *
 * Kotlin, Java, Swift and Objective-C have no parser here yet, so this is a
 * textual match constrained by the same requirement as the parsed case: the line
 * must also mention something sensitive. Confidence is a notch lower to reflect
 * the weaker analysis, which is exactly what the confidence field is for.
 */
function detectNative(context: RuleContext): RawFinding[] {
  const language = context.file.language;
  const isNative =
    language === 'kotlin' ||
    language === 'java' ||
    language === 'swift' ||
    language === 'objective-c' ||
    language === 'objective-cpp';
  if (!isNative) {
    return [];
  }

  const findings: RawFinding[] = [];

  context.lines.forEach((text, index) => {
    const sink = NATIVE_SINKS.find((candidate) => candidate.pattern.test(text));
    if (sink === undefined) {
      return;
    }

    // Only the arguments matter, and only the ones that are *values*. A message
    // that merely mentions a sensitive word — `Log.d(TAG, "session started")` —
    // is ordinary logging, and reporting it is how a rule loses its audience.
    const argumentText = valueExpressions(text.slice(text.indexOf('(') + 1));
    const identifier = /[A-Za-z_][A-Za-z0-9_.]*/g;
    let match: RegExpExecArray | null;

    while ((match = identifier.exec(argumentText)) !== null) {
      const candidate = match[0];
      const kind = sensitiveKindOf(candidate.split('.').pop() ?? candidate);
      if (kind === undefined) {
        continue;
      }

      const line = index + 1;
      findings.push(
        buildFinding({
          ruleId: 'RNSEC-LOG-001',
          title: `${candidate} is written to the log`,
          description:
            `"${candidate}" names ${describeSensitiveKind(kind)} and appears in a ${sink.label} call. ` +
            'Log output is readable outside the application.',
          severity: 'medium',
          confidence: 'medium',
          categories: ['logging', 'privacy'],
          path: context.file.path,
          line,
          evidence: [
            evidence('log-sink', `Passed to ${sink.label}`, {
              line,
              snippet: text.trim().slice(0, 200),
            }),
            evidence('sensitive-name', `"${candidate}" names ${describeSensitiveKind(kind)}`, {
              line,
            }),
          ],
          impact: IMPACT,
          exploitability: EXPLOITABILITY,
          remediation: REMEDIATION,
          structuralContext: sink.label,
          knowledge: KNOWLEDGE,
        })
      );
      break;
    }
  });

  return findings;
}
