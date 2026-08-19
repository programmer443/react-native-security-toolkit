import { calleeName, enclosingContext, staticString, walk } from '../../analysis/ast.js';
import { buildFinding, evidence, nodeLocation, snippetOf } from '../../analysis/findings.js';
import type * as t from '@babel/types';

import type { RawFinding } from '../../types/finding.js';
import type { RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-RN-001 — code built from data at runtime.
 *
 * `eval`, `new Function`, and the string forms of `setTimeout`/`setInterval` all
 * turn a value into executable code. In a React Native application the value is
 * frequently something the application received — a deep link parameter, a
 * response body, a WebView message — and the code runs with the application's
 * full JavaScript privileges.
 *
 * There is also a distinctly mobile version of this: fetching a JavaScript
 * bundle at runtime and executing it. That bypasses store review and turns any
 * compromise of the hosting server, or of the connection to it, into code
 * execution inside the application.
 */

const KNOWLEDGE = {
  cwe: ['CWE-95', 'CWE-94'],
  masvs: ['MASVS-CODE-4'],
  maswe: ['MASWE-0049'],
  mappingConfidence: 'high',
} as const;

const IMPACT =
  "Executed code runs with the application's privileges: it can read the session, the local " +
  'database and anything the native bridge exposes.';

const REMEDIATION =
  'Replace the dynamic construction with ordinary code. Parse data with `JSON.parse`, dispatch ' +
  'behaviour through a lookup table keyed by a validated value, and pass functions rather than ' +
  'strings to timers. Never execute JavaScript fetched at runtime.';

export const dynamicCodeExecutionRule: SecurityRule = {
  id: 'RNSEC-RN-001',
  name: 'Dynamic code execution',
  description: 'Code is constructed from a value at runtime and executed.',
  severity: 'high',
  categories: ['react-native', 'serialization'],
  languages: ['javascript', 'jsx', 'typescript', 'tsx'],
  fileKinds: [],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    const findings: RawFinding[] = [];

    walk(context.parsed, ({ node, ancestors }) => {
      const issue = classify(node);
      if (issue === undefined) {
        return;
      }

      const location = nodeLocation(node);
      const snippet = snippetOf(context.lines, location.line);
      const structural = enclosingContext(ancestors);

      findings.push(
        buildFinding({
          ruleId: 'RNSEC-RN-001',
          title: issue.title,
          description: issue.detail,
          severity: issue.severity,
          confidence: issue.confidence,
          categories: ['react-native', 'serialization'],
          path: context.file.path,
          ...location,
          evidence: [
            evidence('dynamic-execution', issue.title, {
              ...location,
              ...(snippet === undefined ? {} : { snippet }),
            }),
          ],
          impact: IMPACT,
          exploitability:
            'Requires influence over the value being executed — a deep link parameter, a server ' +
            'response, or a message from a WebView. In an application that already accepts any of ' +
            'those, that is not a high bar.',
          remediation: REMEDIATION,
          ...(snippet === undefined ? {} : { codeSnippet: snippet }),
          ...(structural === undefined ? {} : { structuralContext: structural }),
          knowledge: KNOWLEDGE,
        })
      );
    });

    return findings;
  },
};

interface DynamicIssue {
  readonly title: string;
  readonly detail: string;
  readonly severity: RawFinding['severity'];
  readonly confidence: RawFinding['confidence'];
}

function classify(node: t.Node): DynamicIssue | undefined {
  if (node.type === 'CallExpression') {
    const callee = calleeName(node);

    if (callee === 'eval' || callee === 'global.eval' || callee === 'globalThis.eval') {
      return {
        title: 'eval executes a value as code',
        detail: "Whatever string reaches `eval` is executed with the application's privileges.",
        severity: 'critical',
        confidence: 'very-high',
      };
    }

    if (callee === 'Function') {
      return {
        title: 'Function constructor builds code from a string',
        detail: '`Function(...)` compiles its argument, which is `eval` with a different spelling.',
        severity: 'critical',
        confidence: 'very-high',
      };
    }

    if (callee === 'setTimeout' || callee === 'setInterval') {
      const first = node.arguments[0] as t.Node | undefined;
      if (
        first !== undefined &&
        (first.type === 'StringLiteral' ||
          (first.type === 'TemplateLiteral' && staticString(first) === undefined))
      ) {
        return {
          title: `${callee} is given code as a string`,
          detail: `A string passed to ${callee} is compiled and executed, exactly as \`eval\` would.`,
          severity: 'high',
          confidence: 'high',
        };
      }
    }
  }

  if (node.type === 'NewExpression' && calleeName(node) === 'Function') {
    return {
      title: 'Function constructor builds code from a string',
      detail:
        '`new Function(...)` compiles its argument, which is `eval` with a different spelling.',
      severity: 'critical',
      confidence: 'very-high',
    };
  }

  return undefined;
}
