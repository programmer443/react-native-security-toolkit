import { columnOf, lineOf } from './ast.js';
import type * as t from '@babel/types';

import type { Category, RawFinding, SecurityEvidence, Severity } from '../types/finding.js';
import type { KnowledgeRefs } from '../types/rule.js';

/**
 * Helpers for building findings.
 *
 * Every rule has to answer the same ten questions (§40) — what, where, why it
 * matters, how sure, what impact, how exploitable, which standards, how to fix,
 * how to verify. Centralising the construction is what stops the tenth rule from
 * quietly answering fewer of them than the first.
 */

export interface FindingInput {
  readonly ruleId: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly confidence: RawFinding['confidence'];
  readonly categories: readonly Category[];
  readonly path: string;
  // The optional fields accept an explicit `undefined` so that a rule can pass a
  // value it computed without first checking it. `buildFinding` drops undefined
  // fields rather than writing them, which is what the strict finding model
  // needs.
  readonly line?: number | undefined;
  readonly column?: number | undefined;
  readonly evidence: readonly SecurityEvidence[];
  readonly impact: string;
  readonly exploitability: string;
  readonly remediation: string;
  readonly secureExample?: string | undefined;
  readonly structuralContext?: string | undefined;
  readonly knowledge?: KnowledgeRefs | undefined;
  readonly codeSnippet?: string | undefined;
}

export function buildFinding(input: FindingInput): RawFinding {
  return {
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    confidence: input.confidence,
    categories: input.categories,
    location: {
      path: input.path,
      ...(input.line === undefined ? {} : { line: input.line }),
      ...(input.column === undefined ? {} : { column: input.column }),
    },
    evidence: input.evidence,
    impact: input.impact,
    exploitability: input.exploitability,
    remediation: input.remediation,
    ...(input.secureExample === undefined ? {} : { secureExample: input.secureExample }),
    ...(input.structuralContext === undefined
      ? {}
      : { structuralContext: input.structuralContext }),
    ...(input.knowledge === undefined ? {} : { knowledge: input.knowledge }),
    ...(input.codeSnippet === undefined ? {} : { codeSnippet: input.codeSnippet }),
  };
}

/** Location fields for an AST node, omitting what the parser did not record. */
export function nodeLocation(node: t.Node): { line?: number; column?: number } {
  const line = lineOf(node);
  const column = columnOf(node);
  return {
    ...(line === undefined ? {} : { line }),
    ...(column === undefined ? {} : { column }),
  };
}

/** Maximum characters of source quoted in a finding. */
const SNIPPET_LIMIT = 200;

/**
 * A single line of source, trimmed and truncated.
 *
 * Rules that quote source must go through here: an unbounded snippet turns a
 * minified line into a report nobody can read, and a report is often the only
 * artefact a reviewer sees.
 */
export function snippetOf(lines: readonly string[], line: number | undefined): string | undefined {
  if (line === undefined) {
    return undefined;
  }
  const text = lines[line - 1];
  if (text === undefined) {
    return undefined;
  }
  const trimmed = text.trim();
  return trimmed.length > SNIPPET_LIMIT ? `${trimmed.slice(0, SNIPPET_LIMIT)}…` : trimmed;
}

/** Builds one evidence entry, omitting absent fields. */
export function evidence(
  kind: string,
  description: string,
  options: { snippet?: string; line?: number; column?: number } = {}
): SecurityEvidence {
  return {
    kind,
    description,
    ...(options.snippet === undefined ? {} : { snippet: options.snippet }),
    ...(options.line === undefined ? {} : { line: options.line }),
    ...(options.column === undefined ? {} : { column: options.column }),
  };
}
