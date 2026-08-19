import { maxSeverity } from './severity.js';
import type {
  Confidence,
  FindingSource,
  SecurityEvidence,
  SecurityFinding,
  StandardReference,
} from '../types/finding.js';

/**
 * Merges findings that describe the same problem.
 *
 * The same weakness is routinely found more than once: a hardcoded key is a
 * pattern match *and* a string literal in the AST, and later a dependency
 * scanner or an AI pass may reach it too (§82). Reporting it three times trains
 * developers to skim, which costs more than the duplicates do.
 *
 * Merging keeps the **strongest** claim and the **union** of the evidence: the
 * highest severity, the highest confidence, every distinct piece of evidence,
 * and every source that contributed. Nothing is discarded except repetition.
 */

const CONFIDENCE_ORDER: readonly Confidence[] = ['very-low', 'low', 'medium', 'high', 'very-high'];

function maxConfidence(left: Confidence, right: Confidence): Confidence {
  return CONFIDENCE_ORDER.indexOf(left) >= CONFIDENCE_ORDER.indexOf(right) ? left : right;
}

function evidenceKey(evidence: SecurityEvidence): string {
  return [evidence.kind, evidence.description, evidence.snippet ?? '', evidence.line ?? ''].join(
    '|'
  );
}

function mergeEvidence(
  left: readonly SecurityEvidence[],
  right: readonly SecurityEvidence[]
): readonly SecurityEvidence[] {
  const merged = new Map<string, SecurityEvidence>();
  for (const evidence of [...left, ...right]) {
    merged.set(evidenceKey(evidence), evidence);
  }
  return [...merged.values()];
}

function mergeReferences(
  left: readonly StandardReference[] | undefined,
  right: readonly StandardReference[] | undefined
): readonly StandardReference[] | undefined {
  if (left === undefined && right === undefined) {
    return undefined;
  }
  const merged = new Map<string, StandardReference>();
  for (const reference of [...(left ?? []), ...(right ?? [])]) {
    const existing = merged.get(reference.id);
    // The more confident mapping wins; a `low` mapping never overwrites a `high` one.
    if (existing === undefined || existing.mappingConfidence === 'low') {
      merged.set(reference.id, reference);
    }
  }
  return [...merged.values()];
}

function mergeSources(
  left: readonly FindingSource[],
  right: readonly FindingSource[]
): readonly FindingSource[] {
  const merged = new Set<FindingSource>([...left, ...right]);
  // A finding established by more than one kind of analysis is a hybrid, and
  // saying so is more useful than listing the parts.
  return merged.size > 1 && !merged.has('hybrid') ? [...merged, 'hybrid'] : [...merged];
}

function merge(existing: SecurityFinding, incoming: SecurityFinding): SecurityFinding {
  const cwe = mergeReferences(existing.cwe, incoming.cwe);
  const masvs = mergeReferences(existing.masvs, incoming.masvs);
  const maswe = mergeReferences(existing.maswe, incoming.maswe);
  const mastg = mergeReferences(existing.mastg, incoming.mastg);

  return {
    ...existing,
    severity: maxSeverity(existing.severity, incoming.severity),
    confidence: maxConfidence(existing.confidence, incoming.confidence),
    evidence: mergeEvidence(existing.evidence, incoming.evidence),
    sources: mergeSources(existing.sources, incoming.sources),
    // A located finding is more useful than an unlocated one, so a line number
    // from either copy is kept.
    location: existing.location.line === undefined ? incoming.location : existing.location,
    ...(cwe === undefined ? {} : { cwe }),
    ...(masvs === undefined ? {} : { masvs }),
    ...(maswe === undefined ? {} : { maswe }),
    ...(mastg === undefined ? {} : { mastg }),
  };
}

/** Collapses findings that share a fingerprint. Input order is preserved. */
export function deduplicateFindings(
  findings: readonly SecurityFinding[]
): readonly SecurityFinding[] {
  const byFingerprint = new Map<string, SecurityFinding>();

  for (const finding of findings) {
    const existing = byFingerprint.get(finding.fingerprint);
    byFingerprint.set(
      finding.fingerprint,
      existing === undefined ? finding : merge(existing, finding)
    );
  }

  return [...byFingerprint.values()];
}
