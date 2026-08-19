import { deduplicateFindings } from '../dedupe.js';
import type { SecurityFinding } from '../../types/finding.js';

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: 'RNSEC-SECRET-001-abc',
    ruleId: 'RNSEC-SECRET-001',
    title: 'Hardcoded credential',
    description: 'A credential is embedded in source.',
    severity: 'high',
    confidence: 'medium',
    categories: ['secrets'],
    location: { path: 'src/api/client.ts', line: 4 },
    evidence: [{ kind: 'matched-pattern', description: 'AWS access key id' }],
    impact: 'The credential ships with the application.',
    exploitability: 'Extractable from the bundle.',
    remediation: 'Move it to a server.',
    sources: ['deterministic'],
    fingerprint: 'same-fingerprint',
    ...overrides,
  };
}

describe('deduplication', () => {
  it('collapses findings that share a fingerprint', () => {
    const merged = deduplicateFindings([finding(), finding()]);

    expect(merged).toHaveLength(1);
  });

  it('keeps the strongest claim and the union of the evidence', () => {
    const merged = deduplicateFindings([
      finding(),
      finding({
        severity: 'critical',
        confidence: 'very-high',
        sources: ['ast'],
        evidence: [{ kind: 'ast-node', description: 'string literal assigned to apiKey' }],
      }),
    ]);

    expect(merged[0]?.severity).toBe('critical');
    expect(merged[0]?.confidence).toBe('very-high');
    expect(merged[0]?.evidence).toHaveLength(2);
  });

  it('marks a finding established by more than one kind of analysis as hybrid', () => {
    const merged = deduplicateFindings([finding(), finding({ sources: ['ast'] })]);

    expect(merged[0]?.sources).toEqual(expect.arrayContaining(['deterministic', 'ast', 'hybrid']));
  });

  it('keeps a location with a line number over one without', () => {
    const merged = deduplicateFindings([
      finding({ location: { path: 'src/api/client.ts' } }),
      finding({ location: { path: 'src/api/client.ts', line: 4 } }),
    ]);

    expect(merged[0]?.location.line).toBe(4);
  });

  it('does not merge different problems that happen to look alike', () => {
    const merged = deduplicateFindings([finding(), finding({ fingerprint: 'other-fingerprint' })]);

    expect(merged).toHaveLength(2);
  });

  it('never downgrades a confident standard mapping to an uncertain one', () => {
    const merged = deduplicateFindings([
      finding({ cwe: [{ id: 'CWE-798', mappingConfidence: 'high' }] }),
      finding({ cwe: [{ id: 'CWE-798', mappingConfidence: 'low' }] }),
    ]);

    expect(merged[0]?.cwe).toEqual([{ id: 'CWE-798', mappingConfidence: 'high' }]);
  });
});
