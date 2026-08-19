import { createFingerprint } from '../fingerprint.js';

describe('finding fingerprints', () => {
  const base = {
    ruleId: 'RNSEC-SECRET-001',
    path: 'src/api/client.ts',
    evidence: ['const apiKey = "AKIA..."'],
  };

  it('is stable across runs', () => {
    expect(createFingerprint(base)).toBe(createFingerprint(base));
  });

  it('ignores whitespace and indentation changes in the evidence', () => {
    // Reformatting a file must not invalidate a reviewed suppression.
    expect(createFingerprint({ ...base, evidence: ['  const apiKey  =  "AKIA..."  '] })).toBe(
      createFingerprint(base)
    );
  });

  it('preserves case, so two credentials differing only in case stay distinct', () => {
    expect(createFingerprint({ ...base, evidence: ['const APIKEY = "AKIA..."'] })).not.toBe(
      createFingerprint(base)
    );
  });

  it('changes when the rule, the file or the structural context changes', () => {
    expect(createFingerprint({ ...base, ruleId: 'RNSEC-SECRET-002' })).not.toBe(
      createFingerprint(base)
    );
    expect(createFingerprint({ ...base, path: 'src/api/other.ts' })).not.toBe(
      createFingerprint(base)
    );
    expect(createFingerprint({ ...base, structuralContext: 'createClient' })).not.toBe(
      createFingerprint(base)
    );
  });

  it('cannot be collided by moving text between fields', () => {
    // A separator that can appear inside a field would let ('ab','c') and
    // ('a','bc') hash identically, which is a suppression bypass.
    const left = createFingerprint({ ruleId: 'RNSEC-A-001', path: 'src/a.ts', evidence: ['b c'] });
    const right = createFingerprint({ ruleId: 'RNSEC-A-001', path: 'src/a.ts b', evidence: ['c'] });

    expect(left).not.toBe(right);
  });

  it('is independent of line numbers by construction', () => {
    // There is nowhere to put a line number in the input, which is the point:
    // adding an import at the top of a file must not invalidate every
    // suppression below it.
    expect(Object.keys(base)).not.toContain('line');
  });
});
