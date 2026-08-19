import { KnowledgeIndex, knowledge } from '../index.js';
import { RuleRegistry, RuleRegistryError, builtinRules } from '../../engine/ruleRegistry.js';
import type { SecurityRule } from '../../types/rule.js';

function rule(overrides: Partial<SecurityRule> = {}): SecurityRule {
  return {
    id: 'RNSEC-SECRET-001',
    name: 'Test rule',
    description: 'For testing knowledge validation.',
    severity: 'high',
    categories: ['secrets'],
    languages: [],
    fileKinds: [],
    knowledge: {},
    detect: () => [],
    ...overrides,
  };
}

describe('knowledge snapshot', () => {
  it('carries all four standards', () => {
    const counts = knowledge.counts;

    expect(counts.masvs).toBeGreaterThan(0);
    expect(counts.maswe).toBeGreaterThan(0);
    expect(counts.mastg).toBeGreaterThan(0);
    expect(counts.cwe).toBeGreaterThan(0);
    expect(knowledge.version).toMatch(/^\d{4}\.\d+$/);
  });

  it('resolves identifiers to their official titles', () => {
    // The title comes from the standard, not from a rule author's paraphrase, so
    // a report cannot quietly disagree with what it cites.
    expect(knowledge.cwe('CWE-798')?.name).toBe('Use of Hard-coded Credentials');
    expect(knowledge.masvs('MASVS-STORAGE-1')?.title).toContain('sensitive data');
    expect(knowledge.maswe('MASWE-0004')?.title).toBe(
      'Sensitive Data Hardcoded in the App Package'
    );
  });

  it('keeps the upstream mappings a weakness declares', () => {
    const weakness = knowledge.maswe('MASWE-0026');

    expect(weakness?.masvs).toContain('MASVS-NETWORK-1');
    expect(weakness?.cwe).toContain('CWE-319');
  });

  it('links a weakness to the MASTG tests that verify it', () => {
    // This is what lets a report answer "how do I verify the fix?" with a real
    // test identifier rather than a paragraph of advice.
    const tests = knowledge.mastgTestsFor('MASWE-0001');

    expect(tests.length).toBeGreaterThan(0);
    expect(tests.every((test) => /^MASTG-TEST-\d{4}$/.test(test.id))).toBe(true);
  });

  it('returns no tests for a weakness upstream has not written tests for', () => {
    // Not every weakness has coverage in MASTG, and inventing a test identifier
    // to fill the gap is exactly what §32 forbids.
    expect(knowledge.mastgTestsFor('MASWE-0004')).toEqual([]);
  });

  it('contains no identifier that does not match its standard pattern', () => {
    // A malformed identifier is the shape a parsing bug in the sync script would
    // take, and it must never reach a published snapshot.
    const index = knowledge;
    expect(index.cwe('CWE-798')).toBeDefined();

    for (const id of ['CWE-0', 'MASVS-NOPE-1', 'MASWE-9999', 'MASTG-TEST-9999']) {
      expect(
        index.unknownReferences({ cwe: [id] }).length +
          index.unknownReferences({ masvs: [id] }).length
      ).toBeGreaterThan(0);
    }
  });

  describe('reference validation', () => {
    it('accepts identifiers that exist', () => {
      expect(
        knowledge.unknownReferences({
          cwe: ['CWE-798'],
          masvs: ['MASVS-STORAGE-1'],
          maswe: ['MASWE-0004'],
        })
      ).toEqual([]);
    });

    it('names every identifier that does not', () => {
      expect(knowledge.unknownReferences({ cwe: ['CWE-999999'], maswe: ['MASWE-9999'] })).toEqual([
        'CWE-999999',
        'MASWE-9999',
      ]);
    });

    it('fails rule registration when a rule cites an identifier that does not exist', () => {
      // The Phase 7 acceptance criterion: a fabricated identifier fails the
      // build. `MASWE-0104` looks exactly as plausible as `MASWE-0004`.
      expect(() => new RuleRegistry([rule({ knowledge: { maswe: ['MASWE-0104'] } })])).toThrow(
        RuleRegistryError
      );
      expect(() => new RuleRegistry([rule({ knowledge: { maswe: ['MASWE-0104'] } })])).toThrow(
        /MASWE-0104/
      );
    });

    it('registers a rule whose references are all real', () => {
      expect(
        () =>
          new RuleRegistry([
            rule({
              knowledge: { cwe: ['CWE-798'], masvs: ['MASVS-STORAGE-1'], maswe: ['MASWE-0004'] },
            }),
          ])
      ).not.toThrow();
    });

    it('validates every rule shipped with the package', () => {
      expect(() => new RuleRegistry([...builtinRules])).not.toThrow();
    });
  });

  describe('resolution', () => {
    it('attaches titles and the declared mapping confidence', () => {
      const resolved = knowledge.resolve({ cwe: ['CWE-798'], mappingConfidence: 'high' });

      expect(resolved.cwe).toEqual([
        { id: 'CWE-798', title: 'Use of Hard-coded Credentials', mappingConfidence: 'high' },
      ]);
    });

    it('defaults an unstated mapping confidence to medium rather than high', () => {
      // §32: an uncertain mapping is marked, never dressed up.
      expect(knowledge.resolve({ cwe: ['CWE-798'] }).cwe?.[0]?.mappingConfidence).toBe('medium');
    });

    it('drops an unknown identifier instead of citing a standard that does not exist', () => {
      const resolved = knowledge.resolve({ cwe: ['CWE-798', 'CWE-999999'] });

      expect(resolved.cwe).toHaveLength(1);
    });

    it('returns nothing for an empty mapping', () => {
      expect(knowledge.resolve(undefined)).toEqual({});
      expect(knowledge.resolve({})).toEqual({});
    });
  });

  describe('KnowledgeIndex', () => {
    it('can be built over any snapshot, so a scan can pin an older one', () => {
      const index = new KnowledgeIndex({
        version: '2020.1',
        cwe: [{ id: 'CWE-1', name: 'Example' }],
        masvs: [],
        maswe: [],
        mastg: [],
      });

      expect(index.version).toBe('2020.1');
      expect(index.cwe('CWE-1')?.name).toBe('Example');
      expect(index.unknownReferences({ cwe: ['CWE-798'] })).toEqual(['CWE-798']);
    });
  });
});
