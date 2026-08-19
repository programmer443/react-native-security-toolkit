import { RuleRegistry, RuleRegistryError, builtinRules } from '../ruleRegistry.js';
import type { DiscoveredFile } from '../../types/file.js';
import type { SecurityRule } from '../../types/rule.js';

function rule(overrides: Partial<SecurityRule> = {}): SecurityRule {
  return {
    id: 'RNSEC-STORAGE-001',
    name: 'Insecure storage',
    description: 'Sensitive data written to unencrypted storage.',
    severity: 'medium',
    categories: ['storage'],
    languages: [],
    fileKinds: [],
    knowledge: {},
    detect: () => [],
    ...overrides,
  };
}

function file(overrides: Partial<DiscoveredFile> = {}): DiscoveredFile {
  return {
    absolutePath: '/project/src/index.ts',
    path: 'src/index.ts',
    sizeBytes: 10,
    language: 'typescript',
    kind: 'source',
    ...overrides,
  };
}

describe('rule registry', () => {
  it('rejects an identifier that does not follow the published scheme', () => {
    // Identifiers appear in baselines, suppressions and SARIF output, and §78
    // makes them permanent. A typo has to fail the first time it is seen.
    expect(() => new RuleRegistry([rule({ id: 'storage-1' })])).toThrow(RuleRegistryError);
    expect(() => new RuleRegistry([rule({ id: 'RNSEC-STORAGE-1' })])).toThrow(RuleRegistryError);
  });

  it('accepts hyphenated areas', () => {
    expect(() => new RuleRegistry([rule({ id: 'RNSEC-ANDROID-MANIFEST-001' })])).not.toThrow();
  });

  it('refuses to register the same identifier twice', () => {
    expect(() => new RuleRegistry([rule(), rule()])).toThrow(/registered twice/);
  });

  it('selects rules by language', () => {
    const registry = new RuleRegistry([
      rule({ id: 'RNSEC-STORAGE-001', languages: ['typescript'] }),
      rule({ id: 'RNSEC-ANDROID-001', languages: ['kotlin'] }),
    ]);

    expect(registry.rulesFor(file()).map((entry) => entry.id)).toEqual(['RNSEC-STORAGE-001']);
  });

  it('selects rules by file kind', () => {
    const registry = new RuleRegistry([
      rule({ id: 'RNSEC-ANDROID-MANIFEST-001', fileKinds: ['android-manifest'] }),
    ]);

    expect(registry.rulesFor(file())).toHaveLength(0);
    expect(
      registry.rulesFor(
        file({
          path: 'android/app/src/main/AndroidManifest.xml',
          language: 'xml',
          kind: 'android-manifest',
        })
      )
    ).toHaveLength(1);
  });

  it('treats an empty language or kind list as "any", which text rules need', () => {
    const registry = new RuleRegistry([rule({ id: 'RNSEC-SECRET-001' })]);

    expect(registry.rulesFor(file({ language: 'kotlin', kind: 'gradle-build' }))).toHaveLength(1);
  });

  it('omits rules disabled in configuration', () => {
    const registry = new RuleRegistry([rule()]);

    expect(registry.rulesFor(file(), ['RNSEC-STORAGE-001'])).toHaveLength(0);
  });

  it('ships a rule library whose identifiers are unique and well-formed', () => {
    // Registration is the gate: it enforces the identifier scheme, uniqueness,
    // and that every standards reference exists in the knowledge snapshot.
    expect(builtinRules.length).toBeGreaterThan(0);
    expect(() => new RuleRegistry([...builtinRules])).not.toThrow();

    const ids = builtinRules.map((entry) => entry.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('gives every shipped rule the fields a report needs', () => {
    // A rule that cannot say what it detects or how to fix it produces findings
    // nobody can act on (§40).
    for (const entry of builtinRules) {
      expect(entry.name.length).toBeGreaterThan(0);
      expect(entry.description.length).toBeGreaterThan(20);
      expect(entry.categories.length).toBeGreaterThan(0);
    }
  });
});
