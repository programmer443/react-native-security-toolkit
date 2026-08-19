import { SuppressionIndex, scanInlineDirectives } from '../suppression.js';
import { defaultConfig } from '../../config/defaults.js';
import type { AuditorConfig } from '../../types/config.js';
import type { SecurityFinding } from '../../types/finding.js';

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: 'RNSEC-LOG-001-abc',
    ruleId: 'RNSEC-LOG-001',
    title: 'Sensitive value logged',
    description: 'A token is written to the console.',
    severity: 'high',
    confidence: 'high',
    categories: ['logging'],
    location: { path: 'src/api/client.ts', line: 12 },
    evidence: [],
    impact: 'Tokens reach device logs.',
    exploitability: 'Requires log access.',
    remediation: 'Remove the log statement.',
    sources: ['deterministic'],
    fingerprint: 'a1b2c3d4e5f6a7b8',
    ...overrides,
  };
}

function configWith(overrides: Partial<AuditorConfig>): AuditorConfig {
  return { ...defaultConfig(), ...overrides };
}

describe('inline suppression directives', () => {
  it('reads a directive with a reason, whatever the comment syntax', () => {
    const lines = [
      '// security-audit-ignore RNSEC-LOG-001 reason="test fixture"',
      '# security-audit-ignore RNSEC-SECRET-001 reason="documented sample key"',
      '<!-- security-audit-ignore RNSEC-XML-001 reason="template" -->',
    ];

    const result = scanInlineDirectives('src/a.ts', lines);

    expect(result.errors).toHaveLength(0);
    expect(result.directives.map((directive) => directive.ruleIds)).toEqual([
      ['RNSEC-LOG-001'],
      ['RNSEC-SECRET-001'],
      ['RNSEC-XML-001'],
    ]);
    expect(result.directives[0]?.reason).toBe('test fixture');
  });

  it('accepts several rules in one directive', () => {
    const result = scanInlineDirectives('src/a.ts', [
      '// security-audit-ignore RNSEC-LOG-001, RNSEC-SECRET-001 reason="sample"',
    ]);

    expect(result.directives[0]?.ruleIds).toEqual(['RNSEC-LOG-001', 'RNSEC-SECRET-001']);
  });

  it('refuses a directive with no reason, and reports it rather than hiding the finding', () => {
    // Failing open is deliberate: a malformed suppression should show you the
    // finding, not silently swallow it.
    const result = scanInlineDirectives('src/a.ts', ['// security-audit-ignore RNSEC-LOG-001']);

    expect(result.directives).toHaveLength(0);
    expect(result.errors[0]).toMatchObject({ path: 'src/a.ts', line: 1 });
    expect(result.errors[0]?.message).toContain('reason');
  });

  it('refuses a directive that names no rule', () => {
    const result = scanInlineDirectives('src/a.ts', [
      '// security-audit-ignore reason="everything"',
    ]);

    expect(result.directives).toHaveLength(0);
    expect(result.errors[0]?.message).toContain('names no rule');
  });
});

describe('SuppressionIndex', () => {
  it('suppresses a finding whose rule is disabled', () => {
    const index = new SuppressionIndex(configWith({ disabledRules: ['RNSEC-LOG-001'] }));

    expect(index.suppressionFor(finding())).toMatchObject({ kind: 'rule-disabled' });
  });

  it('suppresses a baselined fingerprint and carries the recorded reason', () => {
    const index = new SuppressionIndex(
      configWith({
        ignore: [{ fingerprint: 'a1b2c3d4e5f6a7b8', reason: 'accepted risk, ticket SEC-14' }],
      })
    );

    expect(index.suppressionFor(finding())).toEqual({
      kind: 'baseline',
      reason: 'accepted risk, ticket SEC-14',
    });
  });

  it('suppresses the line a directive sits on and the line below it', () => {
    const index = new SuppressionIndex(defaultConfig());
    index.addFileDirectives('src/api/client.ts', [
      { line: 12, ruleIds: ['RNSEC-LOG-001'], reason: 'sample' },
    ]);

    expect(
      index.suppressionFor(finding({ location: { path: 'src/api/client.ts', line: 12 } }))
    ).toMatchObject({ kind: 'inline' });
    expect(
      index.suppressionFor(finding({ location: { path: 'src/api/client.ts', line: 13 } }))
    ).toMatchObject({ kind: 'inline' });
  });

  it('does not let a directive suppress a different rule or a distant line', () => {
    const index = new SuppressionIndex(defaultConfig());
    index.addFileDirectives('src/api/client.ts', [
      { line: 12, ruleIds: ['RNSEC-LOG-001'], reason: 'sample' },
    ]);

    expect(index.suppressionFor(finding({ ruleId: 'RNSEC-SECRET-001' }))).toBeUndefined();
    expect(
      index.suppressionFor(finding({ location: { path: 'src/api/client.ts', line: 40 } }))
    ).toBeUndefined();
  });

  it('does not let a directive in one file suppress a finding in another', () => {
    const index = new SuppressionIndex(defaultConfig());
    index.addFileDirectives('src/other.ts', [
      { line: 12, ruleIds: ['RNSEC-LOG-001'], reason: 'sample' },
    ]);

    expect(index.suppressionFor(finding())).toBeUndefined();
  });

  it('leaves an unsuppressed finding alone', () => {
    expect(new SuppressionIndex(defaultConfig()).suppressionFor(finding())).toBeUndefined();
  });
});
