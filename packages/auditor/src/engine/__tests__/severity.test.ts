import { compareSeverity, maxSeverity, meetsThreshold, resolveSeverity } from '../severity.js';

describe('severity ordering', () => {
  it('orders from info to critical', () => {
    expect(compareSeverity('critical', 'high')).toBeGreaterThan(0);
    expect(compareSeverity('low', 'medium')).toBeLessThan(0);
    expect(compareSeverity('high', 'high')).toBe(0);
    expect(maxSeverity('low', 'critical')).toBe('critical');
  });

  it('answers threshold questions inclusively', () => {
    expect(meetsThreshold('high', 'high')).toBe(true);
    expect(meetsThreshold('medium', 'high')).toBe(false);
    expect(meetsThreshold('critical', 'info')).toBe(true);
  });
});

describe('contextual severity', () => {
  it('leaves ordinary source code at the rule default', () => {
    expect(resolveSeverity('high', 'src/api/client.ts', 'RNSEC-SECRET-001', [])).toEqual({
      severity: 'high',
    });
  });

  it('downgrades findings in test code, and records why', () => {
    const decision = resolveSeverity(
      'high',
      'src/__tests__/client.test.ts',
      'RNSEC-SECRET-001',
      []
    );

    expect(decision.severity).toBe('medium');
    expect(decision.adjustment).toEqual({
      from: 'high',
      to: 'medium',
      reason: 'file is test code',
    });
  });

  it('downgrades fixtures furthest, because insecure code is their purpose', () => {
    const decision = resolveSeverity(
      'high',
      'src/__fixtures__/vulnerable.ts',
      'RNSEC-SECRET-001',
      []
    );

    expect(decision.severity).toBe('low');
  });

  it('never drops a finding entirely, however weak the context', () => {
    // A real credential committed to a fixture directory is still a real
    // credential. `info` keeps it visible instead of deleting it.
    const decision = resolveSeverity('low', 'fixtures/insecure/app.ts', 'RNSEC-SECRET-001', []);

    expect(decision.severity).toBe('info');
  });

  it('lets a configuration override outrank the engine judgement', () => {
    const decision = resolveSeverity('high', 'src/__tests__/a.test.ts', 'RNSEC-LOG-001', [
      { rule: 'RNSEC-LOG-001', severity: 'critical' },
    ]);

    expect(decision.severity).toBe('critical');
    expect(decision.adjustment?.reason).toBe('configuration override');
  });

  it('applies a path-scoped override only under those paths', () => {
    const overrides = [
      { rule: 'RNSEC-LOG-001', severity: 'low' as const, paths: ['src/debug/**'] },
    ];

    expect(resolveSeverity('high', 'src/debug/log.ts', 'RNSEC-LOG-001', overrides).severity).toBe(
      'low'
    );
    expect(resolveSeverity('high', 'src/api/log.ts', 'RNSEC-LOG-001', overrides).severity).toBe(
      'high'
    );
  });

  it('records no adjustment when an override matches the rule default', () => {
    const decision = resolveSeverity('high', 'src/a.ts', 'RNSEC-LOG-001', [
      { rule: 'RNSEC-LOG-001', severity: 'high' },
    ]);

    expect(decision.adjustment).toBeUndefined();
  });
});
