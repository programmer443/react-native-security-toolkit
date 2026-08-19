import { evaluatePolicy } from '../policy/policyEngine';
import { evaluateRisk } from '../risk/riskEngine';
import type {
  CheckId,
  SecurityCheckResult,
  SecurityConfidence,
  SecurityReport,
  SecuritySignal,
} from '../types';

function signal(id: string, confidence: SecurityConfidence): SecuritySignal {
  return {
    id,
    outcome: 'detected',
    detected: true,
    confidence,
    description: `signal ${id}`,
    metadata: {},
  };
}

function check(
  id: CheckId,
  status: SecurityCheckResult['status'],
  confidence: SecurityConfidence = 'high',
  signals: SecuritySignal[] = []
): SecurityCheckResult {
  return {
    id,
    status,
    detected: status === 'detected',
    confidence,
    platform: 'android',
    signals,
    metadata: {},
    durationMs: 1,
    checkedAt: '2026-08-18T00:00:00.000Z',
  };
}

function report(checks: Partial<Record<CheckId, SecurityCheckResult>>): SecurityReport {
  const risk = evaluateRisk(checks, { developmentMode: false });
  return {
    compromised: risk.level === 'high' || risk.level === 'critical',
    risk,
    platform: 'android',
    checks,
    engineVersion: '0.1.0',
    durationMs: 5,
    checkedAt: '2026-08-18T00:00:00.000Z',
  };
}

const rootedDevice = report({
  root: check('root', 'detected', 'high', [signal('RNSEC-ANDROID-ROOT-005', 'high')]),
});

describe('policy engine', () => {
  it('allows everything under an empty policy', () => {
    const decision = evaluatePolicy(rootedDevice, {});

    expect(decision.allowed).toBe(true);
    expect(decision.reasons).toEqual([]);
  });

  it('denies with an auditable reason when a blocking rule matches', () => {
    const decision = evaluatePolicy(rootedDevice, { blockOnRoot: true });

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toHaveLength(1);
    expect(decision.reasons[0]?.code).toBe('ROOT_DETECTED');
    expect(decision.reasons[0]?.checkId).toBe('root');
    // The evidence travels with the decision so it can be logged and explained.
    expect(decision.reasons[0]?.signalIds).toEqual(['RNSEC-ANDROID-ROOT-005']);
  });

  it('does not block on a check that did not detect anything', () => {
    const clean = report({ root: check('root', 'secure') });

    expect(evaluatePolicy(clean, { blockOnRoot: true }).allowed).toBe(true);
  });

  /**
   * `unknown` is inconclusive, not a detection. Blocking on it would make every
   * device with a restricted probe unusable.
   */
  it('does not block on an inconclusive check', () => {
    const inconclusive = report({ root: check('root', 'unknown') });

    expect(evaluatePolicy(inconclusive, { blockOnRoot: true }).allowed).toBe(true);
  });

  it('does not block on a check the platform does not implement', () => {
    expect(evaluatePolicy(report({}), { blockOnJailbreak: true }).allowed).toBe(true);
  });

  describe('minimumConfidence', () => {
    const weakDetection = report({
      root: check('root', 'detected', 'low', [signal('RNSEC-ANDROID-ROOT-004', 'low')]),
    });

    /** The practical false-positive control. */
    it('ignores detections below the configured floor', () => {
      const decision = evaluatePolicy(weakDetection, {
        blockOnRoot: true,
        minimumConfidence: 'high',
      });

      expect(decision.allowed).toBe(true);
      // The finding is still in the report; it just did not block.
      expect(decision.report.checks.root?.status).toBe('detected');
    });

    it('blocks once the floor is met', () => {
      expect(
        evaluatePolicy(weakDetection, { blockOnRoot: true, minimumConfidence: 'low' }).allowed
      ).toBe(false);
    });

    it('defaults to accepting any confidence', () => {
      expect(evaluatePolicy(weakDetection, { blockOnRoot: true }).allowed).toBe(false);
    });
  });

  describe('risk threshold', () => {
    // One high-confidence Verified Boot signal scores 35, which is `low`.
    it('denies when risk reaches the configured level', () => {
      const decision = evaluatePolicy(rootedDevice, { minimumRiskLevel: 'low' });

      expect(decision.allowed).toBe(false);
      expect(decision.reasons[0]?.code).toBe('RISK_LEVEL_EXCEEDED');
      expect(decision.reasons[0]?.message).toMatch(/score 35/);
    });

    it('allows below the configured level', () => {
      expect(evaluatePolicy(rootedDevice, { minimumRiskLevel: 'medium' }).allowed).toBe(true);
      expect(evaluatePolicy(rootedDevice, { minimumRiskLevel: 'critical' }).allowed).toBe(true);
    });
  });

  describe('capability requirements', () => {
    it('is satisfied by a clean capability check', () => {
      const capable = report({ secureHardware: check('secureHardware', 'secure') });

      expect(evaluatePolicy(capable, { requireSecureHardware: true }).allowed).toBe(true);
    });

    it('denies when the capability is missing', () => {
      const weak = report({
        secureHardware: check('secureHardware', 'detected', 'high', [
          signal('RNSEC-RUNTIME-HARDWARE-001', 'high'),
        ]),
      });

      const decision = evaluatePolicy(weak, { requireSecureHardware: true });

      expect(decision.allowed).toBe(false);
      expect(decision.reasons[0]?.code).toBe('SECURE_HARDWARE_UNAVAILABLE');
    });

    /**
     * A requirement that cannot be shown to hold has not been met. Treating "we
     * could not tell" as satisfaction would make the requirement meaningless.
     */
    it('denies when the capability could not be confirmed', () => {
      const inconclusive = report({ secureHardware: check('secureHardware', 'unknown') });

      expect(evaluatePolicy(inconclusive, { requireSecureHardware: true }).allowed).toBe(false);
    });

    it('denies when the capability check is absent entirely', () => {
      expect(evaluatePolicy(report({}), { requireStrongBiometrics: true }).allowed).toBe(false);
    });
  });

  it('accumulates every reason rather than stopping at the first', () => {
    const bad = report({
      root: check('root', 'detected', 'high', [signal('RNSEC-ANDROID-ROOT-005', 'high')]),
      hooks: check('hooks', 'detected', 'high', [signal('RNSEC-RUNTIME-HOOK-001', 'high')]),
    });

    const decision = evaluatePolicy(bad, {
      blockOnRoot: true,
      blockOnHooking: true,
      minimumRiskLevel: 'low',
    });

    expect(decision.reasons.map((reason) => reason.code).sort()).toEqual([
      'HOOKING_DETECTED',
      'RISK_LEVEL_EXCEEDED',
      'ROOT_DETECTED',
    ]);
  });

  it('carries the full report so a caller can inspect the evidence', () => {
    const decision = evaluatePolicy(rootedDevice, { blockOnRoot: true });

    expect(decision.report).toBe(rootedDevice);
    expect(decision.risk).toBe(rootedDevice.risk);
    expect(decision.evaluatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  /** The toolkit reports; the application decides. */
  it('returns a frozen decision and mutates nothing', () => {
    const decision = evaluatePolicy(rootedDevice, { blockOnRoot: true });

    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.reasons)).toBe(true);
  });
});
