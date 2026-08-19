import { evaluateRisk, levelFor, meetsOrExceeds } from '../risk/riskEngine';
import { RISK_METHODOLOGY_VERSION } from '../risk/weights';
import type { CheckId, SecurityCheckResult, SecuritySignal } from '../types';

function signal(
  id: string,
  confidence: SecuritySignal['confidence'],
  detected = true
): SecuritySignal {
  return {
    id,
    outcome: detected ? 'detected' : 'not-detected',
    detected,
    confidence,
    description: `signal ${id}`,
    metadata: {},
  };
}

function check(
  id: CheckId,
  status: SecurityCheckResult['status'],
  signals: SecuritySignal[] = []
): SecurityCheckResult {
  return {
    id,
    status,
    detected: status === 'detected',
    confidence: 'high',
    platform: 'android',
    signals,
    metadata: {},
    durationMs: 1,
    checkedAt: '2026-08-18T00:00:00.000Z',
  };
}

const noDevelopmentMode = { developmentMode: false };

describe('risk engine', () => {
  it('scores a clean device at zero', () => {
    const risk = evaluateRisk({ root: check('root', 'secure') }, noDevelopmentMode);

    expect(risk.score).toBe(0);
    expect(risk.level).toBe('minimal');
    expect(risk.contributors).toEqual([]);
  });

  it('stamps the methodology version on every result', () => {
    expect(evaluateRisk({}, noDevelopmentMode).methodologyVersion).toBe(RISK_METHODOLOGY_VERSION);
  });

  /**
   * The determinism requirement, pinned to exact numbers. A weight change is
   * meant to break these — that is what makes it a reviewable decision rather
   * than an accident.
   */
  describe('golden vectors', () => {
    it('scores a rooted device deterministically', () => {
      const risk = evaluateRisk(
        {
          root: check('root', 'detected', [
            signal('RNSEC-ANDROID-ROOT-005', 'high'), // 35 × 1.0
            signal('RNSEC-ANDROID-ROOT-001', 'medium'), // 30 × 0.7 = 21
            signal('RNSEC-ANDROID-ROOT-004', 'low'), // 8 × 0.4 = 3.2
          ]),
        },
        noDevelopmentMode
      );

      expect(risk.score).toBe(59.2);
      expect(risk.level).toBe('medium');
    });

    it('applies mitigation credits to a partially clean device', () => {
      const risk = evaluateRisk(
        {
          root: check('root', 'detected', [signal('RNSEC-ANDROID-ROOT-001', 'medium')]), // 21
          integrity: check('integrity', 'secure'), // −10
          secureHardware: check('secureHardware', 'secure'), // −8
        },
        noDevelopmentMode
      );

      expect(risk.score).toBe(3);
      expect(risk.level).toBe('minimal');
    });

    it('scores a thoroughly compromised device as critical', () => {
      const risk = evaluateRisk(
        {
          root: check('root', 'detected', [
            signal('RNSEC-ANDROID-ROOT-005', 'high'), // 35
            signal('RNSEC-ANDROID-ROOT-008', 'high'), // 35
          ]),
          hooks: check('hooks', 'detected', [signal('RNSEC-RUNTIME-HOOK-001', 'medium')]), // 17.5
          integrity: check('integrity', 'detected', [
            signal('RNSEC-RUNTIME-INTEGRITY-001', 'high'), // 40
          ]),
        },
        noDevelopmentMode
      );

      expect(risk.score).toBe(100);
      expect(risk.level).toBe('critical');
    });

    it('is stable across repeated evaluation of the same input', () => {
      const checks = {
        root: check('root', 'detected', [signal('RNSEC-ANDROID-ROOT-002', 'medium')]),
        network: check('network', 'unknown'),
      };

      const first = evaluateRisk(checks, noDevelopmentMode);
      const second = evaluateRisk(checks, noDevelopmentMode);

      expect(first.score).toBe(second.score);
      expect(first.contributors).toEqual(second.contributors);
    });
  });

  it('clamps to the 0-100 range', () => {
    const risk = evaluateRisk(
      {
        integrity: check('integrity', 'secure'),
        secureHardware: check('secureHardware', 'secure'),
        biometrics: check('biometrics', 'secure'),
        screen: check('screen', 'secure'),
      },
      noDevelopmentMode
    );

    // Credits alone total −26; the floor is zero.
    expect(risk.score).toBe(0);
  });

  it('weights a low-confidence detection below a high-confidence one', () => {
    const low = evaluateRisk(
      { root: check('root', 'detected', [signal('RNSEC-ANDROID-ROOT-001', 'low')]) },
      noDevelopmentMode
    );
    const high = evaluateRisk(
      { root: check('root', 'detected', [signal('RNSEC-ANDROID-ROOT-001', 'high')]) },
      noDevelopmentMode
    );

    expect(low.score).toBeLessThan(high.score);
  });

  describe('uncertainty', () => {
    /** `unknown` is not `secure`, and the score has to reflect that. */
    it('penalises a check that could not reach a verdict', () => {
      const risk = evaluateRisk({ root: check('root', 'unknown') }, noDevelopmentMode);

      expect(risk.score).toBe(4);
      expect(risk.contributors[0]?.reason).toMatch(/could not reach a verdict/);
    });

    /** Ignorance alone must not be able to reach a blocking level. */
    it('caps the total uncertainty penalty', () => {
      const risk = evaluateRisk(
        {
          root: check('root', 'unknown'),
          hooks: check('hooks', 'unknown'),
          integrity: check('integrity', 'unknown'),
          network: check('network', 'unknown'),
          screen: check('screen', 'unknown'),
          biometrics: check('biometrics', 'unknown'),
        },
        noDevelopmentMode
      );

      expect(risk.score).toBe(12);
      expect(risk.level).toBe('minimal');
    });

    it('awards no mitigation credit for an inconclusive check', () => {
      const unknown = evaluateRisk({ integrity: check('integrity', 'unknown') }, noDevelopmentMode);
      const secure = evaluateRisk({ integrity: check('integrity', 'secure') }, noDevelopmentMode);

      expect(unknown.score).toBeGreaterThan(secure.score);
    });
  });

  describe('development mode', () => {
    it('ignores debugger, emulator and simulator signals', () => {
      const checks = {
        debugger: check('debugger', 'detected', [signal('RNSEC-ANDROID-DEBUGGER-001', 'high')]),
        emulator: check('emulator', 'detected', [signal('RNSEC-ANDROID-EMULATOR-001', 'medium')]),
        simulator: check('simulator', 'detected', [signal('RNSEC-IOS-SIMULATOR-001', 'high')]),
      };

      expect(evaluateRisk(checks, { developmentMode: true }).score).toBe(0);
      expect(evaluateRisk(checks, { developmentMode: false }).score).toBeGreaterThan(0);
    });

    /** It suppresses development noise, not genuine findings. */
    it('still scores root, hooks and integrity', () => {
      const risk = evaluateRisk(
        { root: check('root', 'detected', [signal('RNSEC-ANDROID-ROOT-005', 'high')]) },
        { developmentMode: true }
      );

      expect(risk.score).toBe(35);
    });
  });

  it('orders contributors by influence', () => {
    const risk = evaluateRisk(
      {
        root: check('root', 'detected', [
          signal('RNSEC-ANDROID-ROOT-004', 'low'),
          signal('RNSEC-ANDROID-ROOT-005', 'high'),
        ]),
      },
      noDevelopmentMode
    );

    expect(risk.contributors[0]?.source).toBe('RNSEC-ANDROID-ROOT-005');
  });

  /**
   * A detector added without a weight must not score zero — that would let a new
   * signal fire with no effect at all, which is the failure most likely to go
   * unnoticed.
   */
  it('gives an unweighted signal a non-zero default', () => {
    const risk = evaluateRisk(
      { root: check('root', 'detected', [signal('RNSEC-ANDROID-ROOT-999', 'high')]) },
      noDevelopmentMode
    );

    expect(risk.score).toBeGreaterThan(0);
  });

  it('ignores signals that did not fire', () => {
    const risk = evaluateRisk(
      {
        root: check('root', 'detected', [
          signal('RNSEC-ANDROID-ROOT-005', 'high', false),
          signal('RNSEC-ANDROID-ROOT-001', 'medium'),
        ]),
      },
      noDevelopmentMode
    );

    expect(risk.contributors).toHaveLength(1);
  });

  it('scores an absent check as nothing at all', () => {
    expect(evaluateRisk({}, noDevelopmentMode).score).toBe(0);
  });

  describe('levels', () => {
    it.each([
      [0, 'minimal'],
      [19.9, 'minimal'],
      [20, 'low'],
      [39.9, 'low'],
      [40, 'medium'],
      [59.9, 'medium'],
      [60, 'high'],
      [79.9, 'high'],
      [80, 'critical'],
      [100, 'critical'],
    ])('maps %s to %s', (score, expected) => {
      expect(levelFor(score as number)).toBe(expected);
    });

    it('compares levels in order', () => {
      expect(meetsOrExceeds('critical', 'high')).toBe(true);
      expect(meetsOrExceeds('high', 'high')).toBe(true);
      expect(meetsOrExceeds('medium', 'high')).toBe(false);
    });
  });
});
