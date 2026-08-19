import { SecurityToolkitError } from '../internal/errors';
import { parseCheckResult } from '../internal/validate';

const signal = (overrides: Record<string, unknown> = {}) => ({
  id: 'RNSEC-ANDROID-ROOT-001',
  outcome: 'not-detected',
  detected: false,
  confidence: 'medium',
  description: 'No su binary found in known locations',
  metadata: {},
  ...overrides,
});

const result = (overrides: Record<string, unknown> = {}) => ({
  id: 'root',
  status: 'secure',
  detected: false,
  confidence: 'high',
  signals: [signal()],
  metadata: { signatureVersion: '2026.08.1' },
  durationMs: 12,
  checkedAtEpochMs: 1_760_000_000_000,
  ...overrides,
});

describe('check result validation', () => {
  it('accepts a well-formed secure result and freezes it', () => {
    const parsed = parseCheckResult(result(), 'android', 'root');

    expect(parsed.status).toBe('secure');
    expect(parsed.platform).toBe('android');
    expect(parsed.signals).toHaveLength(1);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.signals)).toBe(true);
  });

  it('converts native epoch milliseconds to an ISO timestamp', () => {
    const parsed = parseCheckResult(result(), 'android', 'root');

    expect(parsed.checkedAt).toBe(new Date(1_760_000_000_000).toISOString());
  });

  it('omits optional fields rather than setting them undefined', () => {
    const parsed = parseCheckResult(result(), 'android', 'root');

    expect('unavailableReason' in parsed).toBe(false);
    expect('errorMessage' in parsed).toBe(false);
  });

  it('accepts a detected result carrying a detected signal', () => {
    const parsed = parseCheckResult(
      result({
        status: 'detected',
        detected: true,
        signals: [signal({ outcome: 'detected', detected: true })],
      }),
      'android',
      'root'
    );

    expect(parsed.detected).toBe(true);
    expect(parsed.signals[0]?.outcome).toBe('detected');
  });

  it('accepts an unavailable result with its reason', () => {
    const parsed = parseCheckResult(
      result({
        status: 'unavailable',
        confidence: 'low',
        signals: [],
        unavailableReason: 'not-configured',
      }),
      'android',
      'root'
    );

    expect(parsed.unavailableReason).toBe('not-configured');
  });

  it('preserves indeterminate signals as evidence of an inconclusive check', () => {
    const parsed = parseCheckResult(
      result({
        status: 'unknown',
        confidence: 'low',
        signals: [signal({ outcome: 'indeterminate' })],
      }),
      'android',
      'root'
    );

    expect(parsed.status).toBe('unknown');
    expect(parsed.detected).toBe(false);
    expect(parsed.signals[0]?.outcome).toBe('indeterminate');
  });

  /**
   * On a compromised device the native module is exactly what an attacker may
   * control, so a payload that contradicts itself is rejected rather than
   * partially trusted.
   */
  describe('rejects payloads a tampered native module could return', () => {
    const cases: ReadonlyArray<[string, unknown]> = [
      ['a non-object', 'compromised'],
      ['an unknown status', result({ status: 'compromised' })],
      ['an unknown confidence', result({ confidence: 'certain' })],
      [
        'an unknown unavailable reason',
        result({ status: 'unavailable', unavailableReason: 'because' }),
      ],
      ['a non-array signals field', result({ signals: {} })],
      ['a signal with an unknown outcome', result({ signals: [signal({ outcome: 'maybe' })] })],
      ['a missing checkedAtEpochMs', result({ checkedAtEpochMs: undefined })],
      ['a non-numeric durationMs', result({ durationMs: 'fast' })],
    ];

    it.each(cases)('%s', (_label, payload) => {
      expect(() => parseCheckResult(payload, 'android', 'root')).toThrow(SecurityToolkitError);
    });
  });

  it('rejects a result answering a different check than the one requested', () => {
    expect(() => parseCheckResult(result({ id: 'debugger' }), 'android', 'root')).toThrow(
      /expected a result for "root", received one for "debugger"/
    );
  });

  it('rejects a signal whose outcome and detected flag disagree', () => {
    expect(() =>
      parseCheckResult(
        result({ signals: [signal({ outcome: 'indeterminate', detected: true })] }),
        'android',
        'root'
      )
    ).toThrow(/internally inconsistent/);
  });

  it('rejects a result whose status and detected flag disagree', () => {
    expect(() =>
      parseCheckResult(result({ status: 'detected', detected: false }), 'android', 'root')
    ).toThrow(/internally inconsistent/);
  });

  /** A verdict has to be earned by evidence, not merely asserted. */
  it('rejects a detection with no detected signal behind it', () => {
    expect(() =>
      parseCheckResult(
        result({ status: 'detected', detected: true, signals: [signal()] }),
        'android',
        'root'
      )
    ).toThrow(/no signal reported a detection/);
  });

  /** The dangerous direction: claiming safety while the evidence says otherwise. */
  it('rejects a secure verdict that contradicts its own signals', () => {
    expect(() =>
      parseCheckResult(
        result({ status: 'secure', signals: [signal({ outcome: 'detected', detected: true })] }),
        'android',
        'root'
      )
    ).toThrow(/at least one signal reported a detection/);
  });
});
