import { Platform } from 'react-native';
import { SecurityToolkit } from '../SecurityToolkit';
import { SecurityToolkitError } from '../internal/errors';
import { __setNativeModuleForTesting } from '../internal/nativeModule';
import { __resetCheckAllCacheForTesting } from '../runtime/checkAll';
import type { Spec } from '../specs/NativeSecurityToolkit';

const androidChecks = ['root', 'debugger', 'emulator', 'hooks', 'integrity'];

function resultPayload(id: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    status: 'secure',
    detected: false,
    confidence: 'high',
    signals: [],
    metadata: {},
    durationMs: 3,
    checkedAtEpochMs: 1_760_000_000_000,
    ...overrides,
  };
}

function stub(overrides: Partial<Spec> = {}, supportedChecks: string[] = androidChecks): Spec {
  return {
    getEngineInfo: async () => ({
      platform: 'android',
      osVersion: '15',
      engineVersion: '0.1.0',
      supportedChecks,
    }),
    runCheck: async () => ({}),
    runChecks: async (ids: string[]) => ({ results: ids.map((id) => resultPayload(id)) }),
    setScreenProtection: async () => false,
    ...overrides,
  } as Spec;
}

describe('checkAll', () => {
  beforeEach(() => {
    Platform.OS = 'android';
    __resetCheckAllCacheForTesting();
  });

  afterEach(() => {
    __setNativeModuleForTesting(undefined);
    SecurityToolkit.resetConfiguration();
  });

  it('returns a report covering every supported check', async () => {
    __setNativeModuleForTesting(stub());

    const report = await SecurityToolkit.checkAll();

    expect(Object.keys(report.checks).sort()).toEqual([...androidChecks].sort());
    expect(report.platform).toBe('android');
    expect(report.engineVersion).toBe('0.1.0');
  });

  /**
   * The platform-asymmetry rule from §22 of the brief: an iOS-only check must not
   * appear on Android as an error, or as anything at all.
   */
  it('omits checks the platform does not implement', async () => {
    __setNativeModuleForTesting(stub());

    const report = await SecurityToolkit.checkAll();

    expect('jailbreak' in report.checks).toBe(false);
    expect('simulator' in report.checks).toBe(false);
  });

  /** Disabled is different from absent, and the report says which. */
  it('reports a disabled check rather than omitting it', async () => {
    __setNativeModuleForTesting(stub());
    SecurityToolkit.configure({ disabledChecks: ['hooks'] });

    const report = await SecurityToolkit.checkAll();

    expect(report.checks.hooks?.status).toBe('unavailable');
    expect(report.checks.hooks?.unavailableReason).toBe('disabled-by-config');
  });

  it('does not ask the engine to run a disabled check', async () => {
    const runChecks = jest.fn(async (ids: string[]) => ({
      results: ids.map((id) => resultPayload(id)),
    }));
    __setNativeModuleForTesting(stub({ runChecks: runChecks as unknown as Spec['runChecks'] }));
    SecurityToolkit.configure({ disabledChecks: ['hooks'] });

    await SecurityToolkit.checkAll();

    expect(runChecks.mock.calls[0]?.[0]).not.toContain('hooks');
  });

  it('runs every check in a single bridge crossing', async () => {
    const runChecks = jest.fn(async (ids: string[]) => ({
      results: ids.map((id) => resultPayload(id)),
    }));
    __setNativeModuleForTesting(stub({ runChecks: runChecks as unknown as Spec['runChecks'] }));

    await SecurityToolkit.checkAll();

    expect(runChecks).toHaveBeenCalledTimes(1);
  });

  it('passes integrity configuration only when integrity is being run', async () => {
    const runChecks = jest.fn(async (ids: string[], _options: object) => ({
      results: ids.map((id) => resultPayload(id)),
    }));
    __setNativeModuleForTesting(stub({ runChecks: runChecks as unknown as Spec['runChecks'] }));
    SecurityToolkit.configure({ integrity: { expectedPackageName: 'com.example.app' } });

    await SecurityToolkit.checkAll();

    expect(runChecks.mock.calls[0]?.[1]).toEqual({ expectedPackageName: 'com.example.app' });
  });

  it('scores the report and marks a clean device as not compromised', async () => {
    __setNativeModuleForTesting(stub());

    const report = await SecurityToolkit.checkAll();

    expect(report.risk.score).toBe(0);
    expect(report.risk.level).toBe('minimal');
    expect(report.compromised).toBe(false);
  });

  it('marks a high-risk device as compromised', async () => {
    __setNativeModuleForTesting(
      stub({
        runChecks: async (ids: string[]) => ({
          results: ids.map((id) =>
            id === 'root'
              ? resultPayload('root', {
                  status: 'detected',
                  detected: true,
                  signals: [
                    {
                      id: 'RNSEC-ANDROID-ROOT-005',
                      outcome: 'detected',
                      detected: true,
                      confidence: 'high',
                      description: 'Verified Boot reports an unlocked bootloader',
                      metadata: {},
                    },
                    {
                      id: 'RNSEC-ANDROID-ROOT-008',
                      outcome: 'detected',
                      detected: true,
                      confidence: 'high',
                      description: 'A protected directory accepted a write',
                      metadata: {},
                    },
                  ],
                })
              : resultPayload(id)
          ),
        }),
      })
    );

    const report = await SecurityToolkit.checkAll();

    expect(report.risk.level).toBe('high');
    expect(report.compromised).toBe(true);
    expect(report.risk.contributors.length).toBeGreaterThan(0);
  });

  /**
   * Losing ten good results because the eleventh was malformed would be a poor
   * trade, so a bad entry degrades only itself.
   */
  it('degrades one malformed result without failing the whole report', async () => {
    __setNativeModuleForTesting(
      stub({
        runChecks: async (ids: string[]) => ({
          results: ids.map((id) =>
            id === 'hooks' ? { id: 'hooks', status: 'nonsense' } : resultPayload(id)
          ),
        }),
      })
    );

    const report = await SecurityToolkit.checkAll();

    expect(report.checks.hooks?.status).toBe('error');
    expect(report.checks.root?.status).toBe('secure');
  });

  it('ignores a check the engine reports that this version does not know', async () => {
    __setNativeModuleForTesting(stub({}, [...androidChecks, 'timeTravel']));

    const report = await SecurityToolkit.checkAll();

    expect(Object.keys(report.checks)).not.toContain('timeTravel');
  });

  it('caches the engine capability list across calls', async () => {
    const getEngineInfo = jest.fn(async () => ({
      platform: 'android',
      osVersion: '15',
      engineVersion: '0.1.0',
      supportedChecks: androidChecks,
    }));
    __setNativeModuleForTesting(
      stub({ getEngineInfo: getEngineInfo as unknown as Spec['getEngineInfo'] })
    );

    await SecurityToolkit.checkAll();
    await SecurityToolkit.checkAll();

    expect(getEngineInfo).toHaveBeenCalledTimes(1);
  });

  /**
   * `nativeTimeoutMs` is a budget for *one* check. Applying it to a batch means
   * nine checks share what one was allotted, which is how a cold start gets
   * reported as a timeout instead of a result.
   */
  describe('timeout budget', () => {
    afterEach(() => {
      jest.useRealTimers();
    });

    it('scales the budget with the number of checks', async () => {
      jest.useFakeTimers();
      SecurityToolkit.configure({ nativeTimeoutMs: 1_000 });

      let settle: ((value: unknown) => void) | undefined;
      __setNativeModuleForTesting(
        stub({
          runChecks: (() =>
            new Promise((resolve) => {
              settle = resolve;
            })) as unknown as Spec['runChecks'],
        })
      );

      const pending = SecurityToolkit.checkAll();
      // Let the cached engine-info fetch resolve before advancing.
      await Promise.resolve();
      await Promise.resolve();

      // A single check's budget has elapsed; five checks were requested, so this
      // must not have timed out yet.
      jest.advanceTimersByTime(1_500);
      settle?.({ results: androidChecks.map((id) => resultPayload(id)) });

      const report = await pending;
      expect(report.checks.root?.status).toBe('secure');
    });

    it('still gives up eventually', async () => {
      jest.useFakeTimers();
      SecurityToolkit.configure({ nativeTimeoutMs: 100 });
      __setNativeModuleForTesting(
        stub({ runChecks: (() => new Promise(() => {})) as unknown as Spec['runChecks'] })
      );

      const settled = SecurityToolkit.checkAll().catch((error: unknown) => error);
      await Promise.resolve();
      await Promise.resolve();

      // Five checks at 100ms each.
      jest.advanceTimersByTime(500);

      await expect(settled).resolves.toMatchObject({ code: 'NATIVE_TIMEOUT' });
    });
  });

  it('still throws when the native module is not linked', async () => {
    __setNativeModuleForTesting(null);

    await expect(SecurityToolkit.checkAll()).rejects.toThrow(SecurityToolkitError);
  });

  describe('evaluate', () => {
    it('returns an allowed decision for a clean device', async () => {
      __setNativeModuleForTesting(stub());

      const decision = await SecurityToolkit.evaluate({ blockOnRoot: true });

      expect(decision.allowed).toBe(true);
      expect(decision.report.checks.root?.status).toBe('secure');
    });

    it('returns a denial carrying the evidence', async () => {
      __setNativeModuleForTesting(
        stub({
          runChecks: async (ids: string[]) => ({
            results: ids.map((id) =>
              id === 'root'
                ? resultPayload('root', {
                    status: 'detected',
                    detected: true,
                    signals: [
                      {
                        id: 'RNSEC-ANDROID-ROOT-005',
                        outcome: 'detected',
                        detected: true,
                        confidence: 'high',
                        description: 'Verified Boot reports an unlocked bootloader',
                        metadata: {},
                      },
                    ],
                  })
                : resultPayload(id)
            ),
          }),
        })
      );

      const decision = await SecurityToolkit.evaluate({ blockOnRoot: true });

      expect(decision.allowed).toBe(false);
      expect(decision.reasons[0]?.signalIds).toEqual(['RNSEC-ANDROID-ROOT-005']);
    });
  });
});
