import { Platform } from 'react-native';
import { RootDetection } from '../runtime/RootDetection';
import { SecurityToolkit } from '../SecurityToolkit';
import { SecurityToolkitError } from '../internal/errors';
import { __setNativeModuleForTesting } from '../internal/nativeModule';
import type { Spec } from '../specs/NativeSecurityToolkit';

const secureResult = {
  id: 'root',
  status: 'secure',
  detected: false,
  confidence: 'high',
  signals: [
    {
      id: 'RNSEC-ANDROID-ROOT-001',
      outcome: 'not-detected',
      detected: false,
      confidence: 'medium',
      description: 'No su binary found in known locations',
      metadata: {},
    },
  ],
  metadata: {},
  durationMs: 8,
  checkedAtEpochMs: 1_760_000_000_000,
};

function stub(runCheck: Spec['runCheck']): Spec {
  return {
    getEngineInfo: async () => {
      throw new Error('not used');
    },
    runCheck,
    runChecks: async () => ({}),
    setScreenProtection: async () => false,
  } as Spec;
}

describe('RootDetection', () => {
  beforeEach(() => {
    Platform.OS = 'android';
  });

  afterEach(() => {
    __setNativeModuleForTesting(undefined);
    SecurityToolkit.resetConfiguration();
  });

  it('returns the validated native result', async () => {
    __setNativeModuleForTesting(stub(async () => secureResult));

    const status = await RootDetection.getStatus();

    expect(status.id).toBe('root');
    expect(status.status).toBe('secure');
    expect(status.platform).toBe('android');
  });

  it('asks the native engine for the root check specifically', async () => {
    const runCheck = jest.fn(async () => secureResult);
    __setNativeModuleForTesting(stub(runCheck as unknown as Spec['runCheck']));

    await RootDetection.getStatus();

    // Checks receive only the options they need, never the whole configuration.
    expect(runCheck).toHaveBeenCalledWith('root', {});
  });

  /**
   * On iOS the root check does not exist, and the iOS engine says so itself.
   * Reporting that as an error would fill a cross-platform report with failures
   * that are really just platform facts.
   */
  it('passes through platform-not-supported from a platform without the check', async () => {
    Platform.OS = 'ios';
    __setNativeModuleForTesting(
      stub(async () => ({
        id: 'root',
        status: 'unavailable',
        detected: false,
        confidence: 'low',
        signals: [],
        unavailableReason: 'platform-not-supported',
        metadata: {},
        durationMs: 0,
        checkedAtEpochMs: 1_760_000_000_000,
      }))
    );

    const status = await RootDetection.getStatus();

    expect(status.status).toBe('unavailable');
    expect(status.unavailableReason).toBe('platform-not-supported');
    expect(status.detected).toBe(false);
    expect(status.platform).toBe('ios');
  });

  it('reports disabled-by-config when the check is switched off', async () => {
    SecurityToolkit.configure({ disabledChecks: ['root'] });
    __setNativeModuleForTesting(
      stub(async () => {
        throw new Error('must not reach the native module');
      })
    );

    const status = await RootDetection.getStatus();

    expect(status.status).toBe('unavailable');
    expect(status.unavailableReason).toBe('disabled-by-config');
  });

  /** A failing check must never take down the host application. */
  it('degrades a native failure to an error result rather than rejecting', async () => {
    __setNativeModuleForTesting(
      stub(async () => {
        throw new Error('engine exploded');
      })
    );

    const status = await RootDetection.getStatus();

    expect(status.status).toBe('error');
    expect(status.detected).toBe(false);
    expect(status.errorMessage).toBe('engine exploded');
  });

  it('degrades a tampered payload to an error result rather than rejecting', async () => {
    __setNativeModuleForTesting(stub(async () => ({ id: 'root', status: 'totally-fine' })));

    const status = await RootDetection.getStatus();

    expect(status.status).toBe('error');
    expect(status.errorMessage).toMatch(/unexpected payload/);
  });

  it('degrades a hanging native call to an error result', async () => {
    jest.useFakeTimers();
    SecurityToolkit.configure({ nativeTimeoutMs: 150 });
    __setNativeModuleForTesting(stub(() => new Promise<never>(() => {})));

    const pending = RootDetection.getStatus();
    jest.advanceTimersByTime(150);
    const status = await pending;

    expect(status.status).toBe('error');
    expect(status.errorMessage).toMatch(/did not complete within 150ms/);
    jest.useRealTimers();
  });

  /** A missing native module is a build mistake, not a device condition. */
  it('still throws when the native module is not linked', async () => {
    __setNativeModuleForTesting(null);

    await expect(RootDetection.getStatus()).rejects.toThrow(SecurityToolkitError);
  });
});
