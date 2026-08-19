import { SecurityToolkit } from '../SecurityToolkit';
import { SecurityToolkitError, isSecurityToolkitError } from '../internal/errors';
import { __setNativeModuleForTesting } from '../internal/nativeModule';
import type { Spec } from '../specs/NativeSecurityToolkit';

const androidInfo = {
  platform: 'android',
  osVersion: '15',
  engineVersion: '0.1.0',
  supportedChecks: [] as string[],
};

function stub(getEngineInfo: Spec['getEngineInfo']): Spec {
  return { getEngineInfo } as Spec;
}

describe('SecurityToolkit', () => {
  afterEach(() => {
    __setNativeModuleForTesting(undefined);
    SecurityToolkit.resetConfiguration();
    jest.useRealTimers();
  });

  describe('when the native module is not linked', () => {
    beforeEach(() => {
      __setNativeModuleForTesting(null);
    });

    it('reports itself unavailable without throwing', () => {
      expect(SecurityToolkit.isAvailable()).toBe(false);
    });

    it('throws an actionable error rather than a null dereference', async () => {
      await expect(SecurityToolkit.getEngineInfo()).rejects.toThrow(SecurityToolkitError);
      const error = await SecurityToolkit.getEngineInfo().catch((e: unknown) => e);
      expect(isSecurityToolkitError(error)).toBe(true);
      expect((error as SecurityToolkitError).code).toBe('NATIVE_MODULE_UNAVAILABLE');
      // The message has to tell a developer what to actually do about it.
      expect((error as SecurityToolkitError).message).toMatch(/pod install/);
      expect((error as SecurityToolkitError).message).toMatch(/Metro reload alone is not enough/);
    });
  });

  describe('when the native module is linked', () => {
    beforeEach(() => {
      __setNativeModuleForTesting(stub(async () => androidInfo));
    });

    it('reports itself available', () => {
      expect(SecurityToolkit.isAvailable()).toBe(true);
    });

    it('returns validated engine info', async () => {
      await expect(SecurityToolkit.getEngineInfo()).resolves.toEqual(androidInfo);
    });

    it('reports no supported checks before any check is implemented', async () => {
      const info = await SecurityToolkit.getEngineInfo();
      expect(info.supportedChecks).toEqual([]);
    });
  });

  it('rejects a payload from a tampered native module', async () => {
    __setNativeModuleForTesting(stub(async () => ({ platform: 'linux' }) as never));
    const error = await SecurityToolkit.getEngineInfo().catch((e: unknown) => e);
    expect((error as SecurityToolkitError).code).toBe('INVALID_NATIVE_PAYLOAD');
  });

  it('surfaces a native rejection to the caller', async () => {
    const cause = new Error('engine unavailable');
    __setNativeModuleForTesting(stub(() => Promise.reject(cause)));
    await expect(SecurityToolkit.getEngineInfo()).rejects.toBe(cause);
  });

  it('times out a hanging native call using the configured timeout', async () => {
    jest.useFakeTimers();
    __setNativeModuleForTesting(stub(() => new Promise<never>(() => {})));
    SecurityToolkit.configure({ nativeTimeoutMs: 200 });

    const settled = SecurityToolkit.getEngineInfo().catch((error: unknown) => error);
    jest.advanceTimersByTime(200);

    await expect(settled).resolves.toMatchObject({ code: 'NATIVE_TIMEOUT' });
  });

  describe('configuration', () => {
    it('exposes resolved defaults', () => {
      expect(SecurityToolkit.getConfiguration()).toEqual({
        developmentMode: false,
        nativeTimeoutMs: 5_000,
        disabledChecks: [],
        integrity: {},
      });
    });

    it('throws on invalid configuration', () => {
      expect(() => SecurityToolkit.configure({ nativeTimeoutMs: -1 })).toThrow(
        SecurityToolkitError
      );
    });

    it('leaves the previous configuration intact when a new one is rejected', () => {
      SecurityToolkit.configure({ nativeTimeoutMs: 1_000 });
      expect(() => SecurityToolkit.configure({ nativeTimeoutMs: -1 })).toThrow();
      expect(SecurityToolkit.getConfiguration().nativeTimeoutMs).toBe(1_000);
    });
  });
});
