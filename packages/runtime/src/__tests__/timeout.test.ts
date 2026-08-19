import { SecurityToolkitError } from '../internal/errors';
import { withTimeout } from '../internal/timeout';

describe('withTimeout', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('resolves with the underlying value when it settles in time', async () => {
    await expect(withTimeout(Promise.resolve('ok'), 1_000, 'call')).resolves.toBe('ok');
  });

  it('propagates the underlying rejection unchanged', async () => {
    const cause = new Error('native blew up');
    await expect(withTimeout(Promise.reject(cause), 1_000, 'call')).rejects.toBe(cause);
  });

  it('rejects with NATIVE_TIMEOUT when the call hangs', async () => {
    const settled = withTimeout(new Promise<never>(() => {}), 500, 'SecurityToolkit.check()').catch(
      (error: unknown) => error
    );
    jest.advanceTimersByTime(500);

    const error = await settled;
    expect(error).toBeInstanceOf(SecurityToolkitError);
    expect(error).toMatchObject({
      code: 'NATIVE_TIMEOUT',
      message: 'SecurityToolkit.check() did not complete within 500ms',
    });
  });

  it('clears its timer on success so it cannot fire later', async () => {
    await withTimeout(Promise.resolve('ok'), 1_000, 'call');
    expect(jest.getTimerCount()).toBe(0);
  });

  it('clears its timer on failure so it cannot fire later', async () => {
    await withTimeout(Promise.reject(new Error('x')), 1_000, 'call').catch(() => undefined);
    expect(jest.getTimerCount()).toBe(0);
  });
});
