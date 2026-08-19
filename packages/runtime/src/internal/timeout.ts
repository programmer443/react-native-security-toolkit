import { SecurityToolkitError } from './errors';

/**
 * Rejects with a {@link SecurityToolkitError} if `promise` does not settle in time.
 *
 * A detector that never returns must not become a check that never returns. The
 * timer is always cleared, including on the success path, so a resolved check
 * cannot keep a timer alive and delay teardown in a test or a short-lived process.
 */
export function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(
        new SecurityToolkitError(
          'NATIVE_TIMEOUT',
          `${label} did not complete within ${timeoutMs}ms`
        )
      );
    }, timeoutMs);

    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}
