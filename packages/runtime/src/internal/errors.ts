/** Machine-readable error codes for failures the caller can act on. */
export type SecurityToolkitErrorCode =
  /** The native module is not linked into the host application. */
  | 'NATIVE_MODULE_UNAVAILABLE'
  /** Native work exceeded the configured timeout. */
  | 'NATIVE_TIMEOUT'
  /** The native layer returned a payload that failed validation. */
  | 'INVALID_NATIVE_PAYLOAD'
  /** Configuration supplied by the application is invalid. */
  | 'INVALID_CONFIGURATION';

/**
 * The only error type this package throws.
 *
 * Thrown exclusively for **programmer errors** — a missing native module, an
 * invalid configuration value, or a native payload that failed validation.
 * Ordinary platform limitations are never thrown; they are reported as
 * `status: 'unavailable'` on a result (§51).
 */
export class SecurityToolkitError extends Error {
  public readonly code: SecurityToolkitErrorCode;

  constructor(code: SecurityToolkitErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'SecurityToolkitError';
    this.code = code;
    // Preserve a usable prototype chain when compiled to older targets.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Type guard for {@link SecurityToolkitError}. */
export function isSecurityToolkitError(value: unknown): value is SecurityToolkitError {
  return value instanceof SecurityToolkitError;
}
