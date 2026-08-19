import type { CheckId } from './result';

/**
 * Toolkit-wide configuration.
 *
 * Every option is optional and every default is chosen to be safe *and*
 * non-disruptive: the toolkit reports, it never blocks, terminates, or phones
 * home. See `docs/architecture/architecture-proposal.md#12-security-policy-architecture`.
 */
export interface SecurityToolkitOptions {
  /**
   * Marks this build as a development build.
   *
   * This does **not** hide findings — check results are byte-for-byte identical.
   * It only affects policy interpretation (debugger and emulator signals stop
   * contributing to a `blocked` decision) and stamps
   * `metadata.developmentMode = true` on reports so a development run can never
   * be mistaken for a production assessment.
   *
   * @defaultValue `false`
   */
  readonly developmentMode?: boolean;

  /**
   * Per-check timeout for native work, in milliseconds.
   *
   * A detector that hangs must never hang the caller. On timeout the check
   * resolves as `status: 'error'` rather than rejecting.
   *
   * @defaultValue `5000`
   */
  readonly nativeTimeoutMs?: number;

  /**
   * Checks to skip entirely.
   *
   * Skipped checks report `status: 'unavailable'` with
   * `unavailableReason: 'disabled-by-config'` — never a silent `secure`.
   *
   * @defaultValue `[]`
   */
  readonly disabledChecks?: readonly CheckId[];

  /**
   * Configuration for the integrity check.
   *
   * @see {@link IntegrityOptions}
   */
  readonly integrity?: IntegrityOptions;
}

/**
 * Configuration for the application integrity check.
 *
 * Three of the four integrity signals cannot say anything until the application
 * declares what it expects — there is no way to know whether a signing
 * certificate is the right one without being told which one is right. An
 * unconfigured signal reports `indeterminate`, never a passing result.
 */
export interface IntegrityOptions {
  /**
   * SHA-256 fingerprints of the signing certificates you published, one per
   * signer.
   *
   * Case and separators are ignored, so a value pasted from `apksigner`,
   * `keytool` or the Play Console works unchanged.
   */
  readonly signingCertificateSha256?: readonly string[];

  /**
   * Package names permitted to have installed this application, for example
   * `com.android.vending` for Google Play.
   */
  readonly expectedInstallers?: readonly string[];

  /** The package name this application is expected to run under (Android). */
  readonly expectedPackageName?: string;

  /** The bundle identifier this application is expected to run under (iOS). */
  readonly expectedBundleIdentifier?: string;
}

/** Fully resolved configuration, with defaults applied. */
export interface ResolvedSecurityToolkitOptions {
  readonly developmentMode: boolean;
  readonly nativeTimeoutMs: number;
  readonly disabledChecks: readonly CheckId[];
  readonly integrity: IntegrityOptions;
}

/** Information reported by the native security engine. */
export interface NativeEngineInfo {
  /** Platform the native engine was compiled for. */
  readonly platform: 'android' | 'ios';
  /** Operating system version string, as reported by the platform. */
  readonly osVersion: string;
  /** Version of the native engine, matched against the JS package version. */
  readonly engineVersion: string;
  /** Check identifiers this platform's engine implements. */
  readonly supportedChecks: readonly string[];
}
