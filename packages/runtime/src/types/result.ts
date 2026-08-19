/**
 * Core result model for every runtime security check.
 *
 * Design rule: a security check never returns a bare `boolean`. Callers need to
 * distinguish "we looked and found nothing" from "we could not look", and they
 * need the evidence behind a verdict in order to decide how much to trust it.
 *
 * @see docs/architecture/architecture-proposal.md#5-public-api-proposal
 */

/** Platforms the toolkit runs on. */
export type Platform = 'android' | 'ios';

/**
 * Outcome of a security check.
 *
 * These are **not interchangeable**. In particular `secure` asserts that the
 * check ran to completion and found nothing, while `unknown` means the check
 * ran but could not reach a verdict (for example a probe was blocked by the
 * platform). Reporting `unknown` as `secure` would overclaim.
 */
export type SecurityStatus =
  /** The check completed and found no indicators. */
  | 'secure'
  /** The check completed and found one or more indicators. */
  | 'detected'
  /** The check ran but could not reach a verdict; treat as inconclusive. */
  | 'unknown'
  /** The check does not apply here, or prerequisites are missing. */
  | 'unavailable'
  /** The check failed unexpectedly. Never thrown at the caller. */
  | 'error';

/**
 * How much weight a verdict deserves.
 *
 * Confidence is a property of the *evidence*, not of the severity. A single
 * filesystem-path hit is `low` even though root is severe; a hardware-backed
 * attestation is `high` even when it reports a clean device.
 */
export type SecurityConfidence = 'low' | 'medium' | 'high';

/**
 * Why a check reported {@link SecurityStatus} `unavailable`.
 *
 * Without this, `unavailable` is untriageable: an app author cannot tell an
 * expected platform mismatch from a setup step they still owe us.
 */
export type UnavailableReason =
  /** Check belongs to the other platform. Expected; no action needed. */
  | 'platform-not-supported'
  /** The OS denied a permission or query the check depends on. */
  | 'permission-denied'
  /** The device's OS version predates the API this check needs. */
  | 'api-level-too-low'
  /** The check needs configuration the app author has not supplied. */
  | 'not-configured'
  /** The check was switched off through {@link SecurityToolkitOptions}. */
  | 'disabled-by-config'
  /** Required hardware (for example StrongBox) is absent. */
  | 'hardware-not-present'
  /** The check cannot be meaningfully evaluated on a simulator. */
  | 'simulator';

/** Identifiers for the top-level checks exposed by the public API. */
export type CheckId =
  | 'root'
  | 'jailbreak'
  | 'debugger'
  | 'emulator'
  | 'simulator'
  | 'hooks'
  | 'integrity'
  | 'secureHardware'
  | 'biometrics'
  | 'network'
  | 'screen';

/**
 * Outcome of a single detection signal.
 *
 * `indeterminate` exists because a probe that could not run must never be
 * counted as evidence of safety — a blocked `/proc` read and a genuinely clean
 * device look identical unless the two are distinguished here.
 */
export type SignalOutcome = 'detected' | 'not-detected' | 'indeterminate';

/**
 * A single piece of evidence produced by one detector.
 *
 * Signals are additive: a check's verdict is derived from its signals, and the
 * signals are always returned so an app author can audit the reasoning rather
 * than trusting an opaque verdict.
 */
export interface SecuritySignal {
  /** Stable identifier, e.g. `RNSEC-ANDROID-ROOT-001`. Never renumbered once published. */
  readonly id: string;
  /** What the probe concluded. See {@link SignalOutcome}. */
  readonly outcome: SignalOutcome;
  /** Convenience mirror of `outcome === 'detected'`. Never true for `indeterminate`. */
  readonly detected: boolean;
  /** Confidence of this signal **in isolation**, before corroboration. */
  readonly confidence: SecurityConfidence;
  /**
   * Human-readable description, phrased as an indicator rather than a verdict
   * ("Potential Magisk-related runtime indicator detected").
   */
  readonly description: string;
  /** Detector-specific detail. Never contains user data or biometric material. */
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/** Result of one security check. */
export interface SecurityCheckResult {
  /** Which check this is. */
  readonly id: CheckId;
  /** Outcome. See {@link SecurityStatus}. */
  readonly status: SecurityStatus;
  /** Convenience mirror of `status === 'detected'`. Never true for `unknown`. */
  readonly detected: boolean;
  /** Aggregate confidence, raised only by corroborating signals. */
  readonly confidence: SecurityConfidence;
  /** Platform the check ran on. */
  readonly platform: Platform;
  /** Every signal the detector produced, including ones that did not fire. */
  readonly signals: readonly SecuritySignal[];
  /** Present only when `status === 'unavailable'`. */
  readonly unavailableReason?: UnavailableReason;
  /** Present only when `status === 'error'`. Diagnostic text, never a thrown value. */
  readonly errorMessage?: string;
  /** Check-specific detail (capabilities, versions, configuration echoes). */
  readonly metadata?: Readonly<Record<string, unknown>>;
  /** Wall-clock duration of the native check, in milliseconds. */
  readonly durationMs: number;
  /** ISO 8601 timestamp of completion. */
  readonly checkedAt: string;
}
