package com.rnsecurity.engine

/**
 * The result model shared by every Android detector.
 *
 * Mirrors the TypeScript types in `src/types/result.ts`. The distinction the
 * whole model turns on is between *"we looked and found nothing"* and *"we could
 * not look"* — collapsing those two into a boolean is how a security check ends
 * up quietly reporting a compromised device as clean.
 */

/** Outcome of a single detection signal. */
enum class SignalOutcome {
  /** The indicator fired. */
  DETECTED,

  /** The probe ran and the indicator did not fire. */
  NOT_DETECTED,

  /**
   * The probe could not run — a restricted path, a missing API level, a denied
   * permission. Never treated as evidence of safety.
   */
  INDETERMINATE;

  fun wireValue(): String =
    when (this) {
      DETECTED -> "detected"
      NOT_DETECTED -> "not-detected"
      INDETERMINATE -> "indeterminate"
    }
}

/** How much weight a signal carries on its own, before corroboration. */
enum class Confidence {
  LOW,
  MEDIUM,
  HIGH;

  fun wireValue(): String = name.lowercase()
}

/** Outcome of a whole check. */
enum class CheckStatus {
  SECURE,
  DETECTED,
  UNKNOWN,
  UNAVAILABLE,
  ERROR;

  fun wireValue(): String = name.lowercase()
}

/** Why a check reported [CheckStatus.UNAVAILABLE]. */
enum class UnavailableReason {
  PLATFORM_NOT_SUPPORTED,
  PERMISSION_DENIED,
  API_LEVEL_TOO_LOW,
  NOT_CONFIGURED,
  DISABLED_BY_CONFIG,
  HARDWARE_NOT_PRESENT,

  /**
   * The check cannot be meaningfully evaluated on a simulator.
   *
   * Unused on Android — emulator detection is a check in its own right here —
   * but kept so the three layers share one vocabulary.
   */
  SIMULATOR;

  fun wireValue(): String = name.lowercase().replace('_', '-')
}

/**
 * One piece of evidence.
 *
 * @property id stable identifier, e.g. `RNSEC-ANDROID-ROOT-001`. Never renumbered
 *   once published.
 * @property description phrased as an indicator, never as a verdict.
 * @property metadata detector-specific detail. Must never contain user data.
 */
data class SecuritySignal(
  val id: String,
  val outcome: SignalOutcome,
  val confidence: Confidence,
  val description: String,
  val metadata: Map<String, Any?> = emptyMap()
) {
  val detected: Boolean get() = outcome == SignalOutcome.DETECTED
}

/** Result of one check. */
data class CheckResult(
  val id: String,
  val status: CheckStatus,
  val confidence: Confidence,
  val signals: List<SecuritySignal>,
  val unavailableReason: UnavailableReason? = null,
  val errorMessage: String? = null,
  val metadata: Map<String, Any?> = emptyMap(),
  val durationMs: Long = 0,
  val checkedAtEpochMs: Long = 0
) {
  val detected: Boolean get() = status == CheckStatus.DETECTED
}
