package com.rnsecurity.engine

/**
 * Turns a detector's signals into a check verdict.
 *
 * Two rules do the real work here.
 *
 * **`unknown` is not `secure`.** If any probe could not run, the check cannot
 * claim the device is clean — a blocked `/proc` read or a missing `<queries>`
 * declaration produces `unknown`, never `secure`. Reporting the absence of
 * evidence as evidence of absence is the single most dangerous thing a security
 * check can do.
 *
 * **Corroboration raises confidence; a lone weak signal does not.** A single
 * filesystem-path hit stays `low` no matter how severe root is. Confidence is a
 * property of the evidence, not of the consequence.
 */
object SignalAggregator {

  /** Number of independent low-confidence hits that together justify `medium`. */
  private const val LOW_SIGNALS_FOR_MEDIUM = 3

  /** Number of independent medium-confidence hits that together justify `high`. */
  private const val MEDIUM_SIGNALS_FOR_HIGH = 2

  fun aggregate(
    checkId: String,
    signals: List<SecuritySignal>,
    metadata: Map<String, Any?> = emptyMap(),
    durationMs: Long = 0,
    checkedAtEpochMs: Long = 0
  ): CheckResult {
    val detected = signals.filter { it.outcome == SignalOutcome.DETECTED }
    val indeterminate = signals.any { it.outcome == SignalOutcome.INDETERMINATE }

    val status =
      when {
        detected.isNotEmpty() -> CheckStatus.DETECTED
        indeterminate -> CheckStatus.UNKNOWN
        else -> CheckStatus.SECURE
      }

    val confidence =
      when (status) {
        CheckStatus.DETECTED -> detectionConfidence(detected)
        // Some probes were blocked, so "no indicators" is a weak statement.
        CheckStatus.UNKNOWN -> Confidence.LOW
        // Every probe ran and none fired. That is as strong as this check gets —
        // which still says nothing about whether a bypass is in play.
        CheckStatus.SECURE -> Confidence.HIGH
        else -> Confidence.LOW
      }

    return CheckResult(
      id = checkId,
      status = status,
      confidence = confidence,
      signals = signals,
      metadata = metadata,
      durationMs = durationMs,
      checkedAtEpochMs = checkedAtEpochMs
    )
  }

  private fun detectionConfidence(detected: List<SecuritySignal>): Confidence {
    val high = detected.count { it.confidence == Confidence.HIGH }
    val medium = detected.count { it.confidence == Confidence.MEDIUM }
    val low = detected.count { it.confidence == Confidence.LOW }

    return when {
      high > 0 -> Confidence.HIGH
      medium >= MEDIUM_SIGNALS_FOR_HIGH -> Confidence.HIGH
      medium > 0 -> Confidence.MEDIUM
      low >= LOW_SIGNALS_FOR_MEDIUM -> Confidence.MEDIUM
      else -> Confidence.LOW
    }
  }

  /** Builds an `unavailable` result: the check did not run, and says why. */
  fun unavailable(
    checkId: String,
    reason: UnavailableReason,
    checkedAtEpochMs: Long = 0
  ): CheckResult =
    CheckResult(
      id = checkId,
      status = CheckStatus.UNAVAILABLE,
      confidence = Confidence.LOW,
      signals = emptyList(),
      unavailableReason = reason,
      checkedAtEpochMs = checkedAtEpochMs
    )

  /** Builds an `error` result. A failing detector degrades; it never throws at the app. */
  fun error(checkId: String, message: String, checkedAtEpochMs: Long = 0): CheckResult =
    CheckResult(
      id = checkId,
      status = CheckStatus.ERROR,
      confidence = Confidence.LOW,
      signals = emptyList(),
      errorMessage = message,
      checkedAtEpochMs = checkedAtEpochMs
    )
}
