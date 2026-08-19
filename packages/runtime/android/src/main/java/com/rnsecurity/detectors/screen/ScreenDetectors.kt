package com.rnsecurity.detectors.screen

import com.rnsecurity.engine.CheckEngine
import com.rnsecurity.engine.CheckOptions
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.Detector
import com.rnsecurity.engine.SecuritySignal
import com.rnsecurity.engine.SignalOutcome
import com.rnsecurity.probe.ProbeSet

/**
 * Screen capture protection state for Android.
 *
 * Reports whether `FLAG_SECURE` is currently applied. Unlike the detection
 * checks, this one describes something the application itself controls through
 * `ScreenSecurity.enableProtection()`.
 *
 * `FLAG_SECURE` is genuine prevention on Android — screenshots and recordings of
 * a flagged window are blocked by the platform, not merely detected. That is a
 * real asymmetry with iOS, and the feature matrix reflects it rather than
 * flattening the two into one tick.
 *
 * See `docs/runtime/screen-security.md`.
 */
internal class SecureFlagDetector : Detector {
  override val id = "RNSEC-ANDROID-SCREEN-001"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val secure =
      probes.screen.isSecureFlagSet()
        ?: return SecuritySignal(
          id = id,
          outcome = SignalOutcome.INDETERMINATE,
          confidence = Confidence.HIGH,
          description =
            "Screen protection state could not be evaluated: there is no active window to inspect"
        )

    return SecuritySignal(
      id = id,
      outcome = if (secure) SignalOutcome.NOT_DETECTED else SignalOutcome.DETECTED,
      confidence = Confidence.HIGH,
      description =
        if (secure) {
          "Screen capture protection is applied to the current window"
        } else {
          "Screen capture protection is not applied to the current window"
        },
      metadata = mapOf("flagSecureSet" to secure)
    )
  }
}

/** The screen security check. */
internal class ScreenCheckEngine : CheckEngine {
  override val checkId = "screen"

  override fun detectors(options: CheckOptions): List<Detector> = listOf(SecureFlagDetector())

  override fun metadata(probes: ProbeSet, options: CheckOptions): Map<String, Any?> =
    mapOf(
      // Stated in the result because it is the limitation most likely to be
      // missed by someone who enabled protection and assumed it was total.
      "note" to
        "FLAG_SECURE is per-window. Dialogs and React Native modals create their own windows."
    )
}
