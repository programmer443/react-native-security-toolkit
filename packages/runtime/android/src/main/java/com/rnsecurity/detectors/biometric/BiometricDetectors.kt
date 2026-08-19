package com.rnsecurity.detectors.biometric

import android.content.pm.PackageManager
import com.rnsecurity.engine.CheckEngine
import com.rnsecurity.engine.CheckOptions
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.Detector
import com.rnsecurity.engine.SecuritySignal
import com.rnsecurity.engine.SignalOutcome
import com.rnsecurity.probe.ProbeSet

/**
 * Biometric capability reporting for Android.
 *
 * Capability only. **No biometric data is read, stored, transmitted or exposed**
 * by this check, and none is available to it — the platform reports a status
 * code and nothing else. Nothing here can identify a user or say whose finger or
 * face is enrolled.
 *
 * As with secure hardware, `detected` means "a weakness indicator fired", not
 * "an attack was found": the device is capable of less than an application
 * relying on biometric authentication would want.
 *
 * A caveat worth stating plainly: an unenrolled device is not an insecure
 * device. Many people deliberately use a PIN and no biometric, and that is a
 * perfectly good choice. These signals exist so an application can decide
 * whether biometric authentication is a viable gate, not so it can nag.
 *
 * See `docs/runtime/biometrics.md`.
 */

/** Platform `BiometricManager` status codes, named so the mapping is auditable. */
private object BiometricStatus {
  const val SUCCESS = 0
  const val ERROR_HW_UNAVAILABLE = 1
  const val ERROR_NONE_ENROLLED = 11
  const val ERROR_NO_HARDWARE = 12
  const val ERROR_SECURITY_UPDATE_REQUIRED = 15
}

private fun indeterminate(
  id: String,
  confidence: Confidence,
  why: String,
  reason: String? = null
) =
  SecuritySignal(
    id = id,
    outcome = SignalOutcome.INDETERMINATE,
    confidence = confidence,
    description = "Biometric capability could not be determined: $why",
    metadata = mapOf("unavailableReason" to reason)
  )

/** Turns a probe reason code into something an application author can act on. */
private fun explain(reason: String?): String =
  when (reason) {
    "permission" ->
      "the USE_BIOMETRIC permission is not declared by this application, so the platform " +
        "refused the query"
    "api-level" -> "this API level cannot answer the query"
    "service-unavailable" -> "the biometric service was unavailable"
    else -> "the platform did not report a biometric status"
  }

private fun outcomeOf(weaknessPresent: Boolean) =
  if (weaknessPresent) SignalOutcome.DETECTED else SignalOutcome.NOT_DETECTED

/** Platform features backing the three biometric modalities Android recognises. */
private val BIOMETRIC_FEATURES =
  listOf(
    PackageManager.FEATURE_FINGERPRINT,
    PackageManager.FEATURE_FACE,
    PackageManager.FEATURE_IRIS
  )

/**
 * Whether the device has any biometric hardware at all, from platform features.
 *
 * `BiometricManager` is absent on devices with no biometric hardware — including
 * most emulators — so a null status is ambiguous on its own. The feature flags
 * disambiguate it: all three absent means "no hardware", which is a real answer,
 * whereas an unreadable feature list stays `null` and remains inconclusive.
 */
private fun ProbeSet.hasAnyBiometricHardware(): Boolean? {
  val answers = BIOMETRIC_FEATURES.map { device.hasSystemFeature(it) }
  if (answers.all { it == null }) {
    return null
  }
  return answers.any { it == true }
}

/**
 * Class 3 (strong) biometric authentication is not usable.
 *
 * Only Class 3 biometrics can gate an Android Keystore key, which is what makes
 * biometric authentication meaningful rather than decorative. A device offering
 * only weak biometrics can prompt the user, but cannot bind that prompt to a key.
 */
internal class StrongBiometricDetector : Detector {
  override val id = "RNSEC-RUNTIME-BIOMETRIC-001"

  override val minSdk = 30

  override fun detect(probes: ProbeSet): SecuritySignal {
    val status = probes.authentication.strongBiometricStatus()

    if (status == null) {
      // No BiometricManager. If the device also reports no biometric hardware,
      // that is a definite answer rather than an unknown one.
      val reason = probes.authentication.biometricUnavailableReason()
      val hasHardware =
        probes.hasAnyBiometricHardware()
          ?: return indeterminate(id, Confidence.HIGH, explain(reason), reason)

      if (hasHardware) {
        return indeterminate(id, Confidence.HIGH, explain(reason), reason)
      }

      return SecuritySignal(
        id = id,
        outcome = SignalOutcome.DETECTED,
        confidence = Confidence.HIGH,
        description =
          "Strong (Class 3) biometric authentication is not currently usable: no supporting hardware",
        metadata = mapOf("platformStatus" to null, "reason" to "no supporting hardware")
      )
    }

    val usable = status == BiometricStatus.SUCCESS

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(!usable),
      confidence = Confidence.HIGH,
      description =
        if (usable) {
          "Strong (Class 3) biometric authentication is available and enrolled"
        } else {
          "Strong (Class 3) biometric authentication is not currently usable: ${reasonFor(status)}"
        },
      metadata = mapOf("platformStatus" to status, "reason" to reasonFor(status))
    )
  }

  private fun reasonFor(status: Int): String =
    when (status) {
      BiometricStatus.SUCCESS -> "available"
      BiometricStatus.ERROR_NO_HARDWARE -> "no supporting hardware"
      BiometricStatus.ERROR_HW_UNAVAILABLE -> "hardware temporarily unavailable"
      BiometricStatus.ERROR_NONE_ENROLLED -> "nothing enrolled"
      BiometricStatus.ERROR_SECURITY_UPDATE_REQUIRED -> "a security update is required"
      else -> "reported status $status"
    }
}

/**
 * No biometric is enrolled, though the hardware exists.
 *
 * Separated from [StrongBiometricDetector] because the two call for completely
 * different responses: missing hardware is permanent and the application must
 * design around it, whereas nothing enrolled is something the user can change in
 * a few seconds.
 */
internal class BiometricEnrolmentDetector : Detector {
  override val id = "RNSEC-RUNTIME-BIOMETRIC-002"

  override val minSdk = 30

  override fun detect(probes: ProbeSet): SecuritySignal {
    val status = probes.authentication.biometricStatus()

    if (status == null) {
      val reason = probes.authentication.biometricUnavailableReason()
      val hasHardware =
        probes.hasAnyBiometricHardware()
          ?: return indeterminate(id, Confidence.MEDIUM, explain(reason), reason)

      if (hasHardware) {
        return indeterminate(id, Confidence.MEDIUM, explain(reason), reason)
      }

      // Nothing to enrol on. Prompting the user to enrol here would ask them to
      // fix something they cannot fix.
      return SecuritySignal(
        id = id,
        outcome = SignalOutcome.NOT_DETECTED,
        confidence = Confidence.MEDIUM,
        description = "The device has no biometric hardware",
        metadata = mapOf("platformStatus" to null, "hardwarePresent" to false)
      )
    }

    val hardwarePresent = status != BiometricStatus.ERROR_NO_HARDWARE
    val nothingEnrolled = status == BiometricStatus.ERROR_NONE_ENROLLED

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(hardwarePresent && nothingEnrolled),
      confidence = Confidence.MEDIUM,
      description =
        if (hardwarePresent && nothingEnrolled) {
          "The device supports biometrics but nothing is enrolled"
        } else if (!hardwarePresent) {
          "The device has no biometric hardware"
        } else {
          "A biometric is enrolled on this device"
        },
      metadata = mapOf("platformStatus" to status, "hardwarePresent" to hardwarePresent)
    )
  }
}

/**
 * No device credential is set.
 *
 * The floor beneath everything else: without a PIN, pattern or password there is
 * no keyguard, biometric enrolment is impossible, and Keystore keys cannot
 * require user authentication. This is the one signal here that is unambiguously
 * a weakness.
 */
internal class DeviceCredentialDetector : Detector {
  override val id = "RNSEC-RUNTIME-BIOMETRIC-003"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val secure =
      probes.authentication.isDeviceSecure()
        ?: return indeterminate(id, Confidence.HIGH, "the keyguard state was unavailable")

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(!secure),
      confidence = Confidence.HIGH,
      description =
        if (secure) {
          "A device credential (PIN, pattern or password) is set"
        } else {
          "No device credential is set, so the device has no lock screen"
        },
      metadata = mapOf("deviceSecure" to secure)
    )
  }
}

/** The biometrics check. */
internal class BiometricCheckEngine : CheckEngine {
  override val checkId = "biometrics"

  override fun detectors(options: CheckOptions): List<Detector> =
    listOf(StrongBiometricDetector(), BiometricEnrolmentDetector(), DeviceCredentialDetector())

  override fun metadata(probes: ProbeSet, options: CheckOptions): Map<String, Any?> =
    mapOf("note" to "Capability only. No biometric data is read, stored or exposed.")
}
