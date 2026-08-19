package com.rnsecurity.detectors.biometric

import com.rnsecurity.FakeAuthenticationProbe
import com.rnsecurity.FakeDeviceFeatureProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.SignalOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BiometricDetectorsTest {

  private companion object {
    const val SUCCESS = 0
    const val ERROR_HW_UNAVAILABLE = 1
    const val ERROR_NONE_ENROLLED = 11
    const val ERROR_NO_HARDWARE = 12
    const val ERROR_SECURITY_UPDATE_REQUIRED = 15
  }

  // ── strong biometrics ──────────────────────────────────────────────────────

  @Test
  fun `strong biometric detector stays quiet when Class 3 is usable`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      StrongBiometricDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `strong biometric detector fires when no hardware is present`() {
    val signal =
      StrongBiometricDetector()
        .detect(
          cleanDeviceProbes(
            authentication = FakeAuthenticationProbe(strongBiometric = ERROR_NO_HARDWARE)
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals("no supporting hardware", signal.metadata["reason"])
  }

  /** The reason matters: each of these calls for a different application response. */
  @Test
  fun `strong biometric detector distinguishes why Class 3 is unusable`() {
    val cases =
      mapOf(
        ERROR_NONE_ENROLLED to "nothing enrolled",
        ERROR_HW_UNAVAILABLE to "hardware temporarily unavailable",
        ERROR_SECURITY_UPDATE_REQUIRED to "a security update is required"
      )

    for ((status, expected) in cases) {
      val signal =
        StrongBiometricDetector()
          .detect(cleanDeviceProbes(authentication = FakeAuthenticationProbe(strongBiometric = status)))

      assertEquals(SignalOutcome.DETECTED, signal.outcome)
      assertEquals(expected, signal.metadata["reason"])
    }
  }

  /** Hardware present but no status: genuinely unknown. */
  @Test
  fun `strong biometric detector reports indeterminate when hardware exists but status is absent`() {
    val signal =
      StrongBiometricDetector()
        .detect(cleanDeviceProbes(authentication = FakeAuthenticationProbe(strongBiometric = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  /**
   * `BiometricManager` is absent on devices with no biometric hardware, most
   * emulators included. The platform feature flags turn that ambiguity into a
   * definite answer rather than leaving the check inconclusive.
   */
  @Test
  fun `strong biometric detector falls back to feature flags when no status is reported`() {
    val signal =
      StrongBiometricDetector()
        .detect(
          cleanDeviceProbes(
            authentication = FakeAuthenticationProbe(strongBiometric = null),
            device = FakeDeviceFeatureProbe(defaultFeature = false)
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals("no supporting hardware", signal.metadata["reason"])
  }

  /**
   * "Could not be determined" is not actionable. The most common cause — a
   * missing USE_BIOMETRIC declaration — is entirely within the application's
   * control, so the signal has to say so.
   */
  @Test
  fun `strong biometric detector explains a missing permission`() {
    val signal =
      StrongBiometricDetector()
        .detect(
          cleanDeviceProbes(
            authentication =
              FakeAuthenticationProbe(strongBiometric = null, unavailableReason = "permission")
          )
        )

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
    assertTrue(signal.description.contains("USE_BIOMETRIC"))
    assertEquals("permission", signal.metadata["unavailableReason"])
  }

  @Test
  fun `strong biometric detector stays inconclusive when feature flags are unreadable too`() {
    val signal =
      StrongBiometricDetector()
        .detect(
          cleanDeviceProbes(
            authentication = FakeAuthenticationProbe(strongBiometric = null),
            device = FakeDeviceFeatureProbe(defaultFeature = null)
          )
        )

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  @Test
  fun `strong biometric detector is gated to the API level that introduced the query`() {
    assertEquals(30, StrongBiometricDetector().minSdk)
  }

  // ── enrolment ──────────────────────────────────────────────────────────────

  @Test
  fun `enrolment detector fires when hardware exists but nothing is enrolled`() {
    val signal =
      BiometricEnrolmentDetector()
        .detect(
          cleanDeviceProbes(authentication = FakeAuthenticationProbe(biometric = ERROR_NONE_ENROLLED))
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(true, signal.metadata["hardwarePresent"])
  }

  /**
   * A device with no biometric hardware has nothing to enrol. Reporting that as
   * "nothing enrolled" would prompt an application to ask the user to fix
   * something they cannot fix.
   */
  @Test
  fun `enrolment detector does not fire when there is no hardware to enrol on`() {
    val signal =
      BiometricEnrolmentDetector()
        .detect(cleanDeviceProbes(authentication = FakeAuthenticationProbe(biometric = ERROR_NO_HARDWARE)))

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
    assertTrue(signal.description.contains("no biometric hardware"))
  }

  @Test
  fun `enrolment detector stays quiet when a biometric is enrolled`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      BiometricEnrolmentDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `enrolment detector reports indeterminate when hardware exists but status is absent`() {
    val signal =
      BiometricEnrolmentDetector()
        .detect(cleanDeviceProbes(authentication = FakeAuthenticationProbe(biometric = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  @Test
  fun `enrolment detector falls back to feature flags when no status is reported`() {
    val signal =
      BiometricEnrolmentDetector()
        .detect(
          cleanDeviceProbes(
            authentication = FakeAuthenticationProbe(biometric = null),
            device = FakeDeviceFeatureProbe(defaultFeature = false)
          )
        )

    // No hardware means nothing to enrol, which is not a weakness to report.
    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
    assertEquals(false, signal.metadata["hardwarePresent"])
  }

  // ── device credential ──────────────────────────────────────────────────────

  @Test
  fun `device credential detector fires when there is no lock screen`() {
    val signal =
      DeviceCredentialDetector()
        .detect(cleanDeviceProbes(authentication = FakeAuthenticationProbe(deviceSecure = false)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(Confidence.HIGH, signal.confidence)
  }

  @Test
  fun `device credential detector stays quiet when a credential is set`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      DeviceCredentialDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `device credential detector reports indeterminate when the keyguard is unreadable`() {
    val signal =
      DeviceCredentialDetector()
        .detect(cleanDeviceProbes(authentication = FakeAuthenticationProbe(deviceSecure = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  /** Nothing in this check may expose biometric material. */
  @Test
  fun `no signal metadata carries biometric data`() {
    val signals =
      listOf(
        StrongBiometricDetector().detect(cleanDeviceProbes()),
        BiometricEnrolmentDetector().detect(cleanDeviceProbes()),
        DeviceCredentialDetector().detect(cleanDeviceProbes())
      )

    val allowedKeys = setOf("platformStatus", "reason", "hardwarePresent", "deviceSecure")
    for (signal in signals) {
      assertTrue(allowedKeys.containsAll(signal.metadata.keys))
    }
  }
}
