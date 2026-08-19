package com.rnsecurity.detectors.hardware

import com.rnsecurity.FakeDeviceFeatureProbe
import com.rnsecurity.FakeKeystoreProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.SignalOutcome
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * For capability checks, `DETECTED` means "a weakness indicator fired" rather
 * than "an attack was found". These tests pin that polarity down, because
 * getting it backwards would report a hardware-backed device as the problem.
 */
class SecureHardwareDetectorsTest {

  @Test
  fun `key backing detector stays quiet when keys land in secure hardware`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      KeyStorageBackingDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `key backing detector fires when keys are software-backed`() {
    val signal =
      KeyStorageBackingDetector()
        .detect(cleanDeviceProbes(keystore = FakeKeystoreProbe(level = "software")))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(Confidence.HIGH, signal.confidence)
  }

  @Test
  fun `key backing detector treats strongbox as secure hardware`() {
    val signal =
      KeyStorageBackingDetector()
        .detect(cleanDeviceProbes(keystore = FakeKeystoreProbe(level = "strongbox")))

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
    assertEquals("strongbox", signal.metadata["securityLevel"])
  }

  /** "Secure but unnamed" is not the same as "trusted", and must not be reported as it. */
  @Test
  fun `key backing detector reports indeterminate for an unnamed security level`() {
    val signal =
      KeyStorageBackingDetector()
        .detect(cleanDeviceProbes(keystore = FakeKeystoreProbe(level = "unknown")))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  @Test
  fun `key backing detector reports indeterminate when no key can be generated`() {
    val signal =
      KeyStorageBackingDetector().detect(cleanDeviceProbes(keystore = FakeKeystoreProbe(level = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── StrongBox ──────────────────────────────────────────────────────────────

  @Test
  fun `strongbox detector fires when strongbox is absent`() {
    val signal =
      StrongBoxDetector()
        .detect(cleanDeviceProbes(device = FakeDeviceFeatureProbe(defaultFeature = false)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    // Most Android devices have no StrongBox. This must never drive a verdict.
    assertEquals(Confidence.LOW, signal.confidence)
  }

  @Test
  fun `strongbox detector stays quiet when strongbox is present`() {
    assertEquals(SignalOutcome.NOT_DETECTED, StrongBoxDetector().detect(cleanDeviceProbes()).outcome)
  }

  @Test
  fun `strongbox detector reports indeterminate without a feature list`() {
    val signal =
      StrongBoxDetector()
        .detect(cleanDeviceProbes(device = FakeDeviceFeatureProbe(defaultFeature = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── attestation ────────────────────────────────────────────────────────────

  @Test
  fun `attestation detector fires when attestation is unavailable`() {
    val signal =
      KeyAttestationDetector()
        .detect(cleanDeviceProbes(device = FakeDeviceFeatureProbe(defaultFeature = false)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `attestation detector stays quiet when attestation is available`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      KeyAttestationDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `attestation detector is gated to the API level that introduced the feature`() {
    assertEquals(31, KeyAttestationDetector().minSdk)
  }
}
