package com.rnsecurity.detectors.integrity

import com.rnsecurity.FakeApplicationProbe
import com.rnsecurity.FakePackageIntegrityProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.engine.SignalOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IntegrityDetectorsTest {

  private val expectedCert = FakePackageIntegrityProbe.EXPECTED_CERT

  // ── signing certificate ────────────────────────────────────────────────────

  @Test
  fun `signing detector accepts a configured fingerprint`() {
    val signal = SigningCertificateDetector(listOf(expectedCert)).detect(cleanDeviceProbes())

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  @Test
  fun `signing detector fires on an unrecognised certificate`() {
    val signal =
      SigningCertificateDetector(listOf(expectedCert))
        .detect(
          cleanDeviceProbes(
            packageIntegrity =
              FakePackageIntegrityProbe(certificates = listOf("0".repeat(64)))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(1, signal.metadata["unrecognisedSignerCount"])
  }

  /**
   * A fingerprint pasted from `apksigner`, `keytool` or the Play Console carries
   * colons and varying case. Requiring one exact spelling would produce a
   * configuration mistake that looks identical to a tampered build.
   */
  @Test
  fun `signing detector ignores separators and case in configured fingerprints`() {
    val punctuated = expectedCert.chunked(2).joinToString(":").lowercase()
    val signal = SigningCertificateDetector(listOf(punctuated)).detect(cleanDeviceProbes())

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  /**
   * The most important case in this file. An unconfigured check must never look
   * like a check that passed.
   */
  @Test
  fun `signing detector reports indeterminate when nothing is configured`() {
    val signal = SigningCertificateDetector(null).detect(cleanDeviceProbes())

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
    assertTrue(signal.description.contains("no expected signing certificates"))
  }

  @Test
  fun `signing detector reports indeterminate when the certificate is unreadable`() {
    val signal =
      SigningCertificateDetector(listOf(expectedCert))
        .detect(cleanDeviceProbes(packageIntegrity = FakePackageIntegrityProbe(certificates = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  @Test
  fun `signing detector reports indeterminate when no signers are reported`() {
    val signal =
      SigningCertificateDetector(listOf(expectedCert))
        .detect(
          cleanDeviceProbes(packageIntegrity = FakePackageIntegrityProbe(certificates = emptyList()))
        )

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  @Test
  fun `signing detector accepts a multi-signer build when every signer is configured`() {
    val second = "F".repeat(64)
    val signal =
      SigningCertificateDetector(listOf(expectedCert, second))
        .detect(
          cleanDeviceProbes(
            packageIntegrity = FakePackageIntegrityProbe(certificates = listOf(expectedCert, second))
          )
        )

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
    assertEquals(2, signal.metadata["signerCount"])
  }

  // ── install source ─────────────────────────────────────────────────────────

  @Test
  fun `install source detector accepts a configured installer`() {
    val signal = InstallSourceDetector(listOf("com.android.vending")).detect(cleanDeviceProbes())

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  @Test
  fun `install source detector fires on an unexpected installer`() {
    val signal =
      InstallSourceDetector(listOf("com.android.vending"))
        .detect(cleanDeviceProbes(packageIntegrity = FakePackageIntegrityProbe(installer = "com.other.store")))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  /** A null installer means a direct install. That is an answer, not a failure. */
  @Test
  fun `install source detector fires on a direct install`() {
    val signal =
      InstallSourceDetector(listOf("com.android.vending"))
        .detect(cleanDeviceProbes(packageIntegrity = FakePackageIntegrityProbe(installer = null)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertTrue(signal.description.contains("installed directly"))
  }

  @Test
  fun `install source detector reports indeterminate when nothing is configured`() {
    assertEquals(SignalOutcome.INDETERMINATE, InstallSourceDetector(null).detect(cleanDeviceProbes()).outcome)
  }

  // ── package identity ───────────────────────────────────────────────────────

  @Test
  fun `package identity detector accepts the configured package name`() {
    val signal = PackageIdentityDetector("com.example.app").detect(cleanDeviceProbes())

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  @Test
  fun `package identity detector fires on a repackaged application`() {
    val signal =
      PackageIdentityDetector("com.example.app")
        .detect(cleanDeviceProbes(application = FakeApplicationProbe(packageName = "com.evil.clone")))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `package identity detector reports indeterminate when nothing is configured`() {
    assertEquals(
      SignalOutcome.INDETERMINATE,
      PackageIdentityDetector(null).detect(cleanDeviceProbes()).outcome
    )
  }

  // ── APK location ───────────────────────────────────────────────────────────

  @Test
  fun `apk location detector accepts a normal install path`() {
    assertEquals(SignalOutcome.NOT_DETECTED, ApkLocationDetector().detect(cleanDeviceProbes()).outcome)
  }

  /** Preinstalled system applications are legitimate and must not be flagged. */
  @Test
  fun `apk location detector accepts a preinstalled system path`() {
    val signal =
      ApkLocationDetector()
        .detect(
          cleanDeviceProbes(
            packageIntegrity =
              FakePackageIntegrityProbe(sourceDir = "/system/priv-app/Example/Example.apk")
          )
        )

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  @Test
  fun `apk location detector fires on an unusual path`() {
    val signal =
      ApkLocationDetector()
        .detect(
          cleanDeviceProbes(
            packageIntegrity = FakePackageIntegrityProbe(sourceDir = "/data/local/tmp/base.apk")
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `apk location detector reports indeterminate when the path is unreadable`() {
    val signal =
      ApkLocationDetector()
        .detect(cleanDeviceProbes(packageIntegrity = FakePackageIntegrityProbe(sourceDir = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }
}
