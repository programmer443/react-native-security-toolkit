package com.rnsecurity.detectors.integrity

import com.rnsecurity.engine.CheckEngine
import com.rnsecurity.engine.CheckOptions
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.Detector
import com.rnsecurity.engine.SecuritySignal
import com.rnsecurity.engine.SignalOutcome
import com.rnsecurity.probe.ProbeSet

/**
 * Application integrity signals for Android.
 *
 * Two of these need the application to say what it expects — there is no way to
 * know whether a signing certificate is the right one without being told which
 * one is right. An unconfigured signal reports `indeterminate` with a
 * description saying so, never "not detected": silently passing a check that was
 * never actually performed is the worst outcome available here.
 *
 * Genuine integrity assurance on Android comes from **Play Integrity**, verified
 * server-side. These signals detect sideloading, re-signing and repackaging
 * cheaply and locally; they are not a substitute for attestation.
 *
 * See `docs/runtime/integrity.md`.
 */

private fun indeterminate(id: String, confidence: Confidence, why: String) =
  SecuritySignal(
    id = id,
    outcome = SignalOutcome.INDETERMINATE,
    confidence = confidence,
    description = "Integrity indicator could not be evaluated: $why"
  )

private fun outcomeOf(detected: Boolean) =
  if (detected) SignalOutcome.DETECTED else SignalOutcome.NOT_DETECTED

/** Option keys the application supplies through `SecurityToolkit.configure`. */
internal object IntegrityOptionKeys {
  const val SIGNING_CERTIFICATES = "signingCertificateSha256"
  const val EXPECTED_INSTALLERS = "expectedInstallers"
  const val EXPECTED_PACKAGE_NAME = "expectedPackageName"
}

/**
 * The running APK is signed by a certificate the application did not publish.
 *
 * The strongest local integrity signal there is: a repackaged or re-signed build
 * cannot reproduce the original signing key. It is only meaningful once the
 * application supplies the fingerprints it expects.
 */
internal class SigningCertificateDetector(private val expected: List<String>?) : Detector {
  override val id = "RNSEC-RUNTIME-INTEGRITY-001"

  override fun detect(probes: ProbeSet): SecuritySignal {
    if (expected == null) {
      return indeterminate(
        id,
        Confidence.HIGH,
        "no expected signing certificates were configured (see docs/runtime/integrity.md)"
      )
    }

    val actual =
      probes.packageIntegrity.signingCertificateSha256()
        ?: return indeterminate(id, Confidence.HIGH, "the signing certificate could not be read")

    if (actual.isEmpty()) {
      return indeterminate(id, Confidence.HIGH, "the package reported no signing certificates")
    }

    // Comparison is case-insensitive and separator-insensitive so a fingerprint
    // pasted from any of the usual tools works without reformatting.
    val normalisedExpected = expected.map { it.normaliseFingerprint() }.toSet()
    val normalisedActual = actual.map { it.normaliseFingerprint() }
    val unrecognised = normalisedActual.filterNot { normalisedExpected.contains(it) }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(unrecognised.isNotEmpty()),
      confidence = Confidence.HIGH,
      description =
        if (unrecognised.isNotEmpty()) {
          "The application is signed by a certificate that was not configured as expected"
        } else {
          "The application signing certificate matches a configured fingerprint"
        },
      metadata =
        mapOf(
          "signerCount" to actual.size,
          "unrecognisedSignerCount" to unrecognised.size,
          "expectedCount" to normalisedExpected.size
        )
    )
  }

  private fun String.normaliseFingerprint(): String =
    filter { it.isLetterOrDigit() }.uppercase()
}

/**
 * The application was installed from somewhere unexpected.
 *
 * A weaker statement than it first appears. Enterprise deployments, alternative
 * app stores and legitimate development installs all produce an "unexpected"
 * installer, so this is a provenance hint rather than evidence of tampering.
 */
internal class InstallSourceDetector(private val expected: List<String>?) : Detector {
  override val id = "RNSEC-RUNTIME-INTEGRITY-002"

  override fun detect(probes: ProbeSet): SecuritySignal {
    if (expected == null) {
      return indeterminate(
        id,
        Confidence.MEDIUM,
        "no expected installers were configured (see docs/runtime/integrity.md)"
      )
    }

    val installer = probes.packageIntegrity.installerPackageName()

    // A null installer means a direct install — adb, a file manager, or a
    // sideload. That is a real answer, not a probe failure.
    val recognised = installer != null && expected.contains(installer)

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(!recognised),
      confidence = Confidence.MEDIUM,
      description =
        if (!recognised) {
          if (installer == null) {
            "The application was installed directly rather than through a store"
          } else {
            "The application was installed by a package that was not configured as expected"
          }
        } else {
          "The application was installed by an expected package"
        },
      metadata = mapOf("installer" to installer)
    )
  }
}

/**
 * The running package identity does not match what the application expects.
 *
 * Catches the repackaging case where an application is rebuilt under a different
 * package name.
 */
internal class PackageIdentityDetector(private val expected: String?) : Detector {
  override val id = "RNSEC-RUNTIME-INTEGRITY-003"

  override fun detect(probes: ProbeSet): SecuritySignal {
    if (expected == null) {
      return indeterminate(
        id,
        Confidence.HIGH,
        "no expected package name was configured (see docs/runtime/integrity.md)"
      )
    }

    val actual =
      probes.application.packageName()
        ?: return indeterminate(id, Confidence.HIGH, "the package name could not be read")

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(actual != expected),
      confidence = Confidence.HIGH,
      description =
        if (actual != expected) {
          "The running package name does not match the configured identity"
        } else {
          "The running package name matches the configured identity"
        },
      metadata = mapOf("packageName" to actual)
    )
  }
}

/**
 * The APK is running from an unusual location.
 *
 * Normally installed applications run from `/data/app`. Anything else suggests a
 * system-image placement or an unusual install path. Needs no configuration, so
 * it is the one integrity signal that always contributes.
 */
internal class ApkLocationDetector : Detector {
  override val id = "RNSEC-RUNTIME-INTEGRITY-004"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val sourceDir =
      probes.packageIntegrity.applicationSourceDir()
        ?: return indeterminate(id, Confidence.LOW, "the application source path could not be read")

    val expected = EXPECTED_PREFIXES.any { sourceDir.startsWith(it) }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(!expected),
      confidence = Confidence.LOW,
      description =
        if (!expected) {
          "The application is running from an unusual filesystem location"
        } else {
          "The application is running from a normal install location"
        },
      metadata = mapOf("sourceDirPrefix" to sourceDir.substringBeforeLast('/'))
    )
  }

  private companion object {
    // `/product` and `/system` cover preinstalled builds, which are legitimate.
    val EXPECTED_PREFIXES = listOf("/data/app/", "/system/app/", "/system/priv-app/", "/product/app/")
  }
}

/** The integrity check. */
internal class IntegrityCheckEngine : CheckEngine {
  override val checkId = "integrity"

  override fun detectors(options: CheckOptions): List<Detector> =
    listOf(
      SigningCertificateDetector(options.stringList(IntegrityOptionKeys.SIGNING_CERTIFICATES)),
      InstallSourceDetector(options.stringList(IntegrityOptionKeys.EXPECTED_INSTALLERS)),
      PackageIdentityDetector(options.string(IntegrityOptionKeys.EXPECTED_PACKAGE_NAME)),
      ApkLocationDetector()
    )

  override fun metadata(probes: ProbeSet, options: CheckOptions): Map<String, Any?> =
    mapOf(
      // Surfaced so a developer can see at a glance which signals were skipped
      // for want of configuration, rather than wondering why a check is `unknown`.
      "signingCertificatesConfigured" to
        (options.stringList(IntegrityOptionKeys.SIGNING_CERTIFICATES) != null),
      "expectedInstallersConfigured" to
        (options.stringList(IntegrityOptionKeys.EXPECTED_INSTALLERS) != null),
      "expectedPackageNameConfigured" to
        (options.string(IntegrityOptionKeys.EXPECTED_PACKAGE_NAME) != null),
      // Play Integrity is a separate, optional adapter and is deliberately not
      // bundled here. See docs/runtime/integrity.md.
      "playIntegrityAvailable" to false
    )
}
