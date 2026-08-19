import Foundation

/// Application integrity signals for iOS.
///
/// Genuine integrity assurance on iOS comes from **App Attest, verified on your
/// server**. These signals detect sideloading, re-signing and repackaging cheaply
/// and locally; they do not replace attestation, and an attacker who controls the
/// device can defeat them.
///
/// One of the three needs configuration, and — as on Android — an unconfigured
/// signal reports `indeterminate`, never a passing result. A check that was never
/// really performed must not look like one that passed.
///
/// See `docs/runtime/integrity-ios.md`.

private let subject = "Integrity indicator"

/// Option keys the application supplies through `SecurityToolkit.configure`.
public enum IntegrityOptionKeys {
  public static let expectedBundleIdentifier = "expectedBundleIdentifier"
}

/// The running bundle identifier is not the one the application expects.
///
/// Catches repackaging, where an application is rebuilt under a different
/// identity.
public struct BundleIdentityDetector: Detector {
  public let id = "RNSEC-IOS-INTEGRITY-001"

  private let expected: String?

  public init(expected: String?) {
    self.expected = expected
  }

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let expected else {
      return SignalBuilder.indeterminate(
        id,
        .high,
        "no expected bundle identifier was configured (see docs/runtime/integrity-ios.md)",
        subject: subject
      )
    }

    guard let actual = probes.bundle.bundleIdentifier() else {
      return SignalBuilder.indeterminate(
        id, .high, "the bundle identifier could not be read", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(actual != expected),
      confidence: .high,
      description: actual == expected
        ? "The running bundle identifier matches the configured identity"
        : "The running bundle identifier does not match the configured identity",
      metadata: ["bundleIdentifier": actual]
    )
  }
}

/// An embedded provisioning profile is present.
///
/// App Store builds do not carry one. Its presence means the application was
/// installed some other way — TestFlight, an enterprise distribution, a
/// development build, or a re-signed sideload.
///
/// Weaker than it first appears, because the first three of those are entirely
/// legitimate. It is provenance information, not evidence of tampering.
public struct ProvisioningProfileDetector: Detector {
  public let id = "RNSEC-IOS-INTEGRITY-002"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let present = probes.bundle.hasEmbeddedProvisioningProfile() else {
      return SignalBuilder.indeterminate(
        id, .medium, "the application bundle could not be inspected", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(present),
      confidence: .medium,
      description: present
        ? "An embedded provisioning profile is present, so this is not an App Store build"
        : "No embedded provisioning profile is present",
      metadata: ["provisioningProfilePresent": present]
    )
  }
}

/// The main binary is not App Store encrypted.
///
/// App Store binaries carry FairPlay encryption. An unencrypted binary on a
/// physical device suggests it was decrypted and re-signed — the standard first
/// step in repackaging an iOS application.
///
/// **Reports `indeterminate` on the simulator and needs care in development**:
/// simulator builds and locally signed device builds are never encrypted, so this
/// only means anything for a build that came from the App Store. See
/// `docs/runtime/integrity-ios.md`.
public struct BinaryEncryptionDetector: Detector {
  public let id = "RNSEC-IOS-INTEGRITY-003"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    if probes.deviceEnvironment.isSimulator() {
      return SignalBuilder.indeterminate(
        id,
        .medium,
        "simulator builds are never encrypted, so this indicator does not apply",
        subject: subject
      )
    }

    guard let encrypted = probes.bundle.isMainBinaryEncrypted() else {
      return SignalBuilder.indeterminate(
        id, .medium, "the main binary's encryption state could not be read", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!encrypted),
      confidence: .medium,
      description: encrypted
        ? "The main binary carries App Store encryption"
        : "The main binary is not App Store encrypted",
      metadata: ["mainBinaryEncrypted": encrypted]
    )
  }
}

/// The integrity check.
public struct IntegrityCheckEngine: CheckEngine {
  public let checkId = "integrity"

  public init() {}

  public func detectors(_ options: CheckOptions) -> [Detector] {
    [
      BundleIdentityDetector(expected: options.string(IntegrityOptionKeys.expectedBundleIdentifier)),
      ProvisioningProfileDetector(),
      BinaryEncryptionDetector(),
    ]
  }

  public func metadata(_ probes: ProbeSet, _ options: CheckOptions) -> [String: Any] {
    [
      // Surfaced so a developer seeing `unknown` can tell "something is wrong"
      // from "you have not finished setting this up".
      "expectedBundleIdentifierConfigured": options.string(
        IntegrityOptionKeys.expectedBundleIdentifier) != nil,
      // App Attest is a separate, optional adapter and is deliberately not
      // bundled here. See docs/runtime/integrity-ios.md.
      "appAttestAvailable": false,
    ]
  }
}
