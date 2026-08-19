import Foundation

/// Secure hardware capability reporting for iOS.
///
/// A capability report, not a threat detection. `detected` means **a weakness
/// indicator fired** — the platform offers less protection than an application
/// handling sensitive material would want — not that an attack was found.
///
/// And the reverse: a device having a Secure Enclave says **nothing** about
/// whether this application uses it, or uses it correctly. `secure` means the
/// hardware is available. It does not mean your data is safe.
///
/// See `docs/runtime/secure-hardware-ios.md`.

private let subject = "Hardware capability"

/// A Secure Enclave key cannot be created.
public struct SecureEnclaveDetector: Detector {
  public let id = "RNSEC-IOS-HARDWARE-001"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let available = probes.keychain.isSecureEnclaveAvailable() else {
      return SignalBuilder.indeterminate(
        id, .high, "a probe key could not be attempted", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!available),
      confidence: .high,
      description: available
        ? "Keys can be generated inside the Secure Enclave"
        : "Secure Enclave key generation is not available on this device",
      metadata: ["secureEnclaveAvailable": available]
    )
  }
}

/// The keychain cannot be written to.
///
/// Rare, and usually a provisioning problem — a missing keychain-sharing
/// entitlement, for instance — rather than a device weakness. Reported because an
/// application that cannot use the keychain will fall back to something worse.
public struct KeychainAvailabilityDetector: Detector {
  public let id = "RNSEC-IOS-HARDWARE-002"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let usable = probes.keychain.canStoreKeychainItem() else {
      return SignalBuilder.indeterminate(
        id, .medium, "the keychain could not be exercised", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!usable),
      confidence: .medium,
      description: usable
        ? "The keychain is available to this application"
        : "The keychain could not be written to by this application",
      metadata: ["keychainUsable": usable]
    )
  }
}

/// The secure hardware check.
public struct SecureHardwareCheckEngine: CheckEngine {
  public let checkId = "secureHardware"

  public init() {}

  public func detectors(_ options: CheckOptions) -> [Detector] {
    [SecureEnclaveDetector(), KeychainAvailabilityDetector()]
  }

  public func metadata(_ probes: ProbeSet, _ options: CheckOptions) -> [String: Any] {
    ["note": "Hardware availability describes the device, not this application's use of it."]
  }
}
