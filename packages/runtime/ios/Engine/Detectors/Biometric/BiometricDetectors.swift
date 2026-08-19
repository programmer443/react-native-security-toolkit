import Foundation

/// Biometric capability reporting for iOS.
///
/// Capability only. **No biometric data is read, stored, transmitted or exposed**
/// by this check, and none is available to it — `LAContext` reports availability
/// and a biometry type, nothing more. Nothing here can identify a user.
///
/// As on Android, an unenrolled device is not an insecure device. Many people
/// deliberately use a passcode and no biometric. These signals exist so an
/// application can decide whether biometric authentication is a viable gate, not
/// so it can nag.
///
/// See `docs/runtime/biometrics-ios.md`.

private let subject = "Biometric capability"

/// Biometric authentication is not currently usable.
public struct BiometricAvailabilityDetector: Detector {
  public let id = "RNSEC-IOS-BIOMETRIC-001"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let usable = probes.biometry.canEvaluateBiometrics() else {
      return SignalBuilder.indeterminate(
        id, .high, "the platform did not report biometric availability", subject: subject)
    }

    let reason = probes.biometry.biometryUnavailableReason()

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!usable),
      confidence: .high,
      description: usable
        ? "Biometric authentication is available and enrolled"
        : "Biometric authentication is not currently usable: \(explain(reason))",
      metadata: ["reason": reason ?? "available"]
    )
  }

  private func explain(_ reason: String?) -> String {
    switch reason {
    case "not-available": return "no supporting hardware"
    case "not-enrolled": return "nothing enrolled"
    case "lockout": return "locked out after failed attempts"
    case "passcode-not-set": return "no device passcode is set"
    default: return "reported unavailable without a reason"
    }
  }
}

/// The device reports no biometry type.
///
/// Separated from availability because the two call for different responses:
/// no hardware is permanent and the application must design around it, whereas
/// nothing enrolled is something the user can change in seconds.
public struct BiometryTypeDetector: Detector {
  public let id = "RNSEC-IOS-BIOMETRIC-002"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let type = probes.biometry.biometryType() else {
      return SignalBuilder.indeterminate(
        id, .medium, "the platform did not report a biometry type", subject: subject)
    }

    let absent = type == "none"

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(absent),
      confidence: .medium,
      description: absent
        ? "This device reports no biometric hardware"
        : "This device supports \(type) biometric authentication",
      metadata: ["biometryType": type]
    )
  }
}

/// No device passcode is set.
///
/// The floor beneath everything else: without a passcode there is no keychain
/// protection tied to authentication, biometric enrolment is impossible, and
/// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` cannot be used. The one
/// signal here that is unambiguously a weakness.
public struct DevicePasscodeDetector: Detector {
  public let id = "RNSEC-IOS-BIOMETRIC-003"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let available = probes.biometry.canEvaluateDeviceOwnerAuthentication() else {
      return SignalBuilder.indeterminate(
        id, .high, "the platform did not report authentication availability", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!available),
      confidence: .high,
      description: available
        ? "A device passcode is set"
        : "No device passcode is set, so the device has no lock screen",
      metadata: ["devicePasscodeSet": available]
    )
  }
}

/// The biometrics check.
public struct BiometricCheckEngine: CheckEngine {
  public let checkId = "biometrics"

  public init() {}

  public func detectors(_ options: CheckOptions) -> [Detector] {
    [BiometricAvailabilityDetector(), BiometryTypeDetector(), DevicePasscodeDetector()]
  }

  public func metadata(_ probes: ProbeSet, _ options: CheckOptions) -> [String: Any] {
    ["note": "Capability only. No biometric data is read, stored or exposed."]
  }
}
