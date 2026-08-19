import Foundation

/// The result model shared by every iOS detector.
///
/// A direct counterpart to the Kotlin model in
/// `android/src/main/java/com/rnsecurity/engine/Model.kt`, and to the TypeScript
/// types in `src/types/result.ts`. The three must agree on wire values, because
/// the JavaScript layer validates what crosses the bridge and rejects anything
/// that does not match.
///
/// The distinction the whole model turns on is between *"we looked and found
/// nothing"* and *"we could not look"*. Collapsing those into a boolean is how a
/// security check ends up quietly reporting a compromised device as clean.

/// Outcome of a single detection signal.
public enum SignalOutcome: String, Sendable {
  /// The indicator fired.
  case detected

  /// The probe ran and the indicator did not fire.
  case notDetected = "not-detected"

  /// The probe could not run. Never treated as evidence of safety.
  case indeterminate
}

/// How much weight a signal carries on its own, before corroboration.
public enum Confidence: String, Sendable {
  case low
  case medium
  case high
}

/// Outcome of a whole check.
public enum CheckStatus: String, Sendable {
  case secure
  case detected
  case unknown
  case unavailable
  case error
}

/// Why a check reported ``CheckStatus/unavailable``.
public enum UnavailableReason: String, Sendable {
  case platformNotSupported = "platform-not-supported"
  case permissionDenied = "permission-denied"
  case apiLevelTooLow = "api-level-too-low"
  case notConfigured = "not-configured"
  case disabledByConfig = "disabled-by-config"
  case hardwareNotPresent = "hardware-not-present"

  /// The check cannot be meaningfully evaluated on a simulator.
  case simulator
}

/// One piece of evidence.
public struct SecuritySignal: Sendable {
  /// Stable identifier, e.g. `RNSEC-IOS-JAILBREAK-003`. Never renumbered once published.
  public let id: String
  public let outcome: SignalOutcome
  public let confidence: Confidence
  /// Phrased as an indicator, never as a verdict.
  public let description: String
  /// Detector-specific detail. Must never contain user data.
  public let metadata: [String: Any]

  public init(
    id: String,
    outcome: SignalOutcome,
    confidence: Confidence,
    description: String,
    metadata: [String: Any] = [:]
  ) {
    self.id = id
    self.outcome = outcome
    self.confidence = confidence
    self.description = description
    self.metadata = metadata
  }

  public var detected: Bool { outcome == .detected }
}

/// Result of one check.
public struct CheckResult: Sendable {
  public let id: String
  public let status: CheckStatus
  public let confidence: Confidence
  public let signals: [SecuritySignal]
  public let unavailableReason: UnavailableReason?
  public let errorMessage: String?
  public let metadata: [String: Any]
  public let durationMs: Int
  public let checkedAtEpochMs: Double

  public init(
    id: String,
    status: CheckStatus,
    confidence: Confidence,
    signals: [SecuritySignal],
    unavailableReason: UnavailableReason? = nil,
    errorMessage: String? = nil,
    metadata: [String: Any] = [:],
    durationMs: Int = 0,
    checkedAtEpochMs: Double = 0
  ) {
    self.id = id
    self.status = status
    self.confidence = confidence
    self.signals = signals
    self.unavailableReason = unavailableReason
    self.errorMessage = errorMessage
    self.metadata = metadata
    self.durationMs = durationMs
    self.checkedAtEpochMs = checkedAtEpochMs
  }

  public var detected: Bool { status == .detected }

  /// Serialises to the payload the JavaScript layer validates.
  public func toPayload() -> [String: Any] {
    var payload: [String: Any] = [
      "id": id,
      "status": status.rawValue,
      "detected": detected,
      "confidence": confidence.rawValue,
      "signals": signals.map { signal in
        [
          "id": signal.id,
          "outcome": signal.outcome.rawValue,
          "detected": signal.detected,
          "confidence": signal.confidence.rawValue,
          "description": signal.description,
          "metadata": signal.metadata,
        ] as [String: Any]
      },
      "metadata": metadata,
      "durationMs": durationMs,
      "checkedAtEpochMs": checkedAtEpochMs,
    ]
    if let unavailableReason {
      payload["unavailableReason"] = unavailableReason.rawValue
    }
    if let errorMessage {
      payload["errorMessage"] = errorMessage
    }
    return payload
  }
}
