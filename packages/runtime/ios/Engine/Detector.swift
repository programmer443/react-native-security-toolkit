import Foundation

/// Per-call configuration supplied by the application.
///
/// Mirrors the Kotlin `CheckOptions`. Passing configuration per call keeps the
/// native engine stateless, so there is no ordering hazard between configuring
/// and checking.
public struct CheckOptions: Sendable {
  private let values: [String: Any]

  public init(_ values: [String: Any] = [:]) {
    self.values = values
  }

  public func string(_ key: String) -> String? {
    guard let value = values[key] as? String, !value.isEmpty else { return nil }
    return value
  }

  public func stringList(_ key: String) -> [String]? {
    guard let raw = values[key] as? [Any] else { return nil }
    let strings = raw.compactMap { $0 as? String }.filter { !$0.isEmpty }
    return strings.isEmpty ? nil : strings
  }

  public func boolean(_ key: String) -> Bool? { values[key] as? Bool }

  public static let empty = CheckOptions()
}

/// One detection technique.
///
/// A detector produces signals; it does not decide anything. Verdicts are the
/// aggregator's job, risk scoring is TypeScript's, and what to do about it is the
/// application's.
public protocol Detector: Sendable {
  /// Stable identifier, e.g. `RNSEC-IOS-JAILBREAK-003`.
  var id: String { get }

  /// Runs the technique. Implementations must not throw.
  func detect(_ probes: ProbeSet) -> SecuritySignal
}

/// A group of detectors answering one check, e.g. `jailbreak`.
public protocol CheckEngine: Sendable {
  /// Check identifier as exposed to JavaScript.
  var checkId: String { get }

  /// Detectors for this run. A function because some checks are
  /// configuration-shaped.
  func detectors(_ options: CheckOptions) -> [Detector]

  /// Check-level metadata, included in the result so a developer can see why a
  /// signal was inconclusive.
  func metadata(_ probes: ProbeSet, _ options: CheckOptions) -> [String: Any]

  /// A reason this check cannot run at all in the current environment.
  ///
  /// Returning a reason skips the detectors entirely and produces `unavailable`.
  /// That is the honest answer when a question is malformed rather than merely
  /// hard — jailbreak detection on a simulator, for instance.
  func unavailableReason(_ probes: ProbeSet) -> UnavailableReason?
}

extension CheckEngine {
  public func metadata(_ probes: ProbeSet, _ options: CheckOptions) -> [String: Any] { [:] }

  public func unavailableReason(_ probes: ProbeSet) -> UnavailableReason? { nil }
}

/// Helpers shared by detectors, kept in one place so the phrasing stays consistent.
public enum SignalBuilder {
  public static func indeterminate(
    _ id: String,
    _ confidence: Confidence,
    _ why: String,
    subject: String,
    metadata: [String: Any] = [:]
  ) -> SecuritySignal {
    SecuritySignal(
      id: id,
      outcome: .indeterminate,
      confidence: confidence,
      description: "\(subject) could not be evaluated: \(why)",
      metadata: metadata
    )
  }

  public static func outcome(_ detected: Bool) -> SignalOutcome {
    detected ? .detected : .notDetected
  }
}
