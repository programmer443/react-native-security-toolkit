import Foundation

/// Selects and runs check engines on iOS.
///
/// Failure is contained at three levels, exactly as on Android: a detector that
/// misbehaves becomes one `indeterminate` signal, a check engine that fails
/// becomes an `error` result, and neither ever propagates to the host
/// application. A security package that can crash the app it protects has made
/// things worse, not better.
public struct IOSSecurityEngine: Sendable {

  private let probes: ProbeSet
  private let clock: @Sendable () -> Double
  private let enginesById: [String: CheckEngine]

  public init(
    probes: ProbeSet,
    clock: @escaping @Sendable () -> Double = { Date().timeIntervalSince1970 * 1000 },
    engines: [CheckEngine] = IOSSecurityEngine.defaultEngines()
  ) {
    self.probes = probes
    self.clock = clock
    self.enginesById = Dictionary(uniqueKeysWithValues: engines.map { ($0.checkId, $0) })
  }

  public static func defaultEngines() -> [CheckEngine] {
    [
      JailbreakCheckEngine(),
      DebuggerCheckEngine(),
      SimulatorCheckEngine(),
      HookCheckEngine(),
      IntegrityCheckEngine(),
      SecureHardwareCheckEngine(),
      BiometricCheckEngine(),
      NetworkCheckEngine(),
      ScreenCheckEngine(),
    ]
  }

  /// Checks this engine implements.
  ///
  /// Grows only when a check is implemented **and** tested.
  public func supportedChecks() -> [String] {
    enginesById.keys.sorted()
  }

  public func run(_ checkId: String, options: CheckOptions = .empty) -> CheckResult {
    let startedAt = clock()

    guard let engine = enginesById[checkId] else {
      // A check this platform does not implement is a platform fact, not a
      // failure. That is what lets a cross-platform report omit Android-only
      // checks instead of filling itself with errors.
      return SignalAggregator.unavailable(
        checkId: checkId,
        reason: .platformNotSupported,
        checkedAtEpochMs: startedAt
      )
    }

    if let reason = engine.unavailableReason(probes) {
      return SignalAggregator.unavailable(
        checkId: checkId,
        reason: reason,
        checkedAtEpochMs: startedAt
      )
    }

    let signals = engine.detectors(options).map { runDetector($0) }

    return SignalAggregator.aggregate(
      checkId: checkId,
      signals: signals,
      metadata: engine.metadata(probes, options),
      durationMs: Int(clock() - startedAt),
      checkedAtEpochMs: startedAt
    )
  }

  public func runAll(_ checkIds: [String], options: CheckOptions = .empty) -> [CheckResult] {
    checkIds.map { run($0, options: options) }
  }

  private func runDetector(_ detector: Detector) -> SecuritySignal {
    detector.detect(probes)
  }
}
