import Foundation

/// Turns a detector's signals into a check verdict.
///
/// Deliberately identical in behaviour to the Kotlin `SignalAggregator`, down to
/// the corroboration thresholds. Two platforms with different aggregation rules
/// would give the same device two different verdicts, and neither would be
/// explainable.
///
/// **`unknown` is not `secure`.** If any probe could not run, the check cannot
/// claim the device is clean. Reporting absence of evidence as evidence of
/// absence is the single most dangerous thing a security check can do.
///
/// **Corroboration raises confidence; a lone weak signal does not.**
public enum SignalAggregator {

  /// Number of independent low-confidence hits that together justify `medium`.
  private static let lowSignalsForMedium = 3

  /// Number of independent medium-confidence hits that together justify `high`.
  private static let mediumSignalsForHigh = 2

  public static func aggregate(
    checkId: String,
    signals: [SecuritySignal],
    metadata: [String: Any] = [:],
    durationMs: Int = 0,
    checkedAtEpochMs: Double = 0
  ) -> CheckResult {
    let detected = signals.filter { $0.outcome == .detected }
    let hasIndeterminate = signals.contains { $0.outcome == .indeterminate }

    let status: CheckStatus
    if !detected.isEmpty {
      status = .detected
    } else if hasIndeterminate {
      status = .unknown
    } else {
      status = .secure
    }

    let confidence: Confidence
    switch status {
    case .detected:
      confidence = detectionConfidence(detected)
    case .secure:
      // Every probe ran and none fired. As strong as this check gets — which
      // still says nothing about whether a bypass is in play.
      confidence = .high
    default:
      confidence = .low
    }

    return CheckResult(
      id: checkId,
      status: status,
      confidence: confidence,
      signals: signals,
      metadata: metadata,
      durationMs: durationMs,
      checkedAtEpochMs: checkedAtEpochMs
    )
  }

  private static func detectionConfidence(_ detected: [SecuritySignal]) -> Confidence {
    let high = detected.filter { $0.confidence == .high }.count
    let medium = detected.filter { $0.confidence == .medium }.count
    let low = detected.filter { $0.confidence == .low }.count

    if high > 0 { return .high }
    if medium >= mediumSignalsForHigh { return .high }
    if medium > 0 { return .medium }
    if low >= lowSignalsForMedium { return .medium }
    return .low
  }

  /// Builds an `unavailable` result: the check did not run, and says why.
  public static func unavailable(
    checkId: String,
    reason: UnavailableReason,
    checkedAtEpochMs: Double = 0
  ) -> CheckResult {
    CheckResult(
      id: checkId,
      status: .unavailable,
      confidence: .low,
      signals: [],
      unavailableReason: reason,
      checkedAtEpochMs: checkedAtEpochMs
    )
  }

  /// Builds an `error` result. A failing detector degrades; it never throws at the app.
  public static func error(
    checkId: String,
    message: String,
    checkedAtEpochMs: Double = 0
  ) -> CheckResult {
    CheckResult(
      id: checkId,
      status: .error,
      confidence: .low,
      signals: [],
      errorMessage: message,
      checkedAtEpochMs: checkedAtEpochMs
    )
  }
}
