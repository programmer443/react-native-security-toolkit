import XCTest

@testable import RNSecurityEngine

/// The aggregator's behaviour must match Kotlin's exactly. Two platforms with
/// different aggregation rules would give the same device two different verdicts,
/// and neither would be explainable.
final class SignalAggregatorTests: XCTestCase {

  private func signal(
    _ outcome: SignalOutcome,
    _ confidence: Confidence = .medium,
    id: String = "RNSEC-TEST-001"
  ) -> SecuritySignal {
    SecuritySignal(id: id, outcome: outcome, confidence: confidence, description: "test signal")
  }

  func testAllProbesRanAndNothingFiredReportsSecure() {
    let result = SignalAggregator.aggregate(
      checkId: "jailbreak",
      signals: [signal(.notDetected), signal(.notDetected)]
    )

    XCTAssertEqual(result.status, .secure)
    XCTAssertEqual(result.confidence, .high)
    XCTAssertFalse(result.detected)
  }

  /// The single most important behaviour here. A probe that could not run is not
  /// evidence the device is clean.
  func testBlockedProbeReportsUnknownRatherThanSecure() {
    let result = SignalAggregator.aggregate(
      checkId: "jailbreak",
      signals: [signal(.notDetected), signal(.indeterminate)]
    )

    XCTAssertEqual(result.status, .unknown)
    XCTAssertEqual(result.confidence, .low)
    XCTAssertFalse(result.detected)
  }

  func testDetectionOutranksBlockedProbe() {
    let result = SignalAggregator.aggregate(
      checkId: "jailbreak",
      signals: [signal(.indeterminate), signal(.detected, .high)]
    )

    XCTAssertEqual(result.status, .detected)
    XCTAssertEqual(result.confidence, .high)
  }

  func testConfidenceThresholdsMatchAndroid() {
    XCTAssertEqual(
      SignalAggregator.aggregate(checkId: "c", signals: [signal(.detected, .high)]).confidence, .high)
    XCTAssertEqual(
      SignalAggregator.aggregate(checkId: "c", signals: [signal(.detected, .medium)]).confidence,
      .medium)
    XCTAssertEqual(
      SignalAggregator.aggregate(
        checkId: "c",
        signals: [signal(.detected, .medium, id: "a"), signal(.detected, .medium, id: "b")]
      ).confidence, .high)
    XCTAssertEqual(
      SignalAggregator.aggregate(checkId: "c", signals: [signal(.detected, .low)]).confidence, .low)
    XCTAssertEqual(
      SignalAggregator.aggregate(
        checkId: "c",
        signals: [signal(.detected, .low, id: "a"), signal(.detected, .low, id: "b")]
      ).confidence, .low)
    XCTAssertEqual(
      SignalAggregator.aggregate(
        checkId: "c",
        signals: [
          signal(.detected, .low, id: "a"), signal(.detected, .low, id: "b"),
          signal(.detected, .low, id: "c"),
        ]
      ).confidence, .medium)
  }

  func testUnavailableCarriesItsReason() {
    let result = SignalAggregator.unavailable(checkId: "root", reason: .platformNotSupported)

    XCTAssertEqual(result.status, .unavailable)
    XCTAssertEqual(result.unavailableReason, .platformNotSupported)
    XCTAssertFalse(result.detected)
  }

  /// Wire values are what the JavaScript validator checks against. A mismatch
  /// here would be rejected at the bridge, so they are asserted literally.
  func testWireValuesMatchTheTypeScriptUnions() {
    XCTAssertEqual(SignalOutcome.notDetected.rawValue, "not-detected")
    XCTAssertEqual(SignalOutcome.indeterminate.rawValue, "indeterminate")
    XCTAssertEqual(CheckStatus.detected.rawValue, "detected")
    XCTAssertEqual(Confidence.high.rawValue, "high")
    XCTAssertEqual(UnavailableReason.platformNotSupported.rawValue, "platform-not-supported")
    XCTAssertEqual(UnavailableReason.apiLevelTooLow.rawValue, "api-level-too-low")
  }

  func testPayloadShapeMatchesWhatJavaScriptValidates() {
    let result = SignalAggregator.aggregate(
      checkId: "jailbreak",
      signals: [signal(.notDetected)],
      metadata: ["signatureVersion": "2026.08.1"],
      durationMs: 12,
      checkedAtEpochMs: 1_760_000_000_000
    )
    let payload = result.toPayload()

    XCTAssertEqual(payload["id"] as? String, "jailbreak")
    XCTAssertEqual(payload["status"] as? String, "secure")
    XCTAssertEqual(payload["detected"] as? Bool, false)
    XCTAssertEqual(payload["confidence"] as? String, "high")
    XCTAssertEqual(payload["durationMs"] as? Int, 12)
    XCTAssertEqual(payload["checkedAtEpochMs"] as? Double, 1_760_000_000_000)
    XCTAssertNil(payload["unavailableReason"])

    let signals = payload["signals"] as? [[String: Any]]
    XCTAssertEqual(signals?.count, 1)
    XCTAssertEqual(signals?.first?["outcome"] as? String, "not-detected")
  }
}
