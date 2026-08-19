import XCTest

@testable import RNSecurityEngine

final class DebuggerDetectorsTests: XCTestCase {

  // MARK: - Traced process

  func testTracedDetectorFiresWhenTheProcessIsTraced() {
    let signal = TracedProcessDetector().detect(
      cleanDeviceProbes(process: FakeProcessProbe(traced: true)))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
  }

  func testTracedDetectorStaysQuietWhenNotTraced() {
    XCTAssertEqual(TracedProcessDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testTracedDetectorReportsIndeterminateWhenFlagsAreUnreadable() {
    let signal = TracedProcessDetector().detect(
      cleanDeviceProbes(process: FakeProcessProbe(traced: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }

  // MARK: - Parent process

  func testParentDetectorFiresOnAnUnexpectedParent() {
    let signal = ParentProcessDetector().detect(
      cleanDeviceProbes(process: FakeProcessProbe(parentPid: 4711)))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.metadata["parentProcessId"] as? Int, 4711)
  }

  func testParentDetectorStaysQuietWhenLaunchedBySystemLauncher() {
    XCTAssertEqual(ParentProcessDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  /// Simulated applications are children of `launchd_sim`, so this heuristic does
  /// not hold there and every simulator run would otherwise fire it.
  func testParentDetectorReportsIndeterminateOnASimulator() {
    let signal = ParentProcessDetector().detect(
      cleanDeviceProbes(
        deviceEnvironment: FakeDeviceEnvironmentProbe(simulator: true),
        process: FakeProcessProbe(parentPid: 4711)
      ))

    XCTAssertEqual(signal.outcome, .indeterminate)
    XCTAssertTrue(signal.description.contains("launchd"))
  }

  func testParentDetectorReportsIndeterminateWhenThePidIsUnreadable() {
    let signal = ParentProcessDetector().detect(
      cleanDeviceProbes(process: FakeProcessProbe(parentPid: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }

  /// Tracing is observable on a simulator — you can attach Xcode to it — so unlike
  /// the parent-process heuristic, this signal must still answer there.
  func testTracedDetectorStillAnswersOnASimulator() {
    let signal = TracedProcessDetector().detect(
      cleanDeviceProbes(
        deviceEnvironment: FakeDeviceEnvironmentProbe(simulator: true),
        process: FakeProcessProbe(traced: true)
      ))

    XCTAssertEqual(signal.outcome, .detected)
  }
}
