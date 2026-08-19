import XCTest

@testable import RNSecurityEngine

final class SimulatorDetectorsTests: XCTestCase {

  func testFiresOnASimulator() {
    let signal = SimulatorEnvironmentDetector().detect(
      cleanDeviceProbes(deviceEnvironment: FakeDeviceEnvironmentProbe(simulator: true)))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
    XCTAssertEqual(signal.metadata["simulator"] as? Bool, true)
  }

  func testStaysQuietOnAPhysicalDevice() {
    let signal = SimulatorEnvironmentDetector().detect(cleanDeviceProbes())

    XCTAssertEqual(signal.outcome, .notDetected)
    XCTAssertTrue(signal.description.contains("physical device"))
  }

  /// The compile-time environment flag is exact, so unlike Android emulator
  /// detection there is no signature list to go stale and no inconclusive case.
  func testHasNoIndeterminateOutcome() {
    for simulated in [true, false] {
      let signal = SimulatorEnvironmentDetector().detect(
        cleanDeviceProbes(deviceEnvironment: FakeDeviceEnvironmentProbe(simulator: simulated)))

      XCTAssertNotEqual(signal.outcome, .indeterminate)
    }
  }
}
