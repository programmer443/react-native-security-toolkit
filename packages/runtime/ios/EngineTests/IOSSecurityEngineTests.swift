import XCTest

@testable import RNSecurityEngine

final class IOSSecurityEngineTests: XCTestCase {

  private func engine(
    _ probes: ProbeSet = cleanDeviceProbes(),
    engines: [CheckEngine] = IOSSecurityEngine.defaultEngines()
  ) -> IOSSecurityEngine {
    IOSSecurityEngine(probes: probes, clock: { 1_000 }, engines: engines)
  }

  func testACleanDeviceReportsSecureWithEverySignalRecorded() {
    let result = engine().run("jailbreak")

    XCTAssertEqual(result.status, .secure)
    XCTAssertFalse(result.detected)
    // Signals that did not fire are still returned, so the reasoning is auditable.
    XCTAssertEqual(result.signals.count, 7)
    XCTAssertEqual(engine().run("debugger").status, .secure)
  }

  func testAJailbrokenDeviceReportsDetectedWithHighConfidence() {
    let probes = cleanDeviceProbes(
      paths: FakePathProbe(
        existing: ["/var/jb": true, "/Applications/Cydia.app": true],
        symlinks: ["/Applications": true]
      ),
      sandbox: FakeSandboxProbe(wroteOutsideContainer: true),
      dyld: FakeDyldProbe(images: ["/var/jb/usr/lib/libhooker.dylib"])
    )

    let result = engine(probes).run("jailbreak")

    XCTAssertEqual(result.status, .detected)
    XCTAssertEqual(result.confidence, .high)
    XCTAssertGreaterThanOrEqual(result.signals.filter(\.detected).count, 4)
  }

  /// An Android-only check is a platform fact, not an error. This is what lets a
  /// cross-platform report omit it instead of filling itself with failures.
  func testAnAndroidOnlyCheckIsUnavailableRatherThanAnError() {
    let result = engine().run("root")

    XCTAssertEqual(result.status, .unavailable)
    XCTAssertEqual(result.unavailableReason, .platformNotSupported)
  }

  /// On a simulator the question "has this iOS device been modified" is malformed:
  /// there is no iOS device. Reporting `detected` would train developers to
  /// ignore the check, and reporting `secure` would be a lie.
  func testJailbreakIsUnavailableOnASimulatorRatherThanDetectedOrSecure() {
    let simulator = cleanDeviceProbes(
      // Even a filesystem that would otherwise trip signals must not produce a
      // verdict here.
      paths: FakePathProbe(existing: ["/Applications/Cydia.app": true]),
      deviceEnvironment: FakeDeviceEnvironmentProbe(simulator: true)
    )

    let result = engine(simulator).run("jailbreak")

    XCTAssertEqual(result.status, .unavailable)
    XCTAssertEqual(result.unavailableReason, .simulator)
    XCTAssertFalse(result.detected)
    XCTAssertTrue(result.signals.isEmpty)
  }

  func testSupportedChecksOnlyListsImplementedChecks() {
    XCTAssertEqual(
      engine().supportedChecks(),
      [
        "biometrics", "debugger", "hooks", "integrity", "jailbreak", "network", "screen",
        "secureHardware", "simulator",
      ]
    )
  }

  func testEveryRegisteredCheckProducesAResultOfItsOwnId() {
    for checkId in engine().supportedChecks() {
      XCTAssertEqual(engine().run(checkId).id, checkId)
    }
  }

  func testCheckMetadataExplainsWhySignalsMayBeInconclusive() {
    let result = engine(cleanDeviceProbes(urlSchemes: FakeUrlSchemeProbe(configured: false)))
      .run("jailbreak")

    XCTAssertEqual(result.metadata["urlSchemeQueriesConfigured"] as? Bool, false)
    XCTAssertNotNil(result.metadata["signatureVersion"])
  }

  func testResultsCarryTimingSoCallersCanSeeCheckCost() {
    let result = engine().run("jailbreak")

    XCTAssertEqual(result.checkedAtEpochMs, 1_000)
    XCTAssertEqual(result.durationMs, 0)
  }
}
