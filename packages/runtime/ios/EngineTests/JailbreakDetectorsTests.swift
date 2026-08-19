import XCTest

@testable import RNSecurityEngine

final class JailbreakDetectorsTests: XCTestCase {

  // MARK: - Rootful paths

  func testRootfulDetectorFiresOnAClassicArtefact() {
    let signal = RootfulPathDetector().detect(
      cleanDeviceProbes(paths: FakePathProbe(existing: ["/Applications/Cydia.app": true])))

    XCTAssertEqual(signal.outcome, .detected)
    // Phrased as an indicator, never as a verdict.
    XCTAssertTrue(signal.description.hasPrefix("Potential"))
  }

  /// The iOS Simulator runs against the macOS filesystem, where `/bin/bash`,
  /// `/bin/sh` and the ssh binaries all genuinely exist. Including them — as most
  /// published path lists do — makes the check fire on every simulator run, and a
  /// signal that cries wolf during development is one developers learn to ignore.
  func testRootfulPathListExcludesPathsThatExistOnMacOS() {
    let macOSPaths = ["/bin/bash", "/bin/sh", "/usr/bin/ssh", "/usr/sbin/sshd"]

    for path in macOSPaths {
      XCTAssertFalse(
        JailbreakSignatures.rootfulPaths.contains(path),
        "\(path) exists on macOS and would fire on every simulator run")
    }
  }

  func testRootfulDetectorStaysQuietOnACleanDevice() {
    XCTAssertEqual(RootfulPathDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testRootfulDetectorReportsIndeterminateWhenPathsAreUnreadable() {
    let signal = RootfulPathDetector().detect(
      cleanDeviceProbes(paths: FakePathProbe(defaultExists: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }

  // MARK: - Rootless paths

  /// The regression this whole signal exists for: a modern rootless jailbreak
  /// leaves none of the classic artefacts, so a project carrying only the old
  /// path list detects nothing while looking thorough.
  func testRootlessDetectorFiresOnARelocatedFilesystem() {
    let signal = RootlessPathDetector().detect(
      cleanDeviceProbes(paths: FakePathProbe(existing: ["/var/jb": true])))

    XCTAssertEqual(signal.outcome, .detected)
  }

  func testRootlessDetectorFiresOnARelocatedTweakDirectory() {
    let signal = RootlessPathDetector().detect(
      cleanDeviceProbes(paths: FakePathProbe(existing: ["/var/jb/usr/lib/TweakInject": true])))

    XCTAssertEqual(signal.outcome, .detected)
  }

  /// A rootless jailbreak must not be missed by the classic detector alone.
  func testClassicDetectorDoesNotSeeARootlessJailbreak() {
    let rootlessDevice = cleanDeviceProbes(paths: FakePathProbe(existing: ["/var/jb": true]))

    XCTAssertEqual(RootfulPathDetector().detect(rootlessDevice).outcome, .notDetected)
    XCTAssertEqual(RootlessPathDetector().detect(rootlessDevice).outcome, .detected)
  }

  func testRootlessDetectorStaysQuietOnACleanDevice() {
    XCTAssertEqual(RootlessPathDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  // MARK: - Sandbox escape

  /// The polarity test. On a healthy sandboxed app a write outside the container
  /// *fails*, so success is the indicator. An implementation that inverts this
  /// reports every healthy device as jailbroken.
  func testSandboxDetectorFiresWhenAWriteSucceedsOutsideTheContainer() {
    let signal = SandboxEscapeDetector().detect(
      cleanDeviceProbes(sandbox: FakeSandboxProbe(wroteOutsideContainer: true)))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
  }

  func testSandboxDetectorStaysQuietWhenTheWriteIsRefused() {
    let signal = SandboxEscapeDetector().detect(cleanDeviceProbes())

    XCTAssertEqual(signal.outcome, .notDetected)
    XCTAssertTrue(signal.description.contains("refused"))
  }

  func testSandboxDetectorReportsIndeterminateWhenItCannotProbe() {
    let signal = SandboxEscapeDetector().detect(
      cleanDeviceProbes(sandbox: FakeSandboxProbe(wroteOutsideContainer: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }

  // MARK: - Injected libraries

  func testInjectedLibraryDetectorFiresOnASubstrateImage() {
    let signal = InjectedLibraryDetector().detect(
      cleanDeviceProbes(
        dyld: FakeDyldProbe(images: [
          "/usr/lib/libSystem.B.dylib",
          "/Library/MobileSubstrate/MobileSubstrate.dylib",
        ])))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
  }

  func testInjectedLibraryDetectorFiresOnAModernInjector() {
    let signal = InjectedLibraryDetector().detect(
      cleanDeviceProbes(dyld: FakeDyldProbe(images: ["/var/jb/usr/lib/libellekit.dylib"])))

    XCTAssertEqual(signal.outcome, .detected)
  }

  func testInjectedLibraryDetectorStaysQuietOnOrdinaryImages() {
    XCTAssertEqual(InjectedLibraryDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testInjectedLibraryDetectorReportsIndeterminateWhenTheListIsUnreadable() {
    let signal = InjectedLibraryDetector().detect(
      cleanDeviceProbes(dyld: FakeDyldProbe(images: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }

  // MARK: - DYLD environment

  func testDyldEnvironmentDetectorFiresWhenInsertionIsSet() {
    let signal = DyldEnvironmentDetector().detect(
      cleanDeviceProbes(
        environment: FakeEnvironmentProbe(values: [
          "DYLD_INSERT_LIBRARIES": "/var/jb/usr/lib/x.dylib"
        ])))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
  }

  /// The variable's value names a filesystem layout, so only its presence is reported.
  func testDyldEnvironmentDetectorDoesNotReportTheValue() {
    let signal = DyldEnvironmentDetector().detect(
      cleanDeviceProbes(
        environment: FakeEnvironmentProbe(values: [
          "DYLD_INSERT_LIBRARIES": "/var/jb/usr/lib/secret-path.dylib"
        ])))

    let serialised = signal.metadata.map { "\($0.key)=\($0.value)" }.joined()
    XCTAssertFalse(serialised.contains("secret-path"))
  }

  func testDyldEnvironmentDetectorStaysQuietWhenUnset() {
    XCTAssertEqual(DyldEnvironmentDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  // MARK: - URL schemes

  func testUrlSchemeDetectorFiresOnAReachablePackageManager() {
    let signal = UrlSchemeDetector().detect(
      cleanDeviceProbes(urlSchemes: FakeUrlSchemeProbe(openable: ["sileo": true])))

    XCTAssertEqual(signal.outcome, .detected)
  }

  /// Without the declarations `canOpenURL` answers false for everything, which is
  /// a false negative indistinguishable from a clean result.
  func testUrlSchemeDetectorReportsIndeterminateWhenNotConfigured() {
    let signal = UrlSchemeDetector().detect(
      cleanDeviceProbes(urlSchemes: FakeUrlSchemeProbe(configured: false)))

    XCTAssertEqual(signal.outcome, .indeterminate)
    XCTAssertTrue(signal.description.contains("LSApplicationQueriesSchemes"))
  }

  func testUrlSchemeDetectorStaysQuietWhenNothingIsReachable() {
    XCTAssertEqual(UrlSchemeDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  // MARK: - Symlink anomalies

  func testSymlinkDetectorFiresOnAReplacedSystemDirectory() {
    let signal = SymlinkAnomalyDetector().detect(
      cleanDeviceProbes(paths: FakePathProbe(symlinks: ["/Applications": true])))

    XCTAssertEqual(signal.outcome, .detected)
  }

  func testSymlinkDetectorStaysQuietOnACleanDevice() {
    XCTAssertEqual(SymlinkAnomalyDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testSymlinkDetectorReportsIndeterminateWhenUnreadable() {
    let signal = SymlinkAnomalyDetector().detect(
      cleanDeviceProbes(paths: FakePathProbe(defaultSymlink: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }
}
