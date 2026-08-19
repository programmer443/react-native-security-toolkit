import XCTest

@testable import RNSecurityEngine

final class HookDetectorsTests: XCTestCase {

  // MARK: - Symbol origin

  func testStaysQuietWhenSymbolsResolveInsideSystemImages() {
    XCTAssertEqual(SymbolOriginDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testFiresWhenASymbolResolvesOutsideAnySystemImage() {
    let signal = SymbolOriginDetector().detect(
      cleanDeviceProbes(
        symbols: FakeNativeSymbolProbe(origins: ["open": "/var/jb/usr/lib/libhooker.dylib"])))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.metadata["unexpectedSymbols"] as? [String], ["open"])
  }

  /// On the simulator every system path is nested under the Xcode runtime root,
  /// and iOS moves libSystem components between paths across versions. Comparing
  /// full paths would report every device as hooked.
  func testAcceptsSystemPathsWhereverTheyAreNested() {
    let simulatorPath =
      "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform"
      + "/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS.simruntime/Contents/Resources"
      + "/RuntimeRoot/usr/lib/system/libsystem_kernel.dylib"

    let signal = SymbolOriginDetector().detect(
      cleanDeviceProbes(symbols: FakeNativeSymbolProbe(defaultOrigin: simulatorPath)))

    XCTAssertEqual(signal.outcome, .notDetected)
  }

  /// A rootless jailbreak installs to `/var/jb/usr/lib/…`, which *contains*
  /// `/usr/lib/`. Substring matching would classify every injected library on a
  /// modern jailbroken device as a system image and blind this check entirely.
  func testRootlessJailbreakPathsAreNotMistakenForSystemImages() {
    XCTAssertFalse(HookSignatures.isSystemImage("/var/jb/usr/lib/libhooker.dylib"))
    XCTAssertFalse(HookSignatures.isSystemImage("/var/jb/System/Library/Injected.dylib"))
    XCTAssertFalse(HookSignatures.isSystemImage("/private/var/jb/usr/lib/x.dylib"))

    XCTAssertTrue(HookSignatures.isSystemImage("/usr/lib/system/libsystem_kernel.dylib"))
    XCTAssertTrue(HookSignatures.isSystemImage("/System/Library/Frameworks/Foundation.framework/F"))
  }

  func testReportsIndeterminateWhenSymbolResolutionIsUnavailable() {
    let signal = SymbolOriginDetector().detect(
      cleanDeviceProbes(symbols: FakeNativeSymbolProbe(available: false)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }

  func testReportsIndeterminateWhenNoSymbolResolves() {
    let signal = SymbolOriginDetector().detect(
      cleanDeviceProbes(symbols: FakeNativeSymbolProbe(defaultOrigin: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }

  /// A few unresolvable symbols must not mask one that resolved wrong.
  func testStillFiresWhenSomeSymbolsAreUnresolvable() {
    let signal = SymbolOriginDetector().detect(
      cleanDeviceProbes(
        symbols: FakeNativeSymbolProbe(
          origins: ["connect": "/var/jb/usr/lib/injected.dylib", "fopen": nil])))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.metadata["unresolvedSymbols"] as? Int, 1)
  }

  // MARK: - Method swizzling

  func testSwizzlingDetectorStaysQuietOnSystemImplementations() {
    XCTAssertEqual(MethodSwizzlingDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testSwizzlingDetectorFiresOnAReplacedImplementation() {
    let signal = MethodSwizzlingDetector().detect(
      cleanDeviceProbes(
        objcRuntime: FakeObjcRuntimeProbe(images: [
          "NSURLSession.sharedSession": "/var/jb/usr/lib/TweakInject/Intercept.dylib"
        ])))

    XCTAssertEqual(signal.outcome, .detected)
    // Legitimate SDKs swizzle too, so this can only ever corroborate.
    XCTAssertEqual(signal.confidence, .medium)
  }

  func testSwizzlingDetectorReportsIndeterminateWhenNothingCanBeLocated() {
    let signal = MethodSwizzlingDetector().detect(
      cleanDeviceProbes(objcRuntime: FakeObjcRuntimeProbe(defaultImage: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }
}

final class IntegrityDetectorsTests: XCTestCase {

  // MARK: - Bundle identity

  func testBundleIdentityAcceptsTheConfiguredIdentifier() {
    let signal = BundleIdentityDetector(expected: "com.example.app").detect(cleanDeviceProbes())

    XCTAssertEqual(signal.outcome, .notDetected)
  }

  func testBundleIdentityFiresOnARepackagedApplication() {
    let signal = BundleIdentityDetector(expected: "com.example.app").detect(
      cleanDeviceProbes(bundle: FakeBundleProbe(identifier: "com.evil.clone")))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
  }

  /// An unconfigured check must never look like a check that passed.
  func testBundleIdentityReportsIndeterminateWhenNothingIsConfigured() {
    let signal = BundleIdentityDetector(expected: nil).detect(cleanDeviceProbes())

    XCTAssertEqual(signal.outcome, .indeterminate)
    XCTAssertTrue(signal.description.contains("no expected bundle identifier"))
  }

  // MARK: - Provisioning profile

  func testProvisioningDetectorFiresWhenAProfileIsEmbedded() {
    let signal = ProvisioningProfileDetector().detect(
      cleanDeviceProbes(bundle: FakeBundleProbe(provisioningProfile: true)))

    XCTAssertEqual(signal.outcome, .detected)
  }

  func testProvisioningDetectorStaysQuietOnAnAppStoreBuild() {
    XCTAssertEqual(ProvisioningProfileDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  // MARK: - Binary encryption

  func testEncryptionDetectorStaysQuietOnAnEncryptedBinary() {
    XCTAssertEqual(BinaryEncryptionDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testEncryptionDetectorFiresOnADecryptedBinaryOnDevice() {
    let signal = BinaryEncryptionDetector().detect(
      cleanDeviceProbes(bundle: FakeBundleProbe(encrypted: false)))

    XCTAssertEqual(signal.outcome, .detected)
  }

  /// Simulator builds are never encrypted, so without this guard the signal would
  /// fire on every development run.
  func testEncryptionDetectorReportsIndeterminateOnASimulator() {
    let signal = BinaryEncryptionDetector().detect(
      cleanDeviceProbes(
        deviceEnvironment: FakeDeviceEnvironmentProbe(simulator: true),
        bundle: FakeBundleProbe(encrypted: false)
      ))

    XCTAssertEqual(signal.outcome, .indeterminate)
    XCTAssertTrue(signal.description.contains("simulator builds are never encrypted"))
  }

  func testEncryptionDetectorReportsIndeterminateWhenUnreadable() {
    let signal = BinaryEncryptionDetector().detect(
      cleanDeviceProbes(bundle: FakeBundleProbe(encrypted: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }
}
