import XCTest

@testable import RNSecurityEngine

/// For capability checks, `detected` means "a weakness indicator fired" rather
/// than "an attack was found". These tests pin that polarity down, because
/// getting it backwards would report a well-equipped device as the problem.
final class SecureHardwareDetectorsTests: XCTestCase {

  func testStaysQuietWhenTheSecureEnclaveIsAvailable() {
    XCTAssertEqual(SecureEnclaveDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testFiresWhenTheSecureEnclaveIsUnavailable() {
    let signal = SecureEnclaveDetector().detect(
      cleanDeviceProbes(keychain: FakeKeychainProbe(secureEnclave: false)))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
  }

  func testReportsIndeterminateWhenTheProbeCannotRun() {
    let signal = SecureEnclaveDetector().detect(
      cleanDeviceProbes(keychain: FakeKeychainProbe(secureEnclave: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }

  func testKeychainDetectorFiresWhenTheKeychainIsUnusable() {
    let signal = KeychainAvailabilityDetector().detect(
      cleanDeviceProbes(keychain: FakeKeychainProbe(keychainUsable: false)))

    XCTAssertEqual(signal.outcome, .detected)
  }

  func testKeychainDetectorStaysQuietWhenUsable() {
    XCTAssertEqual(
      KeychainAvailabilityDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }
}

final class BiometricDetectorsTests: XCTestCase {

  func testStaysQuietWhenBiometricsAreUsable() {
    XCTAssertEqual(
      BiometricAvailabilityDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  /// Each reason calls for a different application response, so each is surfaced.
  func testDistinguishesWhyBiometricsAreUnusable() {
    let cases = [
      ("not-available", "no supporting hardware"),
      ("not-enrolled", "nothing enrolled"),
      ("lockout", "locked out after failed attempts"),
      ("passcode-not-set", "no device passcode is set"),
    ]

    for (reason, expected) in cases {
      let signal = BiometricAvailabilityDetector().detect(
        cleanDeviceProbes(biometry: FakeBiometryProbe(canEvaluate: false, reason: reason)))

      XCTAssertEqual(signal.outcome, .detected)
      XCTAssertTrue(signal.description.contains(expected), "reason \(reason)")
      XCTAssertEqual(signal.metadata["reason"] as? String, reason)
    }
  }

  func testBiometryTypeDetectorFiresWhenNoBiometryIsPresent() {
    let signal = BiometryTypeDetector().detect(
      cleanDeviceProbes(biometry: FakeBiometryProbe(type: "none")))

    XCTAssertEqual(signal.outcome, .detected)
  }

  func testBiometryTypeDetectorStaysQuietWhenPresent() {
    let signal = BiometryTypeDetector().detect(cleanDeviceProbes())

    XCTAssertEqual(signal.outcome, .notDetected)
    XCTAssertTrue(signal.description.contains("face-id"))
  }

  func testPasscodeDetectorFiresWhenNoPasscodeIsSet() {
    let signal = DevicePasscodeDetector().detect(
      cleanDeviceProbes(biometry: FakeBiometryProbe(deviceOwnerAuth: false)))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
  }

  func testPasscodeDetectorStaysQuietWhenSet() {
    XCTAssertEqual(DevicePasscodeDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  /// Nothing in this check may expose biometric material.
  func testNoSignalMetadataCarriesBiometricData() {
    let signals = [
      BiometricAvailabilityDetector().detect(cleanDeviceProbes()),
      BiometryTypeDetector().detect(cleanDeviceProbes()),
      DevicePasscodeDetector().detect(cleanDeviceProbes()),
    ]

    let allowed: Set<String> = ["reason", "biometryType", "devicePasscodeSet"]
    for signal in signals {
      XCTAssertTrue(allowed.isSuperset(of: signal.metadata.keys))
    }
  }
}

final class NetworkDetectorsTests: XCTestCase {

  func testAtsDetectorFiresWhenArbitraryLoadsArePermitted() {
    let signal = AppTransportSecurityDetector().detect(
      cleanDeviceProbes(networkConfig: FakeNetworkConfigProbe(arbitraryLoads: true)))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
  }

  func testAtsDetectorStaysQuietUnderSecureDefaults() {
    XCTAssertEqual(
      AppTransportSecurityDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testProxyDetectorIsInformationalOnly() {
    let signal = ProxyConfigurationDetector().detect(
      cleanDeviceProbes(networkConfig: FakeNetworkConfigProbe(proxy: true)))

    XCTAssertEqual(signal.outcome, .detected)
    // Corporate networks and content blockers set proxies too.
    XCTAssertEqual(signal.confidence, .low)
  }

  /// On iOS the `utun` family is also used by Personal Hotspot, AirPlay, content
  /// filters and Private Relay — none of which is a VPN.
  func testVpnDetectorIsInformationalOnly() {
    let signal = VpnInterfaceDetector().detect(
      cleanDeviceProbes(networkConfig: FakeNetworkConfigProbe(vpn: true)))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .low)
  }

  func testReportIndeterminateWhenSettingsAreUnreadable() {
    let probes = cleanDeviceProbes(
      networkConfig: FakeNetworkConfigProbe(arbitraryLoads: nil, proxy: nil, vpn: nil))

    XCTAssertEqual(AppTransportSecurityDetector().detect(probes).outcome, .indeterminate)
    XCTAssertEqual(ProxyConfigurationDetector().detect(probes).outcome, .indeterminate)
    XCTAssertEqual(VpnInterfaceDetector().detect(probes).outcome, .indeterminate)
  }
}

final class ScreenDetectorsTests: XCTestCase {

  func testFiresWhileTheScreenIsBeingCaptured() {
    let signal = ScreenCaptureDetector().detect(
      cleanDeviceProbes(screenCapture: FakeScreenCaptureProbe(captured: true)))

    XCTAssertEqual(signal.outcome, .detected)
    XCTAssertEqual(signal.confidence, .high)
  }

  func testStaysQuietWhenNotBeingCaptured() {
    XCTAssertEqual(ScreenCaptureDetector().detect(cleanDeviceProbes()).outcome, .notDetected)
  }

  func testReportsIndeterminateWhenTheStateIsUnreadable() {
    let signal = ScreenCaptureDetector().detect(
      cleanDeviceProbes(screenCapture: FakeScreenCaptureProbe(captured: nil)))

    XCTAssertEqual(signal.outcome, .indeterminate)
  }

  /// The platform asymmetry is stated in the result itself, not only in the docs.
  func testCheckMetadataStatesThatIosCannotPreventCapture() {
    let metadata = ScreenCheckEngine().metadata(cleanDeviceProbes(), .empty)

    XCTAssertTrue((metadata["note"] as? String)?.contains("not prevention") == true)
  }
}
