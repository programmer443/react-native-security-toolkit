import Foundation

@testable import RNSecurityEngine

/// A device, described in data.
///
/// This is the payoff of injecting probes into detectors: a jailbroken phone, a
/// locked-down phone, and a phone whose filesystem is unreadable are all just
/// different values here. Every iOS detector is therefore testable with
/// `swift test` on an ordinary Mac — no simulator, no jailbroken hardware.
///
/// `nil` in any map means "the probe could not determine this", which detectors
/// are required to report as `indeterminate` rather than as "not detected".
struct FakePathProbe: PathProbe {
  var existing: [String: Bool?] = [:]
  var symlinks: [String: Bool?] = [:]
  var defaultExists: Bool? = false
  var defaultSymlink: Bool? = false

  func exists(_ path: String) -> Bool? {
    if let value = existing[path] { return value }
    return defaultExists
  }

  func isSymbolicLink(_ path: String) -> Bool? {
    if let value = symlinks[path] { return value }
    return defaultSymlink
  }
}

struct FakeSandboxProbe: SandboxProbe {
  var wroteOutsideContainer: Bool? = false

  func canWriteOutsideContainer() -> Bool? { wroteOutsideContainer }
}

struct FakeDyldProbe: DyldProbe {
  var images: [String]? = [
    "/usr/lib/libSystem.B.dylib",
    "/System/Library/Frameworks/UIKit.framework/UIKit",
  ]

  func loadedImageNames() -> [String]? { images }
}

struct FakeEnvironmentProbe: EnvironmentProbe {
  var values: [String: String] = [:]

  func value(for key: String) -> String? { values[key] }
}

struct FakeUrlSchemeProbe: UrlSchemeProbe {
  var configured = true
  var openable: [String: Bool?] = [:]
  var defaultOpenable: Bool? = false

  func isConfigured() -> Bool { configured }

  func canOpen(scheme: String) -> Bool? {
    if let value = openable[scheme] { return value }
    return defaultOpenable
  }
}

struct FakeDeviceEnvironmentProbe: DeviceEnvironmentProbe {
  var simulator = false

  func isSimulator() -> Bool { simulator }
}

struct FakeProcessProbe: ProcessProbe {
  var traced: Bool? = false
  var parentPid: Int32? = 1

  func isTraced() -> Bool? { traced }

  func parentProcessId() -> Int32? { parentPid }
}

struct FakeNativeSymbolProbe: NativeSymbolProbe {
  var available = true
  var origins: [String: String?] = [:]
  var defaultOrigin: String? = "/usr/lib/system/libsystem_kernel.dylib"

  func isAvailable() -> Bool { available }

  func originOf(symbol: String) -> String? {
    guard available else { return nil }
    if let value = origins[symbol] { return value }
    return defaultOrigin
  }
}

struct FakeObjcRuntimeProbe: ObjcRuntimeProbe {
  var images: [String: String?] = [:]
  var defaultImage: String? = "/System/Library/Frameworks/Foundation.framework/Foundation"

  func implementationImage(className: String, selector: String) -> String? {
    if let value = images["\(className).\(selector)"] { return value }
    return defaultImage
  }
}

struct FakeBundleProbe: BundleProbe {
  var identifier: String? = "com.example.app"
  var provisioningProfile: Bool? = false
  var encrypted: Bool? = true

  func bundleIdentifier() -> String? { identifier }

  func hasEmbeddedProvisioningProfile() -> Bool? { provisioningProfile }

  func isMainBinaryEncrypted() -> Bool? { encrypted }
}

struct FakeKeychainProbe: KeychainProbe {
  var secureEnclave: Bool? = true
  var keychainUsable: Bool? = true

  func isSecureEnclaveAvailable() -> Bool? { secureEnclave }

  func canStoreKeychainItem() -> Bool? { keychainUsable }
}

struct FakeBiometryProbe: BiometryProbe {
  var canEvaluate: Bool? = true
  var reason: String?
  var type: String? = "face-id"
  var deviceOwnerAuth: Bool? = true

  func canEvaluateBiometrics() -> Bool? { canEvaluate }

  func biometryUnavailableReason() -> String? { reason }

  func biometryType() -> String? { type }

  func canEvaluateDeviceOwnerAuthentication() -> Bool? { deviceOwnerAuth }
}

struct FakeNetworkConfigProbe: NetworkConfigProbe {
  var arbitraryLoads: Bool? = false
  var proxy: Bool? = false
  var vpn: Bool? = false

  func allowsArbitraryLoads() -> Bool? { arbitraryLoads }

  func isProxyConfigured() -> Bool? { proxy }

  func isVpnInterfacePresent() -> Bool? { vpn }
}

struct FakeScreenCaptureProbe: ScreenCaptureProbe {
  var captured: Bool? = false

  func isCaptured() -> Bool? { captured }
}

/// A stock, unmodified device with every probe working.
func cleanDeviceProbes(
  paths: PathProbe = FakePathProbe(),
  sandbox: SandboxProbe = FakeSandboxProbe(),
  dyld: DyldProbe = FakeDyldProbe(),
  environment: EnvironmentProbe = FakeEnvironmentProbe(),
  urlSchemes: UrlSchemeProbe = FakeUrlSchemeProbe(),
  deviceEnvironment: DeviceEnvironmentProbe = FakeDeviceEnvironmentProbe(),
  process: ProcessProbe = FakeProcessProbe(),
  symbols: NativeSymbolProbe = FakeNativeSymbolProbe(),
  objcRuntime: ObjcRuntimeProbe = FakeObjcRuntimeProbe(),
  bundle: BundleProbe = FakeBundleProbe(),
  keychain: KeychainProbe = FakeKeychainProbe(),
  biometry: BiometryProbe = FakeBiometryProbe(),
  networkConfig: NetworkConfigProbe = FakeNetworkConfigProbe(),
  screenCapture: ScreenCaptureProbe = FakeScreenCaptureProbe()
) -> ProbeSet {
  ProbeSet(
    paths: paths,
    sandbox: sandbox,
    dyld: dyld,
    environment: environment,
    urlSchemes: urlSchemes,
    deviceEnvironment: deviceEnvironment,
    process: process,
    symbols: symbols,
    objcRuntime: objcRuntime,
    bundle: bundle,
    keychain: keychain,
    biometry: biometry,
    networkConfig: networkConfig,
    screenCapture: screenCapture
  )
}
