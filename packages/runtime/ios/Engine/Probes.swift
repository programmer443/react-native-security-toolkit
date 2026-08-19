import Foundation

/// The environment, behind protocols.
///
/// Detectors never touch the filesystem, `dyld` or the process environment
/// directly. They ask a probe. That one constraint is what makes every iOS
/// detector unit-testable on an ordinary macOS machine with no jailbroken device
/// anywhere in the loop — a test describes a jailbroken phone as data.
///
/// Probes are also the only place allowed to swallow a failure, and they never
/// swallow it silently: a failed read becomes `nil`, which detectors are required
/// to report as `indeterminate` rather than as "not detected".

/// Filesystem reads.
public protocol PathProbe: Sendable {
  /// Whether a path exists. `nil` when the answer cannot be determined.
  ///
  /// Implementations use `stat`/`access` rather than `FileManager`: `FileManager`
  /// is an Objective-C class and therefore a natural swizzling target, whereas
  /// the syscall wrappers are a harder — not impossible — one.
  func exists(_ path: String) -> Bool?

  /// Whether a path is a symbolic link. `nil` when undeterminable.
  func isSymbolicLink(_ path: String) -> Bool?
}

/// Sandbox boundary checks.
public protocol SandboxProbe: Sendable {
  /// Whether a write **succeeded** at a path outside the application container.
  ///
  /// The polarity matters more than anything else in this file. On a healthy
  /// sandboxed application such a write *fails*, so **success** is the jailbreak
  /// indicator. Treating failure as the indicator — as at least one widely copied
  /// implementation does — reports every healthy device as jailbroken.
  func canWriteOutsideContainer() -> Bool?
}

/// Loaded Mach-O images.
public protocol DyldProbe: Sendable {
  /// Names of images loaded into this process, or `nil` if unreadable.
  func loadedImageNames() -> [String]?
}

/// Process environment.
public protocol EnvironmentProbe: Sendable {
  /// An environment variable's value, or `nil` when unset.
  func value(for key: String) -> String?
}

/// URL scheme interrogation.
public protocol UrlSchemeProbe: Sendable {
  /// Whether the application declared `LSApplicationQueriesSchemes` at all.
  ///
  /// Without those declarations `canOpenURL` answers `false` for everything,
  /// which is a false negative indistinguishable from a clean result.
  func isConfigured() -> Bool

  /// Whether a scheme can be opened, or `nil` when undeterminable.
  func canOpen(scheme: String) -> Bool?
}

/// Process state.
public protocol ProcessProbe: Sendable {
  /// Whether this process is being traced, from `sysctl`'s `P_TRACED` flag.
  ///
  /// Public API, unlike `ptrace`, and therefore App Store safe.
  func isTraced() -> Bool?

  /// This process's parent process identifier, or `nil` if undeterminable.
  func parentProcessId() -> Int32?
}

/// Native symbol resolution.
public protocol NativeSymbolProbe: Sendable {
  /// Whether symbol resolution is available at all.
  func isAvailable() -> Bool

  /// Path of the image providing `symbol`, or `nil` if unresolvable.
  func originOf(symbol: String) -> String?
}

/// Objective-C runtime introspection.
public protocol ObjcRuntimeProbe: Sendable {
  /// Path of the image providing `selector`'s implementation on `className`.
  ///
  /// A method whose implementation lives outside the framework that declared it
  /// has been replaced by something — which is what swizzling looks like from
  /// the inside.
  func implementationImage(className: String, selector: String) -> String?
}

/// The application bundle and its main binary.
public protocol BundleProbe: Sendable {
  func bundleIdentifier() -> String?

  /// Whether an `embedded.mobileprovision` is present in the bundle.
  func hasEmbeddedProvisioningProfile() -> Bool?

  /// Whether the main binary carries App Store encryption (`cryptid`).
  func isMainBinaryEncrypted() -> Bool?
}

/// Keychain and Secure Enclave capabilities.
public protocol KeychainProbe: Sendable {
  /// Whether a Secure Enclave key can actually be created.
  ///
  /// Established by creating one and deleting it. Capability flags describe what
  /// a device *has*; only creating a key tells you what your keys will get.
  func isSecureEnclaveAvailable() -> Bool?

  /// Whether an item can be stored in and removed from the keychain.
  func canStoreKeychainItem() -> Bool?
}

/// Device authentication capabilities.
public protocol BiometryProbe: Sendable {
  /// Whether biometric authentication can be evaluated right now.
  func canEvaluateBiometrics() -> Bool?

  /// Why biometric evaluation is unavailable: `not-available`, `not-enrolled`,
  /// `lockout`, `passcode-not-set`, or `nil` when it is available.
  func biometryUnavailableReason() -> String?

  /// `none`, `touch-id`, `face-id`, `optic-id`, or `nil` if undeterminable.
  func biometryType() -> String?

  /// Whether a device passcode is set, so device-owner authentication is possible.
  func canEvaluateDeviceOwnerAuthentication() -> Bool?
}

/// Network configuration and posture.
public protocol NetworkConfigProbe: Sendable {
  /// Whether App Transport Security permits arbitrary loads for this application.
  func allowsArbitraryLoads() -> Bool?

  /// Whether a system HTTP proxy is configured.
  func isProxyConfigured() -> Bool?

  /// Whether a VPN-style network interface is present.
  func isVpnInterfacePresent() -> Bool?
}

/// Screen capture state.
public protocol ScreenCaptureProbe: Sendable {
  /// Whether the screen is currently being recorded or mirrored.
  func isCaptured() -> Bool?
}

/// Facts about the execution environment itself.
public protocol DeviceEnvironmentProbe: Sendable {
  /// Whether this process is running on the iOS Simulator.
  ///
  /// The simulator runs against the macOS filesystem, so filesystem-based
  /// jailbreak indicators are meaningless there — the question "has this iOS
  /// device been modified" is malformed when there is no iOS device.
  func isSimulator() -> Bool
}

/// Everything a detector may reach for, in one place.
public struct ProbeSet: Sendable {
  public let paths: PathProbe
  public let sandbox: SandboxProbe
  public let dyld: DyldProbe
  public let environment: EnvironmentProbe
  public let urlSchemes: UrlSchemeProbe
  public let deviceEnvironment: DeviceEnvironmentProbe
  public let process: ProcessProbe
  public let symbols: NativeSymbolProbe
  public let objcRuntime: ObjcRuntimeProbe
  public let bundle: BundleProbe
  public let keychain: KeychainProbe
  public let biometry: BiometryProbe
  public let networkConfig: NetworkConfigProbe
  public let screenCapture: ScreenCaptureProbe

  public init(
    paths: PathProbe,
    sandbox: SandboxProbe,
    dyld: DyldProbe,
    environment: EnvironmentProbe,
    urlSchemes: UrlSchemeProbe,
    deviceEnvironment: DeviceEnvironmentProbe,
    process: ProcessProbe,
    symbols: NativeSymbolProbe,
    objcRuntime: ObjcRuntimeProbe,
    bundle: BundleProbe,
    keychain: KeychainProbe,
    biometry: BiometryProbe,
    networkConfig: NetworkConfigProbe,
    screenCapture: ScreenCaptureProbe
  ) {
    self.paths = paths
    self.sandbox = sandbox
    self.dyld = dyld
    self.environment = environment
    self.urlSchemes = urlSchemes
    self.deviceEnvironment = deviceEnvironment
    self.process = process
    self.symbols = symbols
    self.objcRuntime = objcRuntime
    self.bundle = bundle
    self.keychain = keychain
    self.biometry = biometry
    self.networkConfig = networkConfig
    self.screenCapture = screenCapture
  }
}
