import CFNetwork
import Darwin
import Foundation
import LocalAuthentication
import MachO
import ObjectiveC
import Security
import UIKit

/// Real implementations of the engine's probe protocols.
///
/// These live outside the `RNSecurityEngine` Swift Package target on purpose:
/// they use UIKit and iOS-specific syscalls, and keeping them out is what lets
/// the engine itself be unit-tested with `swift test` on a Mac. CocoaPods
/// compiles both directories into the shipped pod.
///
/// Every method is total. A failure becomes `nil`, never an exception and never a
/// fabricated `false`.

/// Filesystem checks through `stat`/`lstat` rather than `FileManager`.
///
/// `FileManager` is an Objective-C class and therefore a natural swizzling
/// target. The syscall wrappers are a harder — not impossible — one, which is a
/// small but free improvement on a check whose whole point is running in a
/// hostile process.
struct RealPathProbe: PathProbe {

  func exists(_ path: String) -> Bool? {
    var info = stat()
    if stat(path, &info) == 0 {
      return true
    }
    return interpretLookupFailure()
  }

  func isSymbolicLink(_ path: String) -> Bool? {
    var info = stat()
    if lstat(path, &info) == 0 {
      return (info.st_mode & S_IFMT) == S_IFLNK
    }
    return interpretLookupFailure()
  }

  /// `ENOENT` genuinely means "not there". Anything else means the sandbox
  /// stopped us looking, which is inconclusive rather than negative.
  private func interpretLookupFailure() -> Bool? {
    switch errno {
    case ENOENT, ENOTDIR, ENAMETOOLONG:
      return false
    default:
      return nil
    }
  }
}

/// Attempts a write outside the application container.
///
/// **Success is the jailbreak indicator.** On a healthy sandboxed application the
/// write is refused, so a refusal is the *good* outcome. Getting this backwards
/// reports every healthy device as jailbroken.
struct RealSandboxProbe: SandboxProbe {

  func canWriteOutsideContainer() -> Bool? {
    let path = "/private/rnsec_sandbox_probe_\(UUID().uuidString)"
    let descriptor = open(path, O_CREAT | O_WRONLY | O_EXCL, 0o600)

    if descriptor >= 0 {
      close(descriptor)
      unlink(path)
      return true
    }

    switch errno {
    case EACCES, EPERM, EROFS, ENOENT:
      // The sandbox refused it. Expected, and healthy.
      return false
    default:
      // Something else went wrong; do not read that as a clean result.
      return nil
    }
  }
}

/// Images loaded into this process, from dyld.
struct RealDyldProbe: DyldProbe {

  func loadedImageNames() -> [String]? {
    let count = _dyld_image_count()
    guard count > 0 else { return nil }

    var names: [String] = []
    names.reserveCapacity(Int(count))

    for index in 0..<count {
      if let name = _dyld_get_image_name(index) {
        names.append(String(cString: name))
      }
    }
    return names.isEmpty ? nil : names
  }
}

struct RealEnvironmentProbe: EnvironmentProbe {

  func value(for key: String) -> String? {
    guard let raw = getenv(key) else { return nil }
    let value = String(cString: raw)
    return value.isEmpty ? nil : value
  }
}

/// URL scheme reachability, captured up front on the main thread.
///
/// `UIApplication.canOpenURL` must be called on the main thread, and the security
/// engine runs on a background queue. Rather than dispatching synchronously to
/// main from a background queue — which invites a deadlock for a signal that is
/// off by default — the answers are captured once during module initialisation
/// and carried as data.
struct RealUrlSchemeProbe: UrlSchemeProbe {

  private let configured: Bool
  private let results: [String: Bool]

  init(configured: Bool, results: [String: Bool]) {
    self.configured = configured
    self.results = results
  }

  func isConfigured() -> Bool { configured }

  func canOpen(scheme: String) -> Bool? { results[scheme] }

  /// Captures scheme reachability. **Must be called on the main thread.**
  @MainActor
  static func capture() -> RealUrlSchemeProbe {
    let declared =
      Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes") as? [String] ?? []

    // Only schemes the application actually declared can be queried; asking about
    // the others would return a meaningless `false`.
    let queryable = Set(declared.map { $0.lowercased() })
    let interesting = JailbreakSignatures.packageManagerSchemes.filter {
      queryable.contains($0.lowercased())
    }

    var results: [String: Bool] = [:]
    for scheme in interesting {
      if let url = URL(string: "\(scheme)://") {
        results[scheme] = UIApplication.shared.canOpenURL(url)
      }
    }

    return RealUrlSchemeProbe(configured: !interesting.isEmpty, results: results)
  }
}

/// Whether this process runs on the iOS Simulator.
///
/// Both a compile-time check and a runtime one: the compile-time flag is exact,
/// and `SIMULATOR_DEVICE_NAME` catches a binary built for a device but running
/// somewhere unexpected.
struct RealDeviceEnvironmentProbe: DeviceEnvironmentProbe {

  func isSimulator() -> Bool {
    #if targetEnvironment(simulator)
      return true
    #else
      return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
    #endif
  }
}

/// Process state through `sysctl`.
///
/// `sysctl` is public API. `ptrace` is not in the public iOS headers, and is a
/// mitigation rather than a detection, so it is deliberately not used here.
struct RealProcessProbe: ProcessProbe {

  /// `P_TRACED` from `sys/proc.h`. Declared locally because it is not surfaced to
  /// Swift by the SDK.
  private static let processTracedFlag: Int32 = 0x0000_0800

  func isTraced() -> Bool? {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

    let result = mib.withUnsafeMutableBufferPointer { pointer in
      sysctl(pointer.baseAddress, u_int(pointer.count), &info, &size, nil, 0)
    }

    guard result == 0 else { return nil }
    return (info.kp_proc.p_flag & Self.processTracedFlag) != 0
  }

  func parentProcessId() -> Int32? { getppid() }
}

/// Native symbol resolution through `dlsym` + `dladdr`.
struct RealNativeSymbolProbe: NativeSymbolProbe {

  func isAvailable() -> Bool { true }

  func originOf(symbol: String) -> String? {
    guard let address = dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) else {
      return nil
    }
    var info = Dl_info()
    guard dladdr(address, &info) != 0, let name = info.dli_fname else { return nil }
    return String(cString: name)
  }
}

/// Objective-C method implementation lookup.
struct RealObjcRuntimeProbe: ObjcRuntimeProbe {

  func implementationImage(className: String, selector: String) -> String? {
    guard let cls = NSClassFromString(className) else { return nil }
    let sel = NSSelectorFromString(selector)

    // Class methods live on the metaclass; try the instance method first, then
    // the class method, so one lookup covers both kinds.
    var implementation = class_getMethodImplementation(cls, sel)
    if implementation == nil, let metaClass = object_getClass(cls) {
      implementation = class_getMethodImplementation(metaClass, sel)
    }
    guard let implementation else { return nil }

    var info = Dl_info()
    guard dladdr(UnsafeRawPointer(implementation), &info) != 0, let name = info.dli_fname else {
      return nil
    }
    return String(cString: name)
  }
}

/// The application bundle and its main Mach-O binary.
struct RealBundleProbe: BundleProbe {

  func bundleIdentifier() -> String? { Bundle.main.bundleIdentifier }

  func hasEmbeddedProvisioningProfile() -> Bool? {
    guard let resourcePath = Bundle.main.resourcePath else { return nil }
    var isDirectory: ObjCBool = false
    let path = resourcePath + "/embedded.mobileprovision"
    return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
  }

  /// Reads `LC_ENCRYPTION_INFO_64` from the main image and reports `cryptid`.
  ///
  /// App Store binaries carry FairPlay encryption; locally built and simulator
  /// binaries do not.
  func isMainBinaryEncrypted() -> Bool? {
    guard let header = _dyld_get_image_header(0) else { return nil }

    return header.withMemoryRebound(to: mach_header_64.self, capacity: 1) { machHeader -> Bool? in
      guard machHeader.pointee.magic == MH_MAGIC_64 else { return nil }

      var cursor = UnsafeRawPointer(machHeader).advanced(by: MemoryLayout<mach_header_64>.size)

      for _ in 0..<machHeader.pointee.ncmds {
        let command = cursor.assumingMemoryBound(to: load_command.self)
        if command.pointee.cmd == UInt32(LC_ENCRYPTION_INFO_64) {
          let info = cursor.assumingMemoryBound(to: encryption_info_command_64.self)
          return info.pointee.cryptid != 0
        }
        cursor = cursor.advanced(by: Int(command.pointee.cmdsize))
      }

      // No encryption load command at all. That is a definite "not encrypted",
      // not a failure to read.
      return false
    }
  }
}

/// Keychain and Secure Enclave capability, established by exercising them.
struct RealKeychainProbe: KeychainProbe {

  func isSecureEnclaveAvailable() -> Bool? {
    let tag = "com.rnsecurity.probe.\(UUID().uuidString)".data(using: .utf8)!

    guard
      let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)
    else {
      return nil
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: false,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: access,
      ],
    ]

    var error: Unmanaged<CFError>?
    let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error)

    if key != nil {
      // Not permanent, so nothing to delete — it goes when the reference does.
      return true
    }

    // A creation failure is a real answer: this device cannot make Secure
    // Enclave keys for us.
    return false
  }

  func canStoreKeychainItem() -> Bool? {
    let account = "com.rnsecurity.probe.\(UUID().uuidString)"
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: account,
      kSecValueData as String: Data("probe".utf8),
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]

    let status = SecItemAdd(query as CFDictionary, nil)

    // Always clean up, whatever happened.
    SecItemDelete(
      [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
      ] as CFDictionary)

    switch status {
    case errSecSuccess, errSecDuplicateItem:
      return true
    case errSecMissingEntitlement, errSecNotAvailable, errSecInteractionNotAllowed:
      return false
    default:
      return nil
    }
  }
}

/// Device authentication capability through `LocalAuthentication`.
struct RealBiometryProbe: BiometryProbe {

  /// `biometryType` is only populated once `canEvaluatePolicy` has been called,
  /// so one evaluated context is reused for every question.
  private func evaluatedContext() -> (context: LAContext, error: NSError?, canEvaluate: Bool) {
    let context = LAContext()
    var error: NSError?
    let canEvaluate = context.canEvaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics, error: &error)
    return (context, error, canEvaluate)
  }

  func canEvaluateBiometrics() -> Bool? { evaluatedContext().canEvaluate }

  func biometryUnavailableReason() -> String? {
    let evaluated = evaluatedContext()
    if evaluated.canEvaluate { return nil }

    switch evaluated.error?.code {
    case LAError.biometryNotAvailable.rawValue: return "not-available"
    case LAError.biometryNotEnrolled.rawValue: return "not-enrolled"
    case LAError.biometryLockout.rawValue: return "lockout"
    case LAError.passcodeNotSet.rawValue: return "passcode-not-set"
    default: return nil
    }
  }

  func biometryType() -> String? {
    let context = evaluatedContext().context
    switch context.biometryType {
    case .none: return "none"
    case .touchID: return "touch-id"
    case .faceID: return "face-id"
    default: return "unknown"
    }
  }

  func canEvaluateDeviceOwnerAuthentication() -> Bool? {
    let context = LAContext()
    var error: NSError?
    return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
  }
}

/// Network configuration from `Info.plist` and the system proxy settings.
struct RealNetworkConfigProbe: NetworkConfigProbe {

  func allowsArbitraryLoads() -> Bool? {
    guard
      let ats = Bundle.main.object(forInfoDictionaryKey: "NSAppTransportSecurity")
        as? [String: Any]
    else {
      // No ATS dictionary at all means the secure defaults apply.
      return false
    }
    return ats["NSAllowsArbitraryLoads"] as? Bool ?? false
  }

  private func proxySettings() -> [String: Any]? {
    CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any]
  }

  func isProxyConfigured() -> Bool? {
    guard let settings = proxySettings() else { return nil }
    return settings["HTTPProxy"] != nil || settings["HTTPSProxy"] != nil
  }

  func isVpnInterfacePresent() -> Bool? {
    guard let settings = proxySettings(),
      let scoped = settings["__SCOPED__"] as? [String: Any]
    else {
      return nil
    }

    let vpnInterfacePrefixes = ["tap", "tun", "ppp", "ipsec", "utun"]
    return scoped.keys.contains { key in
      vpnInterfacePrefixes.contains { key.hasPrefix($0) }
    }
  }
}

/// Screen capture state.
///
/// `UIScreen.isCaptured` is main-thread API and the engine runs on a background
/// queue, so the read hops to main. Safe here because main is never blocked
/// waiting on the engine — but worth knowing before this is called from anywhere
/// else.
struct RealScreenCaptureProbe: ScreenCaptureProbe {

  func isCaptured() -> Bool? {
    if Thread.isMainThread {
      return MainActor.assumeIsolated { UIScreen.main.isCaptured }
    }
    return DispatchQueue.main.sync { MainActor.assumeIsolated { UIScreen.main.isCaptured } }
  }
}

/// Assembles the real probe set.
enum IOSProbeSetFactory {
  @MainActor
  static func create() -> ProbeSet {
    ProbeSet(
      paths: RealPathProbe(),
      sandbox: RealSandboxProbe(),
      dyld: RealDyldProbe(),
      environment: RealEnvironmentProbe(),
      urlSchemes: RealUrlSchemeProbe.capture(),
      deviceEnvironment: RealDeviceEnvironmentProbe(),
      process: RealProcessProbe(),
      symbols: RealNativeSymbolProbe(),
      objcRuntime: RealObjcRuntimeProbe(),
      bundle: RealBundleProbe(),
      keychain: RealKeychainProbe(),
      biometry: RealBiometryProbe(),
      networkConfig: RealNetworkConfigProbe(),
      screenCapture: RealScreenCaptureProbe()
    )
  }
}
