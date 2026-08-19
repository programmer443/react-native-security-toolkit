import Foundation

/// Network posture signals for iOS.
///
/// **A mobile application cannot reliably detect an interception attack**, and
/// nothing here should be read as if it could. These signals describe the
/// application's own configuration and the device's network posture.
///
/// See `docs/runtime/network-security-ios.md`.

private let subject = "Network indicator"

/// App Transport Security permits arbitrary loads.
///
/// A build-time fact about this application, decided by `Info.plist`, which makes
/// it the one signal here that is entirely actionable.
public struct AppTransportSecurityDetector: Detector {
  public let id = "RNSEC-IOS-NETWORK-001"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let permitted = probes.networkConfig.allowsArbitraryLoads() else {
      return SignalBuilder.indeterminate(
        id, .high, "the App Transport Security configuration was unreadable", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(permitted),
      confidence: .high,
      description: permitted
        ? "App Transport Security permits arbitrary loads for this application"
        : "App Transport Security does not permit arbitrary loads",
      metadata: ["allowsArbitraryLoads": permitted]
    )
  }
}

/// A system HTTP proxy is configured.
///
/// Informational. Corporate networks, debugging tools and content blockers all
/// set proxies, and so does an attacker — the signal cannot tell them apart.
public struct ProxyConfigurationDetector: Detector {
  public let id = "RNSEC-IOS-NETWORK-002"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let configured = probes.networkConfig.isProxyConfigured() else {
      return SignalBuilder.indeterminate(
        id, .low, "the system proxy configuration was unreadable", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(configured),
      confidence: .low,
      description: configured
        ? "An HTTP proxy is configured for this device"
        : "No HTTP proxy is configured for this device",
      // The proxy host can identify a corporate or home network; only its
      // presence is reported.
      metadata: ["proxyConfigured": configured]
    )
  }
}

/// A VPN-style network interface is present.
///
/// The highest false-positive signal in the toolkit, and low confidence for it.
/// VPNs are mainstream, and on iOS the `utun` interface family is also used by
/// system features that are not VPNs at all — Personal Hotspot, AirPlay,
/// content filters and iCloud Private Relay among them.
public struct VpnInterfaceDetector: Detector {
  public let id = "RNSEC-IOS-NETWORK-003"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let present = probes.networkConfig.isVpnInterfacePresent() else {
      return SignalBuilder.indeterminate(
        id, .low, "network interfaces were unreadable", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(present),
      confidence: .low,
      description: present
        ? "A VPN-style network interface is present"
        : "No VPN-style network interface is present",
      metadata: ["vpnInterfacePresent": present]
    )
  }
}

/// The network check.
public struct NetworkCheckEngine: CheckEngine {
  public let checkId = "network"

  public init() {}

  public func detectors(_ options: CheckOptions) -> [Detector] {
    [AppTransportSecurityDetector(), ProxyConfigurationDetector(), VpnInterfaceDetector()]
  }

  public func metadata(_ probes: ProbeSet, _ options: CheckOptions) -> [String: Any] {
    [
      "note":
        "Reports configuration and device posture. An application cannot reliably detect "
        + "network interception from inside its own process."
    ]
  }
}
