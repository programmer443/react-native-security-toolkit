import Foundation

/// Jailbreak detection signals for iOS.
///
/// None of these is proof. Each is an indicator that a device has been modified
/// in a way commonly associated with a jailbreak, and each has a documented way
/// of being defeated. They are combined by ``SignalAggregator``, which raises
/// confidence only when independent signals corroborate one another.
///
/// See `docs/runtime/jailbreak-detection.md`.

private let subject = "Jailbreak indicator"

/// Classic rootful jailbreak filesystem artefacts.
///
/// Low confidence on its own, and increasingly so: a modern rootless jailbreak
/// leaves none of these. Kept because rootful jailbreaks still exist on older
/// hardware, and because a hit here is unambiguous when it happens.
public struct RootfulPathDetector: Detector {
  public let id = "RNSEC-IOS-JAILBREAK-001"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    var found: [String] = []
    var undeterminable = 0

    for path in JailbreakSignatures.rootfulPaths {
      switch probes.paths.exists(path) {
      case .some(true): found.append(path)
      case .some(false): break
      case .none: undeterminable += 1
      }
    }

    if found.isEmpty && undeterminable > 0 {
      return SignalBuilder.indeterminate(
        id, .low, "filesystem paths were not readable", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!found.isEmpty),
      confidence: .low,
      description: found.isEmpty
        ? "No classic jailbreak filesystem artefacts found"
        : "Potential jailbreak filesystem artefact detected",
      metadata: ["matchCount": found.count, "paths": found]
    )
  }
}

/// Rootless jailbreak filesystem artefacts.
///
/// The modern counterpart to ``RootfulPathDetector``. A rootless jailbreak
/// relocates its filesystem under a prefix, so the classic path list misses it
/// entirely — which is exactly the staleness this project exists to avoid.
public struct RootlessPathDetector: Detector {
  public let id = "RNSEC-IOS-JAILBREAK-002"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    var found: [String] = []
    var undeterminable = 0

    for prefix in JailbreakSignatures.rootlessPrefixes {
      // The prefix directory itself is the strongest single hit.
      switch probes.paths.exists(prefix) {
      case .some(true): found.append(prefix)
      case .some(false): break
      case .none: undeterminable += 1
      }

      for suffix in JailbreakSignatures.rootlessSuffixes {
        switch probes.paths.exists(prefix + suffix) {
        case .some(true): found.append(prefix + suffix)
        case .some(false): break
        case .none: undeterminable += 1
        }
      }
    }

    if found.isEmpty && undeterminable > 0 {
      return SignalBuilder.indeterminate(
        id, .medium, "filesystem paths were not readable", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!found.isEmpty),
      confidence: .medium,
      description: found.isEmpty
        ? "No rootless jailbreak filesystem artefacts found"
        : "Potential rootless jailbreak filesystem artefact detected",
      metadata: ["matchCount": found.count, "paths": found]
    )
  }
}

/// A write **succeeding** outside the application container.
///
/// The strongest signal available here, and the one most easily got wrong. On a
/// healthy sandboxed application a write outside the container *fails*, so
/// **success** is the indicator. An implementation that treats failure as the
/// indicator reports every healthy device as jailbroken — a mistake present in at
/// least one widely copied library, and the reason this detector's polarity is
/// asserted by name in its tests.
public struct SandboxEscapeDetector: Detector {
  public let id = "RNSEC-IOS-JAILBREAK-003"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let wroteOutsideContainer = probes.sandbox.canWriteOutsideContainer() else {
      return SignalBuilder.indeterminate(
        id, .high, "the sandbox boundary could not be probed", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(wroteOutsideContainer),
      confidence: .high,
      description: wroteOutsideContainer
        ? "A write succeeded outside the application sandbox"
        : "Writes outside the application sandbox were refused",
      metadata: ["wroteOutsideContainer": wroteOutsideContainer]
    )
  }
}

/// Injected libraries in this process's dyld image list.
public struct InjectedLibraryDetector: Detector {
  public let id = "RNSEC-IOS-JAILBREAK-004"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let images = probes.dyld.loadedImageNames() else {
      return SignalBuilder.indeterminate(
        id, .high, "the loaded image list was unreadable", subject: subject)
    }

    let matches = images.filter { image in
      let lower = image.lowercased()
      return JailbreakSignatures.injectedImageMarkers.contains { lower.contains($0) }
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!matches.isEmpty),
      confidence: .high,
      description: matches.isEmpty
        ? "No injected library detected in this process"
        : "Potential injected library detected in this process",
      metadata: ["matchCount": matches.count]
    )
  }
}

/// `DYLD_INSERT_LIBRARIES` present in the environment.
///
/// Has essentially no benign explanation in a shipped application, which is why
/// it carries high confidence despite being a single environment read.
public struct DyldEnvironmentDetector: Detector {
  public let id = "RNSEC-IOS-JAILBREAK-005"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    let inserted = probes.environment.value(for: "DYLD_INSERT_LIBRARIES")

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(inserted != nil),
      confidence: .high,
      description: inserted == nil
        ? "No library insertion environment variable is set"
        : "A library insertion environment variable is set for this process",
      // The value can name a user's filesystem layout; only its presence is reported.
      metadata: ["insertionVariableSet": inserted != nil]
    )
  }
}

/// Jailbreak package managers reachable by URL scheme.
///
/// Opt-in. Querying these requires listing them in `LSApplicationQueriesSchemes`,
/// which becomes visible in the consuming application's `Info.plist` and in App
/// Review. That is the application author's decision, so an unconfigured app gets
/// `indeterminate` rather than a silent false negative.
public struct UrlSchemeDetector: Detector {
  public let id = "RNSEC-IOS-JAILBREAK-006"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard probes.urlSchemes.isConfigured() else {
      return SignalBuilder.indeterminate(
        id,
        .medium,
        "LSApplicationQueriesSchemes is not configured (see docs/runtime/jailbreak-detection.md)",
        subject: subject
      )
    }

    var found: [String] = []
    var undeterminable = 0

    for scheme in JailbreakSignatures.packageManagerSchemes {
      switch probes.urlSchemes.canOpen(scheme: scheme) {
      case .some(true): found.append(scheme)
      case .some(false): break
      case .none: undeterminable += 1
      }
    }

    if found.isEmpty && undeterminable > 0 {
      return SignalBuilder.indeterminate(
        id, .medium, "URL scheme queries failed", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!found.isEmpty),
      confidence: .medium,
      description: found.isEmpty
        ? "No jailbreak package manager URL scheme is reachable"
        : "A jailbreak package manager URL scheme is reachable",
      metadata: ["schemes": found]
    )
  }
}

/// System directories that have become symbolic links.
public struct SymlinkAnomalyDetector: Detector {
  public let id = "RNSEC-IOS-JAILBREAK-007"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    var found: [String] = []
    var undeterminable = 0

    for path in JailbreakSignatures.symlinkCandidates {
      switch probes.paths.isSymbolicLink(path) {
      case .some(true): found.append(path)
      case .some(false): break
      case .none: undeterminable += 1
      }
    }

    if found.isEmpty && undeterminable > 0 {
      return SignalBuilder.indeterminate(
        id, .medium, "symbolic link status was unreadable", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!found.isEmpty),
      confidence: .medium,
      description: found.isEmpty
        ? "System directories are not symbolic links"
        : "A system directory has been replaced with a symbolic link",
      metadata: ["paths": found]
    )
  }
}

/// The jailbreak check.
public struct JailbreakCheckEngine: CheckEngine {
  public let checkId = "jailbreak"

  public init() {}

  public func detectors(_ options: CheckOptions) -> [Detector] {
    [
      RootfulPathDetector(),
      RootlessPathDetector(),
      SandboxEscapeDetector(),
      InjectedLibraryDetector(),
      DyldEnvironmentDetector(),
      UrlSchemeDetector(),
      SymlinkAnomalyDetector(),
    ]
  }

  /// Jailbreak detection is meaningless on a simulator: it runs against the macOS
  /// filesystem, and there is no iOS device to have been modified. Reporting
  /// `detected` there would train developers to ignore the check; reporting
  /// `secure` would be a lie.
  public func unavailableReason(_ probes: ProbeSet) -> UnavailableReason? {
    probes.deviceEnvironment.isSimulator() ? .simulator : nil
  }

  public func metadata(_ probes: ProbeSet, _ options: CheckOptions) -> [String: Any] {
    [
      "signatureVersion": JailbreakSignatures.version,
      // Surfaced so a developer can see why a signal was inconclusive rather
      // than having to guess.
      "urlSchemeQueriesConfigured": probes.urlSchemes.isConfigured(),
    ]
  }
}
