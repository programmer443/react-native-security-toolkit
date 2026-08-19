import Foundation

/// Debugger detection signals for iOS.
///
/// As on Android, a debugger is a development tool rather than an attack. These
/// signals are reported faithfully; deciding whether a debugger *matters* belongs
/// to the application, and `developmentMode` exists so a policy can disregard
/// them without the check having to lie about what it saw.
///
/// Everything here uses **public API**. `ptrace(PT_DENY_ATTACH)` is deliberately
/// absent: it is not in the public iOS headers, requires `dlsym`, has a history of
/// App Review friction, and is a *mitigation* rather than a detection. If it ever
/// ships it will be opt-in and documented, never a default.
///
/// See `docs/runtime/debugger-detection-ios.md`.

private let subject = "Debugger indicator"

/// The kernel's own view of whether this process is traced.
///
/// Read through `sysctl`, which is public API — the same information `ptrace`
/// would give, without the App Review risk.
public struct TracedProcessDetector: Detector {
  public let id = "RNSEC-IOS-DEBUGGER-001"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let traced = probes.process.isTraced() else {
      return SignalBuilder.indeterminate(
        id, .high, "the kernel process flags were unreadable", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(traced),
      confidence: .high,
      description: traced
        ? "This process is being traced by a debugger"
        : "This process is not being traced",
      metadata: ["traced": traced]
    )
  }
}

/// An unexpected parent process.
///
/// A normally launched application is reparented to `launchd` (pid 1). A different
/// parent suggests the process was started by something else — a debugger, or a
/// tool that spawned it.
///
/// Reports `indeterminate` on the **simulator**, where the heuristic simply does
/// not hold: simulated apps are children of `launchd_sim`, so every simulator run
/// would otherwise fire this signal. A check that cries wolf during development is
/// one developers learn to ignore.
public struct ParentProcessDetector: Detector {
  public let id = "RNSEC-IOS-DEBUGGER-002"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    if probes.deviceEnvironment.isSimulator() {
      return SignalBuilder.indeterminate(
        id,
        .medium,
        "simulated applications are not children of launchd, so this heuristic does not apply",
        subject: subject
      )
    }

    guard let parent = probes.process.parentProcessId() else {
      return SignalBuilder.indeterminate(
        id, .medium, "the parent process identifier was unreadable", subject: subject)
    }

    let unexpected = parent != 1

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(unexpected),
      confidence: .medium,
      description: unexpected
        ? "This process was not launched by the system launcher"
        : "This process was launched by the system launcher",
      metadata: ["parentProcessId": Int(parent)]
    )
  }
}

/// The debugger check.
public struct DebuggerCheckEngine: CheckEngine {
  public let checkId = "debugger"

  public init() {}

  public func detectors(_ options: CheckOptions) -> [Detector] {
    [TracedProcessDetector(), ParentProcessDetector()]
  }
}
