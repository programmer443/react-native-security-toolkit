import Foundation

/// Simulator detection for iOS.
///
/// Running on a simulator is **not** a compromise — it is where nearly all
/// development and much automated testing happens. The signal exists so an
/// application can tell a simulated environment from a physical device, and so
/// other checks can decline to answer questions that are malformed there.
///
/// Unlike Android emulator detection, this needs no signature list and has no
/// meaningful false-negative surface: the compile-time environment flag is exact.
///
/// See `docs/runtime/simulator-detection.md`.
public struct SimulatorEnvironmentDetector: Detector {
  public let id = "RNSEC-IOS-SIMULATOR-001"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    let simulated = probes.deviceEnvironment.isSimulator()

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(simulated),
      confidence: .high,
      description: simulated
        ? "This application is running on a simulator"
        : "This application is running on a physical device",
      metadata: ["simulator": simulated]
    )
  }
}

/// The simulator check.
public struct SimulatorCheckEngine: CheckEngine {
  public let checkId = "simulator"

  public init() {}

  public func detectors(_ options: CheckOptions) -> [Detector] {
    [SimulatorEnvironmentDetector()]
  }
}
