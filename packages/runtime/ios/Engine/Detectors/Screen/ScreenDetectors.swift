import Foundation

/// Screen capture state for iOS.
///
/// **iOS provides detection, not prevention.** There is no public API to stop a
/// screenshot, so unlike Android's `FLAG_SECURE` this check reports what is
/// happening rather than what has been prevented. `ScreenSecurity.enableProtection()`
/// resolves to `false` here, because returning `true` would be a lie about a
/// security control.
///
/// See `docs/runtime/screen-security.md`.
public struct ScreenCaptureDetector: Detector {
  public let id = "RNSEC-IOS-SCREEN-001"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard let captured = probes.screenCapture.isCaptured() else {
      return SignalBuilder.indeterminate(
        id, .high, "the screen capture state was unreadable", subject: "Screen capture state")
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(captured),
      confidence: .high,
      description: captured
        ? "The screen is currently being recorded or mirrored"
        : "The screen is not currently being recorded or mirrored",
      metadata: ["captured": captured]
    )
  }
}

/// The screen security check.
public struct ScreenCheckEngine: CheckEngine {
  public let checkId = "screen"

  public init() {}

  public func detectors(_ options: CheckOptions) -> [Detector] { [ScreenCaptureDetector()] }

  public func metadata(_ probes: ProbeSet, _ options: CheckOptions) -> [String: Any] {
    [
      // Stated in the result because it is the asymmetry most likely to be missed
      // by someone who enabled protection on Android and assumed parity.
      "note":
        "iOS offers screen capture detection, not prevention. There is no public API to block "
        + "a screenshot."
    ]
  }
}
