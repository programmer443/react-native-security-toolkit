import Foundation

/// Hook and instrumentation detection for iOS.
///
/// Adversarial in a way the other checks are not: an attacker running a hooking
/// framework can, by definition, modify the code doing the detecting — including
/// this check. **Detection is not guaranteed and cannot be.** What these signals
/// buy is cost.
///
/// Both signals ask the same underlying question in two different layers: *is the
/// runtime still shaped the way it should be*. That is a more durable question
/// than "is a known tool present", because it survives an attacker renaming their
/// library.
///
/// See `docs/runtime/hook-detection-ios.md`.

private let subject = "Instrumentation indicator"

/// A native symbol resolving outside any system image.
///
/// Only whether the providing image is *a* system image is compared, not which
/// one. iOS moves libSystem components between paths across versions, and on the
/// simulator everything is nested under the Xcode runtime root, so comparing full
/// paths would report every device as hooked.
public struct SymbolOriginDetector: Detector {
  public let id = "RNSEC-RUNTIME-HOOK-004"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    guard probes.symbols.isAvailable() else {
      return SignalBuilder.indeterminate(
        id, .high, "symbol resolution is unavailable", subject: subject)
    }

    var unexpected: [String] = []
    var unresolved = 0

    for symbol in HookSignatures.watchedSymbols {
      guard let origin = probes.symbols.originOf(symbol: symbol) else {
        unresolved += 1
        continue
      }
      if !HookSignatures.isSystemImage(origin) {
        unexpected.append(symbol)
      }
    }

    if unexpected.isEmpty && unresolved == HookSignatures.watchedSymbols.count {
      return SignalBuilder.indeterminate(
        id, .high, "no symbols could be resolved", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!unexpected.isEmpty),
      confidence: .high,
      description: unexpected.isEmpty
        ? "System symbols resolve inside system images"
        : "A system symbol resolves inside a non-system image",
      metadata: ["unexpectedSymbols": unexpected, "unresolvedSymbols": unresolved]
    )
  }
}

/// Objective-C methods whose implementation has moved out of a system image.
///
/// Lower confidence than symbol origin because **legitimate SDKs swizzle**:
/// analytics, crash reporting and network-inspection libraries all replace
/// framework methods, and this signal cannot tell them from an attacker. It is
/// reported as an indicator so an application that knows its own dependencies can
/// judge it.
public struct MethodSwizzlingDetector: Detector {
  public let id = "RNSEC-RUNTIME-HOOK-005"

  public init() {}

  public func detect(_ probes: ProbeSet) -> SecuritySignal {
    var replaced: [String] = []
    var undeterminable = 0

    for watched in HookSignatures.watchedMethods {
      guard
        let image = probes.objcRuntime.implementationImage(
          className: watched.className, selector: watched.selector)
      else {
        undeterminable += 1
        continue
      }
      if !HookSignatures.isSystemImage(image) {
        replaced.append("\(watched.className).\(watched.selector)")
      }
    }

    if replaced.isEmpty && undeterminable == HookSignatures.watchedMethods.count {
      return SignalBuilder.indeterminate(
        id, .medium, "no method implementations could be located", subject: subject)
    }

    return SecuritySignal(
      id: id,
      outcome: SignalBuilder.outcome(!replaced.isEmpty),
      confidence: .medium,
      description: replaced.isEmpty
        ? "Watched framework methods are implemented by system images"
        : "A watched framework method is implemented outside any system image",
      metadata: ["replacedMethods": replaced, "undeterminableMethods": undeterminable]
    )
  }
}

/// The hook check.
public struct HookCheckEngine: CheckEngine {
  public let checkId = "hooks"

  public init() {}

  public func detectors(_ options: CheckOptions) -> [Detector] {
    [SymbolOriginDetector(), MethodSwizzlingDetector()]
  }

  public func metadata(_ probes: ProbeSet, _ options: CheckOptions) -> [String: Any] {
    [
      "signatureVersion": HookSignatures.version,
      "nativeSymbolProbeAvailable": probes.symbols.isAvailable(),
    ]
  }
}
