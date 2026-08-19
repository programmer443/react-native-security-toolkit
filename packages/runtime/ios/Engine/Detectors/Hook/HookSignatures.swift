import Foundation

/// Versioned signature data for iOS hook detection.
public enum HookSignatures {

  public static let version = "2026.08.1"

  /// Symbols checked against the image expected to provide them.
  ///
  /// Ordinary libSystem entry points. The question is not "is this symbol
  /// hooked" but "does this symbol still live in a system image" — a redirected
  /// `open` or `connect` resolving inside an injected library is a strong
  /// indicator, and one that renaming the library does not hide.
  public static let watchedSymbols = ["open", "read", "write", "connect", "fopen", "dlsym"]

  /// Classes and selectors whose implementation should come from a system image.
  ///
  /// Chosen because they are the ones instrumentation most often intercepts:
  /// network traffic and pasteboard access.
  public static let watchedMethods: [(className: String, selector: String)] = [
    (className: "NSURLSession", selector: "dataTaskWithRequest:completionHandler:"),
    (className: "NSURLSession", selector: "sharedSession"),
    (className: "UIPasteboard", selector: "generalPasteboard"),
  ]

  /// Absolute prefixes of operating-system image paths on a device.
  public static let systemPrefixes = ["/System/", "/usr/lib/"]

  /// Where the simulator nests those same prefixes.
  private static let simulatorRoot = "/RuntimeRoot"

  /// Whether an image path belongs to the operating system.
  ///
  /// Matched as a **prefix**, not a substring. A rootless jailbreak installs to
  /// `/var/jb/usr/lib/…`, which *contains* `/usr/lib/` — substring matching would
  /// classify every injected library on a modern jailbroken device as a system
  /// image and blind this check entirely, which is precisely where iOS hooks live
  /// today.
  ///
  /// The simulator nests the same prefixes under the Xcode runtime root, so that
  /// one specific nesting is accepted as well.
  public static func isSystemImage(_ path: String) -> Bool {
    if systemPrefixes.contains(where: { path.hasPrefix($0) }) {
      return true
    }
    return systemPrefixes.contains { path.contains(simulatorRoot + $0) }
  }
}
