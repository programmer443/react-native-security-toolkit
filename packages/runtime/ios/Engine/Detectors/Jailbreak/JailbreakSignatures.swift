import Foundation

/// Versioned signature data for jailbreak detection.
///
/// Kept separate from detection logic, and versioned, because this is the data
/// that goes stale fastest.
///
/// The important modernisation: the path lists copied around older iOS projects
/// target **rootful** jailbreaks — `/Applications/Cydia.app`, `/bin/bash`,
/// `/etc/apt`. Modern rootless jailbreaks relocate their entire filesystem under
/// a prefix such as `/var/jb`, so those lists under-detect badly while looking
/// thorough. Both layouts are covered here, and reported as separate signals so a
/// result says which era it matched.
public enum JailbreakSignatures {

  /// Bumped whenever any list below changes. Reported in check metadata.
  public static let version = "2026.08.1"

  /// Classic rootful jailbreak paths.
  ///
  /// Every entry is iOS-specific. Paths that also exist on macOS — `/bin/bash`,
  /// `/bin/sh`, `/usr/bin/ssh`, `/usr/sbin/sshd`, `/usr/libexec/ssh-keysign` —
  /// are deliberately **excluded**, even though they appear in most published
  /// jailbreak path lists. The iOS Simulator runs against the macOS filesystem,
  /// so those paths exist on every developer's machine and make the check fire on
  /// every simulator run. A signal that cries wolf during development is a signal
  /// developers learn to ignore.
  public static let rootfulPaths = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/blackra1n.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/etc/apt/sources.list.d/cydia.list",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/stash",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/usr/libexec/cydia",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libsubstitute.dylib",
  ]

  /// Rootless jailbreak prefixes, where a modern jailbreak relocates its filesystem.
  public static let rootlessPrefixes = ["/var/jb", "/private/var/jb"]

  /// Paths checked beneath each rootless prefix.
  public static let rootlessSuffixes = [
    "/usr/lib/TweakInject",
    "/usr/lib/substitute-inserter.dylib",
    "/usr/bin/sileo",
    "/Applications/Sileo.app",
    "/etc/apt",
    "/usr/libexec/ellekit",
  ]

  /// Injected library names seen in the dyld image list of a hooked process.
  public static let injectedImageMarkers = [
    "mobilesubstrate",
    "substrate",
    "substitute",
    "tweakinject",
    "libhooker",
    "ellekit",
    "cycript",
    "frida",
    "libsandy",
    "rocketbootstrap",
  ]

  /// Directories that are symbolic links on a jailbroken device but not otherwise.
  public static let symlinkCandidates = ["/Applications", "/Library/Ringtones", "/usr/share"]

  /// Package-manager URL schemes. Requires `LSApplicationQueriesSchemes`.
  public static let packageManagerSchemes = ["cydia", "sileo", "zbra", "filza", "undecimus"]
}
