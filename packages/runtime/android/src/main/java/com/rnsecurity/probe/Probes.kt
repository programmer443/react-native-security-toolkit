package com.rnsecurity.probe

/**
 * The environment, behind interfaces.
 *
 * Detectors never touch the filesystem, `PackageManager` or system properties
 * directly. They ask a probe. That one constraint is what makes every detector
 * unit-testable on ordinary CI with no rooted device: a test supplies a fake
 * environment describing a rooted phone, and asserts on the signals produced.
 *
 * Probes are also the only place allowed to swallow an exception, and they never
 * swallow it silently — a failed read becomes `null`, which detectors are
 * required to report as `indeterminate` rather than as "not detected".
 */

/** Filesystem reads. */
interface FileProbe {
  /** Whether the path exists. `null` when the answer cannot be determined. */
  fun exists(path: String): Boolean?

  /** Whether the path exists and is executable. `null` when undeterminable. */
  fun isExecutable(path: String): Boolean?

  /** Reads a text file, or `null` if it cannot be read. */
  fun readText(path: String): String?

  /**
   * Attempts to create and delete a file in [directory].
   *
   * Returns `true` only if a write genuinely succeeded. `File.canWrite()` is not
   * used: it reports `false` on paths that are in fact writable on a rooted
   * device, and `true` in cases where a write would still fail.
   */
  fun canActuallyWrite(directory: String): Boolean?
}

/** Android system properties (`ro.*`, `init.svc.*`, …). */
interface SystemPropertyProbe {
  /** Whether the probe can read properties at all. */
  fun isAvailable(): Boolean

  /** Property value, or `null` if unset or unreadable. */
  fun get(key: String): String?
}

/** Installed-package queries. */
interface PackageProbe {
  /**
   * Whether package visibility has been configured for this app.
   *
   * On Android 11+ an app sees only packages declared in `<queries>`. Without
   * that declaration a package check silently returns "not installed" for
   * everything, which would be a false negative dressed up as a clean result.
   */
  fun canQueryPackages(): Boolean

  /** Whether a package is installed, or `null` if it cannot be determined. */
  fun isInstalled(packageName: String): Boolean?
}

/** `/proc` reads for the current process. */
interface ProcProbe {
  /** Contents of `/proc/self/status`, or `null` if unreadable. */
  fun selfStatus(): String?

  /** Lines of `/proc/self/maps`, or `null` if unreadable. */
  fun selfMaps(): List<String>?

  /** Lines of `/proc/self/mountinfo`, or `null` if unreadable. */
  fun selfMountInfo(): List<String>?

  /**
   * Names of this process's own threads, from `/proc/self/task/<tid>/comm`.
   *
   * Instrumentation frameworks inject worker threads with recognisable names.
   * Only this process is inspected; no other process is examined.
   */
  fun threadNames(): List<String>?
}

/** Managed-runtime introspection. */
interface RuntimeProbe {
  /** Whether a class is loadable, or `null` if the answer cannot be determined. */
  fun isClassPresent(className: String): Boolean?

  /**
   * Class names on the current call stack.
   *
   * A hooking framework that intercepts a call leaves its own frames between the
   * caller and the callee, which is visible from inside the callee.
   */
  fun currentStackClassNames(): List<String>?
}

/** Package identity and provenance. */
interface PackageIntegrityProbe {
  /**
   * SHA-256 of each signing certificate, uppercase hex, one entry per signer.
   *
   * Digested **per certificate**. Feeding several signers into one digest, as
   * some implementations do, produces an order-dependent value that cannot be
   * compared against a published fingerprint.
   */
  fun signingCertificateSha256(): List<String>?

  /** Package that installed this application, or `null` if undeterminable. */
  fun installerPackageName(): String?

  /** Filesystem location of the running APK, or `null` if undeterminable. */
  fun applicationSourceDir(): String?
}

/** Android Keystore capabilities. */
interface KeystoreProbe {
  /**
   * Security level backing a freshly generated key.
   *
   * One of `software`, `trusted-environment`, `strongbox`, or `unknown`.
   * `null` when the keystore could not be exercised at all.
   *
   * Determined by generating a throwaway key, inspecting it, and deleting it —
   * capability flags alone do not tell you what a key you actually create will
   * be backed by.
   */
  fun keySecurityLevel(): String?
}

/** Device authentication capabilities. */
interface AuthenticationProbe {
  /**
   * Raw `BiometricManager` status for any enrolled biometric, or `null` when
   * unavailable on this API level. Platform codes are returned unchanged so the
   * detector does the interpreting, where it can be tested.
   */
  fun biometricStatus(): Int?

  /** Raw `BiometricManager` status restricted to Class 3 (strong) biometrics. */
  fun strongBiometricStatus(): Int?

  /** Whether a PIN, pattern or password is set, or `null` if undeterminable. */
  fun isDeviceSecure(): Boolean?

  /**
   * Why a biometric status is unavailable, or `null` when one was obtained.
   *
   * One of `api-level`, `permission`, or `service-unavailable`. Without this an
   * application sees "could not be determined" and has nothing to act on — and
   * the most common cause, a missing `USE_BIOMETRIC` declaration, is entirely
   * within the application's control.
   */
  fun biometricUnavailableReason(): String?
}

/** Network configuration and posture. */
interface NetworkProbe {
  /** Whether this application is permitted to send cleartext HTTP. */
  fun isCleartextTrafficPermitted(): Boolean?

  /** Configured HTTP proxy host, or `null` when none is set. */
  fun httpProxyHost(): String?

  /**
   * Whether a VPN transport is active.
   *
   * `null` when it cannot be determined — most often because the application has
   * not declared `ACCESS_NETWORK_STATE`.
   */
  fun isVpnActive(): Boolean?

  /** Number of user-added certificate authorities in the system trust store. */
  fun userAddedCaCount(): Int?
}

/** Screen capture protection state. */
interface ScreenProbe {
  /**
   * Whether `FLAG_SECURE` is set on the current window.
   *
   * `null` when there is no current activity to inspect — during a cold start,
   * or while the application is in the background.
   */
  fun isSecureFlagSet(): Boolean?
}

/** Native symbol resolution. */
interface NativeSymbolProbe {
  /** Whether native symbol resolution is available at all. */
  fun isAvailable(): Boolean

  /** Path of the shared library providing [symbol], or `null` if unresolvable. */
  fun originOf(symbol: String): String?
}

/** Build fingerprint values. Separated so tests can describe any device. */
interface BuildProbe {
  fun tags(): String?

  fun fingerprint(): String?

  fun model(): String?

  fun manufacturer(): String?

  fun brand(): String?

  fun product(): String?

  fun device(): String?

  fun hardware(): String?

  fun board(): String?

  fun sdkInt(): Int
}

/** Debugger attachment state. */
interface DebuggerProbe {
  /** Whether a debugger is currently attached, or `null` if undeterminable. */
  fun isDebuggerConnected(): Boolean?

  /** Whether the process is blocked waiting for a debugger to attach. */
  fun isWaitingForDebugger(): Boolean?
}

/** Facts about the host application itself. */
interface ApplicationProbe {
  /** Whether the application is built debuggable, or `null` if undeterminable. */
  fun isDebuggable(): Boolean?

  /** The application's own package name. */
  fun packageName(): String?
}

/** Device-wide settings (`Settings.Global`). */
interface SettingsProbe {
  /**
   * Reads an integer from `Settings.Global`.
   *
   * Returns [defaultValue] when the key is absent, because on Android an absent
   * setting means "the platform default applies" rather than "unknown" — most
   * devices never write these keys at all, and reporting that as inconclusive
   * would make the check useless.
   *
   * Returns `null` only when the settings provider itself could not be read,
   * which genuinely is inconclusive.
   */
  fun globalInt(key: String, defaultValue: Int): Int?
}

/** Hardware and platform capabilities. */
interface DeviceFeatureProbe {
  /** Whether a `PackageManager.FEATURE_*` is present, or `null` if undeterminable. */
  fun hasSystemFeature(feature: String): Boolean?

  /** `TelephonyManager.PHONE_TYPE_*`, or `null` if undeterminable. */
  fun phoneType(): Int?

  /** Number of sensors the platform reports, or `null` if undeterminable. */
  fun sensorCount(): Int?
}

/** Everything a detector may reach for, in one place. */
data class ProbeSet(
  val files: FileProbe,
  val properties: SystemPropertyProbe,
  val packages: PackageProbe,
  val proc: ProcProbe,
  val build: BuildProbe,
  val debugger: DebuggerProbe,
  val application: ApplicationProbe,
  val device: DeviceFeatureProbe,
  val settings: SettingsProbe,
  val runtime: RuntimeProbe,
  val symbols: NativeSymbolProbe,
  val packageIntegrity: PackageIntegrityProbe,
  val keystore: KeystoreProbe,
  val authentication: AuthenticationProbe,
  val network: NetworkProbe,
  val screen: ScreenProbe
)
