package com.rnsecurity

import com.rnsecurity.probe.ApplicationProbe
import com.rnsecurity.probe.BuildProbe
import com.rnsecurity.probe.DebuggerProbe
import com.rnsecurity.probe.DeviceFeatureProbe
import com.rnsecurity.probe.FileProbe
import com.rnsecurity.probe.PackageProbe
import com.rnsecurity.probe.ProbeSet
import com.rnsecurity.probe.AuthenticationProbe
import com.rnsecurity.probe.KeystoreProbe
import com.rnsecurity.probe.NativeSymbolProbe
import com.rnsecurity.probe.NetworkProbe
import com.rnsecurity.probe.PackageIntegrityProbe
import com.rnsecurity.probe.ProcProbe
import com.rnsecurity.probe.RuntimeProbe
import com.rnsecurity.probe.ScreenProbe
import com.rnsecurity.probe.SettingsProbe
import com.rnsecurity.probe.SystemPropertyProbe

/**
 * A device, described in data.
 *
 * This is the payoff of injecting probes into detectors: a rooted phone, a
 * locked-down phone and a phone whose `/proc` is unreadable are all just
 * different values here, so every detector is testable on ordinary CI with no
 * rooted hardware anywhere in the loop.
 *
 * `null` in any map means "the probe could not determine this", which detectors
 * are required to report as `indeterminate` rather than as "not detected".
 */
class FakeFileProbe(
  private val existing: Map<String, Boolean?> = emptyMap(),
  private val executable: Map<String, Boolean?> = emptyMap(),
  private val contents: Map<String, String?> = emptyMap(),
  private val writable: Map<String, Boolean?> = emptyMap(),
  private val defaultExists: Boolean? = false,
  private val defaultWritable: Boolean? = false
) : FileProbe {
  override fun exists(path: String): Boolean? =
    if (existing.containsKey(path)) existing[path] else defaultExists

  override fun isExecutable(path: String): Boolean? =
    if (executable.containsKey(path)) executable[path] else defaultExists

  override fun readText(path: String): String? = contents[path]

  override fun canActuallyWrite(directory: String): Boolean? =
    if (writable.containsKey(directory)) writable[directory] else defaultWritable
}

class FakeSystemPropertyProbe(
  private val available: Boolean = true,
  private val values: Map<String, String?> = emptyMap()
) : SystemPropertyProbe {
  override fun isAvailable(): Boolean = available

  override fun get(key: String): String? = if (available) values[key] else null
}

class FakePackageProbe(
  private val canQuery: Boolean = true,
  private val installed: Map<String, Boolean?> = emptyMap(),
  private val defaultInstalled: Boolean? = false
) : PackageProbe {
  override fun canQueryPackages(): Boolean = canQuery

  override fun isInstalled(packageName: String): Boolean? =
    if (installed.containsKey(packageName)) installed[packageName] else defaultInstalled
}

class FakeProcProbe(
  private val status: String? = "TracerPid:\t0\n",
  private val maps: List<String>? = emptyList(),
  private val mountInfo: List<String>? = emptyList(),
  private val threadNames: List<String>? = listOf("main", "RenderThread", "hwuiTask0")
) : ProcProbe {
  override fun selfStatus(): String? = status

  override fun selfMaps(): List<String>? = maps

  override fun selfMountInfo(): List<String>? = mountInfo

  override fun threadNames(): List<String>? = threadNames
}

class FakeRuntimeProbe(
  private val presentClasses: Set<String> = emptySet(),
  private val stack: List<String>? = listOf("com.example.app.MainActivity", "android.app.Activity"),
  private val classLookupWorks: Boolean = true
) : RuntimeProbe {
  override fun isClassPresent(className: String): Boolean? =
    if (!classLookupWorks) null else presentClasses.contains(className)

  override fun currentStackClassNames(): List<String>? = stack
}

class FakeNativeSymbolProbe(
  private val available: Boolean = true,
  private val origins: Map<String, String?> = emptyMap(),
  private val defaultOrigin: (String) -> String? = { symbol ->
    if (symbol == "dlopen" || symbol == "dlsym") "/apex/com.android.runtime/lib64/bionic/libdl.so"
    else "/apex/com.android.runtime/lib64/bionic/libc.so"
  }
) : NativeSymbolProbe {
  override fun isAvailable(): Boolean = available

  override fun originOf(symbol: String): String? =
    if (!available) null
    else if (origins.containsKey(symbol)) origins[symbol] else defaultOrigin(symbol)
}

class FakeBuildProbe(
  private val tags: String? = "release-keys",
  private val fingerprint: String? = "google/husky/husky:16/AP4A.250105.002/12345:user/release-keys",
  private val model: String? = "Pixel 8 Pro",
  private val manufacturer: String? = "Google",
  private val brand: String? = "google",
  private val product: String? = "husky",
  private val device: String? = "husky",
  private val hardware: String? = "husky",
  private val board: String? = "husky",
  private val sdkInt: Int = 35
) : BuildProbe {
  override fun tags(): String? = tags

  override fun fingerprint(): String? = fingerprint

  override fun model(): String? = model

  override fun manufacturer(): String? = manufacturer

  override fun brand(): String? = brand

  override fun product(): String? = product

  override fun device(): String? = device

  override fun hardware(): String? = hardware

  override fun board(): String? = board

  override fun sdkInt(): Int = sdkInt
}

class FakeDebuggerProbe(
  private val connected: Boolean? = false,
  private val waiting: Boolean? = false
) : DebuggerProbe {
  override fun isDebuggerConnected(): Boolean? = connected

  override fun isWaitingForDebugger(): Boolean? = waiting
}

class FakeApplicationProbe(
  private val debuggable: Boolean? = false,
  private val packageName: String? = "com.example.app"
) : ApplicationProbe {
  override fun isDebuggable(): Boolean? = debuggable

  override fun packageName(): String? = packageName
}

class FakeDeviceFeatureProbe(
  private val features: Map<String, Boolean?> = emptyMap(),
  private val defaultFeature: Boolean? = true,
  private val phoneType: Int? = 1,
  private val sensorCount: Int? = 24
) : DeviceFeatureProbe {
  override fun hasSystemFeature(feature: String): Boolean? =
    if (features.containsKey(feature)) features[feature] else defaultFeature

  override fun phoneType(): Int? = phoneType

  override fun sensorCount(): Int? = sensorCount
}

class FakeSettingsProbe(
  private val values: Map<String, Int> = emptyMap(),
  /** `false` simulates a settings provider that cannot be read at all. */
  private val readable: Boolean = true
) : SettingsProbe {
  override fun globalInt(key: String, defaultValue: Int): Int? =
    if (!readable) null else values[key] ?: defaultValue
}

class FakePackageIntegrityProbe(
  private val certificates: List<String>? = listOf(EXPECTED_CERT),
  private val installer: String? = "com.android.vending",
  private val sourceDir: String? = "/data/app/~~abc==/com.example.app-xyz==/base.apk"
) : PackageIntegrityProbe {
  override fun signingCertificateSha256(): List<String>? = certificates

  override fun installerPackageName(): String? = installer

  override fun applicationSourceDir(): String? = sourceDir

  companion object {
    /** An arbitrary but well-formed SHA-256 fingerprint used across tests. */
    const val EXPECTED_CERT = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90"
  }
}

class FakeKeystoreProbe(private val level: String? = "trusted-environment") : KeystoreProbe {
  override fun keySecurityLevel(): String? = level
}

class FakeAuthenticationProbe(
  private val biometric: Int? = 0,
  private val strongBiometric: Int? = 0,
  private val deviceSecure: Boolean? = true,
  private val unavailableReason: String? = null
) : AuthenticationProbe {
  override fun biometricStatus(): Int? = biometric

  override fun strongBiometricStatus(): Int? = strongBiometric

  override fun isDeviceSecure(): Boolean? = deviceSecure

  override fun biometricUnavailableReason(): String? = unavailableReason
}

class FakeNetworkProbe(
  private val cleartextPermitted: Boolean? = false,
  private val proxyHost: String? = null,
  private val vpnActive: Boolean? = false,
  private val userCaCount: Int? = 0
) : NetworkProbe {
  override fun isCleartextTrafficPermitted(): Boolean? = cleartextPermitted

  override fun httpProxyHost(): String? = proxyHost

  override fun isVpnActive(): Boolean? = vpnActive

  override fun userAddedCaCount(): Int? = userCaCount
}

class FakeScreenProbe(private val secureFlagSet: Boolean? = true) : ScreenProbe {
  override fun isSecureFlagSet(): Boolean? = secureFlagSet
}

/** A stock, unmodified device with every probe working. */
fun cleanDeviceProbes(
  files: FileProbe = FakeFileProbe(contents = mapOf("/sys/fs/selinux/enforce" to "1")),
  properties: SystemPropertyProbe =
    FakeSystemPropertyProbe(
      values =
        mapOf(
          "ro.debuggable" to "0",
          "ro.secure" to "1",
          "ro.boot.verifiedbootstate" to "green",
          "ro.boot.flash.locked" to "1"
        )
    ),
  packages: PackageProbe = FakePackageProbe(),
  proc: ProcProbe = FakeProcProbe(),
  build: BuildProbe = FakeBuildProbe(),
  debugger: DebuggerProbe = FakeDebuggerProbe(),
  application: ApplicationProbe = FakeApplicationProbe(),
  device: DeviceFeatureProbe = FakeDeviceFeatureProbe(),
  settings: SettingsProbe = FakeSettingsProbe(),
  runtime: RuntimeProbe = FakeRuntimeProbe(),
  symbols: NativeSymbolProbe = FakeNativeSymbolProbe(),
  packageIntegrity: PackageIntegrityProbe = FakePackageIntegrityProbe(),
  keystore: KeystoreProbe = FakeKeystoreProbe(),
  authentication: AuthenticationProbe = FakeAuthenticationProbe(),
  network: NetworkProbe = FakeNetworkProbe(),
  screen: ScreenProbe = FakeScreenProbe()
): ProbeSet =
  ProbeSet(
    files,
    properties,
    packages,
    proc,
    build,
    debugger,
    application,
    device,
    settings,
    runtime,
    symbols,
    packageIntegrity,
    keystore,
    authentication,
    network,
    screen
  )
