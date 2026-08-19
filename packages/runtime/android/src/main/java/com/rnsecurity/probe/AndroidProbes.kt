package com.rnsecurity.probe

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.biometrics.BiometricManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.NetworkSecurityPolicy
import android.view.WindowManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.telephony.TelephonyManager
// Generated into the library's namespace, so it needs an explicit import here.
import com.rnsecurity.BuildConfig
import java.io.File
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest

/**
 * Real implementations of the probe interfaces.
 *
 * Every method is total: a failure becomes `null`, never an exception and never
 * a fabricated `false`. Detectors turn `null` into an `indeterminate` signal.
 */

internal class RealFileProbe : FileProbe {

  override fun exists(path: String): Boolean? =
    try {
      File(path).exists()
    } catch (error: SecurityException) {
      null
    }

  override fun isExecutable(path: String): Boolean? =
    try {
      val file = File(path)
      file.exists() && file.canExecute()
    } catch (error: SecurityException) {
      null
    }

  override fun readText(path: String): String? =
    try {
      val file = File(path)
      if (file.exists() && file.canRead()) file.readText() else null
    } catch (error: IOException) {
      null
    } catch (error: SecurityException) {
      null
    } catch (error: OutOfMemoryError) {
      // A hostile or pathological /proc entry must not take the app down.
      null
    }

  override fun canActuallyWrite(directory: String): Boolean? {
    val probe = File(directory, ".rnsec_write_probe_${System.nanoTime()}")
    return try {
      if (!probe.createNewFile()) {
        return false
      }
      probe.delete()
      true
    } catch (error: IOException) {
      // The overwhelmingly common case on an unmodified device.
      false
    } catch (error: SecurityException) {
      null
    }
  }
}

internal class RealSystemPropertyProbe : SystemPropertyProbe {

  override fun isAvailable(): Boolean = NativeProbes.loaded

  override fun get(key: String): String? {
    if (!NativeProbes.loaded) {
      return null
    }
    return try {
      NativeProbes.getSystemProperty(key)?.takeIf { it.isNotEmpty() }
    } catch (error: UnsatisfiedLinkError) {
      null
    }
  }
}

internal class RealPackageProbe(private val context: Context) : PackageProbe {

  /**
   * Package visibility is opt-in from Android 11, and this reports whether the
   * application opted in — as a **build-time fact**, not an inference.
   *
   * Inferring it by asking whether any other package is visible does not work:
   * Android always exposes a handful of system packages regardless of
   * `<queries>`, so the inference answers "yes" on every device. The package
   * check then reports "no root manager found" — a false negative wearing a
   * clean result's clothes, which is precisely the outcome this library exists
   * to avoid.
   *
   * `BuildConfig.PACKAGE_VISIBILITY_DECLARED` is set by the same Gradle flag
   * that selects the manifest carrying the `<queries>` block, so the two cannot
   * disagree.
   */
  override fun canQueryPackages(): Boolean {
    // Before Android 11 every package was visible without declaring anything.
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
      return true
    }
    return BuildConfig.PACKAGE_VISIBILITY_DECLARED
  }

  override fun isInstalled(packageName: String): Boolean? =
    try {
      context.packageManager.getPackageInfo(packageName, 0)
      true
    } catch (error: PackageManager.NameNotFoundException) {
      false
    } catch (error: Exception) {
      null
    }
}

internal class RealProcProbe(private val files: FileProbe) : ProcProbe {

  override fun selfStatus(): String? = files.readText("/proc/self/status")

  override fun selfMaps(): List<String>? = files.readText("/proc/self/maps")?.lineSequence()?.toList()

  override fun selfMountInfo(): List<String>? =
    files.readText("/proc/self/mountinfo")?.lineSequence()?.toList()

  override fun threadNames(): List<String>? =
    try {
      val tasks = File("/proc/self/task").listFiles() ?: return null
      tasks.mapNotNull { task -> files.readText("${task.absolutePath}/comm")?.trim() }
    } catch (error: SecurityException) {
      null
    } catch (error: IOException) {
      null
    }
}

internal class RealRuntimeProbe : RuntimeProbe {

  override fun isClassPresent(className: String): Boolean? =
    try {
      Class.forName(className, false, javaClass.classLoader)
      true
    } catch (error: ClassNotFoundException) {
      false
    } catch (error: Throwable) {
      null
    }

  override fun currentStackClassNames(): List<String>? =
    try {
      Throwable().stackTrace.map { it.className }
    } catch (error: Throwable) {
      null
    }
}

internal class RealNativeSymbolProbe : NativeSymbolProbe {

  override fun isAvailable(): Boolean = NativeProbes.loaded

  override fun originOf(symbol: String): String? {
    if (!NativeProbes.loaded) {
      return null
    }
    return try {
      NativeProbes.getSymbolOrigin(symbol)?.takeIf { it.isNotEmpty() }
    } catch (error: UnsatisfiedLinkError) {
      null
    }
  }
}

internal class RealBuildProbe : BuildProbe {
  override fun tags(): String? = Build.TAGS

  override fun fingerprint(): String? = Build.FINGERPRINT

  override fun model(): String? = Build.MODEL

  override fun manufacturer(): String? = Build.MANUFACTURER

  override fun brand(): String? = Build.BRAND

  override fun product(): String? = Build.PRODUCT

  override fun device(): String? = Build.DEVICE

  override fun hardware(): String? = Build.HARDWARE

  override fun board(): String? = Build.BOARD

  override fun sdkInt(): Int = Build.VERSION.SDK_INT
}

internal class RealDebuggerProbe : DebuggerProbe {

  override fun isDebuggerConnected(): Boolean? =
    try {
      Debug.isDebuggerConnected()
    } catch (error: Exception) {
      null
    }

  override fun isWaitingForDebugger(): Boolean? =
    try {
      Debug.waitingForDebugger()
    } catch (error: Exception) {
      null
    }
}

internal class RealApplicationProbe(private val context: Context) : ApplicationProbe {

  override fun isDebuggable(): Boolean? =
    try {
      (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    } catch (error: Exception) {
      null
    }

  override fun packageName(): String? =
    try {
      context.packageName
    } catch (error: Exception) {
      null
    }
}

internal class RealDeviceFeatureProbe(private val context: Context) : DeviceFeatureProbe {

  override fun hasSystemFeature(feature: String): Boolean? =
    try {
      context.packageManager.hasSystemFeature(feature)
    } catch (error: Exception) {
      null
    }

  override fun phoneType(): Int? =
    try {
      (context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager)?.phoneType
    } catch (error: Exception) {
      null
    }

  override fun sensorCount(): Int? =
    try {
      (context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager)
        ?.getSensorList(Sensor.TYPE_ALL)
        ?.size
    } catch (error: Exception) {
      null
    }
}

internal class RealSettingsProbe(private val context: Context) : SettingsProbe {

  override fun globalInt(key: String, defaultValue: Int): Int? =
    try {
      Settings.Global.getInt(context.contentResolver, key, defaultValue)
    } catch (error: Exception) {
      null
    }
}

internal class RealPackageIntegrityProbe(private val context: Context) : PackageIntegrityProbe {

  override fun signingCertificateSha256(): List<String>? =
    try {
      val certificates =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          val info =
            context.packageManager.getPackageInfo(
              context.packageName,
              PackageManager.GET_SIGNING_CERTIFICATES
            )
          val signingInfo = info.signingInfo
          when {
            signingInfo == null -> null
            // A rotated key reports history; the current signer is what matters,
            // and callers pin whichever they published.
            signingInfo.hasMultipleSigners() -> signingInfo.apkContentsSigners
            else -> signingInfo.signingCertificateHistory
          }
        } else {
          @Suppress("DEPRECATION")
          context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
            .signatures
        }

      // Digest each certificate separately. Concatenating signers into a single
      // digest yields an order-dependent value that matches no published
      // fingerprint.
      certificates?.mapNotNull { signature ->
        signature?.toByteArray()?.let { bytes ->
          MessageDigest.getInstance("SHA-256").digest(bytes).toHexString()
        }
      }
    } catch (error: Exception) {
      null
    }

  override fun installerPackageName(): String? =
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
      } else {
        @Suppress("DEPRECATION")
        context.packageManager.getInstallerPackageName(context.packageName)
      }
    } catch (error: Exception) {
      null
    }

  override fun applicationSourceDir(): String? =
    try {
      context.applicationInfo.sourceDir
    } catch (error: Exception) {
      null
    }

  private fun ByteArray.toHexString(): String {
    val hex = StringBuilder(size * 2)
    for (byte in this) {
      hex.append("0123456789ABCDEF"[(byte.toInt() shr 4) and 0x0F])
      hex.append("0123456789ABCDEF"[byte.toInt() and 0x0F])
    }
    return hex.toString()
  }
}

internal class RealKeystoreProbe : KeystoreProbe {

  override fun keySecurityLevel(): String? {
    val alias = "rnsec_capability_probe_${System.nanoTime()}"
    return try {
      val generator =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
      generator.initialize(
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
          .setDigests(KeyProperties.DIGEST_SHA256)
          .build()
      )
      val privateKey = generator.generateKeyPair().private
      val keyInfo =
        KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
          .getKeySpec(privateKey, KeyInfo::class.java)

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        when (keyInfo.securityLevel) {
          KeyProperties.SECURITY_LEVEL_SOFTWARE -> LEVEL_SOFTWARE
          KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> LEVEL_TRUSTED_ENVIRONMENT
          KeyProperties.SECURITY_LEVEL_STRONGBOX -> LEVEL_STRONGBOX
          // SECURITY_LEVEL_UNKNOWN_SECURE means backed by *something* secure that
          // the platform will not name. Reporting it as trusted would overstate
          // what is known.
          else -> LEVEL_UNKNOWN
        }
      } else {
        @Suppress("DEPRECATION")
        if (keyInfo.isInsideSecureHardware) LEVEL_TRUSTED_ENVIRONMENT else LEVEL_SOFTWARE
      }
    } catch (error: Exception) {
      null
    } finally {
      // Never leave a probe key behind in the user's keystore.
      try {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(alias)
      } catch (error: Exception) {
        // Nothing further to do; the alias is unique per call.
      }
    }
  }

  private companion object {
    const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val LEVEL_SOFTWARE = "software"
    const val LEVEL_TRUSTED_ENVIRONMENT = "trusted-environment"
    const val LEVEL_STRONGBOX = "strongbox"
    const val LEVEL_UNKNOWN = "unknown"
  }
}

internal class RealAuthenticationProbe(private val context: Context) : AuthenticationProbe {

  /** Set by [canAuthenticate] so the detectors can explain an unavailable status. */
  @Volatile private var unavailableReason: String? = null

  override fun biometricStatus(): Int? = canAuthenticate(anyBiometric = true)

  override fun strongBiometricStatus(): Int? = canAuthenticate(anyBiometric = false)

  override fun biometricUnavailableReason(): String? = unavailableReason

  override fun isDeviceSecure(): Boolean? =
    try {
      (context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager)?.isDeviceSecure
    } catch (error: Exception) {
      null
    }

  private fun canAuthenticate(anyBiometric: Boolean): Int? {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
      // The authenticator-type form arrived in API 30. Below that the platform
      // cannot answer the question this detector asks.
      unavailableReason = REASON_API_LEVEL
      return null
    }
    return try {
      val manager = context.getSystemService(BiometricManager::class.java)
      if (manager == null) {
        unavailableReason = REASON_SERVICE_UNAVAILABLE
        return null
      }
      val authenticators =
        if (anyBiometric) {
          BiometricManager.Authenticators.BIOMETRIC_WEAK or
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        } else {
          BiometricManager.Authenticators.BIOMETRIC_STRONG
        }
      val status = manager.canAuthenticate(authenticators)
      unavailableReason = null
      status
    } catch (error: SecurityException) {
      // `canAuthenticate` requires the USE_BIOMETRIC permission. This package
      // does not declare it: a permission in a library manifest is merged into
      // every consuming application and shows up in store review, which is the
      // application author's decision to make, not ours.
      unavailableReason = REASON_PERMISSION
      null
    } catch (error: Exception) {
      unavailableReason = REASON_SERVICE_UNAVAILABLE
      null
    }
  }

  private companion object {
    const val REASON_API_LEVEL = "api-level"
    const val REASON_PERMISSION = "permission"
    const val REASON_SERVICE_UNAVAILABLE = "service-unavailable"
  }
}

internal class RealNetworkProbe(private val context: Context) : NetworkProbe {

  override fun isCleartextTrafficPermitted(): Boolean? =
    try {
      NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted
    } catch (error: Exception) {
      null
    }

  override fun httpProxyHost(): String? =
    try {
      // The JVM proxy properties are what OkHttp and React Native's networking
      // actually honour, and reading them needs no permission.
      System.getProperty("http.proxyHost")?.takeIf { it.isNotEmpty() }
        ?: System.getProperty("https.proxyHost")?.takeIf { it.isNotEmpty() }
    } catch (error: Exception) {
      null
    }

  override fun isVpnActive(): Boolean? =
    try {
      val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
      val capabilities =
        manager?.getNetworkCapabilities(manager.activeNetwork) ?: return null
      capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    } catch (error: SecurityException) {
      // ACCESS_NETWORK_STATE is not declared by the consuming application.
      null
    } catch (error: Exception) {
      null
    }

  override fun userAddedCaCount(): Int? =
    try {
      val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
      store.aliases().toList().count { it.startsWith("user:") }
    } catch (error: Exception) {
      null
    }
}

internal class RealScreenProbe(private val currentActivity: () -> android.app.Activity?) :
  ScreenProbe {

  override fun isSecureFlagSet(): Boolean? =
    try {
      val flags = currentActivity()?.window?.attributes?.flags ?: return null
      (flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
    } catch (error: Exception) {
      null
    }
}

internal object AndroidProbeSet {
  fun create(context: Context, currentActivity: () -> android.app.Activity? = { null }): ProbeSet {
    val files = RealFileProbe()
    return ProbeSet(
      files = files,
      properties = RealSystemPropertyProbe(),
      packages = RealPackageProbe(context),
      proc = RealProcProbe(files),
      build = RealBuildProbe(),
      debugger = RealDebuggerProbe(),
      application = RealApplicationProbe(context),
      device = RealDeviceFeatureProbe(context),
      settings = RealSettingsProbe(context),
      runtime = RealRuntimeProbe(),
      symbols = RealNativeSymbolProbe(),
      packageIntegrity = RealPackageIntegrityProbe(context),
      keystore = RealKeystoreProbe(),
      authentication = RealAuthenticationProbe(context),
      network = RealNetworkProbe(context),
      screen = RealScreenProbe(currentActivity)
    )
  }
}
