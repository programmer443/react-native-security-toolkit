package com.rnsecurity.detectors.root

/**
 * Versioned signature data for root detection.
 *
 * Kept separate from detection logic on purpose. Signature lists go stale faster
 * than anything else in a security package — new root managers appear, paths
 * move — so they need to be updatable without touching the code that interprets
 * them, and versioned so a result can say which list produced it.
 *
 * Nothing here is exhaustive, and an empty match means only that these
 * particular indicators were absent.
 */
internal object RootSignatures {

  /** Bumped whenever any list below changes. Reported in check metadata. */
  const val VERSION = "2026.08.1"

  /** Locations where a `su` binary is not present on an unmodified device. */
  val SU_BINARY_PATHS =
    listOf(
      "/sbin/su",
      "/system/bin/su",
      "/system/xbin/su",
      "/system/sbin/su",
      "/vendor/bin/su",
      "/su/bin/su",
      "/data/local/su",
      "/data/local/bin/su",
      "/data/local/xbin/su",
      "/system/sd/xbin/su",
      "/system/bin/failsafe/su",
      "/system/bin/.ext/.su",
      "/system/usr/we-need-root/su-backup",
      "/system/xbin/mu"
    )

  /** Applications whose purpose is managing root access. */
  val ROOT_MANAGER_PACKAGES =
    listOf(
      "com.topjohnwu.magisk",
      "io.github.huskydg.magisk",
      "com.noshufou.android.su",
      "com.noshufou.android.su.elite",
      "eu.chainfire.supersu",
      "com.koushikdutta.superuser",
      "com.thirdparty.superuser",
      "com.yellowes.su",
      "me.weishu.kernelsu",
      "com.rifsxd.ksunext",
      "me.bmax.apatch"
    )

  /** Properties whose value indicates a debuggable or non-secure build. */
  val DANGEROUS_PROPERTIES =
    mapOf(
      "ro.debuggable" to "1",
      "ro.secure" to "0"
    )

  /** Partitions that should be read-only on an unmodified device. */
  val PROTECTED_MOUNT_POINTS =
    listOf("/system", "/system_ext", "/vendor", "/product", "/odm")

  /** Directories a normal application must never be able to write to. */
  val PROTECTED_DIRECTORIES =
    listOf("/system", "/system/bin", "/system/etc", "/vendor", "/data", "/")

  /** Filesystem artefacts commonly associated with Magisk. */
  val MAGISK_PATHS =
    listOf(
      "/sbin/.magisk",
      "/data/adb/magisk",
      "/data/adb/modules",
      "/cache/.disable_magisk",
      "/init.magisk.rc"
    )

  /** Mount-table markers commonly associated with Magisk. */
  val MAGISK_MOUNT_MARKERS = listOf("magisk", "core/mirror", "core/img")

  /** Memory-map markers associated with Zygisk-style process injection. */
  val ZYGISK_MAP_MARKERS = listOf("zygisk", "jit-cache-zygisk", "memfd:/jit-cache")
}
