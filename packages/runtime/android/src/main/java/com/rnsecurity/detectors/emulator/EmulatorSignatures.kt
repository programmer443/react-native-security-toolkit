package com.rnsecurity.detectors.emulator

/**
 * Versioned signature data for emulator detection.
 *
 * Kept deliberately current: the widely copied lists in older projects target
 * the QEMU/goldfish generation of Android emulators and miss `ranchu`, the
 * `sdk_gphone*` product names, and the cloud device farms that a real attacker
 * is more likely to be using.
 */
internal object EmulatorSignatures {

  /** Bumped whenever any list below changes. Reported in check metadata. */
  const val VERSION = "2026.08.1"

  /** `Build.HARDWARE` values used by emulators and virtualised devices. */
  val HARDWARE_MARKERS =
    listOf("goldfish", "ranchu", "vbox86", "android_x86", "cutf_cvm", "gce_x86", "windows")

  /** Substrings that appear in emulator build fingerprints, products or models. */
  val BUILD_MARKERS =
    listOf(
      "generic",
      "unknown",
      "sdk_gphone",
      "sdk_google",
      "google_sdk",
      "emulator",
      "android sdk built for",
      "emu64",
      "genymotion",
      "bluestacks",
      "nox",
      "droid4x",
      "andy",
      "vbox",
      "cuttlefish",
      "cf_x86",
    )

  /** Device nodes and files that exist only under emulation. */
  val QEMU_FILES =
    listOf(
      "/dev/socket/qemud",
      "/dev/qemu_pipe",
      "/dev/goldfish_pipe",
      "/system/lib/libc_malloc_debug_qemu.so",
      "/sys/qemu_trace",
      "/system/bin/qemu-props",
      "/dev/socket/genyd",
      "/dev/socket/baseband_genyd"
    )

  /** Properties whose presence or value indicates emulation. */
  val QEMU_PROPERTIES =
    listOf(
      "ro.kernel.qemu",
      "ro.kernel.qemu.gles",
      "ro.boot.qemu",
      "init.svc.qemud",
      "init.svc.goldfish-logcat",
      "qemu.sf.lcd_density",
      "ro.boot.hardware.platform"
    )

  /**
   * Sensor count below which a device looks synthetic.
   *
   * Physical phones report well above this; emulator images report a handful.
   * Deliberately generous — a low count is a hint, never a verdict.
   */
  const val MINIMUM_PLAUSIBLE_SENSOR_COUNT = 8
}
