package com.rnsecurity.detectors.hook

/**
 * Versioned signature data for hook and instrumentation detection.
 *
 * Everything here is a name an instrumentation framework happens to use today.
 * Names are the easiest thing in the world to change, which is precisely why
 * these signals are weighted `medium` and why the list is versioned rather than
 * scattered through the detectors.
 */
internal object HookSignatures {

  const val VERSION = "2026.08.1"

  /** Substrings seen in the memory map of a process under dynamic instrumentation. */
  val INSTRUMENTATION_MAP_MARKERS =
    listOf(
      "frida",
      "gadget",
      "gum-js-loop",
      "linjector",
      "libsubstrate",
      "substrate",
      "libwhale",
      "libdobby",
      "libepic"
    )

  /** Worker-thread names injected by instrumentation frameworks. */
  val INSTRUMENTATION_THREAD_NAMES =
    listOf("gmain", "gdbus", "gum-js-loop", "pool-frida", "pool-spawner", "linjector")

  /** Classes that exist only when a managed-code hooking framework is loaded. */
  val HOOK_FRAMEWORK_CLASSES =
    listOf(
      "de.robv.android.xposed.XposedBridge",
      "de.robv.android.xposed.XposedHelpers",
      "de.robv.android.xposed.IXposedHookLoadPackage",
      "org.lsposed.lspd.core.Main",
      "com.saurik.substrate.MS",
      "me.weishu.epic.art.Epic"
    )

  /** Package prefixes that should never appear on this application's call stack. */
  val HOOK_FRAMEWORK_STACK_PREFIXES =
    listOf("de.robv.android.xposed", "org.lsposed", "com.saurik.substrate", "me.weishu.epic")

  /** Memory-map substrings specific to managed-code hooking frameworks. */
  val HOOK_FRAMEWORK_MAP_MARKERS = listOf("lspd", "edxposed", "xposed", "riru", "libriru")

  /**
   * Native symbols checked against the library expected to provide them.
   *
   * Deliberately a short list of ordinary libc entry points. The check is not
   * "is this symbol hooked" but "does this symbol still live where it should" —
   * a redirected `open` or `connect` resolving inside an injected library is a
   * strong indicator, and one that renaming the library does not hide.
   */
  val EXPECTED_SYMBOL_LIBRARIES =
    mapOf(
      "open" to "libc.so",
      "read" to "libc.so",
      "write" to "libc.so",
      "connect" to "libc.so",
      "fopen" to "libc.so",
      "dlopen" to "libdl.so",
      "dlsym" to "libdl.so"
    )
}
