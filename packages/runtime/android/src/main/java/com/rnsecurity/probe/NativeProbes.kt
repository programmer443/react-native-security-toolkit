package com.rnsecurity.probe

import android.util.Log

/**
 * Bridge to the native probe library.
 *
 * The library is loaded once, defensively: if it is missing — stripped by an
 * aggressive packaging step, or absent for this ABI — the engine degrades to
 * reporting `indeterminate` for property-based signals rather than crashing the
 * host application.
 */
internal object NativeProbes {

  private const val TAG = "RNSecurityToolkit"

  val loaded: Boolean =
    try {
      System.loadLibrary("rnsecuritytoolkit")
      true
    } catch (error: UnsatisfiedLinkError) {
      Log.w(TAG, "Native probe library unavailable; property signals will report indeterminate")
      false
    } catch (error: SecurityException) {
      Log.w(TAG, "Native probe library blocked; property signals will report indeterminate")
      false
    }

  @JvmStatic external fun getSystemProperty(key: String): String?

  @JvmStatic external fun getSymbolOrigin(symbol: String): String?

  @JvmStatic external fun isAvailable(): Boolean
}
