package com.rnsecurity.screen

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.view.WindowManager
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Applies and maintains `FLAG_SECURE` on the application's windows.
 *
 * `FLAG_SECURE` is a **per-window** flag, and a window that is destroyed and
 * recreated — a rotation, a configuration change, a new activity — comes back
 * without it. Setting it once and walking away produces protection that silently
 * lapses at exactly the moments a user is most likely to be moving around the
 * app. So the desired state is remembered and re-applied through activity
 * lifecycle callbacks.
 *
 * What this cannot cover is documented rather than papered over: dialogs and
 * React Native modals create their own windows, and this controller only sees
 * activities. See `docs/runtime/screen-security.md`.
 */
internal class ScreenProtectionController(private val application: Application) {

  private val enabled = AtomicBoolean(false)
  private val listenerRegistered = AtomicBoolean(false)

  /** Desired protection state, whether or not a window currently exists to apply it to. */
  fun isEnabled(): Boolean = enabled.get()

  /**
   * Records the desired state and applies it to [activity] if one is available.
   *
   * Must be called on the UI thread.
   *
   * @return whether the flag was applied to a live window. `false` means the
   *   state was recorded and will be applied when a window appears — not that
   *   the request failed.
   */
  fun apply(activity: Activity?, enable: Boolean): Boolean {
    enabled.set(enable)
    registerLifecycleListenerOnce()

    val window = activity?.window ?: return false

    if (enable) {
      window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    } else {
      window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
    return true
  }

  private fun registerLifecycleListenerOnce() {
    if (!listenerRegistered.compareAndSet(false, true)) {
      return
    }

    application.registerActivityLifecycleCallbacks(
      object : Application.ActivityLifecycleCallbacks {
        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
          reapply(activity)
        }

        // Also on resume: an activity can be recreated without this instance
        // seeing its onActivityCreated in every configuration.
        override fun onActivityResumed(activity: Activity) = reapply(activity)

        override fun onActivityStarted(activity: Activity) = Unit

        override fun onActivityPaused(activity: Activity) = Unit

        override fun onActivityStopped(activity: Activity) = Unit

        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

        override fun onActivityDestroyed(activity: Activity) = Unit

        private fun reapply(activity: Activity) {
          if (enabled.get()) {
            activity.window?.setFlags(
              WindowManager.LayoutParams.FLAG_SECURE,
              WindowManager.LayoutParams.FLAG_SECURE
            )
          }
        }
      }
    )
  }
}
