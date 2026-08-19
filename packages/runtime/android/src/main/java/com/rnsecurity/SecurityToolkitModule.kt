package com.rnsecurity

import android.os.Build
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.UiThreadUtil
import com.facebook.react.module.annotations.ReactModule
import com.rnsecurity.engine.AndroidSecurityEngine
import com.rnsecurity.engine.CheckOptions
import com.rnsecurity.engine.ResultMapper
import com.rnsecurity.probe.AndroidProbeSet
import com.rnsecurity.screen.ScreenProtectionController
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * TurboModule entry point for the Android security engine.
 *
 * Two rules govern everything added to this class:
 *
 * 1. **Nothing runs on the JavaScript thread.** Detection reads the filesystem,
 *    `/proc` and system properties; none of that belongs on the caller's thread.
 * 2. **Nothing escapes as an exception the host application did not ask for.** A
 *    failing security check degrades to a result carrying a status, and the
 *    JavaScript layer turns that into a value rather than a crash.
 */
@ReactModule(name = SecurityToolkitModule.NAME)
class SecurityToolkitModule(reactContext: ReactApplicationContext) :
  NativeSecurityToolkitSpec(reactContext) {

  private val executor: ExecutorService =
    Executors.newSingleThreadExecutor { runnable ->
      Thread(runnable, "rnsec-security-engine").apply { isDaemon = true }
    }

  private val screenProtection: ScreenProtectionController by lazy {
    ScreenProtectionController(reactApplicationContext.applicationContext as android.app.Application)
  }

  private val engine: AndroidSecurityEngine by lazy {
    AndroidSecurityEngine(
      AndroidProbeSet.create(reactApplicationContext) { reactApplicationContext.currentActivity }
    )
  }

  override fun getEngineInfo(promise: Promise) {
    submit(promise) {
      Arguments.createMap().apply {
        putString("platform", "android")
        putString("osVersion", Build.VERSION.RELEASE ?: "unknown")
        putString("engineVersion", BuildConfig.ENGINE_VERSION)
        putArray(
          "supportedChecks",
          Arguments.createArray().apply { engine.supportedChecks().forEach { pushString(it) } }
        )
      }
    }
  }

  override fun runCheck(checkId: String, options: ReadableMap?, promise: Promise) {
    // Bridge values must be read on the calling thread; they are not safe to
    // touch once the call has returned.
    val checkOptions = options.toCheckOptions()

    submit(promise) { ResultMapper.toWritableMap(engine.run(checkId, checkOptions)) }
  }

  override fun runChecks(checkIds: ReadableArray, options: ReadableMap?, promise: Promise) {
    val ids = (0 until checkIds.size()).mapNotNull { checkIds.getString(it) }
    val checkOptions = options.toCheckOptions()

    submit(promise) {
      Arguments.createMap().apply {
        putArray(
          "results",
          Arguments.createArray().apply {
            ids.forEach { pushMap(ResultMapper.toWritableMap(engine.run(it, checkOptions))) }
          }
        )
      }
    }
  }

  private fun ReadableMap?.toCheckOptions(): CheckOptions =
    if (this == null) CheckOptions.EMPTY else CheckOptions(toHashMap())

  override fun setScreenProtection(enabled: Boolean, promise: Promise) {
    // Window flags may only be touched on the UI thread.
    UiThreadUtil.runOnUiThread {
      try {
        promise.resolve(screenProtection.apply(reactApplicationContext.currentActivity, enabled))
      } catch (throwable: Throwable) {
        promise.reject(ERROR_CODE, throwable.message ?: throwable.javaClass.simpleName, throwable)
      }
    }
  }

  override fun invalidate() {
    executor.shutdownNow()
    super.invalidate()
  }

  /** Runs [work] off the JavaScript thread and settles [promise] with its outcome. */
  private fun submit(promise: Promise, work: () -> WritableMap) {
    try {
      executor.execute {
        try {
          promise.resolve(work())
        } catch (throwable: Throwable) {
          promise.reject(ERROR_CODE, throwable.message ?: throwable.javaClass.simpleName, throwable)
        }
      }
    } catch (rejected: RejectedExecutionException) {
      // The module was invalidated while a call was in flight.
      promise.reject(ERROR_CODE, "The security engine is shutting down", rejected)
    }
  }

  companion object {
    const val NAME = NativeSecurityToolkitSpec.NAME

    private const val ERROR_CODE = "RNSEC_NATIVE_ERROR"
  }
}
