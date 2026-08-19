package com.rnsecurity.engine

import com.rnsecurity.detectors.biometric.BiometricCheckEngine
import com.rnsecurity.detectors.debugger.DebuggerCheckEngine
import com.rnsecurity.detectors.emulator.EmulatorCheckEngine
import com.rnsecurity.detectors.hook.HookCheckEngine
import com.rnsecurity.detectors.hardware.SecureHardwareCheckEngine
import com.rnsecurity.detectors.integrity.IntegrityCheckEngine
import com.rnsecurity.detectors.network.NetworkCheckEngine
import com.rnsecurity.detectors.screen.ScreenCheckEngine
import com.rnsecurity.detectors.root.RootCheckEngine
import com.rnsecurity.probe.ProbeSet

/**
 * Selects and runs check engines.
 *
 * Failure is contained at three levels: a detector that throws becomes one
 * `indeterminate` signal, a check engine that throws becomes an `error` result,
 * and neither ever propagates to the host application. A security package that
 * can crash the app it protects has made things worse, not better.
 */
class AndroidSecurityEngine(
  private val probes: ProbeSet,
  private val clock: () -> Long = System::currentTimeMillis,
  engines: List<CheckEngine> = defaultEngines()
) {

  private val enginesById: Map<String, CheckEngine> = engines.associateBy { it.checkId }

  /**
   * Checks this engine implements.
   *
   * Grows only when a check is implemented *and* tested. Reporting a capability
   * ahead of its tests would be the first of the overclaims this project exists
   * to avoid.
   */
  fun supportedChecks(): List<String> = enginesById.keys.sorted()

  fun run(checkId: String, options: CheckOptions = CheckOptions.EMPTY): CheckResult {
    val startedAt = clock()
    val engine =
      enginesById[checkId]
        ?: return SignalAggregator.unavailable(
          checkId,
          UnavailableReason.PLATFORM_NOT_SUPPORTED,
          startedAt
        )

    return try {
      val signals = engine.detectors(options).map { runDetector(it) }
      SignalAggregator.aggregate(
        checkId = checkId,
        signals = signals,
        metadata = safeMetadata(engine, options),
        durationMs = clock() - startedAt,
        checkedAtEpochMs = startedAt
      )
    } catch (throwable: Throwable) {
      SignalAggregator.error(
        checkId,
        throwable.message ?: throwable.javaClass.simpleName,
        startedAt
      )
    }
  }

  private fun runDetector(detector: Detector): SecuritySignal =
    try {
      if (probes.build.sdkInt() < detector.minSdk) {
        SecuritySignal(
          id = detector.id,
          outcome = SignalOutcome.INDETERMINATE,
          confidence = Confidence.LOW,
          description =
            "Indicator requires API ${detector.minSdk}; this device reports API ${probes.build.sdkInt()}"
        )
      } else {
        detector.detect(probes)
      }
    } catch (throwable: Throwable) {
      // One misbehaving detector must not lose the other nine.
      SecuritySignal(
        id = detector.id,
        outcome = SignalOutcome.INDETERMINATE,
        confidence = Confidence.LOW,
        description = "Indicator could not be evaluated: ${throwable.javaClass.simpleName}"
      )
    }

  private fun safeMetadata(engine: CheckEngine, options: CheckOptions): Map<String, Any?> =
    try {
      engine.metadata(probes, options)
    } catch (throwable: Throwable) {
      emptyMap()
    }

  companion object {
    fun defaultEngines(): List<CheckEngine> =
      listOf(
        RootCheckEngine(),
        DebuggerCheckEngine(),
        EmulatorCheckEngine(),
        HookCheckEngine(),
        IntegrityCheckEngine(),
        SecureHardwareCheckEngine(),
        BiometricCheckEngine(),
        NetworkCheckEngine(),
        ScreenCheckEngine()
      )
  }
}
