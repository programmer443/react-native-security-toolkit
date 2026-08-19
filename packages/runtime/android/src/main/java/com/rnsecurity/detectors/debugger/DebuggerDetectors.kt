package com.rnsecurity.detectors.debugger

import com.rnsecurity.engine.CheckEngine
import com.rnsecurity.engine.CheckOptions
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.Detector
import com.rnsecurity.engine.SecuritySignal
import com.rnsecurity.engine.SignalOutcome
import com.rnsecurity.probe.ProbeSet

/**
 * Debugger detection signals for Android.
 *
 * These fire constantly during normal development, which is the point worth
 * holding on to: a debugger attached to a debug build is not an attack, and a
 * package that treats it as one makes itself impossible to develop against. The
 * signals are reported faithfully; deciding that a debugger matters is the
 * application's job, and `developmentMode` exists so a policy can ignore them
 * without the check lying about what it saw.
 *
 * See `docs/runtime/debugger-detection.md`.
 */

private fun indeterminate(id: String, confidence: Confidence, why: String) =
  SecuritySignal(
    id = id,
    outcome = SignalOutcome.INDETERMINATE,
    confidence = confidence,
    description = "Debugger indicator could not be evaluated: $why"
  )

private fun outcomeOf(detected: Boolean) =
  if (detected) SignalOutcome.DETECTED else SignalOutcome.NOT_DETECTED

/**
 * A JDWP debugger attached to, or awaited by, this process.
 *
 * The most direct signal available, and also the easiest to defeat: it reports
 * the platform's own view, which is exactly what an attacker with native access
 * can influence.
 */
internal class DebuggerAttachedDetector : Detector {
  override val id = "RNSEC-ANDROID-DEBUGGER-001"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val connected = probes.debugger.isDebuggerConnected()
    val waiting = probes.debugger.isWaitingForDebugger()

    if (connected == null && waiting == null) {
      return indeterminate(id, Confidence.HIGH, "the platform debugger state was unavailable")
    }

    val detected = connected == true || waiting == true

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(detected),
      confidence = Confidence.HIGH,
      description =
        if (detected) {
          "A debugger is attached to this process, or the process is waiting for one"
        } else {
          "No debugger is attached to this process"
        },
      metadata = mapOf("connected" to connected, "waitingForDebugger" to waiting)
    )
  }
}

/**
 * A non-zero `TracerPid`, meaning some process is ptrace-attached to this one.
 *
 * Catches native debuggers and instrumentation that the platform-level check in
 * `DEBUGGER-001` does not see. Profilers legitimately trip it.
 */
internal class TracerPidDetector : Detector {
  override val id = "RNSEC-ANDROID-DEBUGGER-002"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val status =
      probes.proc.selfStatus()
        ?: return indeterminate(id, Confidence.HIGH, "/proc/self/status was not readable")

    val tracerPid =
      status
        .lineSequence()
        .firstOrNull { it.startsWith("TracerPid:") }
        ?.substringAfter(':')
        ?.trim()
        ?.toIntOrNull()
        ?: return indeterminate(id, Confidence.HIGH, "TracerPid was absent or unparseable")

    val detected = tracerPid != 0

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(detected),
      confidence = Confidence.HIGH,
      description =
        if (detected) {
          "Another process is attached to this one as a tracer"
        } else {
          "No process is attached to this one as a tracer"
        },
      metadata = mapOf("tracerPid" to tracerPid)
    )
  }
}

/**
 * The application is built debuggable.
 *
 * A build-configuration fact rather than a runtime event: true by definition in
 * every debug build, and a genuine finding only in something shipped to users.
 */
internal class DebuggableBuildDetector : Detector {
  override val id = "RNSEC-ANDROID-DEBUGGER-003"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val debuggable =
      probes.application.isDebuggable()
        ?: return indeterminate(id, Confidence.HIGH, "the application flags were unavailable")

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(debuggable),
      confidence = Confidence.HIGH,
      description =
        if (debuggable) {
          "The application is built debuggable"
        } else {
          "The application is not built debuggable"
        },
      metadata = mapOf("debuggable" to debuggable)
    )
  }
}

/**
 * Developer options enabled in device settings.
 *
 * Low confidence by design. A large minority of ordinary users have developer
 * options switched on — for a refresh-rate overlay, an animation-scale tweak, or
 * because a support article told them to — and none of that is an attack. This
 * is device posture, not evidence of one.
 */
internal class DeveloperOptionsDetector : Detector {
  override val id = "RNSEC-ANDROID-DEBUGGER-004"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val enabled =
      probes.settings.globalInt(DEVELOPMENT_SETTINGS_ENABLED, DISABLED)
        ?: return indeterminate(id, Confidence.LOW, "device settings were not readable")

    val detected = enabled != 0

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(detected),
      confidence = Confidence.LOW,
      description =
        if (detected) {
          "Developer options are enabled in device settings"
        } else {
          "Developer options are disabled in device settings"
        },
      metadata = mapOf("developerOptionsEnabled" to detected)
    )
  }

  private companion object {
    const val DEVELOPMENT_SETTINGS_ENABLED = "development_settings_enabled"
    const val DISABLED = 0
  }
}

/**
 * ADB debugging enabled, over USB or over the network.
 *
 * A stronger statement than developer options alone: the device is configured to
 * accept debug connections. Wireless ADB is weighted the same but recorded
 * separately, since it does not require physical access to the device.
 */
internal class AdbEnabledDetector : Detector {
  override val id = "RNSEC-ANDROID-DEBUGGER-005"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val usb = probes.settings.globalInt(ADB_ENABLED, DISABLED)
    // Wireless debugging is Android 11+. Below that the key simply does not
    // exist, which the platform expresses as the default — not as unknown.
    val wireless = probes.settings.globalInt(ADB_WIFI_ENABLED, DISABLED)

    if (usb == null && wireless == null) {
      return indeterminate(id, Confidence.MEDIUM, "device settings were not readable")
    }

    val usbEnabled = usb != null && usb != 0
    val wirelessEnabled = wireless != null && wireless != 0
    val detected = usbEnabled || wirelessEnabled

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(detected),
      confidence = Confidence.MEDIUM,
      description =
        if (detected) {
          "The device is configured to accept ADB debugging connections"
        } else {
          "ADB debugging is not enabled on this device"
        },
      metadata = mapOf("usbDebugging" to usbEnabled, "wirelessDebugging" to wirelessEnabled)
    )
  }

  private companion object {
    const val ADB_ENABLED = "adb_enabled"
    const val ADB_WIFI_ENABLED = "adb_wifi_enabled"
    const val DISABLED = 0
  }
}

/** The debugger check. */
internal class DebuggerCheckEngine : CheckEngine {
  override val checkId = "debugger"

  override fun detectors(options: CheckOptions): List<Detector> = DETECTORS

  private companion object {
    private val DETECTORS = listOf(
      DebuggerAttachedDetector(),
      TracerPidDetector(),
      DebuggableBuildDetector(),
      DeveloperOptionsDetector(),
      AdbEnabledDetector()
    )
  }
}
