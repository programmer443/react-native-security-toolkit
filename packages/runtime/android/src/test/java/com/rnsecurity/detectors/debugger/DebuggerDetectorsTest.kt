package com.rnsecurity.detectors.debugger

import com.rnsecurity.FakeApplicationProbe
import com.rnsecurity.FakeDebuggerProbe
import com.rnsecurity.FakeProcProbe
import com.rnsecurity.FakeSettingsProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.SignalOutcome
import org.junit.Assert.assertEquals
import org.junit.Test

class DebuggerDetectorsTest {

  // ── attached debugger ──────────────────────────────────────────────────────

  @Test
  fun `fires when a debugger is connected`() {
    val signal =
      DebuggerAttachedDetector()
        .detect(cleanDeviceProbes(debugger = FakeDebuggerProbe(connected = true)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `fires when the process is waiting for a debugger`() {
    val signal =
      DebuggerAttachedDetector()
        .detect(cleanDeviceProbes(debugger = FakeDebuggerProbe(waiting = true)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `stays quiet when no debugger is present`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      DebuggerAttachedDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `reports indeterminate when the platform state is unavailable`() {
    val signal =
      DebuggerAttachedDetector()
        .detect(cleanDeviceProbes(debugger = FakeDebuggerProbe(connected = null, waiting = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  /** One probe answering is enough; the other being blocked is not a failure. */
  @Test
  fun `answers from a single available sub-probe`() {
    val signal =
      DebuggerAttachedDetector()
        .detect(cleanDeviceProbes(debugger = FakeDebuggerProbe(connected = true, waiting = null)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  // ── TracerPid ──────────────────────────────────────────────────────────────

  @Test
  fun `tracer detector fires on a non-zero TracerPid`() {
    val signal =
      TracerPidDetector()
        .detect(cleanDeviceProbes(proc = FakeProcProbe(status = "Name:\tapp\nTracerPid:\t4711\n")))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(4711, signal.metadata["tracerPid"])
  }

  @Test
  fun `tracer detector stays quiet on a zero TracerPid`() {
    assertEquals(SignalOutcome.NOT_DETECTED, TracerPidDetector().detect(cleanDeviceProbes()).outcome)
  }

  @Test
  fun `tracer detector reports indeterminate when proc is unreadable`() {
    val signal = TracerPidDetector().detect(cleanDeviceProbes(proc = FakeProcProbe(status = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  /** A truncated or reformatted status file must not be read as "no tracer". */
  @Test
  fun `tracer detector reports indeterminate when TracerPid is absent`() {
    val signal =
      TracerPidDetector().detect(cleanDeviceProbes(proc = FakeProcProbe(status = "Name:\tapp\n")))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  @Test
  fun `tracer detector reports indeterminate when TracerPid is unparseable`() {
    val signal =
      TracerPidDetector()
        .detect(cleanDeviceProbes(proc = FakeProcProbe(status = "TracerPid:\tnope\n")))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── debuggable build ───────────────────────────────────────────────────────

  @Test
  fun `debuggable detector fires on a debuggable application`() {
    val signal =
      DebuggableBuildDetector()
        .detect(cleanDeviceProbes(application = FakeApplicationProbe(debuggable = true)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `debuggable detector stays quiet on a release build`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      DebuggableBuildDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `debuggable detector reports indeterminate without application flags`() {
    val signal =
      DebuggableBuildDetector()
        .detect(cleanDeviceProbes(application = FakeApplicationProbe(debuggable = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── developer options ──────────────────────────────────────────────────────

  @Test
  fun `developer options detector fires when the setting is on`() {
    val signal =
      DeveloperOptionsDetector()
        .detect(
          cleanDeviceProbes(
            settings = FakeSettingsProbe(values = mapOf("development_settings_enabled" to 1))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    // Plenty of ordinary users enable developer options. This may corroborate;
    // it must never carry a verdict on its own.
    assertEquals(Confidence.LOW, signal.confidence)
  }

  @Test
  fun `developer options detector stays quiet when the setting is off`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      DeveloperOptionsDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  /**
   * An unreadable settings provider is inconclusive. An *absent* key is not:
   * most devices never write these keys, and on Android absence means the
   * platform default applies.
   */
  @Test
  fun `developer options detector reports indeterminate when settings are unreadable`() {
    val signal =
      DeveloperOptionsDetector().detect(cleanDeviceProbes(settings = FakeSettingsProbe(readable = false)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  @Test
  fun `developer options detector treats an absent key as the platform default`() {
    val signal = DeveloperOptionsDetector().detect(cleanDeviceProbes(settings = FakeSettingsProbe()))

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  // ── ADB debugging ──────────────────────────────────────────────────────────

  @Test
  fun `adb detector fires on USB debugging`() {
    val signal =
      AdbEnabledDetector()
        .detect(cleanDeviceProbes(settings = FakeSettingsProbe(values = mapOf("adb_enabled" to 1))))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(Confidence.MEDIUM, signal.confidence)
    assertEquals(true, signal.metadata["usbDebugging"])
    assertEquals(false, signal.metadata["wirelessDebugging"])
  }

  @Test
  fun `adb detector fires on wireless debugging`() {
    val signal =
      AdbEnabledDetector()
        .detect(
          cleanDeviceProbes(settings = FakeSettingsProbe(values = mapOf("adb_wifi_enabled" to 1)))
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(true, signal.metadata["wirelessDebugging"])
  }

  @Test
  fun `adb detector stays quiet when debugging is off`() {
    assertEquals(SignalOutcome.NOT_DETECTED, AdbEnabledDetector().detect(cleanDeviceProbes()).outcome)
  }

  /**
   * Wireless debugging does not exist below Android 11, so the key is absent
   * there. That must not read as enabled, and must not stop the USB answer.
   */
  @Test
  fun `adb detector answers from USB alone when wireless is absent`() {
    val signal =
      AdbEnabledDetector()
        .detect(cleanDeviceProbes(settings = FakeSettingsProbe(values = mapOf("adb_enabled" to 0))))

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  @Test
  fun `adb detector reports indeterminate when settings are unreadable`() {
    val signal =
      AdbEnabledDetector().detect(cleanDeviceProbes(settings = FakeSettingsProbe(readable = false)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }
}
