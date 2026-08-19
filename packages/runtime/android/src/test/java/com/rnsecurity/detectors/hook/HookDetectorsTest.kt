package com.rnsecurity.detectors.hook

import com.rnsecurity.FakeNativeSymbolProbe
import com.rnsecurity.FakeProcProbe
import com.rnsecurity.FakeRuntimeProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.engine.SignalOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HookDetectorsTest {

  // ── dynamic instrumentation ────────────────────────────────────────────────

  @Test
  fun `fires on an instrumentation agent in the memory map`() {
    val signal =
      DynamicInstrumentationDetector()
        .detect(
          cleanDeviceProbes(
            proc =
              FakeProcProbe(
                maps = listOf("7f0000-7f1000 r-xp 00000000 00:00 0 /data/local/tmp/frida-agent-64.so")
              )
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertTrue(signal.description.startsWith("Potential"))
  }

  @Test
  fun `fires on an injected worker thread name`() {
    val signal =
      DynamicInstrumentationDetector()
        .detect(cleanDeviceProbes(proc = FakeProcProbe(threadNames = listOf("main", "gum-js-loop"))))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(listOf("gum-js-loop"), signal.metadata["threadNameMatches"])
  }

  /**
   * Thread names are matched exactly rather than by substring. `gmain` is a
   * marker; `gmainthread` in an unrelated library is not, and a substring match
   * would flag it.
   */
  @Test
  fun `does not fire on a thread name that merely contains a marker`() {
    val signal =
      DynamicInstrumentationDetector()
        .detect(cleanDeviceProbes(proc = FakeProcProbe(threadNames = listOf("main", "gmainthread"))))

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  @Test
  fun `stays quiet on an ordinary process`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      DynamicInstrumentationDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `reports indeterminate when both sources are unreadable`() {
    val signal =
      DynamicInstrumentationDetector()
        .detect(cleanDeviceProbes(proc = FakeProcProbe(maps = null, threadNames = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  /** One readable source is enough to answer; the other being blocked is not fatal. */
  @Test
  fun `answers from threads alone when the memory map is unreadable`() {
    val signal =
      DynamicInstrumentationDetector()
        .detect(
          cleanDeviceProbes(
            proc = FakeProcProbe(maps = null, threadNames = listOf("main", "pool-frida"))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(false, signal.metadata["mapsReadable"])
  }

  // ── managed hooking frameworks ─────────────────────────────────────────────

  @Test
  fun `fires when a hooking framework class is loadable`() {
    val signal =
      ManagedHookFrameworkDetector()
        .detect(
          cleanDeviceProbes(
            runtime =
              FakeRuntimeProbe(presentClasses = setOf("de.robv.android.xposed.XposedBridge"))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertTrue((signal.metadata["evidenceKinds"] as List<*>).contains("class"))
  }

  @Test
  fun `fires when a framework frame appears on the call stack`() {
    val signal =
      ManagedHookFrameworkDetector()
        .detect(
          cleanDeviceProbes(
            runtime =
              FakeRuntimeProbe(
                stack = listOf("com.example.app.Main", "de.robv.android.xposed.XposedBridge\$1")
              )
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertTrue((signal.metadata["evidenceKinds"] as List<*>).contains("stack-frame"))
  }

  @Test
  fun `fires when a framework library is mapped into the process`() {
    val signal =
      ManagedHookFrameworkDetector()
        .detect(
          cleanDeviceProbes(
            proc = FakeProcProbe(maps = listOf("7f0000-7f1000 r-xp 0 00:00 0 /system/lib64/liblspd.so"))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertTrue((signal.metadata["evidenceKinds"] as List<*>).contains("mapped-library"))
  }

  @Test
  fun `stays quiet on an ordinary runtime`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      ManagedHookFrameworkDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `reports indeterminate when runtime introspection fails`() {
    val signal =
      ManagedHookFrameworkDetector()
        .detect(
          cleanDeviceProbes(
            proc = FakeProcProbe(maps = null),
            runtime = FakeRuntimeProbe(classLookupWorks = false, stack = null)
          )
        )

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── native symbol origins ──────────────────────────────────────────────────

  @Test
  fun `fires when a libc symbol resolves inside another library`() {
    val signal =
      SymbolOriginDetector()
        .detect(
          cleanDeviceProbes(
            symbols =
              FakeNativeSymbolProbe(origins = mapOf("open" to "/data/local/tmp/frida-agent-64.so"))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(mapOf("open" to "frida-agent-64.so"), signal.metadata["unexpectedOrigins"])
  }

  /**
   * Android moves bionic between `/system/lib64` and `/apex/...` across
   * versions. Comparing full paths would report every modern device as hooked,
   * so only the library filename is compared.
   */
  @Test
  fun `does not care which directory bionic lives in`() {
    val signal =
      SymbolOriginDetector()
        .detect(
          cleanDeviceProbes(
            symbols =
              FakeNativeSymbolProbe(
                origins = mapOf("open" to "/system/lib64/libc.so", "read" to "/apex/x/libc.so")
              )
          )
        )

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  @Test
  fun `stays quiet when every symbol resolves where it should`() {
    assertEquals(SignalOutcome.NOT_DETECTED, SymbolOriginDetector().detect(cleanDeviceProbes()).outcome)
  }

  @Test
  fun `reports indeterminate without the native probe`() {
    val signal =
      SymbolOriginDetector().detect(cleanDeviceProbes(symbols = FakeNativeSymbolProbe(available = false)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  /** Nothing resolving at all is a broken probe, not a clean result. */
  @Test
  fun `reports indeterminate when no symbol resolves`() {
    val signal =
      SymbolOriginDetector()
        .detect(cleanDeviceProbes(symbols = FakeNativeSymbolProbe(defaultOrigin = { null })))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  /** A few unresolvable symbols must not mask the ones that did resolve wrong. */
  @Test
  fun `still fires when some symbols are unresolvable and one is redirected`() {
    val signal =
      SymbolOriginDetector()
        .detect(
          cleanDeviceProbes(
            symbols =
              FakeNativeSymbolProbe(
                origins = mapOf("connect" to "/data/app/libinjected.so", "fopen" to null)
              )
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(1, signal.metadata["unresolvedSymbols"])
  }
}
