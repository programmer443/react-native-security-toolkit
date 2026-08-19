package com.rnsecurity.engine

import com.rnsecurity.FakeBuildProbe
import com.rnsecurity.FakeFileProbe
import com.rnsecurity.FakePackageProbe
import com.rnsecurity.FakeSystemPropertyProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.probe.ProbeSet
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidSecurityEngineTest {

  private fun engine(
    probes: ProbeSet = cleanDeviceProbes(),
    engines: List<CheckEngine> = AndroidSecurityEngine.defaultEngines()
  ) = AndroidSecurityEngine(probes, clock = { 1_000L }, engines = engines)

  @Test
  fun `a clean device reports secure with every signal recorded`() {
    val result = engine().run("root")

    assertEquals(CheckStatus.SECURE, result.status)
    assertEquals(false, result.detected)
    // Signals that did not fire are still returned, so the reasoning is auditable.
    assertEquals(10, result.signals.size)
  }

  @Test
  fun `a rooted device reports detected with high confidence`() {
    val probes =
      cleanDeviceProbes(
        files =
          FakeFileProbe(
            executable = mapOf("/system/xbin/su" to true),
            existing = mapOf("/data/adb/magisk" to true),
            contents = mapOf("/sys/fs/selinux/enforce" to "0")
          ),
        properties =
          FakeSystemPropertyProbe(
            values =
              mapOf(
                "ro.debuggable" to "1",
                "ro.boot.verifiedbootstate" to "orange",
                "ro.boot.flash.locked" to "0"
              )
          ),
        packages = FakePackageProbe(installed = mapOf("com.topjohnwu.magisk" to true))
      )

    val result = engine(probes).run("root")

    assertEquals(CheckStatus.DETECTED, result.status)
    assertEquals(Confidence.HIGH, result.confidence)
    assertTrue(result.signals.count { it.detected } >= 5)
  }

  /**
   * An unknown check is a platform fact, not an error. Returning `unavailable`
   * with a reason is what lets `checkAll()` omit iOS checks on Android instead
   * of filling the report with failures.
   */
  @Test
  fun `an unknown check is unavailable rather than an error`() {
    val result = engine().run("jailbreak")

    assertEquals(CheckStatus.UNAVAILABLE, result.status)
    assertEquals(UnavailableReason.PLATFORM_NOT_SUPPORTED, result.unavailableReason)
  }

  @Test
  fun `supported checks only lists implemented checks`() {
    assertEquals(
      listOf(
        "biometrics",
        "debugger",
        "emulator",
        "hooks",
        "integrity",
        "network",
        "root",
        "screen",
        "secureHardware"
      ),
      engine().supportedChecks()
    )
  }

  @Test
  fun `each registered check produces a result of its own id`() {
    for (checkId in engine().supportedChecks()) {
      assertEquals(checkId, engine().run(checkId).id)
    }
  }

  @Test
  fun `a detector that throws costs one signal, not the whole check`() {
    val exploding =
      object : Detector {
        override val id = "RNSEC-TEST-EXPLODE"

        override fun detect(probes: com.rnsecurity.probe.ProbeSet): SecuritySignal =
          throw IllegalStateException("detector bug")
      }

    val checkEngine =
      object : CheckEngine {
        override val checkId = "root"
        override fun detectors(options: CheckOptions) = listOf(exploding)
      }

    val result = engine(engines = listOf(checkEngine)).run("root")

    assertEquals(CheckStatus.UNKNOWN, result.status)
    assertEquals(1, result.signals.size)
    assertEquals(SignalOutcome.INDETERMINATE, result.signals[0].outcome)
  }

  @Test
  fun `a check engine whose metadata throws still produces a result`() {
    val checkEngine =
      object : CheckEngine {
        override val checkId = "root"

        override fun detectors(options: CheckOptions) = emptyList<Detector>()

        override fun metadata(
          probes: com.rnsecurity.probe.ProbeSet,
          options: CheckOptions
        ): Map<String, Any?> = throw IllegalStateException("metadata bug")
      }

    val result = engine(engines = listOf(checkEngine)).run("root")

    assertEquals(CheckStatus.SECURE, result.status)
    assertEquals(emptyMap<String, Any?>(), result.metadata)
  }

  @Test
  fun `a detector below its minimum API level reports indeterminate`() {
    val modern =
      object : Detector {
        override val id = "RNSEC-TEST-MODERN"
        override val minSdk = 35

        override fun detect(probes: com.rnsecurity.probe.ProbeSet): SecuritySignal =
          throw AssertionError("must not run below its minimum API level")
      }

    val checkEngine =
      object : CheckEngine {
        override val checkId = "root"

        override fun detectors(options: CheckOptions) = listOf(modern)
      }

    val result =
      engine(probes = cleanDeviceProbes(build = FakeBuildProbe(sdkInt = 24)), engines = listOf(checkEngine))
        .run("root")

    assertEquals(SignalOutcome.INDETERMINATE, result.signals[0].outcome)
    assertTrue(result.signals[0].description.contains("API 35"))
  }

  @Test
  fun `check metadata explains why signals may be inconclusive`() {
    val result = engine(cleanDeviceProbes(packages = FakePackageProbe(canQuery = false))).run("root")

    assertEquals(false, result.metadata["packageVisibilityConfigured"])
    assertEquals(true, result.metadata["nativePropertyProbeAvailable"])
    assertNotNull(result.metadata["signatureVersion"])
  }

  @Test
  fun `results carry timing so callers can see check cost`() {
    val result = engine().run("root")

    assertEquals(1_000L, result.checkedAtEpochMs)
    assertEquals(0L, result.durationMs)
  }
}
