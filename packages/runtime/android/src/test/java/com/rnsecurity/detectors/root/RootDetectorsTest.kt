package com.rnsecurity.detectors.root

import com.rnsecurity.FakeBuildProbe
import com.rnsecurity.FakeFileProbe
import com.rnsecurity.FakePackageProbe
import com.rnsecurity.FakeProcProbe
import com.rnsecurity.FakeSystemPropertyProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.SignalOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every detector gets the same four questions: does it fire on a compromised
 * device, stay quiet on a clean one, report `indeterminate` when its probe is
 * blocked, and avoid the false positive it is most likely to produce.
 */
class RootDetectorsTest {

  // ── su binaries ────────────────────────────────────────────────────────────

  @Test
  fun `su detector fires on an executable su binary`() {
    val signal =
      SuBinaryDetector()
        .detect(
          cleanDeviceProbes(
            files = FakeFileProbe(executable = mapOf("/system/xbin/su" to true))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(Confidence.MEDIUM, signal.confidence)
    assertEquals(listOf("/system/xbin/su"), signal.metadata["paths"])
  }

  @Test
  fun `su detector stays quiet on a clean device`() {
    assertEquals(SignalOutcome.NOT_DETECTED, SuBinaryDetector().detect(cleanDeviceProbes()).outcome)
  }

  @Test
  fun `su detector reports indeterminate when paths are unreadable`() {
    val signal =
      SuBinaryDetector()
        .detect(cleanDeviceProbes(files = FakeFileProbe(defaultExists = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  /** A path that exists but is not runnable is not treated as a hit. */
  @Test
  fun `su detector does not fire on a non-executable path`() {
    val signal =
      SuBinaryDetector()
        .detect(
          cleanDeviceProbes(
            files =
              FakeFileProbe(
                existing = mapOf("/system/xbin/su" to true),
                executable = mapOf("/system/xbin/su" to false)
              )
          )
        )

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  // ── root manager packages ──────────────────────────────────────────────────

  @Test
  fun `package detector fires on an installed root manager`() {
    val signal =
      RootManagerPackageDetector()
        .detect(
          cleanDeviceProbes(
            packages = FakePackageProbe(installed = mapOf("com.topjohnwu.magisk" to true))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  /**
   * Without `<queries>`, `getPackageInfo` reports "not installed" for everything.
   * Treating that as a clean result would be a false negative wearing a clean
   * result's clothes, so the detector must refuse to answer instead.
   */
  @Test
  fun `package detector reports indeterminate when visibility is not configured`() {
    val signal =
      RootManagerPackageDetector().detect(cleanDeviceProbes(packages = FakePackageProbe(canQuery = false)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
    assertTrue(signal.description.contains("package visibility"))
  }

  @Test
  fun `package detector stays quiet when nothing is installed`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      RootManagerPackageDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  // ── system properties ──────────────────────────────────────────────────────

  @Test
  fun `property detector fires on a debuggable build`() {
    val signal =
      DangerousSystemPropertyDetector()
        .detect(
          cleanDeviceProbes(
            properties = FakeSystemPropertyProbe(values = mapOf("ro.debuggable" to "1"))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(listOf("ro.debuggable"), signal.metadata["properties"])
  }

  @Test
  fun `property detector reports indeterminate without the native probe`() {
    val signal =
      DangerousSystemPropertyDetector()
        .detect(cleanDeviceProbes(properties = FakeSystemPropertyProbe(available = false)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  @Test
  fun `property detector stays quiet on a production build`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      DangerousSystemPropertyDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  // ── test keys ──────────────────────────────────────────────────────────────

  @Test
  fun `test-keys detector fires and stays low confidence`() {
    val signal =
      TestKeysDetector().detect(cleanDeviceProbes(build = FakeBuildProbe(tags = "test-keys")))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    // Custom ROM users are not attackers; this must never carry a verdict alone.
    assertEquals(Confidence.LOW, signal.confidence)
  }

  @Test
  fun `test-keys detector stays quiet on release keys`() {
    assertEquals(SignalOutcome.NOT_DETECTED, TestKeysDetector().detect(cleanDeviceProbes()).outcome)
  }

  /**
   * Emulator and engineering images are commonly signed `dev-keys`. Matching
   * only `test-keys` reported those as release-signed, which is a wrong
   * statement rather than merely a missed detection.
   */
  @Test
  fun `test-keys detector fires on dev-keys`() {
    val signal =
      TestKeysDetector().detect(cleanDeviceProbes(build = FakeBuildProbe(tags = "dev-keys")))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(listOf("dev-keys"), signal.metadata["matchedTags"])
  }

  /** A clean result must not assert a release signature it did not verify. */
  @Test
  fun `test-keys detector does not claim release signing it cannot verify`() {
    val signal = TestKeysDetector().detect(cleanDeviceProbes())

    assertTrue(signal.description.contains("do not indicate"))
  }

  @Test
  fun `test-keys detector reports indeterminate without build tags`() {
    val signal = TestKeysDetector().detect(cleanDeviceProbes(build = FakeBuildProbe(tags = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── verified boot ──────────────────────────────────────────────────────────

  @Test
  fun `verified boot detector fires on an unlocked bootloader`() {
    val signal =
      VerifiedBootDetector()
        .detect(
          cleanDeviceProbes(
            properties =
              FakeSystemPropertyProbe(
                values =
                  mapOf("ro.boot.verifiedbootstate" to "orange", "ro.boot.flash.locked" to "0")
              )
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(Confidence.HIGH, signal.confidence)
  }

  @Test
  fun `verified boot detector stays quiet on a locked green device`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      VerifiedBootDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `verified boot detector reports indeterminate when properties are absent`() {
    val signal =
      VerifiedBootDetector()
        .detect(cleanDeviceProbes(properties = FakeSystemPropertyProbe(values = emptyMap())))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── mounts ─────────────────────────────────────────────────────────────────

  @Test
  fun `mount detector fires on an overlay over system`() {
    val signal =
      MountAnomalyDetector()
        .detect(
          cleanDeviceProbes(
            proc =
              FakeProcProbe(
                mountInfo = listOf("123 45 0:99 / /system rw,relatime - overlay overlay rw")
              )
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `mount detector reports indeterminate when mountinfo is unreadable`() {
    val signal = MountAnomalyDetector().detect(cleanDeviceProbes(proc = FakeProcProbe(mountInfo = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  /** An overlay somewhere harmless is not a root indicator. */
  @Test
  fun `mount detector ignores overlays outside protected partitions`() {
    val signal =
      MountAnomalyDetector()
        .detect(
          cleanDeviceProbes(
            proc =
              FakeProcProbe(
                mountInfo = listOf("123 45 0:99 / /data/app/tmp rw,relatime - overlay overlay rw")
              )
          )
        )

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  // ── writable system paths ──────────────────────────────────────────────────

  @Test
  fun `writable path detector fires when a protected directory accepts a write`() {
    val signal =
      WritableSystemPathDetector()
        .detect(cleanDeviceProbes(files = FakeFileProbe(writable = mapOf("/system" to true))))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(Confidence.HIGH, signal.confidence)
  }

  @Test
  fun `writable path detector stays quiet when writes are refused`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      WritableSystemPathDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `writable path detector reports indeterminate when probes cannot run`() {
    val signal =
      WritableSystemPathDetector()
        .detect(cleanDeviceProbes(files = FakeFileProbe(defaultWritable = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── SELinux ────────────────────────────────────────────────────────────────

  @Test
  fun `selinux detector fires on permissive mode`() {
    val signal =
      SelinuxDetector()
        .detect(
          cleanDeviceProbes(
            files = FakeFileProbe(contents = mapOf("/sys/fs/selinux/enforce" to "0"))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `selinux detector stays quiet when enforcing`() {
    assertEquals(SignalOutcome.NOT_DETECTED, SelinuxDetector().detect(cleanDeviceProbes()).outcome)
  }

  @Test
  fun `selinux detector reports indeterminate when the state is unreadable`() {
    val signal = SelinuxDetector().detect(cleanDeviceProbes(files = FakeFileProbe()))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── Magisk and Zygisk ──────────────────────────────────────────────────────

  @Test
  fun `magisk detector fires on a known artefact`() {
    val signal =
      MagiskDetector()
        .detect(cleanDeviceProbes(files = FakeFileProbe(existing = mapOf("/data/adb/magisk" to true))))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    // Phrased as an indicator, never as a verdict.
    assertTrue(signal.description.startsWith("Potential"))
  }

  @Test
  fun `magisk detector fires on a mount marker`() {
    val signal =
      MagiskDetector()
        .detect(
          cleanDeviceProbes(
            proc = FakeProcProbe(mountInfo = listOf("41 32 0:1 / /system/bin - tmpfs magisk rw"))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `magisk detector stays quiet on a clean device`() {
    assertEquals(SignalOutcome.NOT_DETECTED, MagiskDetector().detect(cleanDeviceProbes()).outcome)
  }

  @Test
  fun `zygisk detector fires on an injection marker in this process`() {
    val signal =
      ZygiskDetector()
        .detect(
          cleanDeviceProbes(
            proc = FakeProcProbe(maps = listOf("7f00000000-7f00001000 r-xp 00000000 00:00 0 /zygisk/lib.so"))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `zygisk detector reports indeterminate when maps are unreadable`() {
    val signal = ZygiskDetector().detect(cleanDeviceProbes(proc = FakeProcProbe(maps = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  @Test
  fun `zygisk detector stays quiet on an ordinary memory map`() {
    val signal =
      ZygiskDetector()
        .detect(
          cleanDeviceProbes(
            proc = FakeProcProbe(maps = listOf("7f00000000-7f00001000 r-xp 00000000 00:00 0 /system/lib64/libc.so"))
          )
        )

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }
}
