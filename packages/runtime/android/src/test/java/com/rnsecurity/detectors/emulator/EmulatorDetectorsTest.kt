package com.rnsecurity.detectors.emulator

import android.telephony.TelephonyManager
import com.rnsecurity.FakeBuildProbe
import com.rnsecurity.FakeDeviceFeatureProbe
import com.rnsecurity.FakeFileProbe
import com.rnsecurity.FakeSystemPropertyProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.SignalOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EmulatorDetectorsTest {

  // ── build identity ─────────────────────────────────────────────────────────

  /**
   * The signature lists copied around older projects test for the QEMU/goldfish
   * generation and miss every modern AVD. These two cases exist to make sure
   * that regression cannot come back unnoticed.
   */
  @Test
  fun `build detector fires on a modern ranchu emulator`() {
    val signal =
      BuildIdentityDetector()
        .detect(
          cleanDeviceProbes(
            build =
              FakeBuildProbe(
                hardware = "ranchu",
                product = "sdk_gphone64_arm64",
                model = "sdk_gphone64_arm64",
                fingerprint = "google/sdk_gphone64_arm64/emu64a:16/BE1A.250327.001/12345:userdebug/test-keys"
              )
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(true, signal.metadata["hardwareMatch"])
  }

  @Test
  fun `build detector fires on a cuttlefish cloud device`() {
    val signal =
      BuildIdentityDetector()
        .detect(cleanDeviceProbes(build = FakeBuildProbe(hardware = "cutf_cvm", product = "cf_x86_64_phone")))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `build detector stays quiet on retail hardware`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      BuildIdentityDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `build detector reports indeterminate when build identity is unavailable`() {
    val signal =
      BuildIdentityDetector()
        .detect(
          cleanDeviceProbes(
            build =
              FakeBuildProbe(
                hardware = null,
                fingerprint = null,
                model = null,
                product = null,
                brand = null,
                device = null,
                board = null,
                manufacturer = null
              )
          )
        )

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── QEMU artefacts ─────────────────────────────────────────────────────────

  @Test
  fun `qemu detector fires on an emulator device node`() {
    val signal =
      QemuArtifactDetector()
        .detect(cleanDeviceProbes(files = FakeFileProbe(existing = mapOf("/dev/qemu_pipe" to true))))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(listOf("/dev/qemu_pipe"), signal.metadata["files"])
  }

  @Test
  fun `qemu detector fires on an emulator property`() {
    val signal =
      QemuArtifactDetector()
        .detect(
          cleanDeviceProbes(properties = FakeSystemPropertyProbe(values = mapOf("ro.kernel.qemu" to "1")))
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  /**
   * `ro.boot.hardware.platform` exists on retail devices too. Treating its mere
   * presence as an emulator signal would report every modern phone as emulated.
   */
  @Test
  fun `qemu detector ignores a platform property with a retail value`() {
    val signal =
      QemuArtifactDetector()
        .detect(
          cleanDeviceProbes(
            properties =
              FakeSystemPropertyProbe(values = mapOf("ro.boot.hardware.platform" to "kalama"))
          )
        )

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  @Test
  fun `qemu detector fires on a platform property naming an emulator`() {
    val signal =
      QemuArtifactDetector()
        .detect(
          cleanDeviceProbes(
            properties =
              FakeSystemPropertyProbe(values = mapOf("ro.boot.hardware.platform" to "ranchu"))
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
  }

  @Test
  fun `qemu detector stays quiet on a clean device`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      QemuArtifactDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `qemu detector reports indeterminate when probes are blocked`() {
    val signal =
      QemuArtifactDetector()
        .detect(
          cleanDeviceProbes(
            files = FakeFileProbe(defaultExists = null),
            properties = FakeSystemPropertyProbe(available = false)
          )
        )

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── hardware profile ───────────────────────────────────────────────────────

  @Test
  fun `hardware detector fires on implausibly few sensors`() {
    val signal =
      HardwareProfileDetector()
        .detect(cleanDeviceProbes(device = FakeDeviceFeatureProbe(sensorCount = 3)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    // Weakest signal here: it may only ever corroborate.
    assertEquals(Confidence.LOW, signal.confidence)
  }

  @Test
  fun `hardware detector fires when telephony is claimed but absent`() {
    val signal =
      HardwareProfileDetector()
        .detect(
          cleanDeviceProbes(
            device = FakeDeviceFeatureProbe(phoneType = TelephonyManager.PHONE_TYPE_NONE)
          )
        )

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertTrue((signal.metadata["anomalies"] as List<*>).contains("telephony-claimed-but-absent"))
  }

  /** A Wi-Fi-only tablet has no telephony and is not an emulator. */
  @Test
  fun `hardware detector does not flag a device that never claimed telephony`() {
    val signal =
      HardwareProfileDetector()
        .detect(
          cleanDeviceProbes(
            device =
              FakeDeviceFeatureProbe(
                defaultFeature = false,
                phoneType = TelephonyManager.PHONE_TYPE_NONE
              )
          )
        )

    assertEquals(SignalOutcome.NOT_DETECTED, signal.outcome)
  }

  @Test
  fun `hardware detector stays quiet on a physical handset`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      HardwareProfileDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `hardware detector reports indeterminate when capabilities are unavailable`() {
    val signal =
      HardwareProfileDetector()
        .detect(
          cleanDeviceProbes(
            device =
              FakeDeviceFeatureProbe(
                defaultFeature = null,
                phoneType = null,
                sensorCount = null
              )
          )
        )

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }
}
