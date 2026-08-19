package com.rnsecurity.detectors.emulator

import android.content.pm.PackageManager
import android.telephony.TelephonyManager
import com.rnsecurity.engine.CheckEngine
import com.rnsecurity.engine.CheckOptions
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.Detector
import com.rnsecurity.engine.SecuritySignal
import com.rnsecurity.engine.SignalOutcome
import com.rnsecurity.probe.ProbeSet

/**
 * Emulator detection signals for Android.
 *
 * Running under emulation is **not** a compromise. Continuous integration runs
 * on emulators, QA runs on device farms, and Google Play Games runs Android apps
 * on desktop hardware. These signals are weighted accordingly — the check is
 * there to inform a risk decision, not to justify blocking a user.
 *
 * See `docs/runtime/emulator-detection.md`.
 */

private fun indeterminate(id: String, confidence: Confidence, why: String) =
  SecuritySignal(
    id = id,
    outcome = SignalOutcome.INDETERMINATE,
    confidence = confidence,
    description = "Emulator indicator could not be evaluated: $why"
  )

private fun outcomeOf(detected: Boolean) =
  if (detected) SignalOutcome.DETECTED else SignalOutcome.NOT_DETECTED

/**
 * Build identity that matches an emulator image rather than retail hardware.
 *
 * Matching is done against current signatures. The lists copied around older
 * projects test for the QEMU/goldfish generation and quietly miss every modern
 * AVD, which produces a check that looks thorough and detects nothing.
 */
internal class BuildIdentityDetector : Detector {
  override val id = "RNSEC-ANDROID-EMULATOR-001"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val hardware = probes.build.hardware()?.lowercase()
    val haystack =
      listOfNotNull(
          probes.build.fingerprint(),
          probes.build.model(),
          probes.build.product(),
          probes.build.brand(),
          probes.build.device(),
          probes.build.board(),
          probes.build.manufacturer()
        )
        .joinToString(" ")
        .lowercase()

    if (hardware == null && haystack.isEmpty()) {
      return indeterminate(id, Confidence.MEDIUM, "build identity was unavailable")
    }

    val hardwareMatch = hardware != null && EmulatorSignatures.HARDWARE_MARKERS.any { hardware.contains(it) }
    val buildMatches = EmulatorSignatures.BUILD_MARKERS.filter { haystack.contains(it) }
    val detected = hardwareMatch || buildMatches.isNotEmpty()

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(detected),
      confidence = Confidence.MEDIUM,
      description =
        if (detected) {
          "Build identity matches a known emulator or virtualised image"
        } else {
          "Build identity matches retail hardware"
        },
      metadata =
        mapOf(
          "hardware" to hardware,
          "hardwareMatch" to hardwareMatch,
          "buildMarkers" to buildMatches
        )
    )
  }
}

/** Device nodes, emulator-only files and QEMU properties. */
internal class QemuArtifactDetector : Detector {
  override val id = "RNSEC-ANDROID-EMULATOR-002"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val foundFiles = mutableListOf<String>()
    var undeterminable = 0

    for (path in EmulatorSignatures.QEMU_FILES) {
      when (probes.files.exists(path)) {
        true -> foundFiles.add(path)
        false -> Unit
        null -> undeterminable++
      }
    }

    val foundProperties =
      if (probes.properties.isAvailable()) {
        EmulatorSignatures.QEMU_PROPERTIES.filter { key ->
          val value = probes.properties.get(key)
          // `ro.boot.hardware.platform` exists on retail devices too; only a
          // value that names an emulator platform counts.
          if (key == "ro.boot.hardware.platform") {
            value != null && EmulatorSignatures.HARDWARE_MARKERS.any { value.lowercase().contains(it) }
          } else {
            value != null
          }
        }
      } else {
        undeterminable++
        emptyList()
      }

    if (foundFiles.isEmpty() && foundProperties.isEmpty() && undeterminable > 0) {
      return indeterminate(id, Confidence.MEDIUM, "filesystem or property probes were incomplete")
    }

    val detected = foundFiles.isNotEmpty() || foundProperties.isNotEmpty()

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(detected),
      confidence = Confidence.MEDIUM,
      description =
        if (detected) {
          "Emulator-only device nodes or properties are present"
        } else {
          "No emulator-only device nodes or properties found"
        },
      metadata = mapOf("files" to foundFiles, "properties" to foundProperties)
    )
  }
}

/**
 * A hardware profile that does not look like a phone.
 *
 * The weakest of the three by a wide margin, and the one most likely to be
 * wrong: Wi-Fi-only tablets have no telephony, and low-end devices carry few
 * sensors. Kept at low confidence so it can only ever corroborate.
 */
internal class HardwareProfileDetector : Detector {
  override val id = "RNSEC-ANDROID-EMULATOR-003"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val hasTelephony = probes.device.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)
    val phoneType = probes.device.phoneType()
    val sensorCount = probes.device.sensorCount()

    if (hasTelephony == null && phoneType == null && sensorCount == null) {
      return indeterminate(id, Confidence.LOW, "device capabilities were unavailable")
    }

    val anomalies = mutableListOf<String>()

    // Only meaningful when the device claims telephony but reports none.
    if (hasTelephony == true && phoneType == TelephonyManager.PHONE_TYPE_NONE) {
      anomalies.add("telephony-claimed-but-absent")
    }
    if (sensorCount != null && sensorCount < EmulatorSignatures.MINIMUM_PLAUSIBLE_SENSOR_COUNT) {
      anomalies.add("implausibly-few-sensors")
    }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(anomalies.isNotEmpty()),
      confidence = Confidence.LOW,
      description =
        if (anomalies.isNotEmpty()) {
          "Hardware profile is inconsistent with a physical handset"
        } else {
          "Hardware profile is consistent with a physical device"
        },
      metadata =
        mapOf("anomalies" to anomalies, "sensorCount" to sensorCount, "phoneType" to phoneType)
    )
  }
}

/** The emulator check. */
internal class EmulatorCheckEngine : CheckEngine {
  override val checkId = "emulator"

  override fun detectors(options: CheckOptions): List<Detector> =
    listOf(BuildIdentityDetector(), QemuArtifactDetector(), HardwareProfileDetector())

  override fun metadata(probes: ProbeSet, options: CheckOptions): Map<String, Any?> =
    mapOf("signatureVersion" to EmulatorSignatures.VERSION)
}
