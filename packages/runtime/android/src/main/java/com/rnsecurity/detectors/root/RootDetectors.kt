package com.rnsecurity.detectors.root

import com.rnsecurity.engine.CheckEngine
import com.rnsecurity.engine.CheckOptions
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.Detector
import com.rnsecurity.engine.SecuritySignal
import com.rnsecurity.engine.SignalOutcome
import com.rnsecurity.probe.ProbeSet

/**
 * Root detection signals for Android.
 *
 * None of these is proof. Each is an indicator that a device has been modified
 * in a way commonly associated with root, and each has a documented way of being
 * defeated. They are combined by [com.rnsecurity.engine.SignalAggregator], which
 * raises confidence only when independent signals corroborate one another.
 *
 * Signature lists live in [RootSignatures] rather than inline, so they can be
 * versioned and updated without touching detection logic.
 *
 * See `docs/runtime/root-detection.md`.
 */

/** Helper for the common "a probe returned null" case. */
private fun indeterminate(id: String, confidence: Confidence, why: String) =
  SecuritySignal(
    id = id,
    outcome = SignalOutcome.INDETERMINATE,
    confidence = confidence,
    description = "Root indicator could not be evaluated: $why"
  )

private fun outcomeOf(detected: Boolean) =
  if (detected) SignalOutcome.DETECTED else SignalOutcome.NOT_DETECTED

/**
 * `su` binaries in locations where a stock device has none.
 *
 * Executability is checked as well as existence: a zero-length placeholder at a
 * known path is a weaker indicator than a runnable binary.
 */
internal class SuBinaryDetector : Detector {
  override val id = "RNSEC-ANDROID-ROOT-001"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val found = mutableListOf<String>()
    var undeterminable = 0

    for (path in RootSignatures.SU_BINARY_PATHS) {
      when (probes.files.isExecutable(path)) {
        true -> found.add(path)
        false -> Unit
        null -> undeterminable++
      }
    }

    if (found.isEmpty() && undeterminable > 0) {
      return indeterminate(id, Confidence.MEDIUM, "filesystem paths were not readable")
    }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(found.isNotEmpty()),
      confidence = Confidence.MEDIUM,
      description =
        if (found.isNotEmpty()) {
          "Executable su binary found in a location not present on an unmodified device"
        } else {
          "No su binary found in known locations"
        },
      metadata = mapOf("matchCount" to found.size, "paths" to found)
    )
  }
}

/**
 * Installed root-manager applications.
 *
 * Requires package visibility. Android 11 hid the installed-package list from
 * apps that do not declare `<queries>`, and without that declaration this check
 * would report "not installed" for every package — a false negative that looks
 * exactly like a clean result. So an unconfigured app gets `indeterminate`.
 */
internal class RootManagerPackageDetector : Detector {
  override val id = "RNSEC-ANDROID-ROOT-002"

  override fun detect(probes: ProbeSet): SecuritySignal {
    if (!probes.packages.canQueryPackages()) {
      return indeterminate(
        id,
        Confidence.MEDIUM,
        "package visibility is not configured (see docs/runtime/root-detection.md)"
      )
    }

    val found = mutableListOf<String>()
    var undeterminable = 0

    for (packageName in RootSignatures.ROOT_MANAGER_PACKAGES) {
      when (probes.packages.isInstalled(packageName)) {
        true -> found.add(packageName)
        false -> Unit
        null -> undeterminable++
      }
    }

    if (found.isEmpty() && undeterminable > 0) {
      return indeterminate(id, Confidence.MEDIUM, "package queries failed")
    }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(found.isNotEmpty()),
      confidence = Confidence.MEDIUM,
      description =
        if (found.isNotEmpty()) {
          "A known root management application is installed"
        } else {
          "No known root management application detected"
        },
      metadata = mapOf("packages" to found)
    )
  }
}

/**
 * Build-time debug properties that a production device does not carry.
 *
 * Read through the NDK. `System.getProperty` reads JVM properties and would
 * always return null here, and reflecting into `android.os.SystemProperties` is
 * a restricted non-SDK interface.
 */
internal class DangerousSystemPropertyDetector : Detector {
  override val id = "RNSEC-ANDROID-ROOT-003"

  override fun detect(probes: ProbeSet): SecuritySignal {
    if (!probes.properties.isAvailable()) {
      return indeterminate(id, Confidence.MEDIUM, "the native property probe is unavailable")
    }

    val matches =
      RootSignatures.DANGEROUS_PROPERTIES.filter { (key, dangerousValue) ->
        probes.properties.get(key) == dangerousValue
      }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(matches.isNotEmpty()),
      confidence = Confidence.MEDIUM,
      description =
        if (matches.isNotEmpty()) {
          "System properties indicate a debuggable or non-secure build"
        } else {
          "System properties match a production build"
        },
      metadata = mapOf("properties" to matches.keys.toList())
    )
  }
}

/**
 * A build signed with something other than a vendor release key.
 *
 * Covers both `test-keys` and `dev-keys`: emulator and engineering images are
 * commonly signed `dev-keys`, and matching only `test-keys` would report those
 * as release-signed — a wrong statement, not merely a missed detection.
 *
 * Low confidence on its own: this is also true of legitimate custom ROMs and of
 * engineering builds, neither of which implies the device is rooted.
 */
internal class TestKeysDetector : Detector {
  override val id = "RNSEC-ANDROID-ROOT-004"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val tags =
      probes.build.tags()
        ?: return indeterminate(id, Confidence.LOW, "build tags were unavailable")

    val matched = NON_RELEASE_TAGS.filter { tags.contains(it, ignoreCase = true) }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(matched.isNotEmpty()),
      confidence = Confidence.LOW,
      description =
        if (matched.isNotEmpty()) {
          "Build is signed with ${matched.joinToString(" and ")} rather than a vendor release key"
        } else {
          // Deliberately not "signed with release keys": absence of a known
          // non-release tag is not proof of a release signature.
          "Build tags do not indicate test or development signing"
        },
      metadata = mapOf("tags" to tags, "matchedTags" to matched)
    )
  }

  private companion object {
    val NON_RELEASE_TAGS = listOf("test-keys", "dev-keys")
  }
}

/**
 * Verified Boot state and bootloader lock state.
 *
 * The strongest signal available without hardware attestation. An unlocked
 * bootloader does not by itself mean the device is rooted — developer devices
 * are routinely unlocked — but it is a precondition for most root methods, and
 * it cannot be hidden by relocating files.
 */
internal class VerifiedBootDetector : Detector {
  override val id = "RNSEC-ANDROID-ROOT-005"

  override fun detect(probes: ProbeSet): SecuritySignal {
    if (!probes.properties.isAvailable()) {
      return indeterminate(id, Confidence.HIGH, "the native property probe is unavailable")
    }

    val bootState = probes.properties.get("ro.boot.verifiedbootstate")
    val flashLocked = probes.properties.get("ro.boot.flash.locked")

    if (bootState == null && flashLocked == null) {
      return indeterminate(id, Confidence.HIGH, "verified boot properties were not exposed")
    }

    // "green" means the bootloader verified a vendor-signed boot chain.
    val bootStateCompromised = bootState != null && !bootState.equals("green", ignoreCase = true)
    val bootloaderUnlocked = flashLocked == "0"
    val detected = bootStateCompromised || bootloaderUnlocked

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(detected),
      confidence = Confidence.HIGH,
      description =
        if (detected) {
          "Verified Boot reports an unlocked bootloader or an unverified boot chain"
        } else {
          "Verified Boot reports a locked bootloader and a verified boot chain"
        },
      metadata = mapOf("verifiedBootState" to bootState, "flashLocked" to flashLocked)
    )
  }
}

/**
 * Mount anomalies over normally read-only partitions.
 *
 * Systemless root implementations commonly overlay system paths rather than
 * modifying them, which leaves traces in the process's own mount table.
 */
internal class MountAnomalyDetector : Detector {
  override val id = "RNSEC-ANDROID-ROOT-007"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val mounts =
      probes.proc.selfMountInfo()
        ?: return indeterminate(id, Confidence.MEDIUM, "/proc/self/mountinfo was not readable")

    val suspicious =
      mounts.filter { line ->
        val overlayOrTmpfs = line.contains(" overlay ") || line.contains(" tmpfs ")
        overlayOrTmpfs && RootSignatures.PROTECTED_MOUNT_POINTS.any { line.contains(" $it ") }
      }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(suspicious.isNotEmpty()),
      confidence = Confidence.MEDIUM,
      description =
        if (suspicious.isNotEmpty()) {
          "A normally read-only partition is overlaid in this process's mount table"
        } else {
          "No mount anomalies over protected partitions"
        },
      metadata = mapOf("matchCount" to suspicious.size)
    )
  }
}

/**
 * Directories that are read-only on an unmodified device but turn out to be writable.
 *
 * Uses a real create-and-delete probe. `File.canWrite()` is unreliable on modern
 * Android in both directions and is not used.
 */
internal class WritableSystemPathDetector : Detector {
  override val id = "RNSEC-ANDROID-ROOT-008"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val writable = mutableListOf<String>()
    var undeterminable = 0

    for (path in RootSignatures.PROTECTED_DIRECTORIES) {
      when (probes.files.canActuallyWrite(path)) {
        true -> writable.add(path)
        false -> Unit
        null -> undeterminable++
      }
    }

    if (writable.isEmpty() && undeterminable > 0) {
      return indeterminate(id, Confidence.HIGH, "write probes could not be attempted")
    }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(writable.isNotEmpty()),
      confidence = Confidence.HIGH,
      description =
        if (writable.isNotEmpty()) {
          "A directory that is read-only on an unmodified device accepted a write"
        } else {
          "Protected directories rejected write attempts"
        },
      metadata = mapOf("paths" to writable)
    )
  }
}

/**
 * SELinux left in permissive mode.
 *
 * Enforcing is commonly preserved even on rooted devices, so a negative result
 * here means very little. A positive one is a strong indicator of a modified system.
 */
internal class SelinuxDetector : Detector {
  override val id = "RNSEC-ANDROID-ROOT-009"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val raw =
      probes.files.readText("/sys/fs/selinux/enforce")
        ?: return indeterminate(id, Confidence.MEDIUM, "the SELinux state was not readable")

    val permissive = raw.trim() == "0"

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(permissive),
      confidence = Confidence.MEDIUM,
      description =
        if (permissive) {
          "SELinux is in permissive mode"
        } else {
          "SELinux is enforcing"
        },
      metadata = mapOf("enforce" to raw.trim())
    )
  }
}

/**
 * Runtime artefacts associated with Magisk.
 *
 * Reported as an indicator, never as proof: these artefacts are relocatable, and
 * their absence says nothing.
 */
internal class MagiskDetector : Detector {
  override val id = "RNSEC-ANDROID-MAGISK-001"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val evidence = mutableListOf<String>()
    var undeterminable = 0

    for (path in RootSignatures.MAGISK_PATHS) {
      when (probes.files.exists(path)) {
        true -> evidence.add("path")
        false -> Unit
        null -> undeterminable++
      }
    }

    val mounts = probes.proc.selfMountInfo()
    if (mounts == null) {
      undeterminable++
    } else if (mounts.any { line -> RootSignatures.MAGISK_MOUNT_MARKERS.any { line.contains(it) } }) {
      evidence.add("mount")
    }

    if (evidence.isEmpty() && undeterminable > 0) {
      return indeterminate(id, Confidence.MEDIUM, "filesystem and mount probes were incomplete")
    }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(evidence.isNotEmpty()),
      confidence = Confidence.MEDIUM,
      description =
        if (evidence.isNotEmpty()) {
          "Potential Magisk-related runtime indicator detected"
        } else {
          "No Magisk-related runtime indicator detected"
        },
      metadata = mapOf("evidenceKinds" to evidence.distinct())
    )
  }
}

/**
 * Indicators of Zygisk-style injection into the app process.
 *
 * Inspects this process's own memory map — no other process is examined.
 */
internal class ZygiskDetector : Detector {
  override val id = "RNSEC-ANDROID-ZYGISK-001"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val maps =
      probes.proc.selfMaps()
        ?: return indeterminate(id, Confidence.MEDIUM, "/proc/self/maps was not readable")

    val matches =
      maps.count { line -> RootSignatures.ZYGISK_MAP_MARKERS.any { line.contains(it) } }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(matches > 0),
      confidence = Confidence.MEDIUM,
      description =
        if (matches > 0) {
          "Potential Zygisk-related injection indicator detected in this process"
        } else {
          "No Zygisk-related injection indicator detected in this process"
        },
      metadata = mapOf("matchCount" to matches)
    )
  }
}

/** The root check: every detector above, aggregated. */
internal class RootCheckEngine : CheckEngine {
  override val checkId = "root"

  override fun detectors(options: CheckOptions): List<Detector> = DETECTORS

  private companion object {
    private val DETECTORS = listOf(
      SuBinaryDetector(),
      RootManagerPackageDetector(),
      DangerousSystemPropertyDetector(),
      TestKeysDetector(),
      VerifiedBootDetector(),
      MountAnomalyDetector(),
      WritableSystemPathDetector(),
      SelinuxDetector(),
      MagiskDetector(),
      ZygiskDetector()
    )
  }

  override fun metadata(probes: ProbeSet, options: CheckOptions): Map<String, Any?> =
    mapOf(
      // Surfaced so a developer can see *why* signals came back inconclusive
      // rather than having to guess.
      "packageVisibilityConfigured" to probes.packages.canQueryPackages(),
      "nativePropertyProbeAvailable" to probes.properties.isAvailable(),
      "signatureVersion" to RootSignatures.VERSION
    )
}
