package com.rnsecurity.detectors.hook

import com.rnsecurity.engine.CheckEngine
import com.rnsecurity.engine.CheckOptions
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.Detector
import com.rnsecurity.engine.SecuritySignal
import com.rnsecurity.engine.SignalOutcome
import com.rnsecurity.probe.ProbeSet

/**
 * Hook and instrumentation detection for Android.
 *
 * Detection here is genuinely adversarial in a way root detection is not: an
 * attacker running a hooking framework is, by definition, able to modify the
 * code doing the detecting. Nothing in this file is guaranteed, and the check
 * must never be described as if it were.
 *
 * What these signals do offer is cost. Each one is independent, two of the three
 * read state that is awkward to forge from managed code, and together they raise
 * the effort required from "attach and go" to "attach, then hide". That is the
 * honest claim.
 *
 * Every signal inspects **this process only**. No other process is examined, and
 * no network probing is performed — scanning for a listening instrumentation
 * port would mean a security library opening sockets, which is a worse trade
 * than the signal is worth.
 *
 * See `docs/runtime/hook-detection.md`.
 */

private fun indeterminate(id: String, confidence: Confidence, why: String) =
  SecuritySignal(
    id = id,
    outcome = SignalOutcome.INDETERMINATE,
    confidence = confidence,
    description = "Instrumentation indicator could not be evaluated: $why"
  )

private fun outcomeOf(detected: Boolean) =
  if (detected) SignalOutcome.DETECTED else SignalOutcome.NOT_DETECTED

/**
 * Dynamic instrumentation artefacts in this process's memory map and threads.
 *
 * Covers the family of tools that inject an agent into a running process. Two
 * independent sources are read, because a framework that hides one often does
 * not bother with the other.
 */
internal class DynamicInstrumentationDetector : Detector {
  override val id = "RNSEC-RUNTIME-HOOK-001"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val maps = probes.proc.selfMaps()
    val threads = probes.proc.threadNames()

    if (maps == null && threads == null) {
      return indeterminate(id, Confidence.MEDIUM, "process memory map and thread list were unreadable")
    }

    val mapMatches =
      maps
        ?.count { line ->
          val lower = line.lowercase()
          HookSignatures.INSTRUMENTATION_MAP_MARKERS.any { lower.contains(it) }
        }
        ?: 0

    val threadMatches =
      threads
        ?.filter { name ->
          val lower = name.lowercase()
          HookSignatures.INSTRUMENTATION_THREAD_NAMES.any { lower == it }
        }
        ?: emptyList()

    val detected = mapMatches > 0 || threadMatches.isNotEmpty()

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(detected),
      confidence = Confidence.MEDIUM,
      description =
        if (detected) {
          "Potential dynamic instrumentation indicator detected in this process"
        } else {
          "No dynamic instrumentation indicator detected in this process"
        },
      metadata =
        mapOf(
          "mappedRegionMatches" to mapMatches,
          "threadNameMatches" to threadMatches,
          "mapsReadable" to (maps != null),
          "threadsReadable" to (threads != null)
        )
    )
  }
}

/**
 * Managed-code hooking frameworks.
 *
 * Three independent sources: whether the framework's classes are loadable,
 * whether its frames appear on this call stack, and whether its libraries are
 * mapped into the process. Class presence alone is the weakest of the three,
 * because a class can be present without being active.
 */
internal class ManagedHookFrameworkDetector : Detector {
  override val id = "RNSEC-RUNTIME-HOOK-002"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val evidence = mutableListOf<String>()
    var undeterminable = 0

    for (className in HookSignatures.HOOK_FRAMEWORK_CLASSES) {
      when (probes.runtime.isClassPresent(className)) {
        true -> evidence.add("class")
        false -> Unit
        null -> undeterminable++
      }
    }

    val stack = probes.runtime.currentStackClassNames()
    if (stack == null) {
      undeterminable++
    } else if (
      stack.any { frame -> HookSignatures.HOOK_FRAMEWORK_STACK_PREFIXES.any { frame.startsWith(it) } }
    ) {
      evidence.add("stack-frame")
    }

    val maps = probes.proc.selfMaps()
    if (maps == null) {
      undeterminable++
    } else if (
      maps.any { line ->
        val lower = line.lowercase()
        HookSignatures.HOOK_FRAMEWORK_MAP_MARKERS.any { lower.contains(it) }
      }
    ) {
      evidence.add("mapped-library")
    }

    if (evidence.isEmpty() && undeterminable > 0) {
      return indeterminate(id, Confidence.MEDIUM, "runtime and memory-map probes were incomplete")
    }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(evidence.isNotEmpty()),
      confidence = Confidence.MEDIUM,
      description =
        if (evidence.isNotEmpty()) {
          "Potential managed-code hooking framework indicator detected"
        } else {
          "No managed-code hooking framework indicator detected"
        },
      metadata = mapOf("evidenceKinds" to evidence.distinct())
    )
  }
}

/**
 * Native symbols resolving outside the library that should provide them.
 *
 * Asks a different question from the other two: not "is a known tool present"
 * but "is the runtime still shaped the way it should be". A redirected `open` or
 * `connect` is an indicator that survives renaming the injected library, which
 * the name-matching signals do not.
 *
 * Only the library *filename* is compared. Android moves bionic between
 * `/system/lib64` and `/apex/...` across versions, so comparing full paths would
 * report every modern device as hooked.
 */
internal class SymbolOriginDetector : Detector {
  override val id = "RNSEC-RUNTIME-HOOK-003"

  override fun detect(probes: ProbeSet): SecuritySignal {
    if (!probes.symbols.isAvailable()) {
      return indeterminate(id, Confidence.MEDIUM, "the native symbol probe is unavailable")
    }

    val unexpected = mutableMapOf<String, String>()
    var unresolved = 0

    for ((symbol, expectedLibrary) in HookSignatures.EXPECTED_SYMBOL_LIBRARIES) {
      val origin = probes.symbols.originOf(symbol)
      if (origin == null) {
        unresolved++
        continue
      }
      val originLibrary = origin.substringAfterLast('/')
      if (originLibrary != expectedLibrary) {
        unexpected[symbol] = originLibrary
      }
    }

    if (unexpected.isEmpty() && unresolved == HookSignatures.EXPECTED_SYMBOL_LIBRARIES.size) {
      return indeterminate(id, Confidence.MEDIUM, "no symbols could be resolved")
    }

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(unexpected.isNotEmpty()),
      confidence = Confidence.MEDIUM,
      description =
        if (unexpected.isNotEmpty()) {
          "A standard library symbol resolves inside an unexpected library"
        } else {
          "Standard library symbols resolve inside their expected libraries"
        },
      metadata = mapOf("unexpectedOrigins" to unexpected, "unresolvedSymbols" to unresolved)
    )
  }
}

/** The hook check. */
internal class HookCheckEngine : CheckEngine {
  override val checkId = "hooks"

  override fun detectors(options: CheckOptions): List<Detector> =
    listOf(DynamicInstrumentationDetector(), ManagedHookFrameworkDetector(), SymbolOriginDetector())

  override fun metadata(probes: ProbeSet, options: CheckOptions): Map<String, Any?> =
    mapOf(
      "signatureVersion" to HookSignatures.VERSION,
      "nativeSymbolProbeAvailable" to probes.symbols.isAvailable()
    )
}
