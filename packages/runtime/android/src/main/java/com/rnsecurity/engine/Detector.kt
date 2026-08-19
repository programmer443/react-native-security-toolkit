package com.rnsecurity.engine

import com.rnsecurity.probe.ProbeSet

/**
 * One detection technique.
 *
 * A detector produces signals; it does not decide anything. Verdicts are the
 * aggregator's job, risk scoring is TypeScript's, and what to do about it is the
 * application's. Keeping those separate is what stops a detector author from
 * quietly encoding a policy.
 */
interface Detector {
  /** Stable identifier, e.g. `RNSEC-ANDROID-ROOT-001`. */
  val id: String

  /** Minimum SDK level this technique applies to. */
  val minSdk: Int get() = 1

  /**
   * Runs the technique.
   *
   * Implementations must not throw: a probe returning `null` becomes an
   * `INDETERMINATE` signal. The registry catches anything that escapes anyway,
   * but relying on that is not a design.
   */
  fun detect(probes: ProbeSet): SecuritySignal
}

/** A group of detectors answering one check, e.g. `root`. */
interface CheckEngine {
  /** Check identifier as exposed to JavaScript, e.g. `root`. */
  val checkId: String

  /**
   * Detectors for this run.
   *
   * A function rather than a list because some checks are configuration-shaped:
   * integrity cannot compare a signing certificate until the application says
   * which one it expects. Checks that ignore configuration simply return a
   * constant.
   */
  fun detectors(options: CheckOptions): List<Detector>

  /**
   * Optional check-level metadata, e.g. whether package visibility is configured.
   * Included in the result so a developer can see why a signal was inconclusive.
   */
  fun metadata(probes: ProbeSet, options: CheckOptions): Map<String, Any?> = emptyMap()
}
