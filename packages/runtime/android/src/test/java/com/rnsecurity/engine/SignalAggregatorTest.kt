package com.rnsecurity.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class SignalAggregatorTest {

  private fun signal(
    outcome: SignalOutcome,
    confidence: Confidence = Confidence.MEDIUM,
    id: String = "RNSEC-TEST-001"
  ) = SecuritySignal(id, outcome, confidence, "test signal")

  @Test
  fun `all probes ran and nothing fired reports secure`() {
    val result =
      SignalAggregator.aggregate(
        "root",
        listOf(signal(SignalOutcome.NOT_DETECTED), signal(SignalOutcome.NOT_DETECTED))
      )

    assertEquals(CheckStatus.SECURE, result.status)
    assertEquals(Confidence.HIGH, result.confidence)
    assertEquals(false, result.detected)
  }

  @Test
  fun `no signals at all reports secure`() {
    assertEquals(CheckStatus.SECURE, SignalAggregator.aggregate("root", emptyList()).status)
  }

  /**
   * The single most important behaviour in this class. A probe that could not
   * run is not evidence that the device is clean, and reporting it as `secure`
   * would be the exact failure this package exists to avoid.
   */
  @Test
  fun `a blocked probe reports unknown rather than secure`() {
    val result =
      SignalAggregator.aggregate(
        "root",
        listOf(signal(SignalOutcome.NOT_DETECTED), signal(SignalOutcome.INDETERMINATE))
      )

    assertEquals(CheckStatus.UNKNOWN, result.status)
    assertEquals(Confidence.LOW, result.confidence)
    assertEquals(false, result.detected)
  }

  @Test
  fun `a detection outranks a blocked probe`() {
    val result =
      SignalAggregator.aggregate(
        "root",
        listOf(signal(SignalOutcome.INDETERMINATE), signal(SignalOutcome.DETECTED, Confidence.HIGH))
      )

    assertEquals(CheckStatus.DETECTED, result.status)
    assertEquals(Confidence.HIGH, result.confidence)
  }

  @Test
  fun `one high-confidence detection is enough for high confidence`() {
    val result =
      SignalAggregator.aggregate("root", listOf(signal(SignalOutcome.DETECTED, Confidence.HIGH)))

    assertEquals(Confidence.HIGH, result.confidence)
  }

  @Test
  fun `one medium detection stays medium`() {
    val result =
      SignalAggregator.aggregate("root", listOf(signal(SignalOutcome.DETECTED, Confidence.MEDIUM)))

    assertEquals(Confidence.MEDIUM, result.confidence)
  }

  @Test
  fun `two corroborating medium detections reach high`() {
    val result =
      SignalAggregator.aggregate(
        "root",
        listOf(
          signal(SignalOutcome.DETECTED, Confidence.MEDIUM, "a"),
          signal(SignalOutcome.DETECTED, Confidence.MEDIUM, "b")
        )
      )

    assertEquals(Confidence.HIGH, result.confidence)
  }

  /** A lone weak indicator must not become a confident verdict. */
  @Test
  fun `a single low detection stays low`() {
    val result =
      SignalAggregator.aggregate("root", listOf(signal(SignalOutcome.DETECTED, Confidence.LOW)))

    assertEquals(Confidence.LOW, result.confidence)
  }

  @Test
  fun `two low detections are still not enough for medium`() {
    val result =
      SignalAggregator.aggregate(
        "root",
        listOf(
          signal(SignalOutcome.DETECTED, Confidence.LOW, "a"),
          signal(SignalOutcome.DETECTED, Confidence.LOW, "b")
        )
      )

    assertEquals(Confidence.LOW, result.confidence)
  }

  @Test
  fun `three low detections corroborate to medium`() {
    val result =
      SignalAggregator.aggregate(
        "root",
        listOf(
          signal(SignalOutcome.DETECTED, Confidence.LOW, "a"),
          signal(SignalOutcome.DETECTED, Confidence.LOW, "b"),
          signal(SignalOutcome.DETECTED, Confidence.LOW, "c")
        )
      )

    assertEquals(Confidence.MEDIUM, result.confidence)
  }

  @Test
  fun `unavailable carries its reason and no signals`() {
    val result = SignalAggregator.unavailable("root", UnavailableReason.NOT_CONFIGURED)

    assertEquals(CheckStatus.UNAVAILABLE, result.status)
    assertEquals(UnavailableReason.NOT_CONFIGURED, result.unavailableReason)
    assertEquals(false, result.detected)
    assertEquals(0, result.signals.size)
  }

  @Test
  fun `error carries its message and is not a detection`() {
    val result = SignalAggregator.error("root", "boom")

    assertEquals(CheckStatus.ERROR, result.status)
    assertEquals("boom", result.errorMessage)
    assertEquals(false, result.detected)
  }

  @Test
  fun `wire values match the TypeScript union members`() {
    assertEquals("not-detected", SignalOutcome.NOT_DETECTED.wireValue())
    assertEquals("indeterminate", SignalOutcome.INDETERMINATE.wireValue())
    assertEquals("detected", CheckStatus.DETECTED.wireValue())
    assertEquals("high", Confidence.HIGH.wireValue())
    assertEquals("platform-not-supported", UnavailableReason.PLATFORM_NOT_SUPPORTED.wireValue())
    assertEquals("api-level-too-low", UnavailableReason.API_LEVEL_TOO_LOW.wireValue())
  }
}
