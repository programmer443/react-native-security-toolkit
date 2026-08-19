package com.rnsecurity.detectors.screen

import com.rnsecurity.FakeScreenProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.engine.SignalOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScreenDetectorsTest {

  /** Protection applied is the healthy state, so the signal must not fire. */
  @Test
  fun `stays quiet when protection is applied`() {
    assertEquals(SignalOutcome.NOT_DETECTED, SecureFlagDetector().detect(cleanDeviceProbes()).outcome)
  }

  @Test
  fun `fires when protection is absent`() {
    val signal =
      SecureFlagDetector().detect(cleanDeviceProbes(screen = FakeScreenProbe(secureFlagSet = false)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(false, signal.metadata["flagSecureSet"])
  }

  /**
   * With no window there is nothing to inspect — during a cold start, or in the
   * background. That is inconclusive, not unprotected.
   */
  @Test
  fun `reports indeterminate when there is no window to inspect`() {
    val signal =
      SecureFlagDetector().detect(cleanDeviceProbes(screen = FakeScreenProbe(secureFlagSet = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
    assertTrue(signal.description.contains("no active window"))
  }
}
