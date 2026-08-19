package com.rnsecurity.detectors.network

import com.rnsecurity.FakeNetworkProbe
import com.rnsecurity.cleanDeviceProbes
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.SignalOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class NetworkDetectorsTest {

  // ── cleartext ──────────────────────────────────────────────────────────────

  @Test
  fun `cleartext detector fires when cleartext is permitted`() {
    val signal =
      CleartextTrafficDetector()
        .detect(cleanDeviceProbes(network = FakeNetworkProbe(cleartextPermitted = true)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(Confidence.HIGH, signal.confidence)
  }

  @Test
  fun `cleartext detector stays quiet when cleartext is blocked`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      CleartextTrafficDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `cleartext detector reports indeterminate when the policy is unreadable`() {
    val signal =
      CleartextTrafficDetector()
        .detect(cleanDeviceProbes(network = FakeNetworkProbe(cleartextPermitted = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }

  // ── proxy ──────────────────────────────────────────────────────────────────

  @Test
  fun `proxy detector fires when a proxy is configured`() {
    val signal =
      ProxyConfigurationDetector()
        .detect(cleanDeviceProbes(network = FakeNetworkProbe(proxyHost = "10.0.2.2")))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    // Corporate networks and ad blockers set proxies too. Informational only.
    assertEquals(Confidence.LOW, signal.confidence)
  }

  /** The proxy host can identify a corporate or home network; it is not collected. */
  @Test
  fun `proxy detector does not report the proxy host`() {
    val signal =
      ProxyConfigurationDetector()
        .detect(cleanDeviceProbes(network = FakeNetworkProbe(proxyHost = "proxy.internal.example")))

    assertFalse(signal.metadata.values.any { it.toString().contains("internal.example") })
  }

  @Test
  fun `proxy detector stays quiet with no proxy`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      ProxyConfigurationDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  // ── VPN ────────────────────────────────────────────────────────────────────

  @Test
  fun `vpn detector fires when a VPN transport is active`() {
    val signal =
      VpnTransportDetector().detect(cleanDeviceProbes(network = FakeNetworkProbe(vpnActive = true)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(Confidence.LOW, signal.confidence)
  }

  @Test
  fun `vpn detector stays quiet with no VPN`() {
    assertEquals(SignalOutcome.NOT_DETECTED, VpnTransportDetector().detect(cleanDeviceProbes()).outcome)
  }

  /** The most common cause is a missing permission, so the signal has to say so. */
  @Test
  fun `vpn detector explains that the permission may be missing`() {
    val signal =
      VpnTransportDetector().detect(cleanDeviceProbes(network = FakeNetworkProbe(vpnActive = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
    assertEquals(true, signal.description.contains("ACCESS_NETWORK_STATE"))
  }

  // ── user CAs ───────────────────────────────────────────────────────────────

  @Test
  fun `user CA detector fires when user certificates are installed`() {
    val signal =
      UserCertificateAuthorityDetector()
        .detect(cleanDeviceProbes(network = FakeNetworkProbe(userCaCount = 2)))

    assertEquals(SignalOutcome.DETECTED, signal.outcome)
    assertEquals(2, signal.metadata["userAddedCaCount"])
  }

  @Test
  fun `user CA detector stays quiet with a clean trust store`() {
    assertEquals(
      SignalOutcome.NOT_DETECTED,
      UserCertificateAuthorityDetector().detect(cleanDeviceProbes()).outcome
    )
  }

  @Test
  fun `user CA detector reports indeterminate when the trust store is unreadable`() {
    val signal =
      UserCertificateAuthorityDetector()
        .detect(cleanDeviceProbes(network = FakeNetworkProbe(userCaCount = null)))

    assertEquals(SignalOutcome.INDETERMINATE, signal.outcome)
  }
}
