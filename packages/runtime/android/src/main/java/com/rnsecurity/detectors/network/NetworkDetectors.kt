package com.rnsecurity.detectors.network

import com.rnsecurity.engine.CheckEngine
import com.rnsecurity.engine.CheckOptions
import com.rnsecurity.engine.Confidence
import com.rnsecurity.engine.Detector
import com.rnsecurity.engine.SecuritySignal
import com.rnsecurity.engine.SignalOutcome
import com.rnsecurity.probe.ProbeSet

/**
 * Network posture signals for Android.
 *
 * A mobile application **cannot reliably detect an interception attack**, and
 * nothing here should be read as if it could. A competent attacker on the
 * network path leaves no trace an app can see from inside the process. What
 * these signals report is the application's own configuration and the device's
 * network posture — both useful inputs to a risk decision, neither evidence of
 * an attack.
 *
 * Two of the four are explicitly informational: proxies and VPNs are used by
 * enormous numbers of ordinary people for entirely ordinary reasons, and an
 * application that blocks on them will block a lot of legitimate users.
 *
 * See `docs/runtime/network-security.md`.
 */

private fun indeterminate(id: String, confidence: Confidence, why: String) =
  SecuritySignal(
    id = id,
    outcome = SignalOutcome.INDETERMINATE,
    confidence = confidence,
    description = "Network indicator could not be evaluated: $why"
  )

private fun outcomeOf(weaknessPresent: Boolean) =
  if (weaknessPresent) SignalOutcome.DETECTED else SignalOutcome.NOT_DETECTED

/**
 * This application is permitted to send cleartext HTTP.
 *
 * A configuration fact about the app itself, decided at build time by the
 * manifest and the Network Security Config — which makes it one of the few
 * signals here that is entirely actionable.
 */
internal class CleartextTrafficDetector : Detector {
  override val id = "RNSEC-ANDROID-NETWORK-001"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val permitted =
      probes.network.isCleartextTrafficPermitted()
        ?: return indeterminate(id, Confidence.HIGH, "the network security policy was unreadable")

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(permitted),
      confidence = Confidence.HIGH,
      description =
        if (permitted) {
          "This application is permitted to send cleartext HTTP traffic"
        } else {
          "This application is not permitted to send cleartext HTTP traffic"
        },
      metadata = mapOf("cleartextPermitted" to permitted)
    )
  }
}

/**
 * A system HTTP proxy is configured.
 *
 * Informational. Corporate networks, debugging tools and ad blockers all set
 * proxies, and so does an attacker — the signal cannot tell them apart, and
 * pretending otherwise would be the overclaim this check exists to avoid.
 */
internal class ProxyConfigurationDetector : Detector {
  override val id = "RNSEC-ANDROID-NETWORK-002"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val host = probes.network.httpProxyHost()
    val configured = host != null

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(configured),
      confidence = Confidence.LOW,
      description =
        if (configured) {
          "An HTTP proxy is configured for this device"
        } else {
          "No HTTP proxy is configured for this device"
        },
      // The host itself is deliberately not reported: it can identify a
      // corporate network or a home setup, and this package collects nothing
      // it does not need.
      metadata = mapOf("proxyConfigured" to configured)
    )
  }
}

/**
 * A VPN transport is active.
 *
 * Informational, and the single highest false-positive signal in the toolkit:
 * VPNs are entirely mainstream. Requires `ACCESS_NETWORK_STATE`, which this
 * package does not declare on the application's behalf.
 */
internal class VpnTransportDetector : Detector {
  override val id = "RNSEC-ANDROID-NETWORK-003"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val active =
      probes.network.isVpnActive()
        ?: return indeterminate(
          id,
          Confidence.LOW,
          "the network state is unreadable, most often because the application has not declared " +
            "ACCESS_NETWORK_STATE"
        )

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(active),
      confidence = Confidence.LOW,
      description =
        if (active) {
          "A VPN transport is active on this device"
        } else {
          "No VPN transport is active on this device"
        },
      metadata = mapOf("vpnActive" to active)
    )
  }
}

/**
 * User-added certificate authorities are present in the system trust store.
 *
 * Worth stating plainly: since Android 7, applications do **not** trust
 * user-added CAs by default, so their presence does not mean this app's traffic
 * is interceptable. It is a signal about the device's posture — someone has
 * installed a CA — not about this application's exposure.
 */
internal class UserCertificateAuthorityDetector : Detector {
  override val id = "RNSEC-ANDROID-NETWORK-004"

  override fun detect(probes: ProbeSet): SecuritySignal {
    val count =
      probes.network.userAddedCaCount()
        ?: return indeterminate(id, Confidence.MEDIUM, "the system trust store was unreadable")

    return SecuritySignal(
      id = id,
      outcome = outcomeOf(count > 0),
      confidence = Confidence.MEDIUM,
      description =
        if (count > 0) {
          "User-added certificate authorities are installed on this device"
        } else {
          "No user-added certificate authorities are installed on this device"
        },
      metadata = mapOf("userAddedCaCount" to count)
    )
  }
}

/** The network check. */
internal class NetworkCheckEngine : CheckEngine {
  override val checkId = "network"

  override fun detectors(options: CheckOptions): List<Detector> =
    listOf(
      CleartextTrafficDetector(),
      ProxyConfigurationDetector(),
      VpnTransportDetector(),
      UserCertificateAuthorityDetector()
    )

  override fun metadata(probes: ProbeSet, options: CheckOptions): Map<String, Any?> =
    mapOf(
      "note" to
        "Reports configuration and device posture. An application cannot reliably detect " +
          "network interception from inside its own process."
    )
}
