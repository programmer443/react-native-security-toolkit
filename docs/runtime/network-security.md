# Network security (Android)

`NetworkSecurity.getStatus()` · check id `network`

> **A mobile application cannot reliably detect an interception attack.** A competent attacker on
> the network path leaves no trace visible from inside the process. This check reports the
> application's own configuration and the device's network posture — useful inputs to a risk
> decision, not evidence of an attack. Nothing here should be described as MITM detection.

## 1. What it detects

- whether **this application may send cleartext HTTP**;
- whether an **HTTP proxy** is configured;
- whether a **VPN transport** is active;
- whether **user-added certificate authorities** are installed on the device.

## 2. Signals

| ID                          | Indicator                             | Confidence | Notes                                                         |
| --------------------------- | ------------------------------------- | ---------- | ------------------------------------------------------------- |
| `RNSEC-ANDROID-NETWORK-001` | Cleartext HTTP permitted for this app | **high**   | Configuration, entirely under your control                    |
| `RNSEC-ANDROID-NETWORK-002` | HTTP proxy configured                 | low        | Informational                                                 |
| `RNSEC-ANDROID-NETWORK-003` | VPN transport active                  | low        | Informational; needs `ACCESS_NETWORK_STATE`                   |
| `RNSEC-ANDROID-NETWORK-004` | User-added CAs present                | medium     | See §4 — this does **not** mean your traffic is interceptable |

Only `NETWORK-001` is actionable in the ordinary sense. It reflects your manifest and Network
Security Config, it is decided at build time, and if it fires you can simply fix it.

## 3. Proxy and VPN are informational, deliberately

Proxies and VPNs are entirely mainstream. Corporate networks route through proxies, ad blockers and
privacy tools run local VPNs, and a large number of ordinary people use a commercial VPN all day.
An attacker's interception proxy looks exactly the same from inside the app.

Since the signal cannot distinguish them, it does not pretend to. Both are `low` confidence and
described as posture, not as findings. **An application that blocks users with a VPN active will
block a great many legitimate users and stop approximately no attackers**, who can trivially avoid
setting a system proxy at all.

The proxy **host is deliberately not reported**. It can identify a corporate network or a home
setup, and this package collects nothing it does not need. A test asserts it does not leak.

## 4. User-added CAs do not mean you are exposed

Since Android 7, applications do **not** trust user-added certificate authorities by default. Unless
your app opts in through a Network Security Config, a user-installed CA cannot intercept your TLS
traffic.

So `NETWORK-004` is a signal about the _device_ — someone installed a CA, which may be a corporate
MDM, a debugging proxy, or an interception attempt — and not about this application's exposure.
Treat it as context for a risk score, not as a breach.

## 5. The `ACCESS_NETWORK_STATE` permission

`NETWORK-003` needs `android.permission.ACCESS_NETWORK_STATE`. **This package does not declare it** —
a permission in a library manifest merges into every consuming application, which is the application
author's decision. The same reasoning applies to `<queries>` in [root detection](root-detection.md)
and `USE_BIOMETRIC` in [biometrics](biometrics.md).

Without it the signal reports `indeterminate` and says so explicitly. To enable it:

```xml
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

## 6. Confidence

| Result              | Meaning                                                        |
| ------------------- | -------------------------------------------------------------- |
| `secure` + `high`   | Cleartext blocked, no proxy or VPN, clean trust store.         |
| `detected` + `high` | Cleartext is permitted. Worth fixing.                          |
| `detected` + `low`  | Only proxy or VPN posture. Context, not a finding.             |
| `unknown` + `low`   | A probe was blocked — most often the missing permission above. |

## 7. False positives

- **Proxy and VPN**: see §3. This is the highest false-positive area in the toolkit.
- **User-added CAs** are routine on managed corporate devices.
- **Emulators** commonly have a proxy configured for host networking.

## 8. False negatives

- An interception attack that does not require a device-side proxy, VPN or CA — the common case for
  a network-position attacker — produces no signal at all here.
- `NETWORK-001` describes policy, not behaviour. An app permitted to send cleartext may never do so;
  an app forbidden from it may still leak through a WebView or a native library.

## 9. Known limitations

- No certificate pinning is performed or verified by this check. Pinning is an integration concern
  for your HTTP client, and a pinning API is a separate piece of work.
- No network requests are made by this check. It reads local configuration only.

## 10. Recommended application response

```ts
const network = await NetworkSecurity.getStatus();

const cleartextPermitted = network.signals.some(
  (signal) => signal.id === 'RNSEC-ANDROID-NETWORK-001' && signal.detected
);

if (cleartextPermitted) {
  // Actionable: tighten your Network Security Config.
}
```

Inspect individual signals rather than the check status. A `detected` result driven only by "user
has a VPN" is not something to act on, and reading it as one is the most likely way to misuse this
check.

## 11. Tests

`android/src/test/java/com/rnsecurity/detectors/network/NetworkDetectorsTest.kt` — 13 cases covering
each signal firing and staying quiet, blocked probes, the permission-explaining message, and an
assertion that the proxy host never appears in signal metadata.
