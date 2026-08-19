# Network security (iOS)

`NetworkSecurity.getStatus()` · check id `network`

> **A mobile application cannot reliably detect an interception attack.** These signals describe the
> application's own configuration and the device's network posture — inputs to a risk decision, not
> evidence of an attack.
>
> See [network-security.md](network-security.md) for the Android signals under the same check id.

## 1. What it detects

- whether **App Transport Security permits arbitrary loads** for this application;
- whether an **HTTP proxy** is configured;
- whether a **VPN-style network interface** is present.

## 2. Signals

| ID                      | Indicator                   | Confidence |
| ----------------------- | --------------------------- | ---------- |
| `RNSEC-IOS-NETWORK-001` | ATS permits arbitrary loads | **high**   |
| `RNSEC-IOS-NETWORK-002` | HTTP proxy configured       | low        |
| `RNSEC-IOS-NETWORK-003` | VPN-style interface present | low        |

Only `NETWORK-001` is actionable in the ordinary sense: it is a build-time fact decided by your
`Info.plist`, and if it fires you can simply fix it. An absent `NSAppTransportSecurity` dictionary is
reported as **not permitted** — the secure defaults apply — rather than as unknown.

## 3. `utun` is not a VPN

`NETWORK-003` is the highest false-positive signal in the toolkit, and low confidence for it.

On iOS the `utun` interface family is used by a great deal that is not a VPN: Personal Hotspot,
AirPlay, content filters, and iCloud Private Relay among them. Add to that the fact that commercial
VPNs are entirely mainstream, and this signal cannot distinguish an attacker's interception setup
from a user's ordinary Tuesday.

The same applies to `NETWORK-002`: corporate networks, debugging tools and content blockers all set
proxies. **The proxy host is deliberately not reported** — it can identify a corporate or home
network, and this package collects nothing it does not need.

## 4. Confidence

| Result              | Meaning                                            |
| ------------------- | -------------------------------------------------- |
| `secure` + `high`   | ATS secure, no proxy, no VPN interface.            |
| `detected` + `high` | ATS permits arbitrary loads. Worth fixing.         |
| `detected` + `low`  | Only proxy or VPN posture. Context, not a finding. |
| `unknown` + `low`   | Settings were unreadable.                          |

## 5. False negatives

- An interception attack that needs no device-side proxy or VPN — the common case for a
  network-position attacker — produces no signal here at all.
- `NETWORK-001` describes policy, not behaviour. An app permitted to send cleartext may never do so;
  an app forbidden from it may still leak through a `WKWebView` or a native library.

## 6. Known limitations

No certificate pinning is performed or verified. Pinning is an integration concern for your HTTP
client. No network requests are made by this check — it reads local configuration only.

## 7. Recommended application response

```ts
const network = await NetworkSecurity.getStatus();

const arbitraryLoads = network.signals.some(
  (signal) => signal.id === 'RNSEC-IOS-NETWORK-001' && signal.detected
);

if (arbitraryLoads) {
  // Actionable: tighten NSAppTransportSecurity in your Info.plist.
}
```

Inspect individual signals rather than the check status. A `detected` result driven only by "the user
has Private Relay on" is not something to act on.

## 8. Tests

`ios/EngineTests/CapabilityDetectorsTests.swift` — 5 cases covering ATS permitted and denied, the
informational weighting of proxy and VPN signals, and unreadable settings.
