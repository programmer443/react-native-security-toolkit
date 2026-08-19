# Application integrity (iOS)

`IntegrityCheck.getStatus()` · check id `integrity`

> Genuine integrity assurance on iOS comes from **App Attest, verified on your server**. The signals
> here detect sideloading, re-signing and repackaging cheaply and locally, and an attacker who
> controls the device can defeat them.
>
> See [integrity.md](integrity.md) for the Android signals under the same check id.

## 1. What it detects

- whether the **bundle identifier** matches the one you configured;
- whether an **embedded provisioning profile** is present, meaning this is not an App Store build;
- whether the **main binary carries App Store encryption**.

## 2. Configuration

`INTEGRITY-001` needs to be told what to expect:

```ts
SecurityToolkit.configure({
  integrity: {
    expectedBundleIdentifier: 'com.example.app',
  },
});
```

As on Android, an **unconfigured signal reports `indeterminate`, never a passing result**. A check
that was never really performed must not look like one that passed. The check metadata reports
`expectedBundleIdentifierConfigured` so a developer seeing `unknown` can tell "something is wrong"
from "you have not finished setting this up".

## 3. Signals

| ID                        | Indicator                                              | Confidence | Needs config |
| ------------------------- | ------------------------------------------------------ | ---------- | ------------ |
| `RNSEC-IOS-INTEGRITY-001` | Bundle identifier differs from the configured identity | **high**   | yes          |
| `RNSEC-IOS-INTEGRITY-002` | Embedded provisioning profile present                  | medium     | no           |
| `RNSEC-IOS-INTEGRITY-003` | Main binary is not App Store encrypted                 | medium     | no           |

`RNSEC-IOS-INTEGRITY-004` is reserved for the **App Attest adapter**, deliberately not bundled: it
requires a server-side verification endpoint, network access, and iOS 14+ hardware. Hard-wiring that
into a core security package would force every consumer to take those dependencies. It ships as a
separate optional adapter, exactly as Play Integrity does on Android.

## 4. `INTEGRITY-003` only means something for App Store builds

App Store binaries carry FairPlay encryption; an unencrypted binary on a device suggests it was
decrypted and re-signed, which is the standard first step in repackaging an iOS application.

But **simulator builds and locally signed device builds are never encrypted either**. So:

- On the **simulator** the signal reports `indeterminate` with an explicit reason, rather than firing
  on every development run.
- On a **development or TestFlight build** it will fire, correctly and unhelpfully. Use
  `developmentMode` and a policy that disregards it outside production.

`cryptid` is read from the `LC_ENCRYPTION_INFO_64` load command of the main image. An absent command
is reported as "not encrypted" — a definite answer, not a failure to read.

## 5. `INTEGRITY-002` is provenance, not tampering

App Store builds carry no `embedded.mobileprovision`. Its presence means the app arrived some other
way — TestFlight, enterprise distribution, a development build, or a re-signed sideload. The first
three are entirely legitimate, which is why this is `medium` and described as provenance.

## 6. Confidence

| Result                | Meaning                                                                   |
| --------------------- | ------------------------------------------------------------------------- |
| `secure` + `high`     | Identity matches, App Store build, encrypted binary.                      |
| `detected` + `high`   | The bundle identifier is wrong. Treat seriously.                          |
| `detected` + `medium` | Provenance or encryption is unexpected. See §4 and §5 before acting.      |
| `unknown` + `low`     | Something was unconfigured or inapplicable. **Check the metadata first.** |

## 7. False positives

- Every **development and TestFlight build** trips `INTEGRITY-002`, and `INTEGRITY-003` on device.
- **Enterprise-distributed applications** legitimately carry provisioning profiles for their whole
  lifetime.

## 8. False negatives

- An attacker who repackages the app _and_ strips this check defeats all of it. In-process integrity
  checking is inherently self-referential.
- A build signed with your own credentials is indistinguishable from your build, because it is one.

## 9. Recommended application response

```ts
const integrity = await IntegrityCheck.getStatus();

if (integrity.status === 'unknown') {
  // Check the metadata before assuming something is wrong — most often this
  // means configuration is incomplete, or you are on a simulator.
}
```

Use these locally to raise friction, and put the real gate on your server behind App Attest.

## 10. Tests

`ios/EngineTests/HookAndIntegrityTests.swift` — 9 integrity cases including matching and mismatching
bundle identifiers, an unconfigured check reporting `indeterminate`, provisioning profile presence,
and the simulator guard on binary encryption.
