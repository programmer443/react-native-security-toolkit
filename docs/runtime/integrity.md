# Application integrity (Android)

`IntegrityCheck.getStatus()` · check id `integrity`

> Genuine integrity assurance on Android comes from **Play Integrity, verified on your server**.
> The signals here detect sideloading, re-signing and repackaging cheaply and locally, and an
> attacker who controls the device can defeat all of them. They inform a server-side decision; they
> do not replace one.

## 1. What it detects

Whether the running application is the one you published:

- its **signing certificate** matches a fingerprint you declared;
- the **package that installed it** is one you expect;
- its **package name** is the one you expect;
- the **APK is running from a normal install location**.

## 2. Configuration is not optional for three of the four

There is no way to know whether a signing certificate is the right one without being told which one
is right. So three of these signals need configuration, and **an unconfigured signal reports
`indeterminate`, never "not detected"**:

```ts
SecurityToolkit.configure({
  integrity: {
    signingCertificateSha256: ['A1:B2:C3:…'], // one per signer you published
    expectedInstallers: ['com.android.vending'],
    expectedPackageName: 'com.example.app',
  },
});
```

That distinction is the point of the whole check. A check that was never really performed must never
look like a check that passed — otherwise the most dangerous possible outcome (silently reporting a
tampered build as clean) is also the default one.

The check metadata reports which signals were configured, so a developer seeing `unknown` can tell
immediately whether it means "something is wrong" or "you have not finished setting this up":

```
signingCertificatesConfigured: false
expectedInstallersConfigured: false
expectedPackageNameConfigured: false
playIntegrityAvailable: false
```

Configuration is sent to native **per call**, not stored there. The native engine holds no
configuration state, so there is no ordering hazard between configuring and checking, and no way for
a check to run against configuration that was replaced halfway through. Each check receives only the
options it needs.

## 3. Signals

| ID                            | Indicator                                                 | Confidence | Needs config |
| ----------------------------- | --------------------------------------------------------- | ---------- | ------------ |
| `RNSEC-RUNTIME-INTEGRITY-001` | Signing certificate not among the configured fingerprints | **high**   | yes          |
| `RNSEC-RUNTIME-INTEGRITY-002` | Installed by an unexpected package, or directly           | medium     | yes          |
| `RNSEC-RUNTIME-INTEGRITY-003` | Package name differs from the configured identity         | **high**   | yes          |
| `RNSEC-RUNTIME-INTEGRITY-004` | APK running from an unusual filesystem location           | low        | no           |

`RNSEC-RUNTIME-INTEGRITY-005` is reserved for the **Play Integrity adapter**, which is deliberately
not bundled: it requires Google Play distribution, Google Play services, network access, a
server-side verification endpoint, and it is quota-limited. Hard-wiring all of that into a core
security package would force every consumer to take those dependencies. It ships as a separate
optional adapter.

### Fingerprints are compared leniently, on purpose

`apksigner`, `keytool` and the Play Console each print SHA-256 fingerprints with different casing
and punctuation. Comparison ignores both, so a value pasted from any of them works unchanged.
Requiring one exact spelling would turn a formatting slip into something indistinguishable from a
tampered build — a false alarm that is very hard to diagnose.

Each certificate is digested **separately**. Feeding multiple signers into a single digest produces
an order-dependent value that matches no published fingerprint, which is a subtle way to build a
check that can never pass.

## 4. Confidence

| Result                | Meaning                                                                                                             |
| --------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `secure` + `high`     | Every configured signal ran and matched.                                                                            |
| `detected` + `high`   | The signing certificate or package identity is wrong. Treat seriously.                                              |
| `detected` + `medium` | Install provenance is unexpected. See §5 before acting.                                                             |
| `unknown` + `low`     | Something was unconfigured or unreadable. **Check the metadata first** — most often this means setup is incomplete. |

## 5. False positives

- **Install source** (`INTEGRITY-002`) is weaker than it looks. Enterprise MDM deployments,
  alternative app stores, and every development install produce an "unexpected" installer. Treat it
  as provenance information, not evidence of tampering.
- **Key rotation.** If you rotate your signing key, configure both the old and new fingerprints
  during the transition, or every existing install will report as tampered.
- **Play App Signing.** The certificate the device sees is the one Google re-signed with, not your
  upload key. Take the fingerprint from the Play Console's _app signing key_, not from your keystore.
- **Preinstalled builds** run from `/system` or `/product`; `INTEGRITY-004` accepts those.

## 6. False negatives

- An attacker who repackages your app _and_ strips this check defeats all of it. In-process
  integrity checking is inherently self-referential.
- A build signed with your real key is indistinguishable from your build, because it is one. Key
  compromise is outside what any client-side check can address.
- `INTEGRITY-004` only knows about common install locations and will not recognise every unusual but
  legitimate deployment.

## 7. Known limitations

- Everything here is observed from inside the process being verified. That is the ceiling.
- These signals answer "does this look like my app" locally and cheaply. They do not answer "is this
  really my app" — only server-verified attestation does that.
- Without Play Integrity, a determined attacker on a device they control will win. The value of
  these signals is against casual repackaging and sideloading, which is most of the volume.

This document deliberately does not describe how to defeat any of these checks.

## 8. Recommended application response

```ts
const integrity = await IntegrityCheck.getStatus();

if (integrity.status === 'unknown') {
  // Check the metadata before assuming something is wrong — most often this
  // means the fingerprints have not been configured yet.
}

if (integrity.status === 'detected' && integrity.confidence === 'high') {
  // A wrong signing certificate or package name is one of the few signals
  // worth acting on decisively: refuse sensitive operations and tell your
  // server, which can make the real decision.
}
```

## 9. Tests

`android/src/test/java/com/rnsecurity/detectors/integrity/IntegrityDetectorsTest.kt` — 18 cases
covering matching and mismatching certificates, punctuation- and case-insensitive fingerprints,
multi-signer builds, unreadable certificates, direct installs, repackaged package names,
preinstalled system paths, and — for every configurable signal — that an unconfigured check reports
`indeterminate` rather than passing.

`src/__tests__/config.test.ts` covers rejection of malformed configuration: truncated, non-hex and
empty fingerprint lists, which would otherwise fail in ways that look like tampering.
