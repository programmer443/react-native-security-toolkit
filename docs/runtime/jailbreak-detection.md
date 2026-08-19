# Jailbreak detection (iOS)

`JailbreakDetection.getStatus()` · check id `jailbreak` · signature pack `2026.08.1`

> Jailbreak detection is a **defence-in-depth signal, not a guarantee**. Every indicator below can be
> defeated by an attacker who controls the device, and several can be defeated together. `unknown`
> must never be read as `secure`.

## 1. What it detects

Indicators that an iOS device has been modified: filesystem artefacts from both classic and modern
jailbreaks, a sandbox escape, injected libraries, the dyld insertion environment variable,
package-manager URL schemes, and system directories replaced with symbolic links.

## 2. Rootless jailbreaks, not just the Cydia era

The single most important modernisation here. Published iOS jailbreak path lists overwhelmingly
target **rootful** jailbreaks — `/Applications/Cydia.app`, `/Library/MobileSubstrate`, `/etc/apt`.
Modern **rootless** jailbreaks relocate their entire filesystem under a prefix such as `/var/jb`, so
those lists detect nothing on a current device while looking thorough.

Both layouts are covered, and reported as **separate signals**, so a result says which era it
matched. There is a test asserting that a rootless device trips `JAILBREAK-002` and _not_
`JAILBREAK-001` — because a library that quietly stopped working would be worse than one that never
claimed to.

## 3. The simulator returns `unavailable`, not a verdict

On the iOS Simulator the check reports:

```
status: 'unavailable'
unavailableReason: 'simulator'
```

The question "has this iOS device been modified" is malformed when there is no iOS device — the
simulator runs against the macOS filesystem. Reporting `detected` there would train developers to
ignore the check; reporting `secure` would be a lie.

Related, and found by actually running this on a simulator: paths that exist on macOS —
`/bin/bash`, `/bin/sh`, `/usr/bin/ssh`, `/usr/sbin/sshd`, `/usr/libexec/ssh-keysign` — are
**excluded from the path list**, even though most published lists include them. They exist on every
developer's machine. Both guards are tested.

## 4. Signals

| ID                        | Indicator                                    | Confidence | Notes                                            |
| ------------------------- | -------------------------------------------- | ---------- | ------------------------------------------------ |
| `RNSEC-IOS-JAILBREAK-001` | Classic rootful filesystem artefact          | low        | Increasingly rare; absent on rootless jailbreaks |
| `RNSEC-IOS-JAILBREAK-002` | Rootless filesystem artefact (`/var/jb`, …)  | medium     | The modern case                                  |
| `RNSEC-IOS-JAILBREAK-003` | A write **succeeded** outside the sandbox    | **high**   | See §5                                           |
| `RNSEC-IOS-JAILBREAK-004` | Injected library in the dyld image list      | **high**   | Substrate, Substitute, libhooker, ElleKit, Frida |
| `RNSEC-IOS-JAILBREAK-005` | `DYLD_INSERT_LIBRARIES` set                  | **high**   | No benign explanation in a shipped app           |
| `RNSEC-IOS-JAILBREAK-006` | Package-manager URL scheme reachable ⚠︎       | medium     | Opt-in; see §6                                   |
| `RNSEC-IOS-JAILBREAK-007` | System directory replaced by a symbolic link | medium     |                                                  |

## 5. The sandbox probe polarity

`JAILBREAK-003` attempts a write to a path outside the application container and treats **success**
as the indicator.

This is worth stating explicitly because it is easy to invert, and the inverted version is actively
harmful. On a healthy sandboxed application the write **fails** — so failure is the _good_ outcome.
An implementation that reports "jailbroken" when the write throws will report **every healthy device
as jailbroken**. That mistake is present in at least one widely used library, and it is the reason
this detector's polarity is asserted by name in its tests.

Path lookups use `stat`/`lstat` rather than `FileManager`, which is an Objective-C class and
therefore a natural swizzling target. A small, free improvement for a check that runs in a hostile
process.

## 6. URL scheme queries are opt-in

`JAILBREAK-006` needs the schemes listed in your `Info.plist`:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
  <string>cydia</string>
  <string>sileo</string>
  <string>zbra</string>
</array>
```

**This package does not add them.** They appear in the consuming application's `Info.plist` and in
App Review, which is the application author's decision — the same reasoning as `<queries>`,
`USE_BIOMETRIC` and `ACCESS_NETWORK_STATE` on Android. Without them, `canOpenURL` answers `false` for
everything, which is a false negative indistinguishable from a clean result; so the signal reports
`indeterminate` and the check metadata carries `urlSchemeQueriesConfigured: false`.

Only schemes the application actually declared are queried. Asking about the others would produce a
meaningless `false`.

## 7. Confidence

| Result                      | Meaning                                                                  |
| --------------------------- | ------------------------------------------------------------------------ |
| `secure` + `high`           | Every probe ran; no indicator fired. Not proof the device is unmodified. |
| `detected` + `high`         | A sandbox escape, injected library, or dyld insertion. Strong.           |
| `detected` + `medium`       | Rootless artefacts, symlink anomalies, or a reachable package manager.   |
| `detected` + `low`          | Only a classic path matched, in isolation.                               |
| `unknown` + `low`           | A probe was blocked. Inconclusive, not clean.                            |
| `unavailable` + `simulator` | Running on a simulator. See §3.                                          |

## 8. False positives

- **Enterprise and MDM-managed devices** occasionally carry unusual filesystem layouts.
- **Developer devices** with unusual entitlements may trip path checks.
- `JAILBREAK-001` is `low` confidence precisely because a single path match is weak evidence.

## 9. False negatives

- A jailbreak that renames its libraries and relocates its filesystem defeats the name- and
  path-based signals. This is the normal case for a determined adversary.
- An attacker who patches these detectors, the aggregator, or the JavaScript calling them defeats
  everything here.
- Signature lists date quickly; `signatureVersion` in the result metadata records which list produced
  a result.

## 10. Known limitations

- Everything runs inside the process being attacked. That is the ceiling, and no additional signal
  moves it.
- Real integrity assurance on iOS comes from **App Attest**, verified on your server. These signals
  detect a modified device cheaply and locally; they do not replace attestation.
- No `ptrace(PT_DENY_ATTACH)` and no `fork()` probe. Both are non-public API with a history of App
  Review friction; where they appear at all they will be opt-in and documented, never a default.

This document deliberately does not describe how to defeat any of these checks.

## 11. Recommended application response

```ts
const jailbreak = await JailbreakDetection.getStatus();

if (jailbreak.status === 'detected' && jailbreak.confidence === 'high') {
  // Proportionate: refuse high-value operations, require server-side
  // re-authentication, log a security event with the signal ids.
}
```

Prefer degrading capability over denying access, and put the real gate on your server.

## 12. Tests

`ios/EngineTests/JailbreakDetectorsTests.swift` — 24 cases run with `swift test` on macOS, no
simulator and no jailbroken device required. They cover each detector against a modified device, a
clean device, and blocked probes, plus three assertions that exist because of specific mistakes:
the sandbox polarity, the rootless-versus-rootful split, and the exclusion of macOS-existing paths.
