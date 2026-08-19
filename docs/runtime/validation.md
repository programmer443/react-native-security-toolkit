# Validation status

What has actually been verified, and what has not. A security tool that is vague about this is asking
you to assume the best.

## Summary

| Area                                                       | Verified how                                                                | Status              |
| ---------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------- |
| Runtime detector logic (Android)                           | Kotlin unit tests with injected probes — a rooted device described as data  | ✅                  |
| Runtime detector logic (iOS)                               | Swift unit tests with injected probes, run with `swift test` on macOS       | ✅                  |
| JavaScript API, bridge validation, risk and policy engines | Jest unit tests                                                             | ✅                  |
| Android build                                              | CI builds the example app on every change                                   | ✅                  |
| iOS build                                                  | CI builds the example app on every change                                   | ✅                  |
| Static auditor, rules, CLI, reporting, MCP                 | Unit tests, adversarial fixtures, end-to-end scans, SARIF schema validation | ✅                  |
| **Behaviour on physical rooted devices**                   | —                                                                           | ❌ **not yet done** |
| **Behaviour on physical jailbroken devices**               | —                                                                           | ❌ **not yet done** |
| **Behaviour across the OS version matrix**                 | —                                                                           | ❌ **not yet done** |
| External security review                                   | —                                                                           | ❌ not yet done     |

## Why the unit tests are not enough

Every detector reaches the platform through an injected probe, which is what makes them testable at
all: a jailbroken phone, a locked-down phone and a phone whose filesystem is unreadable are three
values in a test. That design proves the **logic** — that a blocked probe produces `indeterminate`,
that a sandbox-escape check has the right polarity, that corroboration raises confidence.

It cannot prove the **probes**. Whether `/proc/self/maps` is readable on a given Android build,
whether a rootless jailbreak actually leaves `/var/jb` where the signature pack expects it, whether a
Play Integrity-attested device trips a heuristic that was never meant for it — none of that is
knowable from a unit test, and this project will not imply otherwise.

## The matrix that is still outstanding

Each cell needs a real device or a genuinely representative image.

### Android

| Environment                             | What it must confirm                                                           |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| Stock device, API 24 / 29 / 33 / 35+    | No check reports `detected`; nothing crashes; permissions behave as documented |
| Magisk-rooted, with and without Zygisk  | Root detection reports `detected` with corroborating signals                   |
| Magisk + DenyList applied to the app    | Documents what is still detected — the honest answer may be "little"           |
| Emulator (AVD, `ranchu`) and Cuttlefish | Emulator detection fires; root detection does not misfire on `dev-keys` images |
| Frida attached (gadget and server)      | Hook detection reports indicators                                              |
| Re-signed / repackaged build            | Integrity signals fire when configured                                         |
| Device with no biometric hardware       | Biometric capability reports absence rather than `unknown`                     |

### iOS

| Environment                                  | What it must confirm                                                       |
| -------------------------------------------- | -------------------------------------------------------------------------- |
| Stock device, iOS 15 / 17 / 18+              | No check reports `detected`; the sandbox probe reports refusal             |
| Rootful jailbreak (checkra1n-era)            | Classic path signals fire                                                  |
| Rootless jailbreak (Dopamine-era, `/var/jb`) | Rootless signals fire where classic ones do not                            |
| Simulator                                    | Jailbreak reports `unavailable` with reason `simulator`, not a false alarm |
| Frida / Substrate-family injection           | Hook detection reports indicators                                          |
| TestFlight and App Store builds              | Integrity provenance signals behave differently, and correctly, in each    |

### What "verified" will mean

A cell is only marked verified when the result is recorded — device, OS build, tooling version, the
check output — and a link to the record appears here. Until then, the runtime status in the
[README](../../README.md) says exactly what this page says.

## Measured performance (static auditor)

Synthetic projects of realistic file shape, Node 24 on an Apple Silicon laptop:

|  Files | Wall clock | Per file | Peak heap | Notes                                                         |
| -----: | ---------: | -------: | --------: | ------------------------------------------------------------- |
|  2,000 |     0.53 s |  0.27 ms |     40 MB |                                                               |
| 10,000 |      2.0 s |  0.20 ms |     30 MB |                                                               |
| 20,500 |      4.5 s |  0.23 ms |    106 MB | Hits the 20,000-file cap; report correctly marked `truncated` |

Scaling is linear and heap stays bounded — parse results are cached in a byte-aware LRU, and files
are streamed through a bounded scheduler rather than read all at once. This repository itself scans
in about 0.4 s.

## Known gaps, restated

- No physical-device results yet, for either platform.
- No OS-version matrix.
- No external review.
- No published benchmark on a large real-world React Native application; the numbers above are
  synthetic, and real code parses more slowly than generated code.
