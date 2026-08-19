# Emulator detection (Android)

`EmulatorDetection.getStatus()` · `EmulatorDetection.isEmulator()` · check id `emulator` ·
signature pack `2026.08.1`

> **Running under emulation is not a compromise.** Continuous integration runs on emulators, QA runs
> on device farms, and Google Play Games runs Android apps on desktop hardware. This check informs a
> risk decision; on its own it is a poor reason to block anyone.

## 1. What it detects

Whether the app is running on an Android emulator, a virtualised image, or a cloud device rather
than retail hardware — from build identity, emulator-only device nodes and properties, and hardware
profile.

## 2. How it works

Three detectors, one signal each, combined by `SignalAggregator`. Signature lists live in
`EmulatorSignatures` and are versioned, because this is the check whose data goes stale fastest.

**On staleness specifically:** the emulator signature lists copied around older Android projects
target the QEMU/goldfish generation — `ro.kernel.qemu`, `FINGERPRINT.startsWith("generic")`,
`google_sdk`. Modern AVDs use `ranchu` and `sdk_gphone*`, so those lists produce a check that looks
thorough and detects nothing. Two regression tests exist specifically to stop that returning.

## 3. Signals

| ID                           | Indicator                                    | Confidence | Notes                                                                                         |
| ---------------------------- | -------------------------------------------- | ---------- | --------------------------------------------------------------------------------------------- |
| `RNSEC-ANDROID-EMULATOR-001` | Build identity matches an emulator image     | medium     | `ranchu`, `goldfish`, `sdk_gphone*`, `emu64*`, Genymotion, BlueStacks, Cuttlefish, VirtualBox |
| `RNSEC-ANDROID-EMULATOR-002` | Emulator-only device nodes or properties     | medium     | `/dev/qemu_pipe`, `/dev/goldfish_pipe`, `ro.kernel.qemu`, and similar                         |
| `RNSEC-ANDROID-EMULATOR-003` | Hardware profile inconsistent with a handset | low        | Implausibly few sensors, or telephony claimed but absent                                      |

`EMULATOR-003` is deliberately `low`: a Wi-Fi-only tablet has no telephony and a low-end phone
carries few sensors. It can corroborate the other two; it must never carry a verdict alone.

One subtlety worth noting: `ro.boot.hardware.platform` exists on retail devices as well as
emulators, so `EMULATOR-002` matches on its _value_ rather than its presence. Treating presence as
the signal would report every modern phone as emulated.

## 4. Confidence

| Result                | Meaning                                                                           |
| --------------------- | --------------------------------------------------------------------------------- |
| `secure` + `high`     | Every probe ran; the device looks like retail hardware.                           |
| `detected` + `high`   | Both build identity and QEMU artefacts agree. Strong.                             |
| `detected` + `medium` | One substantive signal fired.                                                     |
| `detected` + `low`    | Only the hardware-profile hint fired. Weak — likely a tablet or a low-end device. |
| `unknown` + `low`     | A probe was blocked. Inconclusive.                                                |

## 5. False positives

- **Wi-Fi-only tablets and low-end devices** can trip `EMULATOR-003`.
- **Google Play Games on PC** runs real users' sessions on virtualised Android.
- **Cloud device farms** used by legitimate QA are correctly detected as non-physical — correct, but
  not evidence of an attacker.
- **Custom ROMs** occasionally carry generic build strings.

## 6. False negatives

- Hardened emulator images exist specifically to defeat these signals, and they are effective
  against the file- and property-based checks.
- Physical devices under instrumentation are not emulators; use hook and root detection for that.

## 7. Known limitations

- Emulator detection is a weak proxy for what most applications actually care about, which is
  whether the runtime is being instrumented. Prefer hook and integrity detection for that question.
- Signature lists date quickly. `signatureVersion` in the result metadata records which list
  produced a result.

## 8. Recommended application response

```ts
const emulator = await EmulatorDetection.getStatus();

if (emulator.status === 'detected' && emulator.confidence !== 'low') {
  // Reasonable: raise a risk score, require stronger authentication for a
  // high-value action, or log a security event.
  // Rarely reasonable: refuse to run.
}
```

Blocking on emulator detection alone breaks CI, breaks QA, and breaks Play Games users, while
stopping an attacker for about as long as it takes to read a blog post.

## 9. Tests

`android/src/test/java/com/rnsecurity/detectors/emulator/EmulatorDetectorsTest.kt` — 15 cases
covering modern `ranchu` AVDs and Cuttlefish images, retail hardware, blocked probes, the
`ro.boot.hardware.platform` value-versus-presence distinction, and the Wi-Fi-only-tablet false
positive.
