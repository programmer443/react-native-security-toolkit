# Root detection (Android)

`RootDetection.getStatus()` · check id `root` · signature pack `2026.08.1`

> Root detection is a **defence-in-depth signal, not a guarantee**. Every indicator below can be
> defeated by an attacker who controls the device, and several can be defeated together. Nothing
> here should be treated as proof that a device is unmodified, and `unknown` must never be read as
> `secure`.

## 1. What it detects

Indicators that the device has been modified in ways commonly associated with root: an unlocked
bootloader, a `su` binary, a root management application, a debuggable system build, overlaid system
partitions, writable protected directories, permissive SELinux, and artefacts associated with Magisk
or Zygisk-style process injection.

It does **not** detect "is this user an attacker". A developer with an unlocked bootloader, a custom
ROM user, and someone actively instrumenting your app all produce overlapping signals.

## 2. How it works

Ten independent detectors each produce one signal. Signals are combined by `SignalAggregator`, which
applies two rules:

- **A blocked probe is not evidence of safety.** If any probe could not run, the check reports
  `unknown`, never `secure`.
- **Confidence comes from corroboration.** One high-confidence signal, or two medium ones, or three
  low ones, is what it takes to report `high`.

Detectors never touch the filesystem, `PackageManager` or system properties directly — they receive
injected probes. That is what makes all of them testable on CI with no rooted device.

## 3. Signals

| ID                         | Indicator                                     | Confidence | Notes                                                    |
| -------------------------- | --------------------------------------------- | ---------- | -------------------------------------------------------- |
| `RNSEC-ANDROID-ROOT-001`   | Executable `su` binary in a known location    | medium     | Existence alone is not enough; the file must be runnable |
| `RNSEC-ANDROID-ROOT-002`   | Root management application installed         | medium     | **Requires package visibility** — see §7                 |
| `RNSEC-ANDROID-ROOT-003`   | `ro.debuggable=1` or `ro.secure=0`            | medium     | Read through the NDK — see §8                            |
| `RNSEC-ANDROID-ROOT-004`   | Build signed with test keys                   | low        | Also true of legitimate custom ROMs                      |
| `RNSEC-ANDROID-ROOT-005`   | Verified Boot unlocked or unverified          | **high**   | Strongest signal available without hardware attestation  |
| `RNSEC-ANDROID-ROOT-007`   | Overlay or tmpfs over a protected partition   | medium     | Reads this process's own mount table only                |
| `RNSEC-ANDROID-ROOT-008`   | Protected directory accepted a write          | **high**   | Real create-and-delete probe, not `File.canWrite()`      |
| `RNSEC-ANDROID-ROOT-009`   | SELinux permissive                            | medium     | Enforcing is commonly preserved on rooted devices        |
| `RNSEC-ANDROID-MAGISK-001` | Magisk-related filesystem or mount artefact   | medium     | Artefacts are relocatable                                |
| `RNSEC-ANDROID-ZYGISK-001` | Zygisk-style injection marker in this process | medium     | Inspects only this app's own memory map                  |

`RNSEC-ANDROID-ROOT-006` (Android Keystore key attestation) is **reserved and not yet implemented**.
It needs the keystore probe that arrives with the secure-hardware check, and it is the one signal
here that is hardware-backed. The ID is held so it cannot be reused.

## 4. Confidence

| Result                        | Meaning                                                                                                                                      |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `secure` + `high`             | Every probe ran; no indicator fired. The strongest statement this check makes — and it still says nothing about whether a bypass is in play. |
| `detected` + `high`           | A hardware-adjacent signal fired, or several independent medium signals agree.                                                               |
| `detected` + `medium` / `low` | Something fired, but weakly or in isolation. Worth logging; think hard before blocking on it alone.                                          |
| `unknown` + `low`             | At least one probe was blocked. **Inconclusive, not clean.**                                                                                 |
| `unavailable`                 | The check did not run. `unavailableReason` says why.                                                                                         |
| `error`                       | The check failed. Never a verdict about the device.                                                                                          |

## 5. False positives

- **Developer and custom-ROM devices.** An unlocked bootloader (`ROOT-005`) and test keys
  (`ROOT-004`) are normal on developer hardware and on legitimate custom ROMs. Neither means the
  user is attacking you.
- **Engineering and `userdebug` builds** legitimately set `ro.debuggable=1` (`ROOT-003`).
- **Emulators** trip several signals at once. Use `developmentMode` and the policy engine's
  `minimumConfidence` rather than blocking outright.
- **Some OEM builds** ship unusual mount layouts that can resemble `ROOT-007`.

## 6. False negatives

- Root implementations that hide their artefacts defeat the path- and package-based signals
  (`ROOT-001`, `ROOT-002`, `MAGISK-001`) by design.
- Read-only root configurations leave `ROOT-008` untripped.
- SELinux is usually left enforcing, so `ROOT-009` is quiet on most rooted devices.
- `/proc` visibility restrictions can blind `ROOT-007` and `ZYGISK-001`; both then report
  `indeterminate`, which turns the whole check into `unknown` rather than `secure`.

## 7. Package visibility (`RNSEC-ANDROID-ROOT-002`)

From Android 11, an app only sees packages it has declared in `<queries>`. Without that declaration
`getPackageInfo` reports "not installed" for everything — a false negative that is indistinguishable
from a clean result.

So this detector reports `indeterminate` rather than "not detected" when visibility is not
configured, and the check's metadata carries `packageVisibilityConfigured: false`.

### Opting in

Add to your application's `gradle.properties`:

```properties
rnsecPackageVisibility=true
```

That selects a library manifest carrying `<queries>` for the root-manager packages in
`RootSignatures.ROOT_MANAGER_PACKAGES`, and the check starts answering.

It is off by default because `<queries>` entries **merge into your application's manifest** and are
visible in store review. That is a decision with consequences, and it belongs to the application
author rather than to a dependency.

`QUERY_ALL_PACKAGES` is **not** used and will not be added: it is a Play-policy-restricted
permission requiring a declared exemption.

### Why this is a build-time fact, not a runtime check

The same Gradle flag sets `BuildConfig.PACKAGE_VISIBILITY_DECLARED`, and the probe reads that rather
than trying to work it out at runtime. The two therefore cannot disagree.

This matters more than it sounds. The obvious runtime inference — ask whether any package other than
our own is visible — **does not work**: Android always exposes a handful of system packages
regardless of `<queries>`, so the inference answers "yes" on every device. The check would then
report "no root management application detected", which is a **false negative wearing a clean
result's clothes** — precisely the outcome this library exists to avoid. An earlier implementation
did exactly that, and it was only caught by reading the check's own metadata on a device that had
declared nothing.

## 8. Why system properties are read natively

`System.getProperty` reads **JVM** properties, not Android system properties — it returns `null` for
every `ro.*` key, which makes a property check that looks like it works but never fires. Reflecting
into `android.os.SystemProperties` is a restricted non-SDK interface. This package calls
`__system_property_get` through a small JNI library instead: public NDK API, subject to neither
problem.

If that library fails to load, property-based signals report `indeterminate` and the check metadata
carries `nativePropertyProbeAvailable: false`.

## 9. Known limitations

- Every signal here is _observable from inside the app process_, which is code the attacker
  controls on a compromised device. This is an inherent ceiling, not an implementation gap.
- Signature lists go stale. They are versioned (`signatureVersion` in the result metadata) so a
  result can be traced to the list that produced it, but a new root manager will not be detected
  until the list is updated.
- A real trust decision belongs on a server, informed by hardware-backed attestation — Play
  Integrity on Android. On-device signals inform that decision; they do not replace it.

This document deliberately does not describe how to defeat any of these checks.

## 10. Recommended application response

The toolkit reports; the application decides. It will not block, terminate, or show UI.

```ts
const root = await RootDetection.getStatus();

switch (root.status) {
  case 'detected':
    if (root.confidence === 'high') {
      // Proportionate: reduce what the app will do, require re-authentication,
      // disable high-value operations, log a security event.
    }
    break;
  case 'unknown':
    // Inconclusive. Treat as reduced assurance, not as compromise.
    break;
  case 'secure':
    // No indicators fired. Not a guarantee.
    break;
}
```

Terminating the app is rarely the right response: it is trivially bypassed, and it punishes
developers and custom-ROM users who are not attacking you. Prefer degrading capability over denying
access, and put the real gate on your server.

## 11. Tests

- `android/src/test/java/com/rnsecurity/detectors/root/RootDetectorsTest.kt` — each detector against
  a compromised device, a clean device, a blocked probe, and its most likely false positive.
- `android/src/test/java/com/rnsecurity/engine/SignalAggregatorTest.kt` — the `unknown ≠ secure` rule
  and every confidence threshold.
- `src/__tests__/checkResult.test.ts` — payload validation, including rejection of a `secure` verdict
  that contradicts its own signals.
