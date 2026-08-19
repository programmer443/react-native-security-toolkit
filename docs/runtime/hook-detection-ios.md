# Hook and instrumentation detection (iOS)

`HookDetection.getStatus()` · check id `hooks` · signature pack `2026.08.1`

> **Adversarial in a way the other checks are not.** An attacker running a hooking framework can
> modify the code performing the detection — including this check. Detection is **not guaranteed and
> cannot be**. What these signals buy is cost.
>
> See [hook-detection.md](hook-detection.md) for the Android signals under the same check id.

## 1. What it detects

Both signals ask the same underlying question in two different layers: **is the runtime still shaped
the way it should be?**

- a **native symbol** resolving outside any operating-system image;
- an **Objective-C method** whose implementation has moved out of a system framework.

That question is more durable than "is a known tool present", because it survives an attacker
renaming their library.

## 2. Signals

| ID                       | Indicator                                                        | Confidence |
| ------------------------ | ---------------------------------------------------------------- | ---------- |
| `RNSEC-RUNTIME-HOOK-004` | A system symbol resolves inside a non-system image               | **high**   |
| `RNSEC-RUNTIME-HOOK-005` | A watched framework method is implemented outside a system image | medium     |

`HOOK-004` resolves `open`, `read`, `write`, `connect`, `fopen` and `dlsym` through `dlsym`, then
asks `dladdr` which image provided each address.

`HOOK-005` looks up the implementation of a few methods that instrumentation most often intercepts —
`NSURLSession` request creation and shared session, `UIPasteboard.generalPasteboard` — and checks
which image provides them.

## 3. Why `HOOK-005` is only `medium`

**Legitimate SDKs swizzle.** Analytics, crash reporting and network-inspection libraries all replace
framework methods, and this signal cannot tell them from an attacker. It is reported as an indicator
so an application that knows its own dependencies can judge it, and it can only ever corroborate —
never carry a verdict alone.

## 4. System images are matched by prefix, not substring

This is worth documenting because getting it wrong silently disables the whole check.

An image is treated as part of the operating system when its path **starts with** `/System/` or
`/usr/lib/` — or, on the simulator, when those prefixes appear nested under the Xcode runtime root
(`…/RuntimeRoot/usr/lib/…`).

A substring match would be catastrophic here. A rootless jailbreak installs to **`/var/jb/usr/lib/`**,
which _contains_ `/usr/lib/`. Substring matching classifies every injected library on a modern
jailbroken device as a system image — precisely where iOS hooks live today. There is a regression
test asserting `/var/jb/usr/lib/libhooker.dylib` is **not** a system image, and it was written
because the first implementation had exactly that bug.

## 5. Confidence

| Result                | Meaning                                                                                           |
| --------------------- | ------------------------------------------------------------------------------------------------- |
| `secure` + `high`     | Symbols and watched methods all come from system images. Not proof the process is uninstrumented. |
| `detected` + `high`   | A native symbol was redirected.                                                                   |
| `detected` + `medium` | Only a swizzled method. Check your own dependencies first.                                        |
| `unknown` + `low`     | A probe could not answer. Inconclusive.                                                           |

## 6. False positives

- **Legitimate swizzling SDKs**, as above. This is the main source.
- **Debug tooling** injected during development.

## 7. False negatives

- Hooks on functions outside the watched list are invisible.
- An attacker who patches these detectors defeats everything here. Not hypothetical: it is the normal
  case for a determined adversary.
- Inline hooks that preserve the symbol's apparent origin are not caught by `HOOK-004`.

## 8. Known limitations

- Everything runs inside the process being attacked. That is the ceiling.
- No `fishhook`-style rebinding table inspection, and no Mach-O prologue byte comparison — the latter
  varies by architecture and iOS version, and produces false positives on legitimate instrumentation.
- Real trust decisions belong on a server, informed by App Attest.

This document deliberately does not describe how to defeat any of these checks.

## 9. Recommended application response

```ts
const hooks = await HookDetection.getStatus();

if (hooks.status === 'detected' && hooks.confidence === 'high') {
  // Proportionate: refuse high-value operations, require server-side
  // re-authentication, log a security event with the signal ids.
}
```

Treat a clean result as worth little and a positive result as worth a lot.

## 10. Tests

`ios/EngineTests/HookAndIntegrityTests.swift` — 10 hook cases run with `swift test`, including the
rootless-path regression test and one asserting that simulator paths nested under the Xcode runtime
root are still recognised as system images.
