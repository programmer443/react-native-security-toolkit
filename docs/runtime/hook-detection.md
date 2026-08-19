# Hook and instrumentation detection (Android)

`HookDetection.getStatus()` · check id `hooks` · signature pack `2026.08.1`

> **This check is adversarial in a way the others are not.** An attacker running a hooking framework
> can modify the code performing the detection — including this check. Detection is **not
> guaranteed and cannot be**. What these signals buy is cost: they raise the effort from "attach and
> go" to "attach, then hide". Any product claim beyond that would be false.

## 1. What it detects

Indicators that this process is being instrumented:

- **dynamic instrumentation** — an agent mapped into the process, or worker threads injected by one;
- **managed-code hooking frameworks** — their classes loadable, their frames on the call stack, or
  their libraries mapped in;
- **symbol redirection** — standard library symbols resolving inside libraries other than the ones
  that should provide them.

## 2. Scope limits, deliberately

- **This process only.** No other process is examined.
- **No network probing.** Scanning for a listening instrumentation port is a well-known technique
  and it is not used here: it would mean a security library opening sockets on a user's device, and
  the signal is not worth that trade. It is also trivially defeated by changing a port number.
- **No attempt to block or unhook anything.** The toolkit reports; countermeasures belong to the
  application, and in-process anti-tamper generally loses to an attacker with native access.

## 3. Signals

| ID                       | Indicator                                        | Confidence | Sources                                                |
| ------------------------ | ------------------------------------------------ | ---------- | ------------------------------------------------------ |
| `RNSEC-RUNTIME-HOOK-001` | Dynamic instrumentation agent or injected thread | medium     | `/proc/self/maps`, `/proc/self/task/<tid>/comm`        |
| `RNSEC-RUNTIME-HOOK-002` | Managed-code hooking framework                   | medium     | Class loadability, call-stack frames, mapped libraries |
| `RNSEC-RUNTIME-HOOK-003` | Symbol resolves inside an unexpected library     | medium     | `dlsym` + `dladdr`, through the native probe           |

Each reads more than one source, because a framework that hides one often does not bother with
another. `HOOK-001` answers from threads alone if the memory map is unreadable, and vice versa.

### Why symbol origin rather than prologue bytes

A common approach to native hook detection compares the first bytes of a function against expected
prologue patterns. That varies by architecture, compiler, and Android version, and it produces false
positives on legitimate instrumentation.

`HOOK-003` instead asks where a symbol actually lives: resolve `open`, `read`, `connect`, `dlopen`
and friends, then ask `dladdr` which library provided the address. If `open` resolves inside an
injected library, the symbol has been redirected. This survives the attacker renaming their library,
which the name-matching signals do not.

Only the library **filename** is compared, never the full path. Android moves bionic between
`/system/lib64` and `/apex/com.android.runtime/...` across versions, so comparing paths would report
every modern device as hooked. There is a regression test for exactly that.

## 4. Confidence

No signal here is rated `high`, and that is deliberate. Every one depends on a name, a path, or a
runtime fact that an attacker with native access can influence. Three medium signals corroborating
each other reach `high` at the check level through the aggregator's normal rules — but no single
indicator earns it alone.

| Result                | Meaning                                                                                                                     |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `secure` + `high`     | Every probe ran; no indicator fired. The strongest statement available — and still not proof the process is uninstrumented. |
| `detected` + `high`   | Two or more independent signals agree.                                                                                      |
| `detected` + `medium` | One signal fired.                                                                                                           |
| `unknown` + `low`     | A probe was blocked. Inconclusive, not clean.                                                                               |

## 5. False positives

- **Legitimate instrumentation.** Some APM, crash-reporting and A/B-testing SDKs hook native or
  managed functions. `HOOK-003` may flag them, and it is not wrong to — the process genuinely is
  hooked. Whether that matters is the application's call.
- **Substring matching in memory maps.** `HOOK-001` matches map lines by substring, so an unrelated
  library whose name contains one of the markers would fire. Thread names are matched _exactly_ for
  this reason — `gmain` is a marker, `gmainthread` is not, and there is a test asserting that.
- **Class presence without activity.** A framework class being loadable does not prove it is doing
  anything, which is why it is one of three evidence kinds rather than sufficient alone.

## 6. False negatives

- A framework that renames its libraries and threads defeats `HOOK-001` and the name-matching parts
  of `HOOK-002`.
- An attacker who patches these detectors, the aggregator, or the JavaScript that calls them defeats
  everything here. This is not a hypothetical: it is the normal case for a determined adversary.
- Hooks placed on functions not in the checked symbol list are invisible to `HOOK-003`.
- `/proc` visibility restrictions blind `HOOK-001`; it then reports `indeterminate`, which turns the
  check into `unknown` rather than `secure`.

## 7. Known limitations

- Everything runs inside the process being attacked. That is the ceiling, and no amount of
  additional signals moves it.
- The signature lists date quickly. `signatureVersion` in the result metadata records which list
  produced a result.
- A real trust decision belongs on a server, informed by hardware-backed attestation. In-process
  hook detection informs that decision; it does not substitute for it.

This document deliberately does not describe how to defeat any of these checks.

## 8. Recommended application response

```ts
const hooks = await HookDetection.getStatus();

if (hooks.status === 'detected' && hooks.confidence === 'high') {
  // Proportionate: refuse high-value operations, require server-side
  // re-authentication, log a security event with the signal ids.
}
```

Because a determined attacker can defeat this check, the sensible design is to **treat a clean
result as worth little and a positive result as worth a lot**. Use it to raise friction on specific
operations, and put the actual gate on your server.

## 9. Tests

`android/src/test/java/com/rnsecurity/detectors/hook/HookDetectorsTest.kt` — 17 cases covering each
detector against an instrumented process, a clean process, partially blocked probes, the exact-match
thread-name rule, the bionic-path-independence rule, and a redirected symbol alongside unresolvable
ones.
