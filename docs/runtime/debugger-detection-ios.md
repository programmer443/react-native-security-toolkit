# Debugger detection (iOS)

`DebuggerDetection.getStatus()` · `DebuggerDetection.isAttached()` · check id `debugger`

> A debugger is a development tool, not an attack. These signals are reported faithfully; deciding
> whether a debugger _matters_ belongs to the application.
>
> See [debugger-detection.md](debugger-detection.md) for the Android signals under the same check id.

## 1. What it detects

- whether the **kernel reports this process as traced**;
- whether the process has an **unexpected parent**, suggesting it was launched by something other
  than the system launcher.

## 2. Everything here is public API

`sysctl` with `KERN_PROC` is public, documented, and App Store safe. It reports the `P_TRACED` flag —
the same fact `ptrace` would give — without the risk.

**`ptrace(PT_DENY_ATTACH)` is deliberately absent.** It is not in the public iOS headers, needs
`dlsym` to reach, has a history of App Review friction, and is a _mitigation_ rather than a detection:
it tries to stop debugging rather than report it. Anti-debugging countermeasures also break
legitimate profiling and crash reporting. If it ever ships it will be opt-in, off by default, and
documented as a review risk — never a default.

The same applies to `fork()`-based jailbreak probes, which are absent for the same reasons.

## 3. Signals

| ID                       | Indicator                                         | Confidence | Notes                                     |
| ------------------------ | ------------------------------------------------- | ---------- | ----------------------------------------- |
| `RNSEC-IOS-DEBUGGER-001` | Kernel reports the process as traced (`P_TRACED`) | high       | Works on device and simulator             |
| `RNSEC-IOS-DEBUGGER-002` | Parent process is not the system launcher         | medium     | `indeterminate` on the simulator — see §4 |

`RNSEC-IOS-DEBUGGER-003` is reserved for `PT_DENY_ATTACH` should it ever ship as an opt-in. The ID is
held so it cannot be reused.

## 4. The simulator exception

`DEBUGGER-002` reports `indeterminate` on the simulator rather than a verdict. Simulated applications
are children of `launchd_sim`, not `launchd`, so the "unexpected parent" heuristic fires on **every
simulator run**. A signal that cries wolf during development is one developers learn to ignore, so it
declines to answer instead.

`DEBUGGER-001` still answers on the simulator — you can attach Xcode to a simulated app, and that is
a real observation. There is a test for each of these behaviours.

## 5. Confidence

| Result                | Meaning                                                  |
| --------------------- | -------------------------------------------------------- |
| `secure` + `high`     | Not traced, launched normally.                           |
| `detected` + `high`   | The kernel says this process is traced.                  |
| `detected` + `medium` | Only the parent-process heuristic fired.                 |
| `unknown` + `low`     | A probe was blocked, or the simulator exception applied. |

## 6. False positives

- **Every Xcode debug session** trips `DEBUGGER-001`. That is correct, and expected.
- **Profilers and instrumentation tools** attach as tracers.
- **TestFlight and CI environments** can produce unusual parent processes.

Handle these with `developmentMode: true` and a policy that disregards debugger signals in
development, rather than suppressing the signals themselves. The check should report what it saw; the
policy decides what that is worth.

## 7. False negatives

- A debugger attached _after_ the check ran is not observed. These are point-in-time samples, not a
  monitor.
- On a jailbroken device the kernel flags themselves are within an attacker's reach.

## 8. Recommended application response

```ts
const debuggerStatus = await DebuggerDetection.getStatus();

if (debuggerStatus.status === 'detected' && !__DEV__) {
  // In a production build this is worth acting on: log a security event,
  // require re-authentication, or degrade high-value operations.
}
```

## 9. Tests

`ios/EngineTests/DebuggerDetectorsTests.swift` — 7 cases covering traced and untraced processes,
unexpected parents, unreadable probes, and both halves of the simulator exception.
