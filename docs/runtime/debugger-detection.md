# Debugger detection (Android)

`DebuggerDetection.getStatus()` · `DebuggerDetection.isAttached()` · check id `debugger`

> A debugger is a development tool, not an attack. These signals fire constantly during normal
> development, and an application that blocks on them is impossible to work on. They are reported
> faithfully; deciding whether a debugger _matters_ belongs to the application.

## 1. What it detects

Three distinct conditions that are easy to conflate:

- a **JDWP debugger** attached to, or awaited by, this process;
- **another process ptrace-attached** to this one, which covers native debuggers and instrumentation
  the platform-level check does not see;
- the application being **built debuggable**, which is a build-configuration fact rather than a
  runtime event;
- **device posture**: whether developer options are enabled, and whether the device is configured to
  accept ADB connections over USB or the network.

## 2. How it works

Each detector reads one source through an injected probe and produces one signal. Signals are
combined by `SignalAggregator`: any blocked probe downgrades the check to `unknown`, never `secure`.

## 3. Signals

| ID                           | Indicator                                               | Confidence | Notes                                                                    |
| ---------------------------- | ------------------------------------------------------- | ---------- | ------------------------------------------------------------------------ |
| `RNSEC-ANDROID-DEBUGGER-001` | `Debug.isDebuggerConnected()` or `waitingForDebugger()` | high       | The platform's own view — and therefore what native access can influence |
| `RNSEC-ANDROID-DEBUGGER-002` | `TracerPid` ≠ 0 in `/proc/self/status`                  | high       | Catches native debuggers; also catches profilers                         |
| `RNSEC-ANDROID-DEBUGGER-003` | `FLAG_DEBUGGABLE` set on the application                | high       | True by definition in debug builds                                       |

Confidence is `high` for all three because each is an unambiguous observation. High confidence
describes the _evidence_, not how alarming the finding is — a debuggable debug build is a
high-confidence detection of something entirely normal.

## 4. Confidence

| Result              | Meaning                                                     |
| ------------------- | ----------------------------------------------------------- |
| `secure` + `high`   | No debugger attached, no tracer, release build.             |
| `detected` + `high` | At least one condition holds. Check `signals` to see which. |
| `unknown` + `low`   | A probe was blocked. Inconclusive, not clean.               |
| `error`             | The check failed. Never a verdict about the process.        |

## 5. False positives

- **Every debug build** trips `DEBUGGER-003`, and usually `DEBUGGER-001` as well.
- **Profilers and performance tools** attach as tracers and trip `DEBUGGER-002`.
- **Some device-management and accessibility tooling** can attach legitimately.
- **Developer options** (`DEBUGGER-004`) are enabled on a great many ordinary users' phones. This is
  the highest-volume false positive in the whole check, which is why it is weighted lowest.
- **USB debugging** (`DEBUGGER-005`) stays enabled on developer and QA devices indefinitely.

The intended handling is `developmentMode: true` plus a policy that ignores debugger signals in
development, rather than suppressing the signals themselves. The check should report what it saw;
the policy decides what that is worth.

## 6. False negatives

- `TracerPid` can be hidden on a device where `/proc` is under the attacker's control; the detector
  then reports `indeterminate` rather than "no tracer".
- A debugger attached after the check ran is not observed. These are point-in-time samples, not a
  monitor.
- Native debuggers that avoid `ptrace` entirely are not visible to `DEBUGGER-002`.

## 7. Known limitations

- All three signals are observed from inside the process, which is code an attacker with device
  control also controls. This is an inherent ceiling.
- The toolkit does **not** call `ptrace(PTRACE_TRACEME)` or otherwise try to _prevent_ debugger
  attachment. Anti-debugging countermeasures are hostile to legitimate development and profiling,
  break crash reporting, and are trivially bypassed. If that changes it will be an explicit opt-in
  with documented consequences, not a default.

This document deliberately does not describe how to defeat any of these checks.

## 8. Recommended application response

```ts
const debuggerStatus = await DebuggerDetection.getStatus();

if (debuggerStatus.status === 'detected' && !__DEV__) {
  // In a production build this is worth acting on: log a security event,
  // require re-authentication, or degrade high-value operations.
}
```

`isAttached()` returns a plain boolean for the common case. It returns `true` only for a `detected`
verdict — `unknown` returns `false`, because a boolean has nowhere to put "inconclusive". Use
`getStatus()` whenever that difference matters.

## 9. Tests

`android/src/test/java/com/rnsecurity/detectors/debugger/DebuggerDetectorsTest.kt` — 21 cases
covering each detector against an attached debugger, a clean process, a blocked probe, malformed
`/proc` output (truncated, missing `TracerPid`, unparseable value), an unreadable settings value,
and wireless debugging being absent rather than disabled. Every one of those must report
`indeterminate` rather than a negative verdict.
