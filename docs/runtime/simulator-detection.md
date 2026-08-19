# Simulator detection (iOS)

`SimulatorDetection.getStatus()` · `SimulatorDetection.isSimulator()` · check id `simulator`

> Running on a simulator is **not** a compromise. It is where nearly all development and much
> automated testing happens. This check exists so an application can tell a simulated environment
> from a physical one — not so it can refuse to run in one.

## 1. What it detects

Whether the process is running on the iOS Simulator.

## 2. Why it earns its own check

Two reasons beyond reporting the fact:

1. **Other checks depend on it.** [Jailbreak detection](jailbreak-detection.md) returns
   `unavailable` with reason `simulator`, and the iOS parent-process debugger heuristic returns
   `indeterminate` there. Both would otherwise produce false positives on every development run.
2. **It is genuinely reliable**, which almost nothing else in this toolkit is.

## 3. Signal

| ID                        | Indicator                    | Confidence |
| ------------------------- | ---------------------------- | ---------- |
| `RNSEC-IOS-SIMULATOR-001` | Running on the iOS Simulator | high       |

Uses the compile-time `targetEnvironment(simulator)` flag, with `SIMULATOR_DEVICE_NAME` as a runtime
cross-check for a binary built for a device but running somewhere unexpected.

## 4. Confidence

The compile-time flag is exact, so this signal has **no `indeterminate` outcome** — there is nothing
to fail to read. That is asserted by a test, and it makes this the only check in the toolkit with no
inconclusive case.

Contrast with [Android emulator detection](emulator-detection.md), which infers from build strings,
device nodes and hardware profile against a signature list that ages, and which hardened emulator
images are built to defeat. The two are not comparable in reliability, and the docs do not pretend
otherwise.

## 5. False positives and negatives

There are no meaningful ones. A binary compiled for the simulator runs on the simulator.

The only edge worth noting: this reports the _environment_, not the _device_. A physical device
attached to Xcode is still a physical device, and this check correctly says so — use
[debugger detection](debugger-detection-ios.md) for that question.

## 6. Recommended application response

```ts
if (await SimulatorDetection.isSimulator()) {
  // Reasonable: skip hardware-dependent flows, use test fixtures, relax a
  // policy that would otherwise block development.
  // Unreasonable: refuse to run. This is where your developers work.
}
```

## 7. Tests

`ios/EngineTests/SimulatorDetectorsTests.swift` — 3 cases, including an assertion that the detector
never produces an `indeterminate` outcome.
