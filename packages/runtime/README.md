# react-native-security-toolkit

Runtime mobile security checks for React Native apps: root, jailbreak, debugger, emulator, hooking,
app integrity, secure hardware, biometrics, network posture and screen capture — on Android and iOS,
through a TurboModule, with **zero dependencies**.

Part of the [React Native Security Toolkit](https://github.com/programmer443/react-native-security-toolkit).

> **Pre-1.0, and not yet validated on physical devices.** The checks are implemented, unit-tested and
> documented, but have not been exercised against real rooted or jailbroken hardware. See
> [validation status](https://github.com/programmer443/react-native-security-toolkit/blob/main/docs/runtime/validation.md).

## Install

```sh
npm install react-native-security-toolkit
cd ios && pod install
```

React Native 0.79+ with the New Architecture, Android `minSdk` 24, iOS 15.1+. A native dependency
needs a rebuild — reloading Metro is not enough.

## Use

```ts
import { SecurityToolkit } from 'react-native-security-toolkit';

const report = await SecurityToolkit.checkAll();

report.risk.level; // 'minimal' | 'low' | 'medium' | 'high' | 'critical'
report.risk.contributors; // every signal that moved the score, and by how much
report.checks.root?.status; // 'secure' | 'detected' | 'unknown' | 'unavailable' | 'error'
```

Individual checks return the evidence behind the verdict:

```ts
import { RootDetection } from 'react-native-security-toolkit';

const root = await RootDetection.getStatus();
root.confidence; // raised only by corroborating signals
root.signals; // each signal, its identifier, and whether it fired
```

**The toolkit reports; your app decides.** Nothing here blocks a user, terminates the process or
shows UI:

```ts
const decision = await SecurityToolkit.evaluate({
  blockOnRoot: true,
  blockOnHooking: true,
  minimumRiskLevel: 'high',
  minimumConfidence: 'high', // ignore weak, uncorroborated detections
});
```

## What it looks like

<p align="center">
  <img src="https://raw.githubusercontent.com/programmer443/react-native-security-toolkit/main/docs/images/ios/posture.png" alt="Risk score of 5 out of 100, with every signal that contributed to it and by how many points" width="180">
  <img src="https://raw.githubusercontent.com/programmer443/react-native-security-toolkit/main/docs/images/ios/checks.png" alt="Nine checks, each showing how many of its signals fired and whether the verdict is clear, inconclusive or indicating" width="180">
  <img src="https://raw.githubusercontent.com/programmer443/react-native-security-toolkit/main/docs/images/ios/policy.png" alt="Policy toggles for root, jailbreak, hooking, integrity and debugger, evaluated against the current report" width="180">
</p>

<p align="center"><sub>The <a href="https://github.com/programmer443/react-native-security-toolkit/tree/main/example">example app</a> on the iOS Simulator: the risk score and its contributors, every check and its verdict, and a policy decision.</sub></p>

## What it will not tell you

- **No check here is bypass-proof.** These are defence-in-depth signals, not guarantees. An attacker
  who controls the device can defeat individual checks, and often several at once.
- **`unknown` is never `secure`.** A probe that could not run says so, rather than reporting a clean
  device.
- **Real trust decisions belong on your server**, informed by hardware-backed attestation — Play
  Integrity on Android, App Attest on iOS.

## Documentation

Every check is documented with its signals, confidence, false positives and negatives, platform
limitations, and what your app should do about a result:
[docs/runtime](https://github.com/programmer443/react-native-security-toolkit/tree/main/docs/runtime).

## Privacy

No telemetry, no analytics, no device identifiers, no hidden network requests. This package declares
no dependencies.

## Licence

MIT © Muhammad Ahmad
