# Biometric capability (iOS)

`BiometricSecurity.getStatus()` · check id `biometrics`

> **No biometric data is read, stored, transmitted or exposed by this check, and none is available to
> it.** `LAContext` reports availability and a biometry type; nothing here can identify a user. A test
> asserts that signal metadata carries nothing beyond those.
>
> See [biometrics.md](biometrics.md) for the Android signals under the same check id.

## 1. What it detects

- whether **biometric authentication can be evaluated** right now, and if not, why;
- which **biometry type** the device supports;
- whether a **device passcode** is set.

## 2. An unenrolled device is not an insecure device

Many people deliberately use a passcode and no biometric, and that is a perfectly good choice. These
signals exist so an application can decide whether biometric authentication is a viable gate — not so
it can nag someone into enrolling a face they do not want to enrol.

The one unambiguous weakness here is `BIOMETRIC-003`: without a passcode there is no lock screen,
biometric enrolment is impossible, and `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` cannot be
used.

## 3. Signals

| ID                        | Indicator                                     | Confidence |
| ------------------------- | --------------------------------------------- | ---------- |
| `RNSEC-IOS-BIOMETRIC-001` | Biometric authentication not currently usable | **high**   |
| `RNSEC-IOS-BIOMETRIC-002` | Device reports no biometry type               | medium     |
| `RNSEC-IOS-BIOMETRIC-003` | No device passcode set                        | **high**   |

### The reason matters as much as the verdict

`BIOMETRIC-001` reports _why_ biometrics are unusable, because each cause calls for a different
response:

| Reason             | What an application should do                           |
| ------------------ | ------------------------------------------------------- |
| `not-available`    | No hardware. Permanent — design around it.              |
| `not-enrolled`     | The user can fix this in seconds. Offer, do not demand. |
| `lockout`          | Temporary, after failed attempts. Retry later.          |
| `passcode-not-set` | The floor is missing; see `BIOMETRIC-003`.              |

`biometryType` is only populated by `LAContext` **after** `canEvaluatePolicy` has been called, so one
evaluated context is reused for every question.

## 4. Confidence

| Result                | Meaning                                          |
| --------------------- | ------------------------------------------------ |
| `secure` + `high`     | Biometrics usable, a type present, passcode set. |
| `detected` + `high`   | Biometrics unusable, or no passcode at all.      |
| `detected` + `medium` | No biometry hardware.                            |
| `unknown` + `low`     | The platform did not answer.                     |

## 5. False positives

- **Nothing enrolled** is a user preference far more often than a security problem.
- **`lockout`** is transient; re-checking later may give a different answer.
- **Managed and supervised devices** can report differently from a personal one.

## 6. Known limitations

Capability only. Whether your application actually uses biometric authentication, binds it to a
keychain item, or handles `evaluatedPolicyDomainState` changes when enrolment changes, is invisible
here.

## 7. Recommended application response

```ts
const biometrics = await BiometricSecurity.getStatus();

const noPasscode = biometrics.signals.some(
  (signal) => signal.id === 'RNSEC-IOS-BIOMETRIC-003' && signal.detected
);

if (noPasscode) {
  // The only signal here worth acting on firmly.
}
```

Do not gate access on biometric enrolment. Offer biometrics where available, fall back to a device
passcode, and put the real gate on your server.

## 8. Tests

`ios/EngineTests/CapabilityDetectorsTests.swift` — 7 cases including one per unavailability reason,
and an assertion that no signal's metadata carries anything beyond a reason, a type and a boolean.
