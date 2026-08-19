# Biometric capability (Android)

`BiometricSecurity.getStatus()` · check id `biometrics`

> **No biometric data is read, stored, transmitted or exposed by this check, and none is available
> to it.** The platform returns a status code; nothing here can identify a user, or say whose finger
> or face is enrolled. Signal metadata is restricted to the platform status code and derived
> booleans, and a test asserts that.

> Like [secure hardware](secure-hardware.md), this is a **capability report**. `detected` means a
> weakness indicator fired, not that an attack was found.

## 1. What it detects

- whether **strong (Class 3)** biometric authentication is usable;
- whether a biometric is **enrolled**, on devices that have the hardware;
- whether a **device credential** — PIN, pattern or password — is set at all.

## 2. An unenrolled device is not an insecure device

Plenty of people deliberately use a PIN and no biometric, and that is a perfectly good choice. These
signals exist so an application can decide whether biometric authentication is a viable gate — not
so it can nag a user into enrolling a fingerprint they do not want to enrol.

The one genuinely unambiguous weakness here is `BIOMETRIC-003`: with no device credential there is
no keyguard, biometric enrolment is impossible, and Keystore keys cannot require user
authentication.

## 3. Signals

| ID                            | Indicator                                   | Confidence | Minimum API |
| ----------------------------- | ------------------------------------------- | ---------- | ----------- |
| `RNSEC-RUNTIME-BIOMETRIC-001` | Class 3 biometric authentication not usable | **high**   | 30          |
| `RNSEC-RUNTIME-BIOMETRIC-002` | Hardware present but nothing enrolled       | medium     | 30          |
| `RNSEC-RUNTIME-BIOMETRIC-003` | No device credential set                    | **high**   | 23          |

### Why Class 3 specifically

Only Class 3 (strong) biometrics can gate an Android Keystore key. A device offering only weak
biometrics can show the user a prompt, but cannot bind that prompt to a key — which makes the
authentication decorative rather than enforceable. `BIOMETRIC-001` asks the question that matters.

### Why enrolment is a separate signal

Missing hardware and nothing-enrolled call for completely different responses: the first is
permanent and the application must design around it, the second the user can change in a few
seconds. Collapsing them into one signal would leave an application unable to tell "offer to enrol"
from "never offer this again".

For the same reason, `BIOMETRIC-002` **does not fire** when there is no biometric hardware. Telling
a user to enrol a fingerprint on a device with no fingerprint sensor is worse than saying nothing.

### The `USE_BIOMETRIC` permission

`BiometricManager.canAuthenticate()` requires `android.permission.USE_BIOMETRIC`. **This package
does not declare it.** A permission in a library manifest is merged into every consuming
application and appears in store review, which is the application author's decision, not ours — the
same reasoning as the `<queries>` declarations in [root detection](root-detection.md#7-package-visibility-rnsec-android-root-002).

Without it, `BIOMETRIC-001` and `BIOMETRIC-002` report `indeterminate` and say exactly why:

> Biometric capability could not be determined: the USE_BIOMETRIC permission is not declared by this
> application, so the platform refused the query

To enable them, add to your application's manifest:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
```

`BIOMETRIC-003` needs no permission and works regardless.

### No third-party dependency

This uses the platform `BiometricManager` rather than `androidx.biometric`, so the package adds no
dependency to consuming applications. The cost is that the authenticator-type query needs API 30;
below that the signals report `indeterminate` rather than guessing.

## 4. Confidence

| Result                | Meaning                                                        |
| --------------------- | -------------------------------------------------------------- |
| `secure` + `high`     | Class 3 biometrics usable, something enrolled, credential set. |
| `detected` + `high`   | No usable strong biometric, or no device credential at all.    |
| `detected` + `medium` | Hardware present, nothing enrolled.                            |
| `unknown` + `low`     | API level below 30, or the platform did not answer.            |

## 5. False positives

- **Nothing enrolled** is a user preference far more often than it is a security problem.
- **`ERROR_HW_UNAVAILABLE`** is frequently transient — the sensor is busy, or locked out after failed
  attempts. Re-checking later may give a different answer.
- **Work profiles and managed devices** can report differently from the personal profile.

## 6. False negatives

- A compromised device can misreport all of this. These are claims the platform makes about itself.
- The check reports capability at a point in time. A user can enrol or unenrol immediately after.

## 7. Known limitations

- Capability only. Whether your application actually _uses_ biometric authentication, binds it to a
  Keystore key, or handles `evaluatedPolicyDomainState`-style enrolment changes is invisible here.
- Class 3 availability does not guarantee a given sensor's quality; it is the platform's own
  classification.

## 8. Recommended application response

```ts
const biometrics = await BiometricSecurity.getStatus();

const noCredential = biometrics.signals.some(
  (signal) => signal.id === 'RNSEC-RUNTIME-BIOMETRIC-003' && signal.detected
);

if (noCredential) {
  // The only signal here worth acting on firmly: without a lock screen there is
  // no keyguard and no user-authentication-bound key storage.
}
```

Do not gate access on biometric enrolment. Offer biometrics where they are available, fall back to a
device credential where they are not, and put the real gate on your server.

## 9. Tests

`android/src/test/java/com/rnsecurity/detectors/biometric/BiometricDetectorsTest.kt` — 13 cases
covering each platform status code and the distinct reason it produces, the no-hardware case not
being reported as unenrolled, missing device credentials, API-level gates, and an assertion that no
signal's metadata carries anything beyond a status code and derived booleans.
