# Secure hardware (iOS)

`SecureHardware.getStatus()` · check id `secureHardware`

> **A capability report, not a threat detection.** `detected` means _a weakness indicator fired_.
>
> And the reverse: a device having a Secure Enclave says **nothing** about whether this application
> uses it, or uses it correctly. `secure` means the hardware is available. It does not mean your data
> is safe.
>
> See [secure-hardware.md](secure-hardware.md) for the Android signals under the same check id.

## 1. What it detects

- whether a **Secure Enclave key can actually be created**;
- whether the **keychain is usable** by this application.

## 2. Why a key is created rather than a flag read

`RNSEC-IOS-HARDWARE-001` creates a non-permanent Secure Enclave key and lets it fall out of scope.
Capability flags describe what a device _has_; only creating a key tells you what **your** keys will
get, which is the question an application is actually asking.

The key is created with `kSecAttrIsPermanent: false`, so nothing is left behind — there is no
keychain entry to clean up.

## 3. Signals

| ID                       | Indicator                                 | Confidence |
| ------------------------ | ----------------------------------------- | ---------- |
| `RNSEC-IOS-HARDWARE-001` | Secure Enclave key generation unavailable | **high**   |
| `RNSEC-IOS-HARDWARE-002` | Keychain could not be written to          | medium     |

`HARDWARE-002` is unusual among these signals in that it usually indicates a **provisioning problem**
— a missing keychain-sharing entitlement, most often — rather than a device weakness. It is reported
because an application that cannot use the keychain will fall back to something worse.

## 4. Confidence

| Result                | Meaning                                      |
| --------------------- | -------------------------------------------- |
| `secure` + `high`     | Secure Enclave available, keychain usable.   |
| `detected` + `high`   | No Secure Enclave. Design around it.         |
| `detected` + `medium` | Keychain unusable — check your entitlements. |
| `unknown` + `low`     | A capability could not be determined.        |

## 5. False positives and negatives

- **Older devices** genuinely lack a Secure Enclave; that is a fact, not a fault.
- A **compromised device can lie**. Everything here is a claim the device makes about itself, and
  **App Attest**, verified server-side, is the only thing that turns such claims into evidence.

## 6. Known limitations

The check reports platform capability. It cannot see whether your application stores its secrets in
the keychain, in `UserDefaults`, or in a plain file — and a Secure Enclave next to a plaintext token
file is not a secure application.

## 7. Recommended application response

```ts
const hardware = await SecureHardware.getStatus();

const noSecureEnclave = hardware.signals.some(
  (signal) => signal.id === 'RNSEC-IOS-HARDWARE-001' && signal.detected
);

if (noSecureEnclave) {
  // Reasonable: keep less material on the device, shorten token lifetimes,
  // require server-side re-authentication more often.
}
```

## 8. Tests

`ios/EngineTests/CapabilityDetectorsTests.swift` — 5 cases covering available and unavailable Secure
Enclave, an unusable keychain, and unreadable probes.
