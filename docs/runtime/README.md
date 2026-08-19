# Runtime security checks

Checks that run inside your application, on the device. Each one reports **signals with confidence
and evidence** — never a bare boolean, and never a claim that a device is definitely clean.

| Check                            | Platforms     | Documentation                                                       |
| -------------------------------- | ------------- | ------------------------------------------------------------------- |
| Root detection                   | Android       | [root-detection.md](root-detection.md)                              |
| Jailbreak detection              | iOS           | [jailbreak-detection.md](jailbreak-detection.md)                    |
| Debugger detection               | Android · iOS | [android](debugger-detection.md) · [ios](debugger-detection-ios.md) |
| Emulator detection               | Android       | [emulator-detection.md](emulator-detection.md)                      |
| Simulator detection              | iOS           | [simulator-detection.md](simulator-detection.md)                    |
| Hook / instrumentation detection | Android · iOS | [android](hook-detection.md) · [ios](hook-detection-ios.md)         |
| App integrity                    | Android · iOS | [android](integrity.md) · [ios](integrity-ios.md)                   |
| Secure hardware                  | Android · iOS | [android](secure-hardware.md) · [ios](secure-hardware-ios.md)       |
| Biometrics                       | Android · iOS | [android](biometrics.md) · [ios](biometrics-ios.md)                 |
| Network posture                  | Android · iOS | [android](network-security.md) · [ios](network-security-ios.md)     |
| Screen capture                   | Android · iOS | [screen-security.md](screen-security.md)                            |

| Topic                                             | Documentation                            |
| ------------------------------------------------- | ---------------------------------------- |
| How the risk score is calculated                  | [risk-scoring.md](risk-scoring.md)       |
| Expressing what your app should do about a result | [security-policy.md](security-policy.md) |
| What has and has not been verified on hardware    | [validation.md](validation.md)           |

## How to read a check page

Every page answers the same questions: what the check detects, how it works, which signals it uses,
what confidence they carry, its **false positives and false negatives**, its platform limitations,
and what your application should do about a result.

Two conventions run through all of them:

- **`unknown` is not `secure`.** A probe that could not run produces `indeterminate`, and any
  indeterminate signal downgrades the whole check to `unknown`. Absence of evidence is never reported
  as evidence of absence.
- **Confidence comes from corroboration.** A single filesystem path is weak evidence, however severe
  root access would be. Confidence rises when independent signals agree.

## What none of these pages will claim

No check here is bypass-proof, and none of them can prove a device is uncompromised. They run inside
the process they protect, which means an attacker with code execution in that process can interfere
with the checks themselves. What they buy is cost: they raise the effort required from "attach and
go" to "attach, then hide".

Real trust decisions belong on a server, informed by hardware-backed attestation — Play Integrity on
Android, App Attest on iOS.
