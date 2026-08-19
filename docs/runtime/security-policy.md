# Security policy

`SecurityToolkit.evaluate(policy)`

> **The toolkit returns a decision and does nothing else.** It will not block a user, terminate the
> process, show UI, or make a network request. What to do about a denial is the application's
> decision.

## 1. Why there is no kill switch

§73 of the project brief forbids automatic termination, and it is the right design regardless.

An in-process kill switch is **trivially bypassed by the attacker it is aimed at** — someone running
a hooking framework can patch out the call before it executes — while reliably punishing developers,
QA, custom-ROM users and anyone whose device tripped a false positive. It trades a real cost against
an imaginary benefit.

The useful version of this control lives on your server, informed by hardware-backed attestation.
These signals raise friction locally; they are not the gate.

## 2. Shape

```ts
const decision = await SecurityToolkit.evaluate({
  blockOnRoot: true,
  blockOnJailbreak: true,
  blockOnHooking: true,
  minimumRiskLevel: 'high',
  minimumConfidence: 'high',
});

if (!decision.allowed) {
  for (const reason of decision.reasons) {
    log(reason.code, reason.signalIds);
  }
}
```

Every field is optional, and an **empty policy allows everything**. That is deliberate: the default
is to report, not to deny.

## 3. Options

| Option                    | Denies when                                      |
| ------------------------- | ------------------------------------------------ |
| `blockOnRoot`             | The `root` check reports `detected`              |
| `blockOnJailbreak`        | The `jailbreak` check reports `detected`         |
| `blockOnDebugger`         | The `debugger` check reports `detected`          |
| `blockOnHooking`          | The `hooks` check reports `detected`             |
| `blockOnIntegrityFailure` | The `integrity` check reports `detected`         |
| `minimumRiskLevel`        | Risk reaches that level or above                 |
| `requireSecureHardware`   | `secureHardware` is anything other than `secure` |
| `requireStrongBiometrics` | `biometrics` is anything other than `secure`     |
| `minimumConfidence`       | — (a filter, see §4)                             |

## 4. `minimumConfidence` is the false-positive control

Detections below the configured floor are **still in the report** — they simply do not block:

```ts
// Log everything; block only on corroborated evidence.
const decision = await SecurityToolkit.evaluate({
  blockOnRoot: true,
  minimumConfidence: 'high',
});
```

This is the practical answer to the tension running through this whole toolkit. Root detection has
real false positives — developer devices, custom ROMs, unusual OEM builds — and a payment flow can
demand corroborated `high`-confidence evidence before denying, while a security log still records
the `low`-confidence hits.

Defaults to `'low'`, meaning any detection blocks.

## 5. `unknown` never blocks a detection rule, but does fail a requirement

Two rules that look inconsistent but are not:

- **`blockOnRoot` and friends only fire on `detected`.** An `unknown` result is inconclusive, and
  blocking on it would make every device with a restricted probe unusable.
- **`requireSecureHardware` and `requireStrongBiometrics` fail on anything but `secure`**, including
  `unknown`.

The difference is the direction of the claim. "Root was detected" needs evidence to act on. "This
device has hardware-backed key storage" is a requirement, and a requirement that cannot be shown to
hold has not been met — treating "we could not tell" as satisfaction would make it meaningless.

## 6. The decision

```ts
interface PolicyDecision {
  allowed: boolean;
  reasons: readonly PolicyReason[]; // every failure, not just the first
  risk: SecurityRisk; // the score and its contributors
  report: SecurityReport; // every check result
  evaluatedAt: string;
}
```

Each reason carries `signalIds`, so a denial can be logged with the exact evidence behind it rather
than as an opaque refusal.

## 7. What to actually do with a denial

The brief lists the sensible responses, and they are all _proportionate_:

- block a specific sensitive operation, not the whole application;
- require re-authentication;
- disable high-value features (payments, KYC) while leaving the rest working;
- show a warning;
- log a security event with the signal ids;
- terminate the session server-side;
- ask the user to remediate their device.

Refusing to launch is rarely on that list. It is the response most likely to hurt someone who was
not attacking you.

## 8. A worked example

```ts
SecurityToolkit.configure({
  developmentMode: __DEV__,
  integrity: {
    signingCertificateSha256: ['A1:B2:…'],
    expectedPackageName: 'com.example.app',
    expectedBundleIdentifier: 'com.example.app',
  },
});

const decision = await SecurityToolkit.evaluate({
  blockOnRoot: true,
  blockOnJailbreak: true,
  blockOnHooking: true,
  blockOnIntegrityFailure: true,
  minimumConfidence: 'high',
});

if (!decision.allowed) {
  await analytics.securityEvent({
    codes: decision.reasons.map((reason) => reason.code),
    signals: decision.reasons.flatMap((reason) => reason.signalIds),
    score: decision.risk.score,
  });
  disableHighValueOperations();
}
```

Note `developmentMode: __DEV__`: the checks still report everything they see, but debugger and
emulator signals stop contributing to the score, so a developer's machine does not sit permanently
at `critical`.

## 9. Tests

`src/__tests__/policyEngine.test.ts` — 17 cases covering each blocking rule, the confidence floor in
both directions, risk thresholds, capability requirements failing on `unknown`, accumulation of
multiple reasons, and that the decision is frozen and mutates nothing.
