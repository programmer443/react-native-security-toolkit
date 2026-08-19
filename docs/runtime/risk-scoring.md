# Risk scoring

`SecurityToolkit.checkAll()` · methodology version `rnsec-risk-1`

> A score nobody can account for is a score nobody should act on. Every result carries the full
> arithmetic that produced it, and **a bare number is never emitted**.

## 1. The three properties

The risk engine is required to be, and is tested to be:

1. **Deterministic.** The same check results always produce the same score. No randomness, no clock,
   no network, no AI. §23 of the project brief forbids AI from influencing runtime scores, and it
   cannot here: `src/risk/` has no dependency through which it could.
2. **Explainable.** Every contributor is returned, ordered by influence.
3. **Versioned.** Weights live in one table stamped with `methodologyVersion`, so a score can always
   be traced to the rules that produced it.

## 2. The formula

```
score = clamp(0, 100, Σ(signal.points × confidenceMultiplier) + uncertaintyPenalty − mitigationCredits)
```

| Confidence | Multiplier |
| ---------- | ---------- |
| low        | 0.4        |
| medium     | 0.7        |
| high       | 1.0        |

Confidence multiplies because it is a property of the **evidence**, not of the consequence. A weak
observation of a severe condition should score below a strong one.

| Score  | Level      |
| ------ | ---------- |
| 0–19   | `minimal`  |
| 20–39  | `low`      |
| 40–59  | `medium`   |
| 60–79  | `high`     |
| 80–100 | `critical` |

## 3. Weights

Full table in [`src/risk/weights.ts`](../../packages/runtime/src/risk/weights.ts). The rough scale:

| Points | Meaning                                | Examples                                                                                     |
| ------ | -------------------------------------- | -------------------------------------------------------------------------------------------- |
| 35–40  | Alone justifies distrusting the device | Verified Boot unlocked, writable system partition, sandbox escape, wrong signing certificate |
| 20–30  | Strong indicator                       | `su` binary, Zygisk artefacts, injected library, hooking                                     |
| 10–15  | Real but ambiguous                     | Debugger attached, cleartext permitted, software-backed keys, no lock screen                 |
| 2–8    | Posture worth recording                | Test keys, developer options, proxy, VPN, no StrongBox                                       |

Two weightings are worth defending explicitly:

- **Emulation scores 5.** CI runs on emulators, QA runs on device farms, and Play Games runs Android
  apps on desktops. Scoring it meaningfully would flag an enormous number of legitimate sessions.
- **Proxy and VPN score 2.** Both are mainstream, and an attacker's interception proxy is
  indistinguishable from a user's ordinary Tuesday.

A signal with **no** weight entry scores a default of 10 rather than zero. Zero would let a newly
added detector fire with no effect on the score at all — the failure most likely to go unnoticed.

## 4. Uncertainty

A check reporting `unknown` adds **4 points**, capped at **12 in total**.

This follows from the rule that runs through the whole toolkit: `unknown` is not `secure`. A device
whose probes could not run has demonstrated less than one whose probes all ran clean, and the score
should say so. The cap exists because uncertainty is not compromise — a device with several
restricted probes must not reach a blocking level on ignorance alone.

For the same reason, **mitigation credits are awarded only for `secure`**, never for `unknown`. A
check that could not reach a verdict has demonstrated nothing and earns nothing.

| Check          | Credit when `secure` |
| -------------- | -------------------- |
| integrity      | −10                  |
| secureHardware | −8                   |
| biometrics     | −5                   |
| screen         | −3                   |

## 5. Development mode

With `developmentMode: true`, signals from the **debugger**, **emulator** and **simulator** checks
contribute nothing.

The results themselves are unchanged — the checks still report exactly what they saw, and the report
still contains every signal. Only the _score_ ignores them. Debuggers and emulators are where
software is built; scoring them in development produces a permanently alarming number that
developers learn to ignore, which costs more than it buys.

It suppresses development noise, not genuine findings: root, jailbreak, hooking and integrity are
scored normally in development mode, and there is a test asserting that.

## 6. Reading a score

```ts
const report = await SecurityToolkit.checkAll();

console.log(`Score: ${report.risk.score} (${report.risk.level})`);
for (const contributor of report.risk.contributors) {
  console.log(`  ${contributor.points > 0 ? '+' : ''}${contributor.points}  ${contributor.reason}`);
}
```

```
Score: 59.2 (medium)
  +35    Verified Boot reports an unlocked bootloader or an unverified boot chain
  +21    Executable su binary found in a location not present on an unmodified device
  +3.2   Build is signed with dev-keys rather than a vendor release key
```

## 7. `compromised` is a convenience, not a verdict

`SecurityReport.compromised` is `true` when the level is `high` or `critical`. It is a **derived
summary**, not an assertion that the device is definitely compromised — runtime checks cannot
establish that, and §4 of the project brief forbids claiming they can.

Read `risk.contributors` before acting on it. A score of 62 driven by three medium signals is a
different situation from one driven by a single hardware-backed detection, and the contributors say
which you have.

## 8. Changing weights

The golden-vector tests in `src/__tests__/riskEngine.test.ts` pin exact scores for fixed inputs.
Changing a weight **is meant to break them** — that is what makes it a deliberate, reviewable
decision rather than an accident. When you change one:

1. Update the weight and bump `RISK_METHODOLOGY_VERSION`.
2. Update the golden vectors, with the new arithmetic shown in the comments.
3. Note the change in `CHANGELOG.md`, since scores are part of the public contract.

## 9. Timeouts

`nativeTimeoutMs` is a budget for **one** check. `checkAll()` scales it by the number of checks it
runs, capped at 60 seconds.

This is not a detail. Applying a single-check budget to a batch of nine means they share what one
was allotted, and measured cold-start costs on Android reach roughly 1.7 seconds for root alone — so
the first launch after an install reports a timeout instead of a result. That was a real failure
observed on device, not a hypothetical.

## 10. Tests

`src/__tests__/riskEngine.test.ts` — 28 cases covering golden vectors, determinism across repeated
evaluation, clamping, the uncertainty penalty and its cap, credits only for `secure`, development
mode, contributor ordering, the unweighted-signal default, and every level boundary.
