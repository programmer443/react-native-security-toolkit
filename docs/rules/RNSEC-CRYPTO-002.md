# RNSEC-CRYPTO-002 — Predictable randomness used for a security value

|                   |                                          |
| ----------------- | ---------------------------------------- |
| **Base severity** | high                                     |
| **Confidence**    | high (parsed) / medium (textual, native) |
| **Categories**    | cryptography                             |
| **Applies to**    | JavaScript/TypeScript, Kotlin, Java      |

## What it detects

A non-cryptographic random source — `Math.random`, `Date.now`, `java.util.Random`,
`kotlin.random.Random` — producing a value whose **name** says it must be unpredictable: a token,
nonce, IV, salt, key, OTP, session id, verifier or seed.

## Why it matters

`Math.random` is seeded from and predictable within a JavaScript engine; an attacker who observes a
few outputs can predict the rest. A predictable token is an impersonation; a predictable IV or nonce
can break the confidentiality of the ciphertext it protects.

## Vulnerable

```ts
const sessionToken = Math.random().toString(36).slice(2);
```

## Secure

```ts
const bytes = new Uint8Array(32);
crypto.getRandomValues(bytes);
const sessionToken = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
```

Android: `SecureRandom`. iOS: `SecRandomCopyBytes`. Never seed a security value from a timestamp.

## Standards

| Standard           | Identifiers                                                                        |
| ------------------ | ---------------------------------------------------------------------------------- |
| CWE                | CWE-338, CWE-330                                                                   |
| MASWE              | MASWE-0012                                                                         |
| MASVS              | MASVS-CRYPTO-1                                                                     |
| MASTG verification | MASTG-TEST-0204, MASTG-TEST-0205 (Android); MASTG-TEST-0311, MASTG-TEST-0349 (iOS) |

## False positives it deliberately avoids

`Math.random` is the right tool for a shuffle, a jitter or a placeholder, and flagging every call is
how a rule gets switched off — taking the real findings with it. The rule fires only when the
enclosing name is security-relevant, and never when it contains a word like `jitter`, `animation`,
`shuffle`, `mock` or `placeholder`.

## Limitations

- Entirely name-driven. `const x = Math.random()` later used as a token is invisible; a data-flow
  analysis would be needed, and is not what this engine does.
- Swift is not covered: `SystemRandomNumberGenerator` and `arc4random` are cryptographically secure,
  so there is no equivalent default to warn about.

## Suppression

```ts
// security-audit-ignore RNSEC-CRYPTO-002 reason="display-only identifier, never used for auth"
```

## Tests

`packages/auditor/src/rules/__tests__/crypto.test.ts`
