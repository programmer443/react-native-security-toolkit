# RNSEC-NETWORK-002 — TLS validation disabled or weakened

|                   |                                                       |
| ----------------- | ----------------------------------------------------- |
| **Base severity** | critical (high for indicators that may be legitimate) |
| **Confidence**    | very-high to medium, per indicator                    |
| **Categories**    | network                                               |
| **Applies to**    | every file the auditor reads                          |

## What it detects

| Indicator                                                              | Confidence                                   |
| ---------------------------------------------------------------------- | -------------------------------------------- |
| `rejectUnauthorized: false`                                            | very-high                                    |
| `NODE_TLS_REJECT_UNAUTHORIZED=0`                                       | very-high                                    |
| A hostname verifier returning `true`, or `ALLOW_ALL_HOSTNAME_VERIFIER` | high                                         |
| A socket factory built from a trust-all trust manager                  | high                                         |
| A hand-written `X509TrustManager`                                      | medium — pinning is implemented this way too |
| `URLCredential(trust:)` in a challenge handler (iOS)                   | medium                                       |

## Why it matters

This converts HTTPS into HTTP with extra steps. An attacker on the path presents any certificate,
decrypts the session, reads credentials and modifies responses the application trusts.

It is almost always introduced deliberately — to make a development proxy or a staging certificate
work — and then survives into release. Nobody sets out to ship it, which is exactly why it needs a
rule.

## Vulnerable

```ts
const agent = new https.Agent({ rejectUnauthorized: false });
```

```kotlin
builder.setHostnameVerifier { _, _ -> true }
```

## Secure

Remove the override and let the platform validate the chain. If a development certificate is the
reason, install its CA on the test device, or scope the exception to debug builds through a Network
Security Config or an ATS exception — never in shared code.

For extra assurance use certificate pinning **with backup pins and a rotation plan**, not a disabled
check. Pinning without a rotation plan is an outage waiting for a certificate renewal.

## Standards

| Standard           | Identifiers                                                 |
| ------------------ | ----------------------------------------------------------- |
| CWE                | CWE-295, CWE-297                                            |
| MASWE              | MASWE-0027                                                  |
| MASVS              | MASVS-NETWORK-1                                             |
| MASTG verification | MASTG-TEST-0234, MASTG-TEST-0282, MASTG-TEST-0283 (Android) |

## False positives it deliberately avoids

- Commented-out overrides.
- Language-scoped patterns: a JavaScript `new HostnameVerifier()` is not an Android hostname verifier.
- One finding per distinct indicator per file, rather than one per occurrence.

## Limitations

- A custom `X509TrustManager` is reported at `medium` because certificate pinning uses the same
  shape. The finding says "verify this validates the chain", not "this is broken".
- Whether an empty `checkServerTrusted` body exists is not determined — Kotlin and Java are not
  parsed, so the rule sees the declaration, not the implementation.

## Suppression

```kotlin
// security-audit-ignore RNSEC-NETWORK-002 reason="pinning trust manager, chain validated in checkServerTrusted"
```

## Tests

`packages/auditor/src/rules/__tests__/network.test.ts`
