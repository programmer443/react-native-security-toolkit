# RNSEC-CRYPTO-001 — Broken or misused cryptographic primitive

|                   |                                       |
| ----------------- | ------------------------------------- |
| **Base severity** | high (medium for unauthenticated CBC) |
| **Confidence**    | high (low for unauthenticated CBC)    |
| **Categories**    | cryptography                          |
| **Applies to**    | every file the auditor reads          |

## What it detects

| Indicator                   | Why                                                                           |
| --------------------------- | ----------------------------------------------------------------------------- |
| MD5                         | Practical collision attacks; unusable where integrity or authenticity matters |
| SHA-1                       | Practical collision attacks; unsuitable for signatures or password handling   |
| DES, Triple DES             | 56-bit key / 64-bit block; withdrawn by NIST                                  |
| RC4                         | Keystream biases; prohibited in TLS by RFC 7465                               |
| ECB mode                    | Identical plaintext blocks produce identical ciphertext blocks                |
| `Cipher.getInstance("AES")` | On Android this **is** ECB, and the code does not say so                      |
| CBC with no MAC             | Confidentiality without integrity; padding-oracle territory                   |

## Why it matters

Data protected by a broken primitive is not protected. Depending on the primitive an attacker may
forge a value that passes an integrity check, recover plaintext structure, or brute-force the key.

## Vulnerable

```kotlin
val digest = MessageDigest.getInstance("MD5").digest(input)
val cipher = Cipher.getInstance("AES")           // silently AES/ECB/PKCS5Padding
```

## Secure

```kotlin
val digest = MessageDigest.getInstance("SHA-256").digest(input)
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
```

Use an authenticated mode with a key from the Android Keystore or the iOS Keychain, and a unique
nonce per message. For passwords use a memory-hard KDF (Argon2id, scrypt, bcrypt) — never a bare
hash. **Never** implement the construction by hand (§34).

## Standards

| Standard           | Identifiers                                                       |
| ------------------ | ----------------------------------------------------------------- |
| CWE                | CWE-327, CWE-328, CWE-326                                         |
| MASWE              | MASWE-0007 (encryption), MASWE-0008 (hashing)                     |
| MASVS              | MASVS-CRYPTO-1                                                    |
| MASTG verification | MASTG-TEST-0221, MASTG-TEST-0232 (Android); MASTG-TEST-0210 (iOS) |

## False positives it deliberately avoids

- Commented-out code is not a call.
- The implicit-ECB rule applies only to Kotlin and Java, where the default holds. `createCipheriv('aes-256-gcm', …)`
  in JavaScript is untouched.
- One finding per weakness per line, however many times the pattern appears on it.

## Limitations

- MD5 and SHA-1 are legitimate as non-security checksums — ETags, cache keys, content addressing. The
  rule cannot see intent, so it reports and explains rather than assuming. Suppress with a reason
  where the use is genuinely non-security.
- Matching is textual, so a primitive selected through a variable (`getInstance(algorithm)`) is not
  seen.
- Unauthenticated CBC is reported at `low` confidence because the MAC may be applied elsewhere.

## Suppression

```kotlin
// security-audit-ignore RNSEC-CRYPTO-001 reason="content-addressing checksum, not a security control"
```

## Tests

`packages/auditor/src/rules/__tests__/crypto.test.ts`
