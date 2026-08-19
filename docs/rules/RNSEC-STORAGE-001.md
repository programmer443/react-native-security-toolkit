# RNSEC-STORAGE-001 — Sensitive data in unencrypted storage

|                   |                                                            |
| ----------------- | ---------------------------------------------------------- |
| **Base severity** | high                                                       |
| **Confidence**    | high (key and value both sensitive) / medium (one of them) |
| **Categories**    | storage                                                    |
| **Applies to**    | JavaScript/TypeScript, Kotlin, Java, Swift                 |

## What it detects

A credential, token or personal data written to storage the platform does not encrypt:
`AsyncStorage`, `localStorage`, MMKV, plain filesystem writes, `SharedPreferences`, `UserDefaults`.

The judgement is about **what is being stored**, read from two directions: the key the value is filed
under, and the name of the variable holding it.

## Why it matters

Unencrypted application storage is readable from a device backup, by forensic tooling, and by
anything with file access on a rooted or jailbroken device. Stored credentials outlive the session
that created them.

## Vulnerable

```ts
await AsyncStorage.setItem('refreshToken', refreshToken);
```

```kotlin
prefs.edit().putString("password", password).apply()
```

## Secure

```ts
import * as SecureStore from 'expo-secure-store';
await SecureStore.setItemAsync('refreshToken', refreshToken);
```

```kotlin
val prefs = EncryptedSharedPreferences.create(context, "secure", masterKey, scheme, scheme)
prefs.edit().putString("accessToken", accessToken).apply()
```

## Standards

| Standard           | Identifiers                                                                        |
| ------------------ | ---------------------------------------------------------------------------------- |
| CWE                | CWE-312, CWE-922                                                                   |
| MASWE              | MASWE-0001                                                                         |
| MASVS              | MASVS-STORAGE-1                                                                    |
| MASTG verification | MASTG-TEST-0207, MASTG-TEST-0287 (Android); MASTG-TEST-0299, MASTG-TEST-0300 (iOS) |

## False positives it deliberately avoids

§34 is explicit that not every `AsyncStorage` call is a vulnerability, and this rule is written
around that:

- Preferences — `theme`, `onboardingComplete`, `lastSyncedAt` — are never reported.
- Files that use an encrypted store (`expo-secure-store`, `react-native-keychain`,
  `EncryptedSharedPreferences`, Keychain) are recognised and left alone.
- Reads are not reported; only writes create the exposure.
- `keyboardHeight` and `passwordPlaceholder` are not credentials.

## Limitations

- Sensitivity is inferred from names. A token stored under the key `"k"` in a variable called `v` is
  invisible to this rule.
- The native passes are textual: the encrypted-store check looks at the whole file, so a file mixing
  encrypted and plain preference writes will under-report.
- Whether a custom wrapper encrypts is not known; only the recognised APIs are.

## Suppression

```ts
// security-audit-ignore RNSEC-STORAGE-001 reason="opaque server-issued id, not a credential"
```

## Tests

`packages/auditor/src/rules/__tests__/insecureStorage.test.ts`
