# RNSEC-LOG-001 — Sensitive data written to a log

|                   |                                                |
| ----------------- | ---------------------------------------------- |
| **Base severity** | medium                                         |
| **Confidence**    | high (parsed) / medium (textual or serialised) |
| **Categories**    | logging, privacy                               |
| **Applies to**    | every file the auditor reads                   |

## What it detects

A value whose name indicates a credential, token or personal data passed to a log sink:
`console.*`, `android.util.Log`, `System.out`, `println`, `NSLog`, `os_log`, `print`.

For JavaScript the argument is read from the AST — identifiers, member expressions, template
interpolations, shorthand object properties, and through `JSON.stringify`. For native languages the
line is read textually, with string _contents_ excluded so a message that merely mentions a
sensitive word is not a finding.

## Why it matters

Log output leaves the application boundary. It is readable over a debug bridge, is routinely
collected by crash reporters and analytics SDKs, and persists in system logs. A token in a log line
is a token in a place the application no longer controls.

## Vulnerable

```ts
console.log('signed in with token', accessToken);
console.debug('login', { refreshToken });
```

```kotlin
Log.d(TAG, "token=" + accessToken)
```

## Secure

```ts
console.log('signed in', { userId });
```

Log an identifier or a redacted form. Where a value is genuinely needed while debugging, gate the
statement behind a development flag and strip it from release builds — a ProGuard rule that removes
log calls on Android, a wrapper that compiles away outside `DEBUG` on iOS.

## Standards

| Standard           | Identifiers                                                                        |
| ------------------ | ---------------------------------------------------------------------------------- |
| CWE                | CWE-532, CWE-359                                                                   |
| MASWE              | MASWE-0005                                                                         |
| MASVS              | MASVS-STORAGE-2                                                                    |
| MASTG verification | MASTG-TEST-0203, MASTG-TEST-0231 (Android); MASTG-TEST-0296, MASTG-TEST-0297 (iOS) |

## False positives it deliberately avoids

§34 is explicit: do not flag every logging statement.

- `console.log('App mounted')` and `console.error('Failed to load profile', error)` are not findings.
- A sensitive word inside a _message_ — `Log.d(TAG, "session started")` — is prose, not data. Only
  values are considered, plus the interpolations inside Kotlin and Swift string templates.
- `tokenCount`, `tokenizer` and `publicKey` are not secrets.
- One finding per statement, however many sensitive arguments it has.

## Limitations

- Name-driven: `console.log(x)` where `x` holds a token is invisible.
- A custom logging wrapper (`logger.info(...)` on an application-specific object) is only matched by
  the generic `Logger.` pattern in native files, not in JavaScript.
- Redaction inside a logging helper is not detected, so a project with a redacting logger will see
  false positives. Suppress those with a reason, or disable the rule for that module.

## Suppression

```ts
// security-audit-ignore RNSEC-LOG-001 reason="logger redacts token-shaped values before writing"
```

## Tests

`packages/auditor/src/rules/__tests__/sensitiveLogging.test.ts`
