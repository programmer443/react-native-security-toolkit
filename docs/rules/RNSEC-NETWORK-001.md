# RNSEC-NETWORK-001 — Cleartext HTTP endpoint

|                   |                                                            |
| ----------------- | ---------------------------------------------------------- |
| **Base severity** | high                                                       |
| **Confidence**    | high                                                       |
| **Categories**    | network                                                    |
| **Applies to**    | source and configuration files (documentation is excluded) |

## What it detects

A remote endpoint addressed with `http://`.

## Why it matters

Everything on an HTTP connection is readable and modifiable by anything on the path — the access
point, the operator, an on-path device. For a mobile application that includes the session token in
the request header.

## Vulnerable

```ts
const baseUrl = 'http://api.example-bank.com/v1';
```

## Secure

```ts
const baseUrl = 'https://api.example-bank.com/v1';
```

Keep the platform protections on: `android:usesCleartextTraffic="false"` with a Network Security
Config, and App Transport Security at its defaults on iOS.

## Standards

| Standard           | Identifiers                                                                            |
| ------------------ | -------------------------------------------------------------------------------------- |
| CWE                | CWE-319                                                                                |
| MASWE              | MASWE-0026                                                                             |
| MASVS              | MASVS-NETWORK-1                                                                        |
| MASTG verification | MASTG-TEST-0217, MASTG-TEST-0218, MASTG-TEST-0233 (Android); MASTG-TEST-0236 (network) |

## False positives it deliberately avoids

Most of this rule's work is _not_ reporting `http://` strings that are not endpoints:

- XML namespaces and DTD identifiers — `http://schemas.android.com/apk/res/android` is in every
  AndroidManifest.xml ever written.
- URLs inside comments, including multi-line licence headers. A link in an Apache header is a
  citation, not a request.
- `localhost`, `127.0.0.1`, `10.0.2.2` (the Android emulator's host alias), and private LAN ranges.
- RFC 2606 documentation domains (`example.com`, `example.org`, `example.net`).
- Documentation files are not scanned at all.

One finding per host per file: a base URL repeated across ten call sites is one decision to fix.

## Limitations

- A URL assembled at runtime (`` `${scheme}://${host}` ``) is not seen.
- Comment stripping does not model string literals, so a URL inside a string that also contains a
  `#` may be truncated. The trade is deliberate: not reporting every licence header is worth more.

## Suppression

```ts
// security-audit-ignore RNSEC-NETWORK-001 reason="on-device loopback to the bundled server"
```

## Tests

`packages/auditor/src/rules/__tests__/network.test.ts`
