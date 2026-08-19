# RNSEC-IOS-PLIST-001 — App Transport Security weakened

|                   |                                                                                     |
| ----------------- | ----------------------------------------------------------------------------------- |
| **Base severity** | high (global), medium (web content, per-domain, TLS version), low (forward secrecy) |
| **Confidence**    | high                                                                                |
| **Categories**    | ios, network, configuration                                                         |
| **Applies to**    | `Info.plist`                                                                        |

## What it detects

| Key                                              | Severity                                 |
| ------------------------------------------------ | ---------------------------------------- |
| `NSAllowsArbitraryLoads`                         | high — ATS off for the whole application |
| `NSAllowsArbitraryLoadsInWebContent`             | medium — WebViews may load cleartext     |
| `NSExceptionAllowsInsecureHTTPLoads`             | medium — cleartext to one domain         |
| `NSExceptionMinimumTLSVersion` below 1.2         | medium                                   |
| `NSExceptionRequiresForwardSecrecy` set to false | low                                      |

## Why it matters

ATS is on by default and requires HTTPS with TLS 1.2 or better. Every one of these keys is something
a developer added deliberately, usually to make one endpoint work, and which then applies far more
broadly than intended.

## Vulnerable

```xml
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsArbitraryLoads</key>
  <true/>
</dict>
```

## Secure

Leave ATS alone. Where a single third-party host is genuinely the obstacle, scope the exception to
that host:

```xml
<key>NSExceptionDomains</key>
<dict>
  <key>legacy.partner.com</key>
  <dict>
    <key>NSExceptionMinimumTLSVersion</key>
    <string>TLSv1.2</string>
  </dict>
</dict>
```

App Review also asks for a justification for `NSAllowsArbitraryLoads`, which is worth knowing before
a submission deadline.

## Standards

| Standard           | Identifiers                                                                       |
| ------------------ | --------------------------------------------------------------------------------- |
| CWE                | CWE-319                                                                           |
| MASWE              | MASWE-0026                                                                        |
| MASVS              | MASVS-NETWORK-1                                                                   |
| MASTG verification | MASTG-TEST-0217, MASTG-TEST-0218 (Android equivalents); MASTG-TEST-0236 (network) |

## False positives it deliberately avoids

- **React Native's Metro exception.** A debug `Info.plist` allows cleartext to `localhost` so the
  bundler can serve the bundle. That is expected, and exceptions for `localhost`, `127.0.0.1`, `::1`
  and `.local` are never reported.
- Explicit `<false/>` values are not findings.
- The severity gradation is deliberate: reporting a scoped exception as loudly as a global one pushes
  people towards the blunt fix.

## Limitations

- On modern iOS an `NSExceptionDomains` entry takes precedence over the global flag; the rule still
  reports the global flag, because it applies wherever no exception matches and relying on that
  ordering is fragile.
- Only `Info.plist` files are read. ATS can also be affected by build settings and by frameworks with
  their own plists.
- Domain names are recovered from a dotted key path, so an exception key nested unusually deep may be
  reported without the domain name.

## Suppression

```xml
<!-- security-audit-ignore RNSEC-IOS-PLIST-001 reason="debug plist only, release build has ATS defaults" -->
```

## Tests

`packages/auditor/src/rules/__tests__/platformConfiguration.test.ts`
