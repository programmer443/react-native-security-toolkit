# RNSEC-WEBVIEW-001 — Unsafe WebView configuration

|                   |                                           |
| ----------------- | ----------------------------------------- |
| **Base severity** | high (medium for narrower cases)          |
| **Confidence**    | high (medium for injected-script case)    |
| **Categories**    | webview                                   |
| **Applies to**    | JSX/TSX, Kotlin, Java, Swift, Objective-C |

## What it detects

| Configuration                                                                        | Why it matters                                                          |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| `originWhitelist={['*']}`                                                            | Any page the WebView reaches runs with the WebView's privileges         |
| `allowFileAccess`, `allowFileAccessFromFileURLs`, `allowUniversalAccessFromFileURLs` | Loaded content can reach the file system                                |
| `mixedContentMode="always"` / `MIXED_CONTENT_ALWAYS_ALLOW`                           | An HTTPS page may load HTTP scripts, which an on-path attacker replaces |
| `addJavascriptInterface`                                                             | Exposes a native object to whatever page is loaded                      |
| Injected script with no origin restriction                                           | The script runs in a page the application may not have chosen           |

## Why it matters

A WebView is a browser inside the application, holding the application's identity. Content it loads
can reach whatever the WebView is allowed to reach — local files, native bridges, the session.

## Vulnerable

```tsx
<WebView originWhitelist={['*']} javaScriptEnabled allowFileAccess source={{ uri }} />
```

## Secure

```tsx
<WebView
  originWhitelist={['https://app.example.com']}
  javaScriptEnabled={false}
  allowFileAccess={false}
  mixedContentMode="never"
  source={{ uri }}
/>
```

Handle everything outside the allow-list in the system browser via `onShouldStartLoadWithRequest`,
and treat every message from the page as untrusted input.

## Standards

| Standard           | Identifiers                                                                                             |
| ------------------ | ------------------------------------------------------------------------------------------------------- |
| CWE                | CWE-749, CWE-79, CWE-94                                                                                 |
| MASWE              | MASWE-0033 (native functionality exposed), MASWE-0034 (local resources), MASWE-0035 (untrusted content) |
| MASVS              | MASVS-PLATFORM-2                                                                                        |
| MASTG verification | MASTG-TEST-0250, MASTG-TEST-0251, MASTG-TEST-0252 (Android); MASTG-TEST-0333 (iOS)                      |

## False positives it deliberately avoids

- Explicit `false` values are not findings.
- Components that merely accept a similar prop are ignored; the element name must end in `WebView`.
- A restricted `originWhitelist` is exactly the fix, and is never reported.

## Limitations

- Only literal attribute values are read. `<WebView {...props} />` hides its configuration from the
  rule.
- The native pass is textual: settings applied through a helper, or on an object the file does not
  name, are missed.
- A safe configuration in one file and a dangerous one in another is judged per file.

## Suppression

```tsx
{
  /* security-audit-ignore RNSEC-WEBVIEW-001 reason="renders bundled offline help only" */
}
```

## Tests

`packages/auditor/src/rules/__tests__/webviewAndDeepLinks.test.ts`
