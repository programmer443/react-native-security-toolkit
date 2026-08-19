# RNSEC-DEEPLINK-001 — Deep link handled without validation

|                   |                                            |
| ----------------- | ------------------------------------------ |
| **Base severity** | high (JS sinks) / medium (manifest)        |
| **Confidence**    | low (JS sinks) / high (manifest)           |
| **Categories**    | deep-links, android                        |
| **Applies to**    | JavaScript/TypeScript, AndroidManifest.xml |

## What it detects

**Unvalidated navigation.** A file that reads a URL from a deep link (`Linking.getInitialURL`, a
`url` event, `route.params`, `searchParams.get`) and passes a non-literal URL to `Linking.openURL`,
`WebBrowser.openBrowserAsync` or a similar sink.

**Unverified app links.** An Android `intent-filter` accepting `http`/`https` without
`android:autoVerify="true"`.

## Why it matters

A deep link is remote input: a web page, a message or another installed application can send one.
Following one without validation is an open redirect, and on Android an unverified filter can be
claimed by any other installed application — which then receives the link, including any
authorization code in it.

## Vulnerable

```ts
const url = await Linking.getInitialURL();
const next = new URL(url).searchParams.get('next');
await Linking.openURL(next);
```

```xml
<intent-filter>
  <data android:scheme="https" android:host="app.example.com" />
</intent-filter>
```

## Secure

```ts
const parsed = new URL(url);
if (parsed.protocol === 'https:' && ALLOWED_HOSTS.has(parsed.hostname)) {
  navigateToKnownRoute(parsed.pathname);
}
```

```xml
<intent-filter android:autoVerify="true">
  <data android:scheme="https" android:host="app.example.com" />
</intent-filter>
```

Publish an `assetlinks.json` for the domain so only your application can claim the link.

## Standards

| Standard           | Identifiers                                                                        |
| ------------------ | ---------------------------------------------------------------------------------- |
| CWE                | CWE-939                                                                            |
| MASWE              | MASWE-0029                                                                         |
| MASVS              | MASVS-PLATFORM-1                                                                   |
| MASTG verification | MASTG-TEST-0393, MASTG-TEST-0394 (Android); MASTG-TEST-0370, MASTG-TEST-0371 (iOS) |

## False positives it deliberately avoids

- A hardcoded destination is chosen by the developer, not the caller, and is never reported.
- A file that opens URLs but never reads a link is not a deep-link handler.
- Custom-scheme filters (`myapp://`) are not reported: they cannot be domain-verified, so demanding
  `autoVerify` there would be wrong.
- `<data>` elements are scoped to the filter they belong to, so a launcher activity does not inherit
  the schemes of a deep-link filter further down the manifest.

## Limitations

- The JavaScript half is a **heuristic at `low` confidence**. Whether validation happens elsewhere
  cannot be established without data-flow analysis. It says "review this", not "this is broken".
- iOS universal links are not checked; the equivalent configuration lives in an entitlements file and
  a server-side `apple-app-site-association`.

## Suppression

```ts
// security-audit-ignore RNSEC-DEEPLINK-001 reason="host allow-list applied in validateTarget()"
```

## Tests

`packages/auditor/src/rules/__tests__/webviewAndDeepLinks.test.ts`
