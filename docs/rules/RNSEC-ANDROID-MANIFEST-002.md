# RNSEC-ANDROID-MANIFEST-002 — Exported component without a permission

|                   |                                      |
| ----------------- | ------------------------------------ |
| **Base severity** | medium (high for a content provider) |
| **Confidence**    | medium                               |
| **Categories**    | android, authorization               |
| **Applies to**    | `AndroidManifest.xml`                |

## What it detects

An `<activity>`, `<activity-alias>`, `<service>`, `<receiver>` or `<provider>` with
`android:exported="true"` and no `android:permission` (or `android:readPermission` /
`android:writePermission` on a provider).

## Why it matters

Any application on the device can send an intent to an unguarded exported component — no permissions
required. For a provider it is worse: another application can read or write the data it exposes,
subject only to whatever checks the provider implements itself.

## Vulnerable

```xml
<service android:name=".SyncService" android:exported="true" />
```

## Secure

```xml
<service android:name=".SyncService" android:exported="false" />

<!-- or, when it genuinely is an entry point -->
<service android:name=".SyncService" android:exported="true" android:permission="com.app.SYNC" />
```

Validate everything in an incoming intent as untrusted input, and prefer a signature-level permission
so only your own applications can call it.

## Standards

| Standard           | Identifiers                                                 |
| ------------------ | ----------------------------------------------------------- |
| CWE                | CWE-926                                                     |
| MASWE              | MASWE-0018                                                  |
| MASVS              | MASVS-PLATFORM-1                                            |
| MASTG verification | MASTG-TEST-0355, MASTG-TEST-0356, MASTG-TEST-0357 (Android) |

## False positives it deliberately avoids

§36 warns against blindly flagging every exported component, and the launcher is the clearest reason:

- The **launcher activity** is exported by necessity and is never reported.
- A component requiring any permission is not reported.
- Components that are not exported are not reported.

## Limitations

- Confidence is `medium` by design. Exporting a component is often deliberate, and the rule cannot
  know whether the component validates its own callers.
- Components exported implicitly by having an intent filter without an explicit `android:exported`
  are **not** reported: since API 31 the attribute is mandatory in that case, and the build fails
  without it.
- Permission _protection level_ is not checked — a `normal` permission is little protection, and this
  rule does not currently distinguish it from `signature`.

## Suppression

```xml
<!-- security-audit-ignore RNSEC-ANDROID-MANIFEST-002 reason="public share target, input validated in onCreate" -->
```

## Tests

`packages/auditor/src/rules/__tests__/platformConfiguration.test.ts`
