# RNSEC-ANDROID-MANIFEST-001 — Insecure AndroidManifest configuration

|                   |                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------- |
| **Base severity** | high (`debuggable`, `usesCleartextTraffic`), medium (`allowBackup`), low (`testOnly`) |
| **Confidence**    | high, except `debuggable` at medium                                                   |
| **Categories**    | android, configuration                                                                |
| **Applies to**    | `AndroidManifest.xml`                                                                 |

## What it detects

Attributes on the `<application>` element that weaken the app:

| Attribute                             | Effect                                                                     |
| ------------------------------------- | -------------------------------------------------------------------------- |
| `android:debuggable="true"`           | A debugger can attach to the installed application on any device           |
| `android:allowBackup="true"`          | Application data is copied into device and cloud backups                   |
| `android:usesCleartextTraffic="true"` | Re-enables plain HTTP, which the platform blocks by default from Android 9 |
| `android:testOnly="true"`             | A development artefact that can only be installed with `adb install -t`    |

## Vulnerable

```xml
<application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
```

## Secure

```xml
<application
  android:allowBackup="false"
  android:usesCleartextTraffic="false"
  android:networkSecurityConfig="@xml/network_security_config">
```

Where backups are wanted, keep them and exclude sensitive files with `android:dataExtractionRules`
(API 31+) and `android:fullBackupContent`. Credentials belong in the Keystore, which is never backed
up.

## Standards

| Standard           | Identifiers                                                 |
| ------------------ | ----------------------------------------------------------- |
| CWE                | CWE-489 (debug), CWE-312 (backup), CWE-319 (cleartext)      |
| MASWE              | MASWE-0063, MASWE-0006, MASWE-0026                          |
| MASVS              | MASVS-RESILIENCE-4, MASVS-STORAGE-2, MASVS-NETWORK-1        |
| MASTG verification | MASTG-TEST-0216, MASTG-TEST-0262, MASTG-TEST-0217 (Android) |

Each finding carries the mapping for **its own** attribute rather than the union, so a backup finding
does not cite a network control.

## False positives it deliberately avoids

- The same attribute on a component rather than the `<application>` element is not reported.
- `debuggable` is reported at **medium** confidence: Gradle sets it per build type, so a manifest
  value may be overridden in the release build. The finding says so and asks for verification
  against the built APK.

## Limitations

- Manifest merging is not modelled. A library manifest can introduce these attributes, and the merged
  result is what ships — check with `./gradlew :app:processReleaseManifest` output.
- Build-type overrides in Gradle are invisible to a static read of the manifest.

## Suppression

```xml
<!-- security-audit-ignore RNSEC-ANDROID-MANIFEST-001 reason="debug manifest, not merged into release" -->
```

## Tests

`packages/auditor/src/rules/__tests__/platformConfiguration.test.ts`
