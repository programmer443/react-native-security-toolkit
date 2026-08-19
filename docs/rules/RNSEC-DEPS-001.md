# RNSEC-DEPS-001 — Dependency resolved from an unpinned or unauthenticated source

|                   |                                              |
| ----------------- | -------------------------------------------- |
| **Base severity** | medium (high for unauthenticated transports) |
| **Confidence**    | high / medium                                |
| **Categories**    | dependencies, configuration                  |
| **Applies to**    | `package.json`                               |

## What it detects

| Specifier                  | Problem                                               |
| -------------------------- | ----------------------------------------------------- |
| `*`, `latest`, empty       | The build takes whatever the registry serves that day |
| `git://…`, `http://…`      | Fetched with no transport authentication              |
| `github:owner/repo#branch` | A branch or tag can be moved after review             |

## Why it is not a vulnerability scanner

§38 asks for pluggable vulnerability databases and warns against embedding an obsolete one. A
snapshot of advisories baked into a release is stale the week it ships, and a security tool that
reports confidently from stale data is worse than one that says nothing. This rule reports only what
a manifest can establish on its own — that resolution is not deterministic or not authenticated.

Advisory data belongs behind a provider interface, fetched at scan time by a project that opts in.
That is future work, and is not claimed here.

## Vulnerable

```json
{ "dependencies": { "analytics-sdk": "*", "internal-ui": "git://github.com/example/ui.git" } }
```

## Secure

```json
{
  "dependencies": {
    "react-native": "^0.87.0",
    "internal-ui": "git+https://github.com/example/ui.git#4f2c1a9d8e7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a"
  }
}
```

Commit a lockfile, and install with a frozen lockfile in CI so the build fails rather than drifting.

## Standards

| Standard           | Identifiers                                                                        |
| ------------------ | ---------------------------------------------------------------------------------- |
| CWE                | CWE-1104                                                                           |
| MASWE              | MASWE-0044                                                                         |
| MASVS              | MASVS-CODE-3                                                                       |
| MASTG verification | MASTG-TEST-0272, MASTG-TEST-0274 (Android); MASTG-TEST-0273, MASTG-TEST-0275 (iOS) |

Mapping confidence is **medium**: MASWE-0044 is about dependencies with known vulnerabilities, which
overlaps with but is not identical to unpinned resolution. §32 asks for that to be marked rather than
dressed up.

## False positives it deliberately avoids

- Caret and tilde ranges — the ecosystem's normal practice — are not reported.
- A wildcard in `peerDependencies` is a compatibility statement, not something the build resolves.
- `workspace:` and `file:` protocols inside a monorepo are not reported.
- A manifest that is not valid JSON is a build problem, and the toolchain will say so.

## Limitations

- Only `package.json` is read. Gradle and CocoaPods dependency declarations are not covered yet.
- Lockfile contents are not verified, so a range with an out-of-date lockfile is invisible.
- Dependency confusion — a private-scope name resolvable from the public registry — is not detected;
  doing it properly needs registry knowledge the auditor deliberately does not fetch.

## Suppression

```json
// security-audit-ignore RNSEC-DEPS-001 reason="internal mirror, integrity enforced by the lockfile"
```

## Tests

`packages/auditor/src/rules/__tests__/dependenciesAndDynamicCode.test.ts`
