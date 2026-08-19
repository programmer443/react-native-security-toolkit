# RNSEC-SECRET-001 — Hardcoded credential

|                   |                                                        |
| ----------------- | ------------------------------------------------------ |
| **Base severity** | critical (pattern match) / high (name-and-shape match) |
| **Confidence**    | very-high / medium                                     |
| **Categories**    | secrets                                                |
| **Applies to**    | every file the auditor reads                           |

## What it detects

A credential, API key or private key embedded in the application rather than supplied at runtime.

Two passes, at different confidences:

1. **Provider patterns** — values whose published format identifies their issuer: AWS access key ids,
   Google API keys, Stripe secret keys, GitHub and Slack tokens, npm tokens, Twilio and SendGrid
   keys, PEM private key blocks and JSON Web Tokens. These fire in any language.
2. **A sensitive name assigned a secret-shaped literal** — `const apiSecret = "Kq7#pR2..."`. This
   pass is JavaScript-family only, because it needs to know the value is a _static_ string.

## Why it matters

Anything in an application binary is readable by anyone holding the application. A credential
committed here should be treated as public and as compromised the moment it shipped. Removing it
from source does not un-ship it: the exposed credential has to be rotated.

## Vulnerable

```ts
// security-audit-ignore RNSEC-SECRET-001 reason="illustration in rule documentation, not a live key"
const stripeKey = 'sk_test_EXAMPLEONLY000000';
const apiSecret = 'Kq7#pR2vX9!mZ4tW8bN6yL3sD5fG1hJ0';
```

The directive above is real, not decoration: this page contains a credential-shaped string, so the
rule fires on its own documentation. Suppressing it with a reason is exactly what a project is
expected to do — and it is why the toolkit's self-audit reports nothing.

## Secure

```ts
// Supplied at runtime; never built into the binary.
const apiKey = process.env.API_KEY;
const token = await SecureStore.getItemAsync('sessionToken');
```

## Standards

| Standard           | Identifiers                                                                                                           |
| ------------------ | --------------------------------------------------------------------------------------------------------------------- |
| CWE                | CWE-798, CWE-312                                                                                                      |
| MASWE              | MASWE-0004                                                                                                            |
| MASVS              | MASVS-STORAGE-1                                                                                                       |
| MASTG verification | MASTG has no test mapped to MASWE-0004 in the shipped snapshot. Verify by extracting strings from the built artefact. |

## False positives it deliberately avoids

- UUIDs, git object ids, semantic versions and dotted numeric identifiers.
- Placeholders: `YOUR_API_KEY_HERE`, `changeme`, `xxxxxxxx`, `${...}` templates.
- Data URIs and base64 assets assigned to names that are not sensitive.
- Values read from the environment, a keychain, or any non-literal expression — the correct pattern.
- Benign compounds: `tokenizer`, `tokenCount`, `passwordPlaceholder`, `publicKey`.

## Limitations

- A credential assigned to an innocuously named variable, in a format no provider pattern covers, is
  only caught by the entropy heuristic — which is deliberately conservative and will miss some.
- The name-and-shape pass needs a parse, so it does not run on Kotlin, Swift or Gradle files. Provider
  patterns still do.
- The rule cannot tell a live credential from a revoked or sample one. It reports what it sees.

## Reported values are masked

Only a short prefix survives into the report. A findings file travels into pull requests and CI logs
— much further than the source file it came from.

## Suppression

```ts
// security-audit-ignore RNSEC-SECRET-001 reason="documented sample key, not live"
```

## Tests

`packages/auditor/src/rules/__tests__/hardcodedSecret.test.ts`
