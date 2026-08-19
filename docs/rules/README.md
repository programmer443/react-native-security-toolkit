# Security rules

Every rule shipped by `@rn-security/auditor`. Identifiers are permanent: once published, a rule id
is never reused or renumbered, because it appears in baselines, suppressions and SARIF output (§78).

| ID                                                          | Rule                                          | Base severity | Applies to                    |
| ----------------------------------------------------------- | --------------------------------------------- | ------------- | ----------------------------- |
| [RNSEC-SECRET-001](RNSEC-SECRET-001.md)                     | Hardcoded credential                          | critical      | any file                      |
| [RNSEC-STORAGE-001](RNSEC-STORAGE-001.md)                   | Sensitive data in unencrypted storage         | high          | JS/TS, Kotlin, Java, Swift    |
| [RNSEC-CRYPTO-001](RNSEC-CRYPTO-001.md)                     | Broken or misused cryptographic primitive     | high          | any file                      |
| [RNSEC-CRYPTO-002](RNSEC-CRYPTO-002.md)                     | Predictable randomness for a security value   | high          | JS/TS, Kotlin, Java           |
| [RNSEC-NETWORK-001](RNSEC-NETWORK-001.md)                   | Cleartext HTTP endpoint                       | high          | source and configuration      |
| [RNSEC-NETWORK-002](RNSEC-NETWORK-002.md)                   | TLS validation disabled or weakened           | critical      | any file                      |
| [RNSEC-WEBVIEW-001](RNSEC-WEBVIEW-001.md)                   | Unsafe WebView configuration                  | high          | JSX/TSX, Kotlin, Java, Swift  |
| [RNSEC-DEEPLINK-001](RNSEC-DEEPLINK-001.md)                 | Deep link handled without validation          | high          | JS/TS, AndroidManifest.xml    |
| [RNSEC-LOG-001](RNSEC-LOG-001.md)                           | Sensitive data written to a log               | medium        | any file                      |
| [RNSEC-ANDROID-MANIFEST-001](RNSEC-ANDROID-MANIFEST-001.md) | Insecure manifest configuration               | high          | AndroidManifest.xml           |
| [RNSEC-ANDROID-MANIFEST-002](RNSEC-ANDROID-MANIFEST-002.md) | Exported component without a permission       | medium        | AndroidManifest.xml           |
| [RNSEC-IOS-PLIST-001](RNSEC-IOS-PLIST-001.md)               | App Transport Security weakened               | high          | Info.plist                    |
| [RNSEC-DEPS-001](RNSEC-DEPS-001.md)                         | Unpinned or unauthenticated dependency        | medium        | package.json                  |
| [RNSEC-RN-001](RNSEC-RN-001.md)                             | Dynamic code execution                        | high          | JS/TS                         |
| [RNSEC-AI-001](RNSEC-AI-001.md)                             | Prompt injection aimed at an AI code reviewer | medium        | any file except documentation |

## How to read a rule page

Each page states what the rule detects, why it matters, and — as importantly — **the false positives
it deliberately avoids**. A static analyser is judged on the findings it does not produce as much as
on the ones it does, and every rule here has tests for both.

Severity shown above is the rule's **base**. The engine adjusts it for context: findings in test
code drop one level, findings in fixtures drop two, and a configured override wins outright. Every
adjustment is recorded on the finding.

## Standards mappings

Rules carry identifiers only — CWE, MASWE, MASVS, and the MASTG tests that verify a fix. Those
identifiers are checked at registration against a snapshot generated from the official OWASP and
MITRE sources, so a rule citing something that does not exist fails immediately rather than shipping
a report nobody can verify. See [the knowledge layer](../auditor/knowledge.md).

## Suppression

Any finding can be suppressed with a reason — never without one. See
[configuration](../auditor/configuration.md#3-suppression).
