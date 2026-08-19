# @rn-security/auditor

Static security analysis for React Native projects: the scanning engine, the rule library, and the
versioned OWASP/CWE knowledge layer.

Part of the [React Native Security Toolkit](https://github.com/programmer443/react-native-security-toolkit).
Most people want the [CLI](https://www.npmjs.com/package/@rn-security/cli) instead — this package is
the library behind it.

## Install

```sh
npm install --save-dev @rn-security/auditor
```

Node 22.11+. Developer and CI tooling — **never part of a mobile bundle**.

## Use

```ts
import { auditProject, builtinRules, getReporter, loadConfig } from '@rn-security/auditor';

const { config } = await loadConfig(projectRoot);
const report = await auditProject({ root: projectRoot, config, rules: [...builtinRules] });

process.stdout.write(getReporter('sarif').render(report));
```

## What it does

Fifteen rules covering secrets, insecure storage, broken cryptography, predictable randomness,
cleartext traffic, disabled TLS validation, WebView configuration, deep links, sensitive logging,
AndroidManifest and Info.plist configuration, dependency resolution, dynamic code execution, and
prompt injection aimed at AI code reviewers.

Findings carry severity, confidence, evidence, remediation, and **real** CWE / MASVS / MASWE / MASTG
identifiers — generated from the official OWASP and MITRE sources rather than typed from memory. A
rule citing an identifier that does not exist fails at startup.

Reports render as console text, JSON, Markdown, HTML or SARIF 2.1.0.

## Two commitments

**The repository under analysis is hostile.** No file from it is ever executed, imported, evaluated
or installed — including its own configuration file, which is parsed and statically evaluated rather
than loaded. Symbolic links are never followed; size, count, depth and time limits are enforced and
reported when hit.

**A partial scan is never reported as complete.** Every limit, skip, rule failure and malformed
suppression appears in the result, because "no findings" from a truncated scan means something
different.

## Documentation

- [Architecture](https://github.com/programmer443/react-native-security-toolkit/blob/main/docs/auditor/architecture.md)
- [Rules](https://github.com/programmer443/react-native-security-toolkit/blob/main/docs/rules/README.md)
- [Configuration and suppression](https://github.com/programmer443/react-native-security-toolkit/blob/main/docs/auditor/configuration.md)
- [Knowledge layer](https://github.com/programmer443/react-native-security-toolkit/blob/main/docs/auditor/knowledge.md)

## Licence

MIT © Muhammad Ahmad
