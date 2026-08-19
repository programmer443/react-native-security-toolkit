# Security Policy

## Supported versions

This project is pre-1.0 and under active development. Until 1.0.0 is released, only the latest
published version receives security fixes.

| Version      | Supported |
| ------------ | --------- |
| Latest `0.x` | ✅        |
| Older `0.x`  | ❌        |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull
requests.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/programmer443/react-native-security-toolkit/security/advisories/new)
for this repository.

Please include, as far as you can:

- the affected version and platform (Android/iOS, OS version, React Native version);
- a description of the issue and its impact;
- reproduction steps or a proof of concept;
- any suggested mitigation.

## What to expect

| Stage                                                           | Target                 |
| --------------------------------------------------------------- | ---------------------- |
| Acknowledgement of your report                                  | within 3 working days  |
| Initial assessment and severity triage                          | within 10 working days |
| Fix or documented mitigation for confirmed high/critical issues | within 90 days         |

We will keep you informed as the assessment progresses, credit you in the advisory unless you prefer
otherwise, and coordinate disclosure timing with you. Reports are not made public before a fix or
documented mitigation is available.

## Scope

**In scope**

- Vulnerabilities in this package's runtime, native code, CLI, or static analyzer.
- Detection logic that reports `secure` in a state it should report as `detected` or `unknown`.
- Any path by which scanning a repository could execute code, exfiltrate data, or exhaust resources.
- Any path by which source code or secrets could reach an AI provider without explicit opt-in.

**Out of scope**

- The existence of a bypass for a runtime detection signal. Every runtime check is a
  defence-in-depth signal and is bypassable by an attacker who controls the device; this is
  documented, not a vulnerability. A _systematic_ weakness that defeats the aggregate engine is in
  scope — please report it.
- Vulnerabilities in applications that use this package but do not originate here.
- Findings that require a rooted or jailbroken device to affect only that device's own user.

## Our commitments

- No telemetry, analytics, device identifiers, or hidden network requests are shipped in this
  package.
- No source code leaves a developer's machine unless AI analysis is explicitly enabled and
  configured.
- Security-relevant changes are called out in [CHANGELOG.md](CHANGELOG.md).
