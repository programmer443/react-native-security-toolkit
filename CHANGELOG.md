# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-08-19

First release. Pre-1.0: the runtime checks have not yet been validated on physical rooted or
jailbroken hardware, and the public API may change in a minor release. See
[docs/runtime/validation.md](docs/runtime/validation.md).

### Added

- Release tooling: a tagged `Release` workflow that re-runs every CI gate, checks the tag against the
  package versions, inspects what would be published, and publishes all four packages with npm
  provenance; `pnpm release:check` as a local preflight; and `pnpm release:dry-run` to rehearse the
  whole thing without publishing.
- A README and a LICENSE in every published package — npm shows both on the package page, and a
  package without them looks abandoned before anyone reads a line of it.
- [`docs/release.md`](docs/release.md), including an honest status for each of the project's
  acceptance criteria and why this is 0.1.0 rather than 1.0.

- Opt-in Android package visibility via `rnsecPackageVisibility=true` in the consuming app's
  `gradle.properties`, which selects a library manifest carrying `<queries>` for known root-manager
  packages. Off by default: `<queries>` merge into the consumer's manifest and appear in store
  review, so enabling them belongs to the application author. `QUERY_ALL_PACKAGES` is never used.

- Project foundation: pnpm workspace, strict TypeScript, ESLint, Prettier, Jest and a hardened
  GitHub Actions workflow.
- Public TypeScript API surface: `SecurityToolkit`, `SecurityToolkitError`,
  `isSecurityToolkitError`, and the structured result model (`SecurityCheckResult`,
  `SecuritySignal`, `SecurityStatus`, `SecurityConfidence`, `UnavailableReason`).
- Codegen TurboModule bridge with Kotlin (Android) and Objective-C++/Swift (iOS) engine skeletons,
  each running work off the JavaScript thread.
- `SecurityToolkit.getEngineInfo()` as an installation smoke test.
- Runtime validation of every payload crossing the native boundary.
- Configuration with validation, per-call native timeouts, and an example app.
- Example app: theme-aware Lottie animations reflecting native engine state (example-only
  dependency; the published package still declares `dependencies: {}`).
- `docs/architecture/build-and-workspace.md` recording the workspace, Gradle, CocoaPods, Metro and
  Babel decisions and the failure modes behind them.

- Android root detection (`RootDetection.getStatus()`): ten independent signals covering su
  binaries, root management applications, build and boot-state properties, mount anomalies,
  writable protected directories, SELinux state, and Magisk/Zygisk artefacts, behind a versioned
  signature pack.
- Android security engine: injectable probe layer, detector registry, signal aggregator and bridge
  mapper, with 53 Kotlin unit tests that run without a rooted device.
- JNI probe for Android system properties via `__system_property_get`, replacing approaches that
  either silently fail (`System.getProperty`) or rely on restricted non-SDK interfaces.
- `SignalOutcome` (`detected` / `not-detected` / `indeterminate`) on every signal, so a blocked
  probe is distinguishable from a clean result.
- Android debugger detection (`DebuggerDetection.getStatus()` / `isAttached()`): JDWP attachment,
  `TracerPid`, debuggable-build, developer-options-enabled and ADB-debugging-enabled signals.
- Android emulator detection (`EmulatorDetection.getStatus()` / `isEmulator()`): build identity,
  emulator-only device nodes and properties, and hardware profile, against a signature pack that
  covers modern `ranchu` and Cuttlefish images rather than only the QEMU/goldfish generation.
- Android hook and instrumentation detection (`HookDetection.getStatus()`): dynamic instrumentation
  agents and injected threads, managed-code hooking frameworks, and native symbol redirection
  detected via `dlsym`/`dladdr` rather than prologue-byte matching.
- Android application integrity (`IntegrityCheck.getStatus()`): signing-certificate pinning,
  install source, package identity and APK location. Unconfigured signals report `indeterminate`
  rather than passing, so a check that was never performed cannot look like one that passed.
- `integrity` configuration on `SecurityToolkit.configure`, validated up front — a truncated or
  non-hex fingerprint is rejected rather than making every launch look like a tampered build.
- Android secure hardware capability (`SecureHardware.getStatus()`): key storage backing determined
  by generating and deleting a throwaway Keystore key, StrongBox availability, and hardware-backed
  key attestation availability.
- Android biometric capability (`BiometricSecurity.getStatus()`): Class 3 biometric usability,
  enrolment state, and device credential presence, using the platform `BiometricManager` so the
  package adds no dependency to consuming applications.
- Android network posture (`NetworkSecurity.getStatus()`): cleartext traffic policy, proxy
  configuration, VPN transport, and user-added certificate authorities. Proxy and VPN are weighted
  as informational because both are mainstream, and the proxy host is never collected.
- Android screen capture protection (`ScreenSecurity.getStatus()` / `enableProtection()` /
  `disableProtection()`): `FLAG_SECURE` applied and re-applied across activity lifecycle events so
  it survives rotation and activity recreation.
- Runtime detector documentation covering signals, confidence, false positives, false negatives,
  limitations and recommended application response:
  [root](docs/runtime/root-detection.md), [debugger](docs/runtime/debugger-detection.md),
  [emulator](docs/runtime/emulator-detection.md), [hooks](docs/runtime/hook-detection.md),
  [integrity](docs/runtime/integrity.md), [secure hardware](docs/runtime/secure-hardware.md),
  [biometrics](docs/runtime/biometrics.md), [network](docs/runtime/network-security.md),
  [screen](docs/runtime/screen-security.md).

- iOS security engine: Foundation-only Swift core with injected probes, published as a Swift Package
  so it can be unit-tested with `swift test` on macOS — no simulator and no jailbroken device. Real
  probe implementations live outside the package target and are compiled into the pod.
- iOS jailbreak detection (`JailbreakDetection.getStatus()`): classic **and rootless** filesystem
  artefacts as separate signals, a correctly oriented sandbox escape probe, injected libraries,
  `DYLD_INSERT_LIBRARIES`, opt-in package-manager URL schemes, and symbolic-link anomalies.
- iOS debugger detection: kernel `P_TRACED` flag via public `sysctl`, and an unexpected-parent
  heuristic that declines to answer on the simulator rather than firing on every development run.
  `ptrace(PT_DENY_ATTACH)` is deliberately not used — non-public API, App Review risk, and a
  mitigation rather than a detection.
- iOS simulator detection (`SimulatorDetection.getStatus()` / `isSimulator()`), the one check in the
  toolkit with no inconclusive case.
- iOS hook and instrumentation detection: native symbol origin via `dlsym`/`dladdr`, and
  Objective-C method implementations checked against the framework that should provide them.
- iOS application integrity: bundle identity, embedded provisioning profile, and main-binary
  FairPlay encryption read from `LC_ENCRYPTION_INFO_64`. App Attest remains a separate optional
  adapter, as Play Integrity does on Android.
- `integrity.expectedBundleIdentifier` configuration for iOS.
- iOS secure hardware capability: Secure Enclave key creation (attempted, not inferred from a flag)
  and keychain usability.
- iOS biometric capability: `LAContext` availability with the specific reason it is unusable,
  biometry type, and device passcode presence. No biometric data is read or exposed.
- iOS network posture: App Transport Security arbitrary-loads policy, proxy configuration, and
  VPN-style interface presence — the last two weighted as informational, since `utun` on iOS is also
  used by Personal Hotspot, AirPlay, content filters and Private Relay.
- iOS screen capture **detection** via `UIScreen.isCaptured`. iOS has no public API to prevent a
  screenshot, so `enableProtection()` resolves to `false` there rather than claiming success.
- [`docs/runtime/secure-hardware-ios.md`](docs/runtime/secure-hardware-ios.md),
  [`docs/runtime/biometrics-ios.md`](docs/runtime/biometrics-ios.md),
  [`docs/runtime/network-security-ios.md`](docs/runtime/network-security-ios.md).
- [`docs/runtime/hook-detection-ios.md`](docs/runtime/hook-detection-ios.md),
  [`docs/runtime/integrity-ios.md`](docs/runtime/integrity-ios.md),
  [`docs/runtime/jailbreak-detection.md`](docs/runtime/jailbreak-detection.md),
  [`docs/runtime/debugger-detection-ios.md`](docs/runtime/debugger-detection-ios.md),
  [`docs/runtime/simulator-detection.md`](docs/runtime/simulator-detection.md).

- Deterministic, versioned risk engine (`rnsec-risk-1`): weighted signal scoring with confidence
  multipliers, capped uncertainty penalties for inconclusive checks, mitigation credits awarded only
  for checks that completed cleanly, and a full contributor list on every result — a bare score is
  never emitted.
- Security policy engine (`SecurityToolkit.evaluate`): blocking rules per check, a risk-level
  threshold, capability requirements, and a `minimumConfidence` floor so weak detections are recorded
  without denying. The decision is returned and nothing is enforced.
- `SecurityToolkit.checkAll()`: runs every check the platform implements in a single bridge
  crossing, omitting checks the platform does not implement rather than reporting them as errors.
- [`docs/runtime/risk-scoring.md`](docs/runtime/risk-scoring.md),
  [`docs/runtime/security-policy.md`](docs/runtime/security-policy.md).

- Static security auditor (`@rn-security/auditor`, `packages/auditor`): the scanning engine —
  hostile-repository-safe file discovery, language and file-role classification, JavaScript/
  TypeScript/JSX/TSX parsing with a content-keyed parse cache, the rule contract, line-number-free
  fingerprints, deduplication, three-layer suppression, contextual severity resolution and
  configuration loading. A separate package so that an application installing the runtime never
  installs a parser. Rules themselves land in the next phase; `builtinRules` is intentionally empty.
- Auditor configuration (`security-toolkit.config.{ts,mts,cts,js,mjs,cjs,json}`) is **parsed and
  statically evaluated, never imported**. Literals, template strings without substitutions, spreads,
  `as const` and one level of top-level `const` reference are supported; anything dynamic is refused
  by naming what was rejected and where.
- Suppression at three layers — disabled rules, a fingerprint baseline, and inline
  `security-audit-ignore RULE-ID reason="..."` directives in any comment syntax. A directive without
  a reason does not suppress: it is reported as a suppression error, so a malformed suppression
  shows the finding rather than swallowing it.
- Adversarial test suite for the auditor: symbolic links pointing outside the project and back into
  it, symbolic-link loops, files that are enormous or binary or both, pathological nesting, unicode
  and awkward path names, a manifest with install scripts, a configuration file with side effects,
  and prompt injection in source. The assertions are mostly about what the auditor did _not_ do.
- [`docs/auditor/architecture.md`](docs/auditor/architecture.md) and
  [`docs/auditor/configuration.md`](docs/auditor/configuration.md), including the auditor's known
  limitations: a single hostile file can stall a scan because parsing cannot be interrupted, and
  only the JavaScript family is parsed so far.

- Fourteen security rules covering secrets, insecure storage, broken cryptography, predictable
  randomness, cleartext traffic, disabled TLS validation, WebView configuration, deep links,
  sensitive logging, AndroidManifest configuration, exported components, iOS App Transport Security,
  dependency resolution and dynamic code execution. Each has a documentation page in
  [docs/rules](docs/rules/README.md) and four classes of test — true positive, true negative, edge
  case, and the false positive it would most plausibly produce.
- Versioned security knowledge layer: CWE, MASWE, MASVS and MASTG identifiers generated from the
  official OWASP and MITRE sources by `pnpm --filter @rn-security/auditor knowledge:sync`, pinned to
  upstream commits and committed so scans work offline and reproduce. Snapshot `2026.1` carries 24
  MASVS controls, 78 MASWE weaknesses, 181 MASTG tests and 101 CWE entries (catalogue 4.20).
- **A fabricated standards identifier now fails at rule registration.** Rules carry identifiers only;
  titles are resolved from the snapshot, and `knowledge.mastgTestsFor()` answers "how do I verify the
  fix?" with a real MASTG test rather than a paragraph of advice. Mapping confidence is declared per
  rule, so an arguable mapping is published as arguable.
- `pnpm security:audit` — the toolkit scans its own repository (§58), configured by
  `security-toolkit.config.ts` at the root, which doubles as the worked example of the configuration
  format. The repository currently reports no findings.
- Fixture projects under `fixtures/`: `vulnerable-react-native` exists to make every rule fire, and
  `secure-react-native` is the same application written safely, where **every finding would be a
  false positive**. Both are scanned end to end by the test suite.
- Analysis helpers shared by rules: a bounded AST walker, sensitive-name heuristics with an explicit
  benign-compound list, entropy shaping that ignores UUIDs, hashes and placeholders, and an XML and
  property-list scanner that never resolves an entity — so a hostile manifest has nothing to expand.

- Five report formats — console, JSON, Markdown, HTML and SARIF 2.1.0 — rendered from one scan, so a
  CI job that publishes SARIF and prints a summary is describing the same run. Every format states
  when a scan was incomplete, keeps the local project root out unless asked, and escapes content
  that came from the repository under analysis.
- SARIF output is validated in CI against the specification's own schema, committed unmodified under
  `packages/auditor/src/reporting/__tests__/fixtures/`. It carries `security-severity` and a
  `security` tag so GitHub code scanning grades alerts correctly, the line-number-free fingerprint as
  a `partialFingerprint` so an alert survives edits above it, suppressed findings as dismissed
  results with their recorded reason, and an incomplete scan as a tool notification.
- CI generates and uploads SARIF to GitHub code scanning (`github/codeql-action/upload-sarif`, pinned
  to a commit SHA, with `security-events: write` scoped to that one job).
- `node packages/auditor/scripts/self-audit.mjs [path] --format <name> [--min <severity>] [--out FILE]`
  renders any format from a real scan. The full CLI is Phase 9.

- `@rn-security/cli` — the `rn-security` command: `audit`, `secrets`, `dependencies`, `runtime`,
  `report` and `rules`, with `--format`, `--out`, `--fail-on`, `--min`, `--config` and colour
  control. Argument parsing uses Node's own `parseArgs`, so the CLI adds no dependency beyond the
  auditor itself.
- Fixed exit codes, so a pipeline can tell events apart: `0` nothing met the threshold, `1` a finding
  met `--fail-on`, `2` usage or configuration error, `3` a bug in the tool. Rule errors and an
  incomplete scan are reported loudly but never fail a run — conflating a flaky timeout with a
  vulnerability is how a gate stops being trusted.
- `rn-security runtime` reports **project readiness**, and says plainly that it cannot check a
  device: it looks for the declarations that decide whether a runtime signal returns a verdict or an
  honest `unknown` (`USE_BIOMETRIC`, `ACCESS_NETWORK_STATE`, `networkSecurityConfig`,
  `LSApplicationQueriesSchemes`, `NSFaceIDUsageDescription`, and integrity configuration).
- `rn-security report` re-renders a saved JSON report in another format, so a CI job publishes SARIF
  and a Markdown summary from one scan rather than two.
- `rn-security rules --format json` includes the MASTG test identifiers that verify each rule's
  weakness, so "how do I check the fix?" has a machine-readable answer.
- CI now gates on `pnpm security:audit`, which runs `rn-security audit . --fail-on high` against this
  repository, and generates its SARIF through the same CLI.
- [`docs/auditor/cli.md`](docs/auditor/cli.md).

- `@rn-security/mcp` — a Model Context Protocol server exposing the toolkit's findings to whichever
  AI model the developer already uses. **No API key, no vendor, no source upload**: it speaks stdio
  to a client on the same machine, so the model is one the developer already chose and already
  trusts. Four read-only tools: `security_audit`, `security_rules`, `security_rule_details` and
  `security_runtime_readiness`, each finding carrying severity, confidence, evidence, remediation,
  CWE/MASVS/MASWE references with official titles, and the MASTG tests that verify a fix.
- `rn-security mcp [path]` runs that server from the CLI, and explains how to install it when the
  optional package is absent.
- MCP `2025-06-18` implemented directly — one file, no dependencies. The official SDK brings
  seventeen transitive packages (express, hono, jose, ajv, zod) for HTTP transports and OAuth this
  server does not use.
- **Path confinement**: the model chooses every tool argument, so every path is resolved and confined
  to the root the server started in. `../../etc` and `/etc` are refused. Without it, "audit this
  project" is an arbitrary-file-read tool.
- **Untrusted-content labelling**: every payload names the fields quoted from the scanned repository
  and tells the client they are data, and the server's `initialize` instructions say the same. AI is
  non-authoritative by construction here — every finding comes from a deterministic rule, and the
  model cannot change a severity.
- `RNSEC-AI-001` — a rule for prompt injection aimed at an AI code reviewer: text in the repository
  telling a model to ignore its instructions, report the code as safe, disclose its prompt or
  exfiltrate secrets. Reported and quoted verbatim, never rewritten. Mapped to CWE-1427 at **low**
  confidence, because that weakness describes an application prompting an LLM and this is a
  repository addressing someone else's.
- [`docs/mcp.md`](docs/mcp.md) and [`docs/rules/RNSEC-AI-001.md`](docs/rules/RNSEC-AI-001.md).

- [`docs/security/threat-model.md`](docs/security/threat-model.md) — assets, threat actors, trust
  boundaries, and an explicit list of what the toolkit does **not** defend against.
- [`docs/security/dependencies.md`](docs/security/dependencies.md) — every dependency justified, and
  the ones that were rejected with the reason. A consumer installing only the runtime package
  downloads nothing; the auditor pulls five packages, all Babel.
- [`docs/runtime/validation.md`](docs/runtime/validation.md) — what has actually been verified and
  what has not. Physical-device validation for both platforms is outstanding, and the README says so
  rather than implying otherwise.
- [`docs/runtime/README.md`](docs/runtime/README.md) — an index of the runtime checks.
- Measured performance for the static auditor: 2,000 files in 0.53 s, 10,000 in 2.0 s, and 20,500 in
  4.5 s with the file cap correctly reported as truncation. Scaling is linear and peak heap stays
  under 106 MB.

### Changed

- The README is rewritten for people evaluating the toolkit rather than for people building it:
  what it does, what it refuses to claim, install, usage for all three parts, coverage, and an honest
  status table. Internal phase tracking and specification cross-references are gone.
- `.gitignore` rewritten. Build output was matched by root-anchored patterns that missed
  `example/android/**/build`, `packages/*/android/build`, `.cxx`, `Pods` and vendored gems entirely —
  a first commit would have published 30,467 files instead of 411. It now also **re-includes**
  `README.md`, `*.png`, `Gemfile.lock` and `Podfile.lock`, which a user-level global ignore was
  excluding: without that, the published repository would have had no readme, no launcher icons and
  no reproducible pod install, with nothing in the repository to explain why.
- `CLAUDE.md` is no longer published. It is the project brief written for an AI assistant working on
  this repository, not documentation for people using the toolkit.

- Runtime readiness analysis moved from the CLI into the auditor, where both the CLI and the MCP
  server can use one implementation.
- `ai.enabled: true` now explains that this package runs no model and points at the MCP server,
  rather than saying the feature is "not available in this version" — it is available, and it works
  the other way round.

- The auditor's `self-audit.mjs` script is replaced by the CLI. It existed so the capability was real
  before the CLI landed; keeping both would have meant two implementations of the same pipeline.
- The auditor exports its XML and property-list scanners, sensitivity heuristics and entropy helpers,
  so a consumer building its own checks has the primitives the built-in rules use.

- The native specification exposes generic `runCheck` / `runChecks` rather than one method per
  check, so each platform's engine declares its own support instead of JavaScript hardcoding which
  checks exist where.
- Check configuration is passed per call rather than stored natively, keeping the native engine
  stateless: there is no ordering hazard between configuring and checking.

- `UnavailableReason` gains `simulator`, shared across the TypeScript, Kotlin and Swift layers.

### Fixed

- The CLI reported a hardcoded version, which would have drifted from `package.json` at the first
  release and been recorded in every JSON and SARIF report it wrote. It now reads the version from
  its own manifest.

- `RNSEC-AI-001` matched ordinary prose about scanners — "a rule handed an empty tree would report
  the file as clean" is a comment in this package's own parser, and the rule reported it on its first
  run against this repository. It now matches whole comment blocks rather than single lines, so a
  wrapped sentence is read as the description it is.

- Auditor false positives found by scanning this repository and the secure fixture, each now covered
  by a test: an Android intent filter inheriting the schemes of a filter declared later in the
  manifest; a log message that merely mentioned a sensitive word being treated as logging one; a
  kebab-case constant (`security-audit-ignore`) scoring high enough on entropy to look like a
  credential; licence and documentation URLs inside comments reported as cleartext endpoints; and
  prose mentioning `security-audit-ignore` being parsed as a malformed suppression directive.
- Swift package build output (`.build/`) is excluded by default. Without it a scan of this repository
  discovered 2,681 files instead of 300, most of them compiler module caches.
- Rules that describe code no longer run on documentation: a page explaining that MD5 is broken
  contains the string `MD5`, and reporting it reports the warning rather than the weakness. Secret
  detection still scans documentation, because a credential pasted into a README is a shipped
  credential — the rule's own page suppresses its illustrative key inline, with a reason.

- SARIF artifact URIs are percent-encoded. A repository can contain a file named
  `src/<img src=x onerror=alert(1)>.ts`, which is a legal POSIX filename and not a legal URI; emitted
  raw it produced a SARIF file that failed schema validation, and a rejected upload is silent from
  the developer's side. Found by the hostile-content fixture.

- **Package visibility was being inferred and the inference was wrong.**
  `RNSEC-ANDROID-ROOT-002` asked at runtime whether any other package was visible, but Android
  always exposes a handful of system packages regardless of `<queries>` — so the check reported
  "no root management application detected" on applications that had declared nothing. A false
  negative presented as a clean result. It is now a build-time fact
  (`BuildConfig.PACKAGE_VISIBILITY_DECLARED`) set by the same Gradle flag that selects the manifest,
  so the two cannot disagree.

- `checkAll()` scales its native timeout by the number of checks rather than borrowing the
  single-check budget. On an Android cold start nine sequential checks exceeded the 5 s default and
  the whole aggregate reported `NATIVE_TIMEOUT` instead of a result.

- `RNSEC-ANDROID-ROOT-004` now matches `dev-keys` as well as `test-keys`, and no longer describes a
  clean result as "signed with release keys" — a claim it had not verified. Emulator and engineering
  images are commonly `dev-keys`, and were being reported as release-signed.
- Biometric signals now explain _why_ a status was unavailable — most usefully, that the
  application has not declared `USE_BIOMETRIC` — rather than reporting an unactionable
  "could not be determined".
- iOS hook detection matches system image paths by **prefix** rather than substring. A rootless
  jailbreak installs to `/var/jb/usr/lib/`, which _contains_ `/usr/lib/`; substring matching
  classified every injected library on a modern jailbroken device as a system image, blinding the
  check to precisely where iOS hooks live.
- Jailbreak detection reports `unavailable` with reason `simulator` rather than a verdict when run
  on the iOS Simulator, and its path list excludes paths that exist on macOS (`/bin/bash`, `/bin/sh`,
  the ssh binaries). Both were making the check fire on every simulator run — the kind of false
  alarm that teaches developers to ignore a signal.
- Native library is explicitly linked with 16 KB page alignment. NDK r27 does not align by default,
  which made the app fall back to page-size compatibility mode on Android 15+ devices.
- The Android NDK version is pinned rather than defaulting to the highest installed on the build
  machine, which was neither reproducible nor reliably complete.

### Security

- The native module is resolved with `TurboModuleRegistry.get` rather than `getEnforcing`, so
  importing the package cannot crash a host application when the native side is not linked.
- Native payloads are validated at runtime rather than trusted from their Codegen types, on the
  premise that a compromised device may control the native side.
- CI pins every third-party action to a full commit SHA and runs with least-privilege permissions.
- Check results are rejected if they contradict themselves — in particular a `secure` verdict whose
  own signals report a detection, which is the direction a tampered native module would lie in.
- A probe that cannot run produces `indeterminate`, and any `indeterminate` signal downgrades the
  whole check to `unknown`. Absence of evidence is never reported as evidence of absence.

### Notes

- No security check is implemented yet. `supportedChecks` is intentionally empty.

[unreleased]: https://github.com/programmer443/react-native-security-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/programmer443/react-native-security-toolkit/releases/tag/v0.1.0
