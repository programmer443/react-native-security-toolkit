# Contributing

Thanks for your interest in this project. It is security-sensitive infrastructure, so the bar for
changes is deliberately high — please read this before opening a pull request.

## Getting set up

```sh
pnpm install
pnpm verify          # format check, lint, typecheck, JS unit tests

# Native engine tests
pnpm --filter react-native-security-toolkit test:android   # Kotlin, via Gradle
pnpm --filter react-native-security-toolkit test:ios       # Swift, via `swift test`
```

The iOS engine is a Swift Package (`packages/runtime/Package.swift`) so it can be tested with
`swift test` on an ordinary Mac — no simulator, no jailbroken device. That works because the engine
sources in `ios/Engine` are Foundation-only and reach the platform through injected probes. The real
probe implementations live in `ios/Probes` and are outside the package target; CocoaPods compiles
both into the shipped pod.

Requirements: Node 22.11+, pnpm 11+, JDK 17, Xcode 26+, Android SDK with `compileSdk` 36.

The workspace uses a **hoisted** `node_modules` layout (`nodeLinker: hoisted` in
`pnpm-workspace.yaml`). React Native's Metro bundler, Gradle autolinking and CocoaPods all resolve
modules by walking real directories, and pnpm's default isolated layout hides transitive
dependencies from that walk. Please do not change this without checking that all three still work.

## Layout

```
packages/runtime/   the published React Native package (native code lives here)
example/            example app, used as the end-to-end smoke test
docs/               architecture, threat model, runtime and rule documentation
scripts/            repository tooling
```

## Running the example app

```sh
pnpm example:android
pnpm example:ios      # run `pod install` in example/ios first
```

The example app calls `SecurityToolkit.getEngineInfo()` on launch. If it reports the native module
as unavailable, rebuild the app — a Metro reload is not enough after a native change.

## Working on the toolkit

A few rules that are specific to this project:

1. **Never claim more than the evidence supports.** No check is bypass-proof, and nothing in the
   code, docs or README may imply otherwise. `unknown` is not `secure`; `unavailable` is not
   `secure`. See §77 of `CLAUDE.md` for the language expected in user-facing text.
2. **A capability is only listed once it is implemented _and_ tested.** `supportedChecks` and the
   README feature matrix grow together with real tests, never ahead of them.
3. **Detectors take injected probes, never the filesystem directly.** This is what makes them
   testable without a rooted or jailbroken device. A detector that calls `File(...)`,
   `PackageManager` or `FileManager` directly will be sent back.
4. **Every detector needs documentation** in `docs/runtime/` covering what it detects, its signals,
   confidence, false positives, false negatives, platform limitations and the recommended
   application response. Do not publish operational bypass instructions.
5. **Nothing runs on the JavaScript thread.** Native work goes through the engine's executor
   (Android) or serial queue (iOS).
6. **Validate everything crossing the native boundary.** On a compromised device the native side is
   what the attacker may control; Codegen's types are a compile-time convenience, not a runtime
   guarantee.
7. **No telemetry, no analytics, no hidden network requests.** Not behind a flag, not "just for
   diagnostics".

## Coding standards

- Strict TypeScript. No `any`, no `@ts-ignore` — both fail lint in `packages/*/src`.
- Public APIs carry TSDoc explaining behaviour _and_ limitations.
- Explicit error handling; no silent catches.
- Prefer platform cryptography. Never implement a cryptographic primitive.

## Commits and pull requests

- Keep changes small and reviewable. Large speculative diffs will be asked to be split up.
- `pnpm verify` must pass before you open a pull request.
- Update `CHANGELOG.md`, and use its **Security** section for anything security-relevant.
- New rule or detector IDs are permanent once published — choose carefully.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
