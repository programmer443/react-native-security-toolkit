# Build and workspace decisions

Notes on how this repository is assembled, and why. Most entries exist because something did not
work the obvious way — the reasoning is recorded so the next person does not rediscover it.

Established in Phase 1. See [architecture-proposal.md](architecture-proposal.md) for the product
architecture.

## Layout

```
packages/runtime/   published package: TypeScript API + Android (Kotlin) + iOS (Obj-C++/Swift)
example/            example app; also the end-to-end smoke test for the native bridge
scripts/            repository tooling
docs/               architecture, runtime and rule documentation
```

`packages/auditor`, `packages/ai` and `packages/cli` arrive in Phases 5, 10 and 9 respectively. They
are not scaffolded ahead of time.

## pnpm with a hoisted `node_modules`

`pnpm-workspace.yaml` sets `nodeLinker: hoisted`.

pnpm's default isolated layout only exposes a package's _direct_ dependencies. React Native's
build tooling resolves transitive dependencies by walking real directories — Gradle needs
`@react-native/gradle-plugin`, CocoaPods needs `react-native/scripts/react_native_pods.rb`, Metro
needs to see the whole graph — and none of those are direct dependencies of the example app. Under
the isolated layout the Android build fails at the first line of `settings.gradle`.

Hoisting places everything at the workspace root, which is what the React Native toolchain expects.

**Consequence:** transitive packages live in `<repo>/node_modules`, _not_ `example/node_modules`.
Gradle files in `example/android` therefore point two levels up. Declaring the packages as explicit
dev-dependencies of the example app does **not** move them — pnpm keeps a single hoisted copy.

## Install scripts are opt-in

`allowBuilds` in `pnpm-workspace.yaml` is an allowlist: a dependency may not run install scripts
unless it is named there. Adding an entry is a supply-chain decision and should be justified in a
comment. Today the list contains exactly one entry, `unrs-resolver`, which is lint tooling.

## Gradle

`example/android/settings.gradle` and `app/build.gradle` point at the hoisted root:

```gradle
pluginManagement { includeBuild("../../node_modules/@react-native/gradle-plugin") }
```

```gradle
react {
    reactNativeDir = file("../../../node_modules/react-native")
    codegenDir = file("../../../node_modules/@react-native/codegen")
    cliFile = file("../../../node_modules/react-native/cli.js")
}
```

Resolving these through `node --print "require.resolve(...)"` inside `pluginManagement` was tried
first. Node resolves the correct path, but Gradle 9 did not register the resulting included build
and reported the settings plugin as missing. Literal paths work and are easier to debug.

The library's `android/build.gradle` reads the engine version straight out of `package.json`:

```gradle
def packageJson = new groovy.json.JsonSlurper().parse(file("../package.json"))
buildConfigField "String", "ENGINE_VERSION", "\"${packageJson.version}\""
```

### Duplicate Codegen targets

Running `npx react-native codegen` by hand generates the library's spec into the **app's** build
directory. The library's own Gradle build generates it too, and CMake then fails with:

```
add_library cannot create target "react_codegen_SecurityToolkitSpec" because another target
with the same name already exists
```

Do not run codegen manually. If you already have, delete `example/android/app/build/generated`,
`example/android/app/.cxx` and `packages/runtime/android/build`.

## iOS

### The podspec filename must match `s.name`

The podspec declares `s.name = "SecurityToolkit"`, so the file must be `SecurityToolkit.podspec`.
Autolinking reads the podspec, takes the pod name from it, and then looks for a file of that name —
naming the file after the npm package fails with `No podspec found for 'SecurityToolkit'`.

The pod name also determines the Codegen spec header (`<SecurityToolkitSpec/SecurityToolkitSpec.h>`)
and the Swift interop header (`SecurityToolkit-Swift.h`), so it is not free to change.

### TurboModule conformance is Objective-C++, not Swift

Codegen emits a C++/Objective-C protocol that Swift cannot conform to directly; the official library
generator only offers `kotlin-objc` or `cpp` for turbo modules. So:

- `ios/SecurityToolkit.mm` — conforms to the generated protocol, owns the serial dispatch queue,
  forwards to Swift. Kept deliberately thin.
- `ios/SecurityToolkitEngine.swift` — the engine. Detectors are written here from Phase 3 onward.

The Swift half is reached through the generated umbrella header, imported defensively because the
path differs between framework and static-library builds:

```objc
#if __has_include(<SecurityToolkit/SecurityToolkit-Swift.h>)
#import <SecurityToolkit/SecurityToolkit-Swift.h>
#else
#import "SecurityToolkit-Swift.h"
#endif
```

### Adding a Swift file requires `pod install`

SwiftPM globs its target directory at build time, so `swift test` picks up a new engine source file
immediately. CocoaPods does not: it snapshots the file list into the Xcode project when
`pod install` runs. A new file in `ios/Engine` therefore passes `swift test` and fails the iOS build
with `cannot find 'X' in scope` until pods are reinstalled.

```sh
cd example/ios && pod install
```

### Engine version

Gradle can read `package.json` directly; iOS has no equally clean hook. CocoaPods' `prepare_command`
does not run for path-based development pods, and Swift compilation conditions cannot carry string
values. So `scripts/sync-native-version.mjs` generates `ios/SecurityToolkitVersion.h`, which is
committed. `node scripts/sync-native-version.mjs --check` fails CI if it drifts.

## Metro and Babel

Two things in the example app assume the library sits at the repository root. Both need pointing at
`packages/runtime`:

- **`example/babel.config.js`** feeds `react-native-builder-bob/babel-config` the _library's_
  manifest. Pointed at the workspace root it fails with
  `Couldn't determine the source directory. Does your config specify a 'source' field?`, because the
  root manifest has no `react-native-builder-bob` field.
- **`example/metro.config.js`** uses `react-native-monorepo-config`, which expects a Yarn/npm-style
  `workspaces` array in the root `package.json`. This workspace is declared in
  `pnpm-workspace.yaml`, so the config reads the `packages:` list from there and passes it as the
  `workspaces` option — one source of truth, and no YAML dependency.

Neither surfaces during a debug native build, because debug builds do not bundle JavaScript. They
appear the first time Metro serves the app.

## Jest

The runtime package does **not** use the React Native Jest preset. It touches exactly two React
Native APIs, so `packages/runtime/__mocks__/react-native.js` replaces the module wholesale. Tests
run in a plain Node environment in well under a second, and — more usefully for this project — can
simulate an unlinked native module and either platform on demand.

`@react-native/jest-preset` was also removed from the example app, which has no test suite: it
pulled a second, older Jest tree that shadowed the runtime package's Jest 30 under the hoisted
layout, producing `this._moduleMocker.clearMocksOnScope is not a function`.

## Example app animations

The example app uses `lottie-react-native` for its state animations. This is an **example-only**
dependency: `packages/runtime` ships `dependencies: {}` and must stay that way. Animation sources
and the reasoning behind which were included are documented in
[`example/src/animations/README.md`](../../example/src/animations/README.md).

## Prettier

`CLAUDE.md` is in `.prettierignore`. It is author-owned prose and its formatting is not ours to
normalise.
