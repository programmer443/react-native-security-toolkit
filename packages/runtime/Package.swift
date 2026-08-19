// swift-tools-version:5.9
import PackageDescription

/// Swift Package manifest for the iOS security engine.
///
/// This exists so the engine can be unit-tested with `swift test` on an ordinary
/// macOS machine — no simulator, no Xcode project, no jailbroken device. The
/// engine sources are deliberately Foundation-only and reach the platform through
/// injected probes, which is what makes that possible.
///
/// The real probe implementations live in `ios/Probes` and are **not** part of
/// this package: they use UIKit and iOS-specific syscalls. CocoaPods compiles
/// both directories into the shipped pod, so the engine and its probes end up in
/// one module there.
let package = Package(
  name: "RNSecurityEngine",
  platforms: [.macOS(.v13), .iOS(.v15)],
  products: [
    .library(name: "RNSecurityEngine", targets: ["RNSecurityEngine"])
  ],
  targets: [
    .target(name: "RNSecurityEngine", path: "ios/Engine"),
    .testTarget(
      name: "RNSecurityEngineTests",
      dependencies: ["RNSecurityEngine"],
      path: "ios/EngineTests"
    ),
  ]
)
