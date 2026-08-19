require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "SecurityToolkit"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/programmer443/react-native-security-toolkit.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift,cpp}"
  # Engine unit tests are run with `swift test` on macOS and never shipped.
  s.exclude_files = "ios/EngineTests/**/*"
  s.private_header_files = "ios/**/*.h"

  s.swift_version = "5.9"

  install_modules_dependencies(s)
end
