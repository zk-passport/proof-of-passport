# SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
# SPDX-License-Identifier: BUSL-1.1

require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "selfxyz-rn-nfc-passport"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = "https://self.xyz"
  s.license      = { :type => "BUSL-1.1" }
  s.authors      = { "Self Protocol" => "engineering@self.xyz" }
  s.platforms    = { :ios => "15.0" }
  s.source       = { :git => "https://github.com/selfxyz/self.git", :tag => "rn-nfc-passport-#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift}"
  s.swift_version = "5.9"
  s.static_framework = true

  s.dependency "React-Core"

  # NFC readers ship as prebuilt binary xcframeworks (RN-08 policy) — the same b478e1f
  # NFCPassportReader fork app/ios ships (no iOS parity gap). scripts/postinstall.js downloads
  # + sha256-verifies them from the private selfxyz/self-sdk-dist release (rn-v<version>) into
  # ios/Frameworks/ at npm install, then they are vendored here. Without a GitHub token (OSS/CI)
  # the download skips gracefully and the frameworks are absent — the Swift module then compiles
  # in its stub branch (#if canImport(SelfSdkNfc)) and scan rejects NOT_AVAILABLE, so `pod install`
  # never hard-fails on a missing private artifact.
  passport_frameworks = %w[SelfSdkNfc SelfNFCPassportReader Mixpanel]
    .map { |name| "ios/Frameworks/#{name}.xcframework" }
    .select { |path| File.directory?(File.join(__dir__, path)) }
  s.vendored_frameworks = passport_frameworks unless passport_frameworks.empty?

  # Honesty guard: define SELF_NFC_AVAILABLE only when the binaries are actually vendored.
  # Swift self-guards via `#if canImport(SelfSdkNfc)`; ObjC (SelfPassportReader.m) has no
  # canImport, so the RCT_EXTERN_MODULE registration must be wrapped in
  # `#if SELF_NFC_AVAILABLE` — otherwise the module registers in the stub build and JS
  # isSelfPassportReaderAvailable() reports true even though every scan rejects NOT_AVAILABLE.
  xcconfig = { "DEFINES_MODULE" => "YES" }
  unless passport_frameworks.empty?
    xcconfig["GCC_PREPROCESSOR_DEFINITIONS"] = "$(inherited) SELF_NFC_AVAILABLE=1"
    xcconfig["SWIFT_ACTIVE_COMPILATION_CONDITIONS"] = "$(inherited) SELF_NFC_AVAILABLE"
    # The vendored xcframeworks are static libraries whose Swift modules live under Headers/.
    # CocoaPods only exposes them to clang (HEADER_SEARCH_PATHS); the Swift frontend needs the
    # module dirs on its own search path or `#if canImport(SelfSdkNfc)` is silently false — the
    # class then compiles out while the SELF_NFC_AVAILABLE-guarded ObjC extern module still
    # references it, breaking the link. The XCFrameworkIntermediates copy can't be used here:
    # CocoaPods rsyncs every xcframework's Headers/ into the same dir with --delete, so the
    # three modules clobber each other. Point Swift at the vendored slices directly instead.
    device_headers = passport_frameworks
      .map { |path| "\"${PODS_TARGET_SRCROOT}/#{path}/ios-arm64/Headers\"" }
      .join(" ")
    simulator_headers = passport_frameworks
      .map { |path| "\"${PODS_TARGET_SRCROOT}/#{path}/ios-arm64_x86_64-simulator/Headers\"" }
      .join(" ")
    xcconfig["SWIFT_INCLUDE_PATHS[sdk=iphoneos*]"] = "$(inherited) #{device_headers}"
    xcconfig["SWIFT_INCLUDE_PATHS[sdk=iphonesimulator*]"] = "$(inherited) #{simulator_headers}"
  end
  s.pod_target_xcconfig = xcconfig

  # Mixpanel is pulled transitively by the reader fork; its SPM resource bundle is needed at
  # runtime (Bundle.module lookup).
  if File.directory?(File.join(__dir__, "ios", "Frameworks", "Mixpanel_Mixpanel.bundle"))
    s.resources = "ios/Frameworks/Mixpanel_Mixpanel.bundle"
  end

  # SelfNFCPassportReader's .swiftinterface does `import OpenSSL`. The public C pod serves it;
  # pinned to the version the binaries were compiled against (self-sdk-swift/Package.resolved).
  # The consumer app must avoid a second OpenSSL.xcframework on the link line — see README
  # (Didit AutoDetection variant workaround mirrored from app/ios/Podfile).
  s.dependency "OpenSSL-Universal", "~> 1.1.2301"
end
