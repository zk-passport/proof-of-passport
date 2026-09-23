# RN SDK Example App

Example React Native app showing a third-party integration of `@selfxyz/rn-sdk` with the
optional capture packages `@selfxyz/rn-mrz-scanner` (passport MRZ camera scan) and
`@selfxyz/rn-nfc-passport` (NFC chip read).

## What it demonstrates

- `<SelfVerification mode="self-app" />` — the full WebView-driven verification flow:
  MRZ camera scan → NFC chip read → proof, with `onSuccess`/`onFailure`/`onCancelled` callbacks.
- Standalone usage of the capture packages (`DirectCaptureScreen.tsx`): `startScanning()` for
  MRZ, then `scan`/`scanPassport` with the MRZ-derived BAC keys for the chip read.
- Capability detection via `isMrzScannerAvailable()` / `isSelfPassportReaderAvailable()`.

## Prerequisites

- `SELF_SDK_GITHUB_TOKEN` (a GitHub token with `read:packages` on `selfxyz/self-sdk-dist`)
  exported **before `pnpm install`**. The capture packages' postinstall downloads the iOS
  xcframeworks (SelfSdkOcr, SelfSdkNfc); the Android build resolves `xyz.self.sdk:*` AARs from
  the same token-gated Maven repo. **Without the token the app still builds, but both capture
  modules compile as stubs and the capability panel shows `unavailable`.**
- Physical device: camera and NFC do not work in simulators/emulators.
- iOS: an Apple team whose provisioning profile for `com.selfxyz.rnexample` carries the
  Near Field Communication Tag Reading capability. Set the team locally in Xcode; do not
  commit `DEVELOPMENT_TEAM`.

## Setup and run

```bash
export SELF_SDK_GITHUB_TOKEN=...   # before install
pnpm install                       # repo root

# Build the workspace packages (none commit dist/)
pnpm --filter @selfxyz/rn-sdk build          # builds webview-app → assets/self-wallet → tsup
pnpm --filter @selfxyz/rn-mrz-scanner build
pnpm --filter @selfxyz/rn-nfc-passport build

# iOS
pnpm --filter @selfxyz/rn-sdk-example-app install-app   # bundle install + pod install
pnpm --filter @selfxyz/rn-sdk-example-app start         # Metro
# then build/run SelfRNExampleApp.xcworkspace from Xcode on a physical iPhone

# Android
cd packages/rn-sdk-example-app/android && ./gradlew :app:assembleDebug
```

## WebView bundle delivery

- Android: `@selfxyz/rn-sdk`'s own gradle `assets.srcDirs` merges `assets/self-wallet` into the
  APK — no app wiring needed.
- iOS: the Xcode project has a "Copy self-wallet assets" build phase that copies
  `node_modules/@selfxyz/rn-sdk/assets/self-wallet` into the app bundle. Keep it ordered before
  the "Bundle React Native code and images" phase.

## iOS debug networking

- `Info.plist` keeps ATS strict for non-debug builds.
- `Info-Debug.plist` enables arbitrary loads for debug testing.
