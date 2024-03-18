# Proof of Passport App

## Requirements

Install `nodejs v18`, [circom](https://docs.circom.io/) and [snarkjs](https://github.com/iden3/snarkjs)

For Android, install Java, Android Studio and the Android SDK

For iOS, install Xcode and [cocoapods](https://cocoapods.org/)

## Installation

```bash
yarn
```

In `/common`, also run:
```bash
yarn
```

## Run the app

Let's run the app with the currently deployed zkey to mint the Proof of Passport SBT.

First, connect your phone to your computer and allow access.

### Android

Launch the react-native server:
```
yarn start
```
Then press `a` to open the app on Android.

To see the Android logs you'll have to use the Android Studio Logcat.

### iOS

Download the currently deployed arkzkey:
```
./scripts/download_current_zkey.sh
```
This will place it at `circuits/build`.

Then, build the iOS native module:
```
./scripts/build_ios_module.sh
```

Then launch the server:
```
yarn start
```
Press `i` to open the app on iOS.
To see the native logs, run the app on Xcode.

## Modify the circuits

If you want to modify the circuits, you'll have to adapt a few things.

First, go to the `circuit` folder of the monorepo, modify the circuits and build them.

### Android

Right now, the `ark-circom-passport/src/passport.rs` includes custom code that handles the inputs. Adapt it to your circuit.

Build the android native module:
```
./scripts/build_android_module.sh
```

You might need to set the rust-toolchain rust version as global default. Example:
```
rustup default 1.67.0
```

For macOS users you might also need to set-up the path to sdk:
in /app/android create local.properties

Add the following line:
sdk.dir=/Users/<user>/Library/Android/sdk or any relevant path to your sdk

### iOS

The iOS module swiftly handles changes in the interface of the circuit, courtesy of [mopro](https://github.com/oskarth/mopro). 

You should not have to adapt anything except the inputs you pass in `App.tsx`.

Build the iOS native module:
```
./scripts/build_ios_module.sh
```

## Export a new release

Don't forget to comment out the presets in .env when doing a release.

### Android
Because of the size of the arkzkey, it has to be downloaded dynamically on android.

Upload it at a publicly accessible location, then update the path in `app/deploymets/arkzkeyUrl.json`.

Then run:
```
./scripts/build_android_module.sh --download-arkzkey
```

#### Export as apk
```
cd android
./gradlew assembleRelease
```
The built apk it located at `android/app/build/outputs/apk/release/app-release.apk`

#### Publish on the Play Store
As explained [here](https://reactnative.dev/docs/signed-apk-android), first setup `android/app/my-upload-key.keystore` and the private vars in `~/.gradle/gradle.properties`, then run:
```
npx react-native build-android --mode=release
```
This builds `android/app/build/outputs/bundle/release/app-release.aab`.

Then to test the release on an android phone, delete the previous version of the app and run:
```
yarn android --mode release
```

### iOS

Build the iOS native module:
```
./scripts/build_ios_module.sh
```

In Xcode, go to `Product>Archive` then follow the flow.
