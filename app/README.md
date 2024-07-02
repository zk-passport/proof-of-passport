# Proof of Passport App

## Requirements

| Requirement | Version | Installation Guide |
|-------------|---------|--------------------|
| nodejs      | > v18     | [Install nodejs](https://nodejs.org/) |
| circom      | Latest  | [Install circom](https://docs.circom.io/) |
| snarkjs     | Latest  | [Install snarkjs](https://github.com/iden3/snarkjs) |


### Android
| Requirement | Version | Installation Guide |
|-------------|---------|--------------------|
| Java        | 17      | [Install Java](https://www.oracle.com/java/technologies/downloads/#java17) |
| Android Studio (Optional)* | Latest | [Install Android Studio](https://developer.android.com/studio) |
| Android SDK | Latest  | [Install Android SDK](https://developer.android.com/studio#downloads) |
| Android NDK         | 23.1.7779620 | [Install NDK](https://developer.android.com/studio) or [GPT4 guide](https://chatgpt.com/share/a6e2544b-d32a-4554-a452-402511d03ffc) |

\* To facilitate the installation of the SDK and the NDK, and to pair with development devices with a conventient QR code, you can use Android Studio.

### iOS
| Requirement | Version | Installation Guide |
|-------------|---------|--------------------|
| Xcode       | Latest  | [Install Xcode](https://developer.apple.com/xcode/) |
| cocoapods   | Latest  | [Install cocoapods](https://cocoapods.org/) |


## Installation

> All of the commands in this guide are run from the `proof-of-passport/app` directory

Install dependencies
```bash
yarn install
yarn install-app
```

### Android

#### Using Android Studio

In Android Studio, go to **Tools** > **SDK Manager** in the menu

Under **SDK Platforms**, install the platform with the highest API number

Under **SDK Tools**, check the **Show Package Details** checkbox, expand **NDK (Side by side)**, select version **23.1.7779620** and install.


#### Using sdkmanager via CLI

Create a directory for the Android SDK. For example `~/android_sdk`. Define the environment variable `ANDROID_HOME` to point that directory.

Install sdkmanager under `ANDROID_HOME` according to the instructions on https://developer.android.com/tools/sdkmanager



List available SDK platforms
```bash
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --list | grep platforms
```

In the list of platforms, find the latest version and install it. (Replace *NN* with the latest version number)
```bash
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --install "platforms;android-NN"
```

Install the NDK
```bash
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --install "ndk;23.1.7779620"
```
Define the environment variable `ANDROID_NDK` to `$ANDROID_HOME/ndk/23.1.7779620`

Install Platform Tools, needed for the `adb` tool
```bash
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --install platform-tools
```

Add `$ANDROID_HOME/platform-tools` to your `$PATH` variable


## Run the app

### Android

#### Pair and connect to the phone

##### Using Android Studio

In Android Studio, use Device Manager to pair with and connect to your phone.

##### Using adb

In your phone's developer settings, select **Wireless debugging** > **Pair the device using a pairing code**. Using the displayed information, run
```
adb pair PHONE_IP:PAIRING_PORT PAIRING_CODE
```

To connect to the device, find the IP number and port (different port than in the pairing step) directly under Wireless debugging, and run
```
adb connect PHONE_IP:DEVELOPMENT_PORT
```

#### Run the app

Create the file `android/local.properties` specifying the SDK directory, for example:
```
sdk.dir=/path/to/your/android/sdk
```

or create it with
```bash
echo sdk.dir=$ANDROID_HOME > android/local.properties
```


Launch the React Native server:
```bash
yarn start
```

Press `a` to open the app on Android.

To view the Android logs, use the Logcat feature in Android Studio, or use the `adb logcat` command-line tool.

### iOS

> :warning: To run the app on iOS, you will need a paying Apple Developer account. Free accounts can't run apps that use NFC reading.<br/>
> Contact us if you need it to contribute.

Open the ios project on Xcode and add your provisioning profile in Targets > ProofOfPassport > Signing and Capabilities

Then, install pods:
```
cd ios
pod install
```

And run the app in Xcode.

## Modify the circuits

If you want to modify the circuits, you'll have to adapt a few things.

First, go to the `circuit` folder of the monorepo, modify the circuits and build them.

Then, upload the zipped zkeys built at publicly available urls and replace the urls in `app/src/utils/zkeyDownload.ts`.

Adapt the input generation in `common/src/utils/generateInputs.ts`, and adapt and redeploy the contracts.

### Android

Make sure that `ANDROID_NDK` is defined as per the instructions above. Then build the android native module:
```
./scripts/build_android_module.sh
```

### iOS

Find your [development team id](https://chat.openai.com/share/9d52c37f-d9da-4a62-acb9-9e4ee8179f95) and run:
```
export DEVELOPMENT_TEAM="<your-development-team-id>"
./scripts/build_ios_module.sh
```

## Export a new release

### Android

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

Don't forget to bump `versionCode` in `android/app/build.gradle`.

### iOS

In Xcode, go to `Product>Archive` then follow the flow.

Don't forget to bump the build number.

## FAQ

If you get something like this:
```
'std::__1::system_error: open: /proof-of-passport/app: Operation not permitted'
```
You might want to try [this](https://stackoverflow.com/questions/49443341/watchman-crawl-failed-retrying-once-with-node-crawler):
```
watchman watch-del-all
watchman shutdown-server
```
