# Android test harness

A debuggable, Gradle-free APK that runs the two product executables (`shaar-server`, `shaar-client`) inside an app sandbox, so that Android behaviour is observed in the real app domain and not only through `adb shell`. It is a test vehicle, not a product: one activity that shows each command and follows its log in muted colors (wrapped to the screen width, newest line in view), no packaging for distribution, no release signing (the build creates a throwaway key).

| File | Purpose |
|---|---|
| `AndroidManifest.xml` | `INTERNET`, debuggable, native libraries extracted to disk |
| `Runner.java` | Starts one named command; allows only `@LIB@/libshaar_*.so`; logs to `files/NAME.log`, exit code to `files/NAME.exit`; `@echo PORT` is a loopback echo target |
| `build-apk.sh` | `javac` + `d8` + `aapt2` + `zipalign` + `apksigner` from the SDK build-tools |
| `emulator-up.sh` | Creates the `shaar-x86_64-35` AVD when missing and runs it headless |
| `emulator-case.sh` | Installs the APK and drives one end-to-end case through intents |

## Run (local machine, Windows host)

For a physical arm64 phone (USB debugging on); the ABI directory name of the APK is `arm64-v8a`:

```text
export ANDROID_HOME='D:\path\to\android-sdk'
wnice -c 10 -m 10g -- cargo ndk -t arm64-v8a -P 24 build --locked --offline -p shaar-server -p shaar-client
bash crates/shaar-platform/android/build-apk.sh arm64-v8a \
    target/aarch64-linux-android/debug/shaar-server target/aarch64-linux-android/debug/shaar-client target/android
ANDROID_SERIAL=<serial from adb devices> bash crates/shaar-platform/android/emulator-case.sh target/android/shaar-harness.apk
```

For the x86_64 emulator use `-t x86_64`, the ABI `x86_64` and `bash emulator-up.sh` as a background job; stop it with `adb -s emulator-5554 emu kill`. `ANDROID_SERIAL` is mandatory: the scripts never guess a target when several devices are attached.

The case initialises a server and a client with the new subcommands, allowlists the client key, runs both roles in the app and checks that an exact payload crosses client, direct QUIC, server and the echo target and returns. It leaves the app installed so its logs can be read; remove it with `adb -s <serial> uninstall dev.shaar.harness`.

## Evidence boundary

CI does not execute this directory (it only checks structure); every result comes from a local run on one device and is reported as such. Observed on 2026-11-17: the case passed on one physical arm64-v8a phone (Xiaomi, Android 17, debug build of both products, USB-installed app removed afterwards): the exact payload crossed client, direct QUIC, server and echo target and returned (`route path=native`, 23 bytes each way). The case is loopback-only: carrier NAT, battery policies, vendor process killers and any path between two devices are not exercised. Observed on the development machine (Windows, WHPX): the x86_64 emulator did not boot when started inside a `wnice` Job Object (hard CPU rate cap, and again with only an affinity limit: the qemu process stayed at 0-2 s of CPU time for tens of minutes); the cause was not isolated.
