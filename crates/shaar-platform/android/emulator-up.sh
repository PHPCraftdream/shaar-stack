#!/usr/bin/env bash
# Creates the test AVD when it is missing and runs the emulator in the foreground, headless.
# Start it as a background job of the caller; stop it with "adb emu kill".
# usage: emulator-up.sh [AVD_NAME]                           (ANDROID_HOME must be set)
set -euo pipefail
export MSYS2_ARG_CONV_EXCL='*'

avd=${1:-shaar-x86_64-35}
sdk=$(cygpath -u "$ANDROID_HOME" 2>/dev/null || echo "$ANDROID_HOME")
if ! "$sdk/emulator/emulator.exe" -list-avds | tr -d '\r' | grep -qx "$avd"; then
    echo no | "$sdk/cmdline-tools/latest/bin/avdmanager.bat" create avd -n "$avd" \
        -k "system-images;android-35;google_apis;x86_64" -d pixel_6 --force
fi
exec "$sdk/emulator/emulator.exe" -avd "$avd" -no-window -no-audio -no-snapshot-save \
    -gpu swiftshader_indirect -memory 2048 -cores 2
