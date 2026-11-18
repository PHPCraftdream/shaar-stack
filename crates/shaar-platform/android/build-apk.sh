#!/usr/bin/env bash
# Builds the debug-signed harness APK around the two product executables, without Gradle.
# usage: build-apk.sh ABI SERVER_EXE CLIENT_EXE OUT_DIR      (ANDROID_HOME must be set)
# The executables are packed as native libraries (libshaar_*.so) so the package manager
# extracts them to the native library directory, the one place an app may execute from.
set -euo pipefail
export MSYS2_ARG_CONV_EXCL='*'

abi=$1 server=$2 client=$3 out=$4
here=$(cd "$(dirname "$0")" && pwd)
w() { cygpath -m "$1" 2>/dev/null || echo "$1"; }
sdk=$(cygpath -u "$ANDROID_HOME" 2>/dev/null || echo "$ANDROID_HOME")
bt=$(printf '%s\n' "$sdk"/build-tools/* | sort -V | tail -1)
android_jar="$sdk/platforms/android-35/android.jar"

rm -rf "$out"
mkdir -p "$out/classes" "$out/stage/lib/$abi"
javac --release 8 -encoding UTF-8 -classpath "$(w "$android_jar")" -d "$(w "$out/classes")" "$(w "$here/Runner.java")"
mapfile -t classes < <(find "$out/classes" -name '*.class' -exec cygpath -m {} \;)
java -cp "$(w "$bt/lib/d8.jar")" com.android.tools.r8.D8 --release --min-api 26 \
    --lib "$(w "$android_jar")" --output "$(w "$out/stage")" "${classes[@]}"
"$bt/aapt2.exe" link -o "$(w "$out/base.apk")" -I "$(w "$android_jar")" \
    --manifest "$(w "$here/AndroidManifest.xml")" --min-sdk-version 26 --target-sdk-version 35 \
    --version-code 1 --version-name harness
cp "$server" "$out/stage/lib/$abi/libshaar_server.so"
cp "$client" "$out/stage/lib/$abi/libshaar_client.so"
(cd "$out/stage" && jar --update --no-manifest --file ../base.apk classes.dex lib)
"$bt/zipalign.exe" -f -p 4 "$(w "$out/base.apk")" "$(w "$out/aligned.apk")"
# A throwaway key for this one build; it never leaves the output directory.
keytool -genkeypair -keystore "$(w "$out/harness.jks")" -storepass harness -keypass harness \
    -alias harness -dname "CN=Shaar harness" -keyalg RSA -keysize 2048 -validity 30 >/dev/null 2>&1
java -jar "$(w "$bt/lib/apksigner.jar")" sign --ks "$(w "$out/harness.jks")" \
    --ks-pass pass:harness --key-pass pass:harness --min-sdk-version 26 \
    --out "$(w "$out/shaar-harness.apk")" "$(w "$out/aligned.apk")"
echo "apk=$out/shaar-harness.apk"
