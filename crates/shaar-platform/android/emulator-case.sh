#!/usr/bin/env bash
# One end-to-end case on a running emulator: both product roles run inside the app and an exact
# byte exchange crosses client -> direct QUIC -> server -> echo target and back.
# usage: ANDROID_SERIAL=SERIAL emulator-case.sh APK          (ANDROID_HOME must be set)
# The case works on an emulator and on a physical device; it contacts no public network:
# the server binds and the echo target listens on the loopback of the device.
set -euo pipefail
export MSYS2_ARG_CONV_EXCL='*'

apk=$1
sdk=$(cygpath -u "$ANDROID_HOME" 2>/dev/null || echo "$ANDROID_HOME")
# Every call is pinned to one device: the target is never guessed when several are attached.
serial=${ANDROID_SERIAL:?set ANDROID_SERIAL to the emulator or the device under test}
adb() { "$sdk/platform-tools/adb.exe" -s "$serial" "$@"; }
pkg=dev.shaar.harness
payload=shaar-android-roundtrip

fail() { echo "FAIL: $*" >&2; exit 1; }
file() { adb shell run-as "$pkg" cat "files/$1" 2>/dev/null | tr -d '\r'; }
start() { adb shell am start -W -n "$pkg/.Runner" --es name "$1" --es argv "'$2'" >/dev/null; }

# wait_for NAME_OF_FILE PATTERN SECONDS: the file content must match the pattern in time.
wait_for() {
    for _ in $(seq "$3"); do
        if file "$1" | grep -Eq "$2"; then return 0; fi
        sleep 1
    done
    fail "$1 did not show '$2' in $3 s: $(file "$1")"
}
# step NAME ARGV: run one command to completion and require exit code 0.
step() {
    start "$1" "$2"
    wait_for "$1.exit" '^[0-9-]+$' 30
    [ "$(file "$1.exit")" = 0 ] || fail "$1 exited with $(file "$1.exit"): $(file "$1.log")"
}
key_of() { file "$1.log" | grep -Eo 'public_key=[0-9a-f]{64}' | head -1 | cut -d= -f2; }

adb wait-for-device
for _ in $(seq 240); do
    [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1 ] && break
    sleep 2
done
adb install -r "$apk" >/dev/null
adb shell am force-stop "$pkg"
adb shell run-as "$pkg" rm -rf files/s files/c

start echo '@echo 47100'
wait_for echo.log 'listening=' 20

lib='@LIB@/libshaar'
step sinit "${lib}_server.so init --dir @FILES@/s --private"
server_key=$(key_of sinit)
[ -n "$server_key" ] || fail "no server key: $(file sinit.log)"
step stgt "${lib}_server.so config set target 127.0.0.1:47100 --dir @FILES@/s"
step sbind "${lib}_server.so config set bind 127.0.0.1:47101 --dir @FILES@/s"
step cinit "${lib}_client.so init $server_key --address 127.0.0.1:47101 --dir @FILES@/c --private"
client_key=$(key_of cinit)
[ -n "$client_key" ] || fail "no client key: $(file cinit.log)"
step sallow "${lib}_server.so allow add $client_key --dir @FILES@/s"

start srv "${lib}_server.so run --dir @FILES@/s"
wait_for srv.log '^bound=' 60
start cli "${lib}_client.so connect --dir @FILES@/c"
wait_for cli.log '^listening=' 60

reply=$(adb shell "printf $payload | toybox nc -w 5 127.0.0.1 2222" | tr -d '\r')
echo "server log:"; file srv.log; echo "client log:"; file cli.log
[ "$reply" = "$payload" ] || fail "expected '$payload', got '$reply'"
echo "PASS: $payload crossed client -> QUIC -> server -> echo and back on $(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
