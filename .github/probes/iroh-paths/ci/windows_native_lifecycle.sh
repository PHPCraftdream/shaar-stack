#!/usr/bin/env bash
# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
test_name=network::signaling::endpoint::tests::native_app_and_both_joined_backends_close_with_sessions_and_factories_retained
for trial in {1..12}; do
  printf 'Native path lifecycle trial %s/12\n' "$trial"
  log="$RUNNER_TEMP/shaar-native-path-$trial.log"
  if cargo test -p shaar --lib --locked "$test_name" -- --exact --color never >"$log" 2>&1; then
    status=0
  else
    status=$?
  fi
  if ! python -I -X utf8 .github/scripts/scan_identity_output.py "$log"; then exit 1; fi
  cat "$log"
  if [[ "$status" -ne 0 ]]; then exit "$status"; fi
  grep -Fx "test $test_name ... ok" "$log"
done
