#!/usr/bin/env bash
set -euo pipefail

if [[ "${CI:-}" != "true" ]]; then
  printf '%s\n' 'Infrastructure compilation and tests run in CI only.' >&2
  exit 1
fi

verify() {
  local name="$1" selector="$2" expected="$3"
  local log="$RUNNER_TEMP/shaar-infrastructure-$name.log"
  local status
  if cargo test -p shaar-p2p --lib --locked "$selector" >"$log" 2>&1; then
    status=0
  else
    status=$?
  fi
  if ! python -I -X utf8 .github/scripts/scan_identity_output.py "$log"; then exit 1; fi
  cat "$log"
  if [[ "$status" -ne 0 ]]; then exit "$status"; fi
  grep -E "^test result: ok\. $expected passed; 0 failed;" "$log"
}

verify registry 'discovery::roles::infrastructure::tests::' 20
verify admission carrier_infrastructure_admission_ 7
verify network carrier_infrastructure_network_ 8
