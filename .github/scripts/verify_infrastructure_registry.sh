#!/usr/bin/env bash
set -euo pipefail

if [[ "${CI:-}" != "true" ]]; then
  printf '%s\n' 'Infrastructure compilation and tests run in CI only.' >&2
  exit 1
fi

verify() {
  local name="$1" selector="$2"
  bash .github/scripts/p2p/discovery/owned_dns/run.sh "$selector" "infrastructure-$name" "$RUNNER_TEMP/shaar-infrastructure-$name.log"
}

verify registry 'discovery::roles::infrastructure::tests::'
verify admission carrier_infrastructure_admission_
verify network carrier_infrastructure_network_
