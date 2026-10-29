# Owned DNS and shaar-p2p library inventory gate.
set -euo pipefail
selector="${1:-owned_dns_}"
name="${2:-owned-dns}"
log="${3:-$RUNNER_TEMP/shaar-owned-dns.log}"
bash .github/scripts/p2p/discovery/owned_dns/cargo.sh "$selector" "$name" "$log" shaar_p2p crates/shaar-p2p/src/lib.rs target normal -p shaar-p2p --lib --locked
