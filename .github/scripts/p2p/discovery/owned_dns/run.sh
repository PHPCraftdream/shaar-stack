# Owned DNS test inventory gate, invoked from the CI owned DNS foundation step.
# Builds the shaar-p2p lib tests once, scans build output for identity material,
# and delegates the dynamic test inventory/run verification to verify.py.
set -euo pipefail
python -I .github/scripts/p2p/discovery/owned_dns/checks.py
work="$RUNNER_TEMP/shaar-owned-dns"
mkdir -p "$work"
build_log="$work/build.jsonl"
if cargo test -p shaar-p2p --lib --locked --no-run --message-format=json >"$build_log" 2>"$work/build.stderr"; then build_status=0; else build_status=$?; fi
if [[ "$build_status" -ne 0 ]]; then
  if python -I -X utf8 .github/scripts/scan_identity_output.py "$build_log" && python -I -X utf8 .github/scripts/scan_identity_output.py "$work/build.stderr"; then cat "$work/build.stderr" "$build_log"; fi
  exit "$build_status"
fi
python -I -X utf8 .github/scripts/scan_identity_output.py "$build_log"
python -I -X utf8 .github/scripts/scan_identity_output.py "$work/build.stderr"
python -I .github/scripts/p2p/discovery/owned_dns/verify.py --artifacts "$build_log" --target-dir target --directory "$work" --status "$build_status" --scanner .github/scripts/scan_identity_output.py
