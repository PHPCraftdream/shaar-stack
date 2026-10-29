# CI-only dynamic inventory for one explicitly selected Cargo library target.
set -euo pipefail
selector="$1"
name="$2"
log="$3"
target_name="$4"
source="$5"
target_dir="$6"
mode="$7"
shift 7
python -I .github/scripts/p2p/discovery/owned_dns/checks.py
work="$RUNNER_TEMP/shaar-inventory-$name"
mkdir -p "$work"
: >"$log"
if cargo test "$@" --no-run --message-format=json >"$work/build.jsonl" 2>"$work/build.stderr"; then status=0; else status=$?; fi
cat "$work/build.stderr" "$work/build.jsonl" >"$log"
if python -I -X utf8 .github/scripts/scan_identity_output.py "$work/build.stderr" && python -I -X utf8 .github/scripts/scan_identity_output.py "$work/build.jsonl" && python -I -X utf8 .github/scripts/scan_identity_output.py "$log"; then
  cat "$log"
else
  if [[ "$status" -ne 0 ]]; then exit "$status"; fi
  exit 1
fi
if [[ "$status" -ne 0 ]]; then exit "$status"; fi
run_args=()
if [[ -n "$selector" ]]; then run_args+=("$selector"); fi
mode_args=()
if [[ "$mode" == show-output ]]; then
  run_args+=(-- --color never --show-output)
  mode_args=(--show-output)
fi
if cargo test "$@" "${run_args[@]}" >"$work/cargo-run.log" 2>&1; then status=0; else status=$?; fi
cat "$work/cargo-run.log" >>"$log"
if python -I -X utf8 .github/scripts/scan_identity_output.py "$log"; then
  cat "$work/cargo-run.log"
else
  if [[ "$status" -ne 0 ]]; then exit "$status"; fi
  exit 1
fi
if [[ "$status" -ne 0 ]]; then exit "$status"; fi
python -I .github/scripts/p2p/discovery/owned_dns/verify.py --artifacts "$work/build.jsonl" --target-dir "$target_dir" --directory "$work" --status 0 --scanner .github/scripts/scan_identity_output.py --selector "$selector" --cargo-output "$work/cargo-run.log" --target-name "$target_name" --source "$source" "${mode_args[@]}"
