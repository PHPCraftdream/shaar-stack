# CI-only package campaign; all arguments are fixed by the selection policy.
set -euo pipefail
mode="$1"
packages=()
if [[ "$CI_P2P" == true ]]; then packages+=(-p shaar-p2p); fi
if [[ "$CI_SDK" == true ]]; then packages+=(-p shaar); fi
if [[ "$CI_APPS" == true ]]; then
  packages+=(-p shaar-server -p shaar-client -p shaar-platform -p shaar-ygg)
fi
if [[ "${#packages[@]}" -eq 0 ]]; then
  printf 'No product package selected for requested Rust campaign\n'
  exit 1
fi
case "$mode" in
  lint)
    cargo clippy --locked "${packages[@]}" --all-targets -- -D warnings ;;
  test)
    log="$RUNNER_TEMP/shaar-targeted-product.log"
    if cargo test --locked "${packages[@]}" >"$log" 2>&1; then status=0; else status=$?; fi
    python -I -X utf8 .github/scripts/scan_identity_output.py "$log"
    cat "$log"
    exit "$status" ;;
  *) printf 'Unknown product campaign\n'; exit 1 ;;
esac
