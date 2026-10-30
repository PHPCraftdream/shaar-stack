# CI-only runner; selectors come from the validated diff plan, never shell text.
set -euo pipefail
python -I .github/ci/run.py "$1"
