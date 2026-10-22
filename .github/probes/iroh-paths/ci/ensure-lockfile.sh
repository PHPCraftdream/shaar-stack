#!/usr/bin/env bash
# Lockfile handling for the iroh-paths baseline substage.
#
# - If Cargo.lock is missing (fresh checkout), bootstrap it with
#   `cargo generate-lockfile` and print an explicit BOOTSTRAP line.
# - Otherwise run fully LOCKED (`cargo test --locked`) so CI fails on any
#   dependency drift instead of silently resolving new versions.
#
# SSLKEYLOGFILE: CI creates target/iroh-paths/sslkeylog.txt BEFORE the cargo
# process starts and exports SSLKEYLOGFILE pointing at it. It holds
# test-only synthetic keys for the in-memory transport; harmless today, but
# a later substage may wire iroh v1.3.0's public `Builder::keylog(bool)`
# (iroh/src/endpoint.rs, rustls KeyLogFile via iroh/src/tls.rs), which reads
# exactly this variable.
#
# IROH_TEST_QLOG is deliberately NOT set: this substage uses the PUBLIC
# `QuicTransportConfig::builder().qlog_from_path(dir, prefix)` API
# (iroh v1.3.0, feature "qlog"); no env gate is involved.
#
# Usage: ci/ensure-lockfile.sh [extra cargo args...]
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="LOCKED"
if [[ ! -f Cargo.lock ]]; then
  MODE="BOOTSTRAP"
  echo "ensure-lockfile: BOOTSTRAP mode - Cargo.lock missing, generating it"
  cargo generate-lockfile
else
  echo "ensure-lockfile: LOCKED mode - using existing Cargo.lock"
fi

mkdir -p target/iroh-paths
touch target/iroh-paths/sslkeylog.txt
export SSLKEYLOGFILE="$PWD/target/iroh-paths/sslkeylog.txt"
echo "ensure-lockfile: SSLKEYLOGFILE=$SSLKEYLOGFILE (synthetic test keys)"

cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked "$@"
