#!/usr/bin/env bash
# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

mkdir -p target/publication-archives
curl --fail --location --max-time 120 --max-filesize 16777216 \
  https://static.crates.io/crates/iroh-dns/iroh-dns-1.3.0.crate \
  --output target/publication-archives/iroh-dns-1.3.0.crate
curl --fail --location --max-time 120 --max-filesize 2097152 \
  https://static.crates.io/crates/simple-dns/simple-dns-0.12.0.crate \
  --output target/publication-archives/simple-dns-0.12.0.crate
python -I .github/scripts/p2p/discovery/mainline/ci/publication/execution/ci.py \
  --archive target/publication-archives/iroh-dns-1.3.0.crate \
  --simple-dns-archive target/publication-archives/simple-dns-0.12.0.crate \
  --evidence target/publication-evidence
