# Reviewed backend source preparation

This directory owns the Noq 1.3.0 application-payload transformation and the
minimal iroh 1.3.0 configuration forwarder. P03's isolated fixtures import the
same functions, rather than maintaining a second production policy.

`prepare.py` consumes separately downloaded, reviewed archives and the pinned
probe lock as **data**. It checks both complete SHA256 values and lock identities
before creating a fresh output directory, extracts each package separately with
the data filter, verifies package/version/license, and applies exact-count source
edits. It preserves the upstream license files. Existing destinations are refused;
preparation never overwrites a previous source tree. A failed preparation is not
usable; `provenance.json` is emitted only after all edits finish successfully.
No archive code is imported or executed by preparation.

The production source contains only application readiness/eligibility, STREAM and
DATAGRAM writer checks, bounded empty-DATAGRAM accounting and the iroh forwarder.
It does not add explicit path-open/disable-NAT hooks, a Transmit constructor,
fixture tests, or encrypted packet logging. Normal upstream qlog behavior is not
rewritten. Upstream versions and the original standalone lock remain unchanged.

## Explicit preparation, not a build script

Run the script from the repository root, with Python isolated mode:

```text
python -I .github/scripts/backend/prepare.py --noq-archive <archive-dir>/noq-proto.crate --iroh-archive <other-archive-dir>/iroh.crate --lock .github/probes/iroh-paths/Cargo.lock --destination target/backend
```

Archive acquisition is a separate bounded HTTPS operation; the script does not
fetch from the network and is never called by `build.rs`. All actual dependency
compilation and runtime checks in this project run in GitHub CI, not locally.
Keep downloaded archives, extracted sources and maintained scripts separate.

Trade-off: this unpublished source workspace needs an explicit preparation stage
before Cargo can consume the patched dependencies. It avoids a new public fork,
package publication, checked-in upstream source copies and network-dependent
build-script rewriting. The generated third-party trees are dependency artifacts,
not a way to hide maintained project code from its 700-line/7-item rules. Our
maintained patch scripts and tests remain subject to both limits.

## Verification and current integration boundary

`checks.py` runs only in CI. It compares all four patched Noq runtime files with
the spike's output, requires original bytes for the packet builder/qlog and other
untouched iroh files, checks absence of fixture hooks, and exercises checksum,
size, lock, source-anchor and existing-destination failures. It also prepares a
clean calibration package using the same-version standalone lock. Linux/Windows
CI compile the clean sources and run the real constant deny/allow iroh control
and payload calibration, separately from instrumented wire/NAT fixtures.

[Run 39871119928](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39871119928)
at `3bcd2f6` passed on Linux and Windows. Each OS ran five preparation checks,
18 unit tests and one real deny/allow calibration against the clean sources;
completed job logs were inspected. The instrumented bridge matrix, Noq regression,
workspace CI and physical loss/re-punch regression also completed successfully.

### Verified product lock and dependency test

[Run 39875127492](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39875127492)
at `043b222` passed the staged product workspace on Linux and Windows, including
formatting, clippy and the real native dependency test. Completed logs and both
lock artifacts were inspected. The Linux/Windows locks are byte-identical (SHA256
`2a2ae5b3f1f02df6f767a348562034d14974d1b14cb874fc93332e336704080e`).
All 120 previous registry package identities/checksums are retained; the additional
network dependency closure comes from the reviewed pinned graph. No project or
existing dependency version was raised. The backend family remains exactly 1.3.0.

The actual workspace now adopts that verified lock and the same iroh dependency.
Its root `[patch.crates-io]` entries point to the prepared sources under
`target/backend/{iroh,noq-proto}/`. Preparation is mandatory **before any Cargo
command that resolves the workspace**, including formatting or clippy. A missing
prepared source fails; there is no silent fallback to stock upstream. Main CI
prepares fresh sources before its ordinary `--locked` checks. The temporary
workspace-copy/resolution tool has been removed; normal CI does not regenerate
the committed lock.

The owned test is now `crates/shaar/tests/backend_gate.rs`. It uses real loopback
UDP and public synthetic Ed25519 fixtures, verifies peer identity, control-only
handshake, both payload directions, bounded backpressure, reset and shutdown,
with constant deny/allow calibration. It uses no probe transport or qlog hooks.
RESET_STREAM is allowed control: it can expose lower stream IDs without STREAM
bytes. The test first checks both no-delivery directions, then verifies lower-ID
non-delivery and the exact peer reset code while STREAM/DATAGRAM counters stay zero.
The earlier failure was a fixture interleaving mistake, not a reason to weaken the
payload gate. Full dependency graph resolution and immutable-identity guards also
passed before adoption; `--no-deps` metadata alone was correctly rejected as proof.

This actual-workspace adoption still needs its fresh CI run. Dependency integration
is not a working public SDK networking API or selected-custom transport authority;
those remain separate implementation tasks. Yggdrasil integration's permission/
lifecycle gate is unchanged.
