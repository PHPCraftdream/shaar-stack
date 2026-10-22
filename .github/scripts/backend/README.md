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

These checks are authored; acceptance requires actual CI results. Workspace Cargo
dependency wiring and production SDK integration are not yet installed. This stage
must not be reported as a working production SDK or as selected-custom transport
authorization. Yggdrasil integration's separate permission/lifecycle gate remains.
