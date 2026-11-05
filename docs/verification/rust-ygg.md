# Native Rust Yggdrasil backend: source gate

Status: source investigation only; no dependency integrated, compilation,
execution, interoperability test, or P07 acceptance established.

The user selected a Rust implementation on 2026-10-22. Yggdrasil-ng is a
candidate, not an accepted backend. All source links below pin revision
`c9a54f1587bb133a06072596484c972a336db0d2`.

## Confirmed surface

- The [workspace manifest](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/Cargo.toml)
  declares Rust `ironwood`, `yggdrasil`, and a local `salsa20` fork.
- The [Yggdrasil manifest](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/Cargo.toml)
  declares package `yggdrasil 0.3.1`, MPL-2.0, separate library and binary
  targets, and optional `tun`, `ckr`, and service-related features.
- The [library root](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/lib.rs#L1-L17)
  exports `core`; `tun` is feature-gated. This is not merely an admin client.
- [Core](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/core.rs#L179-L284)
  exposes asynchronous key-addressed `read_from` and `write_to`. MTU is the
  underlying MTU minus one byte, capped at 65535. Its packet API does not
  require a TUN adapter. No privilege-free runtime test has yet been run.
- The [README](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/README.md)
  calls the implementation experimental and claims interoperability with
  yggdrasil-go 0.5.x. That claim is not our interoperability proof.

## Blocking lifecycle findings

These findings describe source mechanisms, not measured leak-test results.

### Detached renewal task retains the node

[Core::new, lines 155–167](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/core.rs#L155-L167)
spawns an inbound protocol handler and TLS renewal task with strong `Arc<Core>`
references and discards their join handles.

[The renewal loop, lines 578–621](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/core.rs#L578-L621)
waits twelve hours between checks and has no exit condition or cancellation
branch. [Core::close, lines 339–345](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/core.rs#L339-L345)
closes links and the inner packet connection, but does not stop this task.
Thus closing and dropping the caller's handle on a still-running shared
runtime does not release the node through this task. SDK shutdown must not
be implemented as `core.close()` alone.

The inbound handler additionally owns the receiver while its retained Core
owns `proto_in_tx`; closure of that channel is not established by this method.

### Strong ownership cycles

[Core::init_links, lines 333–336](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/core.rs#L333-L336)
stores a strong clone of the Core in Links. [Links, lines 567–575](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/links.rs#L567-L575)
contains `Option<Arc<Core>>`, and [set_core, lines 616–635](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/links.rs#L616-L635)
sets it. This produces `Core -> Links -> Core` after initialization.
[Links::close, lines 1023–1037](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/links.rs#L1023-L1037)
aborts stored tasks without joining them and does not clear that Core field.
Stopping an executor alone does not break this ownership cycle.

If the optional IPv6 wrapper is attached,
[Core::set_path_notify](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/core.rs#L172-L177)
and [ReadWriteCloser's Core field](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/ipv6rwc.rs#L37-L54)
form a second strong cycle. The key-addressed adapter need not use this wrapper;
that does not eliminate the other lifecycle findings.

The [daemon's periodic peer-key seeding task](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/main.rs#L356-L376)
is binary code, not automatically part of a library consumer. It must not be
misattributed to `Core::new`.

## Dependency consumption and cryptography

The upstream workspace patches crates.io `salsa20` to its SIMD fork. Cargo
patches in a dependency workspace are not inherited by the consuming root;
a plain git library dependency would need its own reviewed resolution.

[The daemon, main.rs line 310](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/main.rs#L306-L310)
uses `salsa20::active_backend()`, a fork-specific API. This call is in the
binary, not the library root. A library dependency does not build that binary,
but a complete library module-graph check and CI compilation without the patch
remain outstanding. Neither successful compilation nor cryptographic
interchangeability is inferred from the README or this call's location.

No SIMD patch, vendored crypto, or dependency fork has been adopted. The
standard crate and fork require resolved-source and security review before
selection; no full upstream unsafe inventory has been performed.

## Resource limits: evidence boundary

[Core construction](https://github.com/Revertron/Yggdrasil-ng/blob/c9a54f1587bb133a06072596484c972a336db0d2/crates/yggdrasil/src/core.rs#L69-L130)
configures a peer message limit of `65535 * 2` and protocol channels of
capacity 64. Configuration alone does not prove enforcement of every frame,
session, cache, or allocation bound inside ironwood. The same constructor's
path-notify callback spawns work per notification; concurrent task admission
and cleanup require separate review.

## Acceptance before production integration

- Select a consumption path without silently importing a custom crypto patch.
- Resolve task ownership, cancellation, joining, and strong cycles before
  accepting an in-process SDK lifecycle. A safe Rust API alone does not prove
  these properties. Any upstream correction or alternative backend requires
  a separate reviewed change; no correction is claimed here.
- In GitHub CI only: compile the chosen library graph on Linux and Windows,
  run authenticated datagram exchange with fixed test keys, check MTU and
  malformed inputs, and prove repeated create/close releases owned resources.
- Run without TUN, route changes, services, root, or administrative privileges.
  Creating and removing a TUN is not an acceptance scenario for this SDK.
- Establish wire interoperability with an independently pinned 0.5 reference
  test node. If Go is used as that external test oracle, it must remain outside
  Sha'ar's runtime and build dependencies; no such harness is configured here.
- Keep the independent P03 signaling-only/NAT gate open. A Rust Yggdrasil core
  does not establish iroh/Noq's application-data exclusion policy.

## Current operational blocker

The tool rejected preparation of third-party backend integration as
`Untrusted Code Integration`. This source-only investigation was permitted
instead. No dependency, probe code, workflow, or lockfile was added. Permission
for actual integration and CI execution remains unresolved; source review is
not a replacement for that execution.

## Prepared source and isolated crate (leaf 53.1)

Status: authored; not yet executed in CI.

- The pinned archive (`c9a54f1587bb133a06072596484c972a336db0d2`, tar.gz sha256
  `4d978c1a8714e0569fd0a3782adab2f6b81b9c9e54d733dbeaa023aaebae96c1`) is fetched in CI and
  prepared by `.github/probes/ygg/prepare.py` into `target/ygg/<pinned directory>/`.
  Authority is the per-file content manifest `ygg-manifest.json` (43 files, tree digest
  `b05902627173ccce95f88fc0a0e36f043646b7c129dc46e8e03d7512771ae2d0`); the archive hash is
  recorded evidence. Only `LICENSE`, `crates/ironwood/` and `crates/yggdrasil/` are extracted. No
  source patch is applied in this leaf; lifecycle repairs belong to leaf 53.2. The provenance
  receipt is uploaded with the source-preparation logs (`ygg.provenance.json`).
- The core is consumed by the new standalone crate `crates/shaar-ygg-core` (own `[workspace]`,
  own `Cargo.lock`, `yggdrasil` with `default-features = false`, stock crates.io `salsa20`, no
  tun/ckr/systemd/ctl/ws/quic). It is excluded from the root workspace together with the prepared
  tree. The product `Cargo.lock`, `crates/shaar` and the accepted SDK normal graph are unchanged:
  the existing `shaar -> shaar-ygg` scaffold edge would otherwise pull about 84 not yet reviewed
  crates into the SDK graph guard. P10 connects `shaar-ygg` to this crate with its own graph review.
- The nested lock is produced by CI, never by hand: Actions -> CI -> Run workflow with
  `native_graph_resolve: true` runs `cargo generate-lockfile` for the crate and uploads
  `ygg-core.Cargo.lock.candidate` in the `native-graph-preparation-diagnostics` artifact; the
  coordinator adopts it as `crates/shaar-ygg-core/Cargo.lock` for `--locked` runs.
- The selected-test runner runs the crate by `--manifest-path` (`.github/ci/policy.py` `NESTED`),
  formatting covers it through `cargo fmt --manifest-path`.

Known gaps, not claimed as covered: the root dependency-license report and the structure checker
read only the root workspace, so the nested closure's licenses (MPL-2.0 for `yggdrasil` and
`ironwood`) and the first-line `#![forbid(unsafe_code)]` of the nested crate are checked only by the
crate's own unit test and by the later notices work (#72/#73); the `scope: full` clippy command
(`--workspace`) does not include the nested crate; compilation of the prepared core with
`default-features = false` is unverified until CI runs.
