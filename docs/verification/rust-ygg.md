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
  recorded evidence. Only `LICENSE`, `crates/ironwood/` and `crates/yggdrasil/` are extracted.
  Leaf 53.1 applies no source patch; lifecycle repairs belong to leaf 53.2. The provenance
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

## Lifecycle patch (leaf 53.2)

Status: accepted at `630b264` (CI run `42026035312`, Linux and Windows green; nothing was run
locally).

- `.github/probes/ygg/lifecycle_patch.py` plus `patches/{core,links,proto}.py` express the
  reviewed lifecycle corrections as exact byte replacements ("old occurs exactly once"), pinned
  to the manifest's original per-file hashes; each `PATCHED_SHA256` pins the patched bytes of
  `crates/yggdrasil/src/{core,links,proto}.rs` (computed from the literal hunks over the pinned
  data; every old text occurs exactly once); a mismatch fails preparation closed.
- Hunks: core.rs gains a cancellation-token root and stored join handles for the proto sender,
  inbound proto handler, proto cleanup handler and TLS renewal loop; each loop selects the
  token; `close()` clears the path-notify slot, runs links close (which cancels and joins the
  rate, listener and reconnect tasks, abort-then-joins tracked per-connection tasks and breaks
  the Core->Links cycle by clearing the Links core field), cancels the root token, awaits the
  stored handles, then closes the inner ironwood connection; a `close_started` flag makes close
  idempotent. proto.rs cleanup loop exits on a child token (`ProtoHandler::with_shutdown`;
  `new` is unchanged). links.rs rate task gains a cancel branch; TCP per-connection spawns are
  tracked in a `JoinSet` reaped opportunistically.
- Executed in CI on Linux and Windows (receipts list the five `lifecycle` tests next to the two
  smoke tests): `crates/shaar-ygg-core/tests/lifecycle.rs` runs three create/listen/close cycles, concurrent and repeated close,
  and a two-core loopback peering closed listener-first and dialer-first. Each close finishes
  under a timeout, the caller holds the only strong reference after close, the runtime's
  alive-task count (`RuntimeMetrics::num_alive_tasks`, stable; the test body runs under
  `block_on` and is not counted) reaches zero within a bounded poll, `Weak<Core>` stops
  upgrading after drop, and the same loopback port binds again.
- Known gaps (independent review, recorded before execution): the `ironwood` router actor and
  peer writer tasks are cancelled but not joined by `close()`; the bounded alive-task poll
  observes that they exit on an idle core, but an in-flight 10-second peer write can outlast
  the five-second poll. Leaf 53.2b corrects the one `ironwood` hunk the review proved
  necessary: the encrypted reader awaited `recv_tx.send(msg)` outside its cancellation select
  (`encrypted/mod.rs`), so a full receive queue (the adapter not reading) could block
  `close()`; the hunk selects on the cancellation token. Regression evidence (CI, Linux and
  Windows): the test `flooding_a_silent_receiver_fills_its_receive_queue` proves the flood
  delivers at least 512 datagrams to a silent receiver, and
  `close_returns_while_the_receive_queue_is_full` closes that receiver in time. A throwaway
  negative control without the hunk (run `42030065755`, deleted afterwards) failed exactly
  that test with `close() did not finish within 10s` on both OS while the precondition passed;
  the patched run `42030031014` is green. Path discovery between two fresh cores takes time:
  writes are accepted before any datagram is delivered, so key-addressed exchange (53.3)
  must wait for a delivered probe first.
  The QUIC listener branch is feature-gated off in
  this crate and is not patched; `remove_peer` still aborts without joining (outside the
  adapter path). A cancelled `close()` after its handles were drained leaves the core
  half-closed; callers must not cancel it.
- MPL-2.0 note: the modified `core.rs`, `links.rs`, `proto.rs` and ironwood `encrypted/mod.rs` are file-level
  MPL-protected. Decision of 2026-11-05 (user): this repository is the way to obtain their source
  (the patch hunks under `.github/probes/ygg/patches/` and the pinned upstream revision with its
  file hashes), so no further publication step is required; upstream `LICENSE` is preserved in the
  prepared tree. The license check allows MPL-2.0 narrowly, for the pinned `ironwood` and
  `yggdrasil` packages only.

## Key-addressed transport (leaf 53.3)

Status: accepted at `3396840` (CI run `42033089403`, Linux and Windows green; nothing was run
locally).

- `crates/shaar-ygg-core/src/transport.rs` exposes `YggTransport` (`start`, `send_to`, `recv`,
  `mtu`, `public_key`, `close`), `YggConfig` (seed, listen and peer URIs, allowlist keys, group
  password; `Debug` redacts secrets) and `YggError` (`Closed`, `Oversize`, `BufferTooSmall`,
  `Start { stage }`, `Io`). The adapter owns no queue: bounds and backpressure are the core's.
  `recv` needs a buffer of `mtu() + 1` bytes because the core reads in place; the payload is
  moved to the start of the buffer.
- `Start` carries only the failed stage: upstream error text can echo peer URIs that contain
  secrets, so it is dropped.
- Executed: `tests/exchange.rs` (two transports on loopback exchange datagrams both ways by key,
  `recv` reports the sender key, payloads of 1, 1000 and `mtu` bytes arrive intact, `mtu + 1`
  is rejected with `Oversize` and nothing arrives, a small buffer is rejected with
  `BufferTooSmall`, six paced concurrent senders deliver all 150 datagrams, cancelled receives
  lose nothing including a race with datagrams in flight, both transports close with no task
  alive and a free port) and the unit test that both cores are released after close.
- Path discovery: writes are accepted before any datagram is delivered, so every test first
  exchanges probe datagrams in both directions. P10 must treat a fresh path the same way.
- Not covered (53.4): negative controls, full typed startup errors (field naming), the per-key
  registry, allowlist enforcement, key-to-address vectors, behaviour after `close()` beyond the
  idempotent call. Datagrams are unreliable by contract; the load test is paced and does not
  prove loss-free delivery, and a scheduling stall on a loaded runner could drop datagrams.

## Negative controls and key vectors (leaf 53.4)

Status: accepted at `efa5c62` (CI run `42035672563`, Linux and Windows green; nothing was run
locally). The first run failed on a test-key collision, not on product code.

- `start` validates before creating a core: `InvalidConfig { field }` for `listen`, `peers` and
  `group_password`. The check is lexical (scheme `tcp` or `tls`, case-insensitive, no
  whitespace or control characters); the core can still reject a value at start, reported as
  `Start { stage }`. `Some("")` is rejected as an adapter policy because the core treats an
  empty password as an open network.
- A process-wide registry makes a second live transport on one key fail with `KeyInUse`. The key
  is released by `close()` or a failed start; a repeated `close()` cannot free a key a newer
  transport holds. A transport dropped without `close()` keeps its key claimed because its core
  keeps running.
- After `close()` has started, `send_to` and `recv` return `Closed` before any argument check.
- Allowlist: with the receiver's `allowed_public_keys` set to the dialer, the dialer's datagram
  is delivered and a third node that dials the same listener gets nothing through in a 3-second
  window. This observes non-delivery, not the enforcement mechanism.
- `address_for_key` reproduces the yggdrasil-go v0.5.14 golden address and the 255-ones edge.
  For the all-zero key the pinned core clamps the leading-ones count to 255 while the SDK
  implementation in `shaar` wraps it to 0 like Go; the key is not a usable identity and the
  divergence is recorded, not endorsed.
- Guarantees are for the adapter's own messages: the core's tracing output can mention peer URIs.
