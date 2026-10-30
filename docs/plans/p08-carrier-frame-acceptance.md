# P08 real-carrier frame acceptance

Status: scoped acceptance plan, not execution evidence. Tasks 201–204 implement
this remaining part of task 63. Public infrastructure, Yggdrasil, host routes,
TUN/root operations and a full-workspace campaign are not authorized by this plan.

## Accepted implementation and the remaining gap

| Component | Accepted revision | Evidence and boundary |
|---|---|---|
| Bounded query/source ownership | `1823bc1d5002446af4b075eddb9fbe51f3909007` | Fork CI 41023910350 and integration CI 41024712641, Linux/Windows; 260/262 selected project cases, including owned seed-to-referral traffic. |
| Discovery-to-reservation handoff | `e29134fc4ce0515029fcb0fe227811e7fb9c8614` | Fork CI 41031834416 and integration CI 41033123351, 87 selected project cases per OS, including seven new gate/handoff cases. |
| Configured SDK caller | `07a9a9c941661db9ca18c18ea7b546b5656fc961` | Fork CI 41037773356 and integration CI 41039119278, 49 selected SDK cases per OS, including five new startup/identity/owned-DNS-shutdown cases. |

These are component acceptance results, not a new full-sprint run. SDK discovery
configuration is explicit and in-memory; Server/Client ktav schemas and direct-only
startup remain unchanged. Constructors do not automatically bootstrap or reserve.

The existing P03 wire oracle correlates finalized encrypted Noq packets with decoded
frame metadata over a bounded in-memory custom transport and an owned UDP fixture.
Its own documented boundary excludes actual libp2p deployment. The existing
`carrier-wire-proof` fixture checks protocol-poll/lifetime barriers, not Noq frame
contents. Neither ciphertext appearance nor application non-delivery closes that
gap. Existing accepted proofs must not be relabeled as real-carrier frame evidence.

## Fixed provenance baseline

Base implementation revision: `07a9a9c941661db9ca18c18ea7b546b5656fc961`.

- Product `Cargo.lock` SHA256:
  `c090de1dccbf4c4b2dfae57bec3acac03aabde512aa3221603f35917b027ccb4`.
- Original reviewed P03 probe lock SHA256:
  `122e16a01b4b2d76a4ace23b2a25caba8856b2996fe901b1300e4c686a706b16`.
- iroh 1.3.0 archive SHA256:
  `885787b892b5e2507c701f132ecbd45d2bad4bbb75157a19427087c16dadb833`.
- noq 1.3.0 archive SHA256:
  `b78be567e796cfa74bb9bdc4117790af2d505eb887019cf8803244353eb09d89`.
- noq-proto 1.3.0 archive SHA256:
  `7c1e5b6fe668491eca022f745a0a9402585626c73a7b839b3424ace15d6a9c8f`.
- libp2p 0.57.1 registry checksum:
  `9bd752f66522780daa3acfd0103a2dccb3921e4c09db5f777bfca98227c8e74d`.
- libp2p-relay 0.22.0 archive SHA256:
  `e5227b053db429996242c00f6c756fd9b5382b942a03eec34b465431df29697a`.
- Reused `gate/bridge/support/wire_oracle.rs` SHA256:
  `40a3945e9e6cd3ec4a45cab61fe167f7f9be27292b602acf11c1f651f1abe080`.
- Reused `gate/bridge/support/packet_identity.py` SHA256:
  `c4e299523dd1b5c118855952992cce9ac9f65d7a018f9b9cfd42bce14d92d50a`.

Paths in the last two entries are relative to `.github/probes/iroh-paths/`.
These values were read as data, without executing project or downloaded code.
Prepared product path packages retain their versions; their exact transformed
source and feature/edge receipts must also be recorded by the new fixture. Do not
substitute the older independently resolved probe graph for the product graph.

## Reuse and exact observation points

1. Reuse `add_packet_identity` and the existing bounded `wire_oracle::Index`.
   The former adds finalized ciphertext to `quic:packet_sent.data.raw.data` next
   to decoded frame metadata, after packet encryption. It is fixture-only, never
   installed in production sources. No TLS key logging is required.
2. The actual-carrier observation point is
   `crates/shaar-p2p/src/bridge/driver.rs::receive_loop`, after `handle.is_current`
   and both `Shared::matches` checks, immediately before `permit.send(Inbound)`.
   At this point the packet has traversed an authenticated real carrier connection
   and has a current peer, `ConnectionId`, `Route` and sealed `CustomAddr` binding.
3. Record the receiving carrier identity, authenticated remote peer, actual
   connection, route/generation and custom address instance/epoch alongside the
   complete received datagram. `Shared::address` encodes an instance and epoch;
   their meaning comes from validated binding membership, not prefix authority.
4. Do not use `send_worker` queue admission or RPC completion as physical-egress
   evidence: a send can fail after bytes were written. Successful authenticated
   receive plus exact ciphertext correlation supplies the observable boundary.
5. Preserve honest inbound route attribution: `Route::Relayed { relay: None, .. }`
   is not fabricated into a known hop. Bind the paired outbound circuit and owned
   reservation/control evidence separately. Unknown or stale scope must fail.
6. Each endpoint trace must be tied to its authenticated Noq peer/connection and
   the actual carrier scopes observed in that case. Never bless a stale packet by
   looking up a newer connection from `PeerId` alone.

## Fixture and graph constraints

- Keep the product sources and lock immutable. The product does not enable qlog.
  A disposable observation reference may enable only Iroh/Noq qlog and an exact
  SDK test dependency on the already reviewed serde_json 1.0.154. Its extra
  n0-qlog 0.2.0/JSON closure must come from the original reviewed probe lock;
  no new registry identity or version change is accepted. Record the exact
  derived-lock and observability-feature delta rather than claiming byte equality.
  The instrumented variants must match that independently constructed reference's
  normal/build features and edges exactly. Source receipts, exact hook anchors,
  production-byte reversal and checked fixture outputs remain mandatory.
- Prefer a focused harness under `.github/probes/iroh-paths/carrier/`; the probe
  root has room for that purpose-specific component. Each code file stays at
  most 700 lines and each directory at most seven direct project items.
- Reuse existing fixture-only native-path admission/NAT-withholding helpers where
  necessary. They are not product APIs or permission for host-network changes.
- The SDK normally disables QUIC DATAGRAM queues. A fixture may enable bounded
  adversarial queues in both strict and allow-all variants to exercise the gate;
  record that profile delta explicitly. Do not increase production budgets.
- Do not expose raw Noq handles through a new public SDK API. A disposable SDK
  test module may access its existing private owner/connection state to queue
  adversarial application frames that the public Session API already rejects.
- Keep capture limits at the reviewed bounds: 256 datagrams per direction and
  boundary, 16 MiB trace input and 1024 packet identities. Overflow is failure,
  not permission to discard observations. Preserve all existing protocol and
  resource limits, including retained terminal charges.
- No filesystem I/O, callbacks, wake or resource destruction under authority
  registry locks; no locks across await. Owned observation tasks must join.

## Required cases and acceptance conditions

### Strict policy

Use a real owned Rust relay, TCP/Noise/Yamux carrier and the actual Iroh/Noq bridge
on Linux and Windows. Establish authenticated custom control, queue bounded
STREAM/FIN and DATAGRAM work once in each direction, and require continuing
control traffic. Every received carrier byte must match finalized decoded packet
metadata, with zero carrier STREAM/DATAGRAM frames. Require complete correlation;
unobserved payload, duplicate/prefix-ambiguous identity, missing trace, trailing
bytes, unknown scope and truncation all fail closed.

### Positive sensitivity

With the same carrier, peer/control/generation checks and capture path, a separate
fixture-only allow-all payload callback must produce observed STREAM and DATAGRAM
frames and exact application bytes on the actual carrier in both directions.
Handshake/setup/capture failures cannot satisfy this calibration. Do not weaken
role, admission, lease, framing or native resource policies to make it pass.

### Path and control lifetime

Use only owned portable UDP observation/forwarding to exercise native path gain
and physical loss, then carrier disconnect/reconnect. Prove the claimed original
Noq connection/peer scope, distinguish successor carrier generations and reject
old-scope observations. Observe native payload positively where native is admitted;
zero carrier payload must hold throughout. Existing controlled-NAT evidence remains
separate; this work does not claim arbitrary NAT or authorize a new NAT campaign.

### Oracle controls and cleanup

Exercise wrong peer/instance/connection/generation, corrupt/missing/coalesced/
duplicate/partial ciphertext, missing frame metadata and bounded capture overflow.
Preserve the existing oracle's controls. Join both endpoints, carrier/pump, relay,
observers and all managed work; verify socket/resource release even with snapshots
and capabilities retained. Record actual observed counts, not fixed suite sizes.

## CI and completion

A new diff-owned frame-proof segment must select this harness and its small
contracts, not all SDK/workspace/vendor campaigns. A normal candidate must not
silently become full scope. Full remains a current standalone `[ci:full]` line or
manual Actions `scope: full`, and is not requested here. No local compilation or
tests: only standalone formatting, syntax and own isolated data readers locally.

After the exact candidate passes both OSes, inspect inventories, expected events,
negative/sensitivity preconditions, source/graph receipts and cleanup evidence.
Fetch collaborators before exact-SHA integration, watch post-integration CI and
remove the clean integrated worktree. Update the acceptance record with real run
IDs, hashes, limits and exclusions. Tasks 202/203 remain open until this happens.

Task 204 is separately permission-blocked public Amino/relay smoke. No cron, goal,
task completion or local-fixture result authorizes that operation. Do not close
full P08 acceptance or claim public-infrastructure readiness while that gate is
unmet. Yggdrasil and release permissions remain separate as well.
