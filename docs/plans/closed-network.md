# Closed network with an authority, relays and signed files (design note, proposal)

**Status: proposal for the owner's approval.** No protocol, cryptographic or network code starts before the owner approves this note (the rule used for L3b). Written 2026-11-17 from the owner's decisions recorded in the [north-star decision log](north-star.md). Nothing here is implemented, compiled or run; items marked *verify* are assumptions about pinned dependencies that the first leaf must check against the prepared sources.

## 1. What the owner asked for

Quotes are in the decision log. In short: one main Server is the authority of a closed network and has its own signature. Every other participant connects to it and registers as a relay; the authority registers the relay and gives its address to others. A registered participant may then (a) relay connections to the authority and (b) distribute files signed by the authority. The network is a real private Kademlia DHT, a new mode next to the public Mainline/Yggdrasil one; a relay sees ciphertext only; file distribution is the leaf right after relaying.

Scenario steps advanced (north-star): step 3 (reach the Server), step 5 (a path when direct QUIC is blocked, here through registered relays), step 6 (allowlist unchanged). The closed network is an additional scenario; the public one is untouched.

## 2. Roles and trust

| Role | Holds | Trusted for |
|---|---|---|
| Authority | the Server's Ed25519 identity key; the allowlists | signing relay certificates, the relay index and file manifests |
| Relay | its own identity key plus an authority certificate | forwarding opaque bytes; serving authority-signed files |
| Client | its own identity key; the authority public key (pinned in its configuration) | nothing beyond its own allowlist entry |

The trust root is the authority public key in the configuration of every participant. Anything not signed by it, or by a node holding its unexpired certificate, is ignored. There is no authority rotation in the first version: a compromised authority key means a new network (stated risk).

## 3. Private DHT (CN-1)

Recommendation: `libp2p-kad` (already prepared in the pinned set, same Ed25519 identity, TCP so that the Android emulator can reach a host through `10.0.2.2` and `adb forward`) with a private protocol name derived from the authority key, so a node can never join another network nor the public IPFS DHT. Alternative: `n0-mainline` in server mode over UDP; it needs the native Mainline contract changed from client-only ([native-mainline-contract](../architecture/native-mainline-contract.md), resource row "client-only") and a new review of the responding side; not recommended for the first version.

- Authority and relays run in Kademlia server mode; clients in client mode.
- A custom record store accepts only records that verify: relay index shards and file manifests signed by the authority; node self-records signed by the node key with an unexpired authority certificate attached. Everything else is rejected before storage.
- Bounds (to be fixed in the leaf acceptance): record at most 2 KiB, at most 1024 stored records, at most 8 per publishing key, lifetime at most 1 h with refresh, at most 64 routing-table peers per bucket slice. *verify*: the prepared `libp2p-kad` 0.49 exposes the record-store trait and the protocol-name setting needed for this.
- The DHT carries records only. It never carries application data (libp2p rule unchanged).

## 4. Registration and certificates (CN-2)

1. A node dials the authority (libp2p request-response over the existing carrier, Noise-authenticated, so the authority knows the node key).
2. Admission. Recommendation: the authority admits only keys on its relay allowlist (`shaar-server allow relay add KEY`), because open registration lets anyone become a relay and observe traffic metadata. Alternative: a shared join token. Owner answer of 2026-11-18 (question 1): any client that has already connected to the Server may register itself as a relay, and the Server then gives its addresses to other clients; registration stays closed to strangers, and there is no join token.
3. The authority returns a certificate: its signature over a domain-separated message with the node key, `not_before`, `not_after` (at most 24 h) and the capability set (`relay`, `files`). The node renews it by registering again before expiry; expiry is the only revocation.
4. The authority publishes the relay index in the DHT as signed shards (a record holds about a dozen entries because of the 2 KiB bound; shards are numbered) and answers a direct "list relays" request with the same signed data. Clients verify the signature and expiry and pin nothing else.

## 5. Relay data path (CN-3)

The client wants the authority's service. With a direct path blocked, it picks a certified relay from the index and reaches the authority through it. The end-to-end QUIC (or an inner Noise layer, see below) is between the client key and the authority key, so the relay sees ciphertext, the two keys, timing and volume; it cannot read, alter or inject.

- Owner answer of 2026-11-18 (question 2): the relay is a plain proxy. The client connects to the relay as it would to the Server (the Server key is known to both), the relay forwards to the Server, and the encryption stays between client and Server, so the relay sees nothing inside the traffic. Whatever the mechanism, it keeps this contract.
- Mechanism *verify* in a spike before the leaf is accepted: reuse the custom-transport path that the Yggdrasil standby uses in the iroh endpoint (the relay forwards QUIC datagrams addressed to the authority key). Fallback if that path cannot carry a third-party hop: the relay splices a byte stream and the client and authority run an inner end-to-end Noise session over it.
- The relay forwards only toward the authority (and servers the authority lists); it is not an open proxy. The authority still applies its client allowlist; a disallowed client reaches no target, as in step 6.
- Relay limits (to be fixed in the leaf): concurrent splices, bytes per second per client key, idle timeout, total memory. Backpressure is mandatory; a relay never buffers beyond a fixed window.
- Path policy: the relay path is one more candidate below direct QUIC and above nothing else in this mode; direct keeps data priority.

## 6. Signed files (CN-4, the leaf right after CN-3)

The authority signs a manifest: name, size, chunk size, BLAKE3 root of a chunk-hash list, version, sequence, expiry. Relays holding the file serve chunks; every receiver verifies each chunk against the signed hashes, so a malicious relay can withhold but not poison. A node serves only files whose manifest verifies against the authority key. Bounds: file size, chunk size, concurrent transfers and storage per relay are fixed in the leaf. Not included: discovery of files by arbitrary names, deletion, partial-update formats, any file that the authority did not sign.

## 7. Configuration (ktav 0.8)

A `network` object gains the closed form for Server, Client and relays: `network: { closed: { authority: <64 hex>, bootstrap: [host:port] } }` next to the existing public form; the two forms are mutually exclusive in one file. Relay and file settings (`relay: { max_splices, ... }`, `files: { dir, max_bytes }`) are separate top-level objects validated by the same schema rules, errors naming the field and never a secret. Role packaging (open question 3): a relay is a Client that also serves, so `shaar-client relay` and `shaar-server allow relay ...`; no third binary.

## 8. Threat model (first version)

| Threat | Handling |
|---|---|
| Fake node registers or publishes records | Only certified keys' records are stored; certificates expire within 24 h |
| Sybil or eclipse of the routing table | The authority index is signed and fetched directly from the authority first; the DHT is a second source |
| Relay reads or tampers with traffic | End-to-end encryption between client and authority; tamper means the stream fails |
| Relay as an open proxy | Forwards only toward the authority and its listed servers |
| Replay of an old index or manifest | Sequence numbers and expiry checked against the last seen value |
| Authority key compromise | Not handled in v1: new network |
| Flood of registrations or records | Registration allowlist, per-key and total bounds, rate limits |
| Traffic analysis by a relay | Accepted: keys, timing and volume are visible to it |

## 9. Leaves, acceptance and non-goals

| Leaf | Observable acceptance | Non-goals |
|---|---|---|
| AND-1 | A debuggable minimal APK runs `shaar-server` and `shaar-client` on the local x86_64 emulator and an exact payload crosses client, QUIC, server and an echo target | Store packaging, real devices, UI beyond one activity, CI execution |
| CN-1 | In-process nodes form a private DHT from one bootstrap; a record signed by a non-certified key is rejected; bounds hold under a flood; no contact with the public DHT | Public DHT interop, NAT traversal inside the DHT |
| CN-2 | A relay on the allowlist registers and obtains a certificate; an unlisted key is refused; an expired certificate is ignored; the signed index lists the relay | Authority rotation, revocation lists |
| CN-3 | With direct QUIC blocked in the controlled fixture, a client reaches the authority's service through one relay with exact bytes; a disallowed client reaches no target; the relay never sees plaintext; limits and backpressure tested | Multi-hop, relay incentives, UDP forwarding |
| CN-4 | A relay serves a file; a receiver verifies it against the manifest; a poisoned chunk and an unsigned manifest are rejected | Arbitrary-name search, deletion, large-scale swarming |
| CN-5 | The Android app joins the closed network as a relay and as a client on the local emulator | Real devices, mobile carrier networks |

Verification stays as in the project rules: unit and loopback integration tests and the namespace matrix run in CI; the Android cases run on the local emulator and are reported as local evidence only. No public network is contacted.

## 10. Open questions for the owner

1. **Admission.** *Answered 2026-11-18:* any client that has already connected to the Server may register as a relay; the Server hands its addresses to other clients. (Was: allowlist or open with a join token.)
2. **Relay mechanism.** *Answered 2026-11-18:* a plain proxy with end-to-end encryption between client and Server; the relay sees nothing inside. (Was: spike-first plan.)
3. **Packaging.** A relay is `shaar-client relay` (recommended) or a third binary?
4. **No rotation.** Accept that a compromised authority key means a new network in the first version?
5. **Scope of CN-4.** *Answered 2026-11-18:* a relay forwards traffic or distributes files that the Server signed, and only those. (Was: delegated publishers or not.)

Still open: 3 (packaging: `shaar-client relay` or a third binary), 4 (no key rotation in the first version) and the approval of the note.
