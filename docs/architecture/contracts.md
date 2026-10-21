# Sha’ar Stack External Contracts (P01)

Date: 2026-10-21. Status: research, implementation not started.
No local builds/tests were run.

Every fact is tagged with a confidence level:
- **read from source** — by reading the sources of the specified tag/file
  (with a full URL); without a full URL of the tag, a fact does not count as
  such;
- **requires a CI/P03 experiment** — must be exercised/run as an experiment;
- **unconfirmed** — not verified by reading and not verified by running;
  must not be used as a basis for a contract.

## 1. Primary version set

- iroh **1.3.0** — version metadata confirmed by reading the Cargo.toml of tag
  v1.3.0 (`https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/Cargo.toml`):
  `package.version = 1.3.0`, `edition = 2024`, `rust-version = 1.91`,
  license MIT OR Apache-2.0; dependencies `noq`/`noq-proto`/`noq-udp`
  = 1.3.0; feature `qlog = ["noq/qlog"]`; the feature
  `unstable-custom-transports` is present. crates.io publish date not
  verified. Primary choice; age is not proof of stability.
  The newest version is 1.4.1, NOT chosen. Do not switch to 1.4.1 without an
  explicit decision. The `unstable-custom-transports` feature is mandatory.
- libp2p **0.57.1** (tag v0.57.1 =
  commit `2fed78f074af91e0c7440eedd08b8f898ad4a3fe`, MIT, MSRV 1.88,
  confirmed via `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/Cargo.toml`)
  + **libp2p-stream 0.5.0-alpha** (workspace version confirmed via
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/protocols/stream/Cargo.toml`);
  crates.io publish dates not verified. Compatibility confirmed via
  dependency requirements: both require libp2p-core ^0.44.0 and
  libp2p-swarm ^0.48.0. Caution: libp2p-stream 0.5.0-alpha is a pre-release;
  the alternative is libp2p 0.56.0 + libp2p-stream 0.4.0-alpha
  (decide at P02; after choosing, do not bump).
- yggdrasil-go **v0.5.14** (tag, commit `422836eeb21a99790caa286aa63d493bbc4766d7`;
  go.mod requires go 1.25.0; the Arceliar/ironwood dependency is pinned to
  `d50055b11f5e` from 2026-06-13). License: **LGPLv3 with a special
  exception** — static linking into a Combined Work is allowed without
  disclosing application code provided LGPL is otherwise observed (LICENSE,
  tag v0.5.14).
- ktav **0.8.0** (repo ktav-lang/rust, tag v0.8.0; metadata confirmed via
  `https://raw.githubusercontent.com/ktav-lang/rust/v0.8.0/Cargo.toml`:
  version 0.8.0, spec-version 0.8.0, rust-version 1.71, MIT OR Apache-2.0;
  serde-native; crates.io publish date not verified). Format = Ktav spec
  0.8.0 (ktav-lang/spec).
- Toolchain: Rust stable >= 1.91 (iroh MSRV), Go >= 1.25.0.
  Target OSes: Windows (amd64) and Linux (amd64).

## 2. iroh 1.3.0 — custom transport, paths, disabling n0

Read from the sources of tag v1.3.0:

- Traits (`https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/socket/transports/custom.rs`):
  `CustomTransport: Debug + Send + Sync + 'static`:
  `fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>>`;
  `CustomEndpoint: Debug + Send + Sync + 'static`:
  `poll_recv(&mut self, cx: &mut Context, bufs: &mut [io::IoSliceMut<'_>],
  metas: &mut [noq_udp::RecvMeta], recv_infos: &mut [RecvInfo])
  -> Poll<io::Result<usize>>`,
  `watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>>`,
  `create_sender(&self) -> Arc<dyn CustomSender>`,
  `max_transmit_segments(&self) -> NonZeroUsize`
  (default `NonZeroUsize::MIN`);
  `CustomSender: Debug + Send + Sync + 'static`:
  `is_valid_send_addr(&self, &CustomAddr) -> bool`,
  `poll_send(&self, cx: &mut Context, dst: &CustomAddr,
  src: Option<&CustomAddr>, transmit: &Transmit<'_>)
  -> Poll<io::Result<()>>`. Exported only under the feature
  `unstable-custom-transports`.
- Path selection: `PathSelector::select(&PathSelectionContext) -> PathSelection`
  (confirmed in the example
  `https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/examples/custom-transport.rs`);
  the traits `PathSelector`/`PathSelectionContext`/`PathSelection` live in
  `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/socket/remote_map/remote_state.rs`
  (internal module `socket/remote_map`, not `endpoint`).
  In `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/socket/biased_rtt_path_selector.rs`
  the default selector for custom transports is PRIMARY without RTT bias,
  so an explicit path policy is necessary (the file exists in the v1.3.0 tree).
  `PathSelection::none()` means no NEW path selection, NOT a ban on
  transferring data over the path: the "none → keep-current" rule is visible
  in the selector (the current best path is kept, `set` is not called).
  The location of path_watcher is confirmed in the tag v1.3.0 tree:
  `iroh/src/socket/remote_map/remote_state/path_watcher.rs` and
  `iroh/src/socket/biased_rtt_path_selector.rs`
  (`https://github.com/n0-computer/iroh/tree/v1.3.0/iroh/src/socket/remote_map/remote_state/`)
  — this is the location of the source, NOT proof of behavior;
  behavior is P03. The observations `conn.paths()`,
  `path.is_selected()`, `path.rtt()` come from the v1.3.0 example.
- TRANSPORTS.md exists in v1.3.0 as well; its contents were confirmed by
  reading: `https://github.com/n0-computer/iroh/blob/v1.3.0/TRANSPORTS.md` —
  custom address ids: 0x00–0x1F reserved, 0x20 test,
  0x544F52 Tor (experimental), 0x424C45 BLE (reserved).
  Registering a new id requires a PR to iroh; a local non-contested id is
  allowed, with a collision risk.
- Disabling n0: presets (`https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/endpoint/presets.rs`):
  `Minimal` — crypto provider only, WITHOUT n0 lookup and relays;
  `N0` — iroh.link DNS publish/resolve + default_relay_mode + crypto
  provider; `N0DisableRelay` — N0 + RelayMode::Disabled, WARNING:
  it leaves n0 DNS lookup in place — NOT suitable for fully disabling n0.
  The empty builder — "Creates an empty builder with no address lookup
  services, and [RelayMode::Disabled]"
  (`https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/endpoint.rs`).
  The correct way: `Endpoint::builder(presets::Minimal)` (or Empty + your own
  crypto_provider) plus your own address_lookup/transports.
  Do NOT use `clear_ip_transports()` to disable n0:
  it also removes the needed direct UDP path.
- pkarr/Mainline: the iroh 1.x crate does not include mainline-DHT lookup
  (the feature `address-lookup-pkarr-dht` existed only in 0.98.x;
  in 1.x it is absent from the features; n0_mainline is used in
  iroh-dns-server). The N0 preset publishes/resolves only in n0 DNS
  (pkarr relay). HOWEVER:
  `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/address_lookup.rs`
  explicitly states that Mainline-DHT Address Lookup lives in a separate
  crate `iroh-mainline-address-lookup` (docs:
  `https://docs.rs/iroh-mainline-address-lookup`). Per the crates.io index
  (`https://index.crates.io/ir/oh/iroh-mainline-address-lookup`)
  versions 0.5.0, 0.6.0, 0.6.1 exist, `rust-version = 1.91`,
  a plain iroh ^1.0.0 dependency (default-features = false) —
  a compatible candidate with iroh 1.3. The existence of the crate is
  confirmed; a GitHub search found no regular repo (only a blinded variant),
  which does NOT prove the published crate is absent.

### 2.1. Mainline adapter — researched result (sources read (via the provided URLs))

Repository: `https://github.com/n0-computer/iroh-address-lookups`,
tag `iroh-mainline-address-lookup-v0.6.1` = commit
`0f5f547cc65514e4537d4e66f776319ea8e30a2e`.
Sources:
`https://raw.githubusercontent.com/n0-computer/iroh-address-lookups/iroh-mainline-address-lookup-v0.6.1/iroh-mainline-address-lookup/Cargo.toml`,
`https://raw.githubusercontent.com/n0-computer/iroh-address-lookups/iroh-mainline-address-lookup-v0.6.1/iroh-mainline-address-lookup/README.md`,
`https://raw.githubusercontent.com/n0-computer/iroh-address-lookups/iroh-mainline-address-lookup-v0.6.1/iroh-mainline-address-lookup/src/lib.rs`.

- Cargo: version 0.6.1, MSRV 1.91, MIT OR Apache-2.0; iroh ^1.0.0
  (default-features = false), iroh-base ^1.0.0 (features key+relay),
  iroh-dns 1.0.0, n0-mainline 0.7. PRIMARY choice: adapter 0.6.1 +
  iroh 1.3.0, without bumping iroh; compatibility is confirmed by the
  dependency ranges, actual compilation — CI only.
- Builder API (read in src/lib.rs): `DhtAddressLookup::builder()`,
  `.dht_builder(DhtBuilder)`, `.secret_key(SecretKey)`, `.ttl(u32)`,
  `.republish_delay(Duration)`, `.no_publish()`,
  `.addr_filter(AddrFilter)`, `.build() -> Result`; it implements
  `AddressLookupBuilder` and, when attached, receives
  `endpoint.secret_key().clone()`. Defaults: enable_publish = true,
  addr_filter = relay_only(), ttl = 30 s, republish = 3600 s;
  updates replace the publish task's `AbortOnDropHandle`,
  debounce 50 ms. Via `n0_mainline::Dht` —
  get_mutable_most_recent/put_mutable, WITHOUT mandatory n0 HTTP/DNS relay.
- IMPORTANT: `relay_only()` filters `IROH TransportAddr::Relay`,
  NOT our libp2p CustomAddr circuit-relay → an explicit `AddrFilter`
  with allowed custom/IP addresses per policy is needed; do NOT use
  `presets::N0` and do not add an HTTP pkarr relay.
- Remaining gates: DHT bootstrap infrastructure and the actual absence of
  n0 network requests are verified by P02/P09 + CI; do not claim the full
  property merely from the name.

### 2.2. Custom serialization and the budget (sources read (via the provided URLs))

- Source:
  `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh-dns/src/endpoint_info.rs` —
  `endpoint_info_to_attrs`: Relay → `relay=url`, Ip → `addr=socket`,
  Custom → `addr=CustomAddr::to_string`; `endpoint_info_from_attrs`
  tries `SocketAddr::from_str`, otherwise `CustomAddr::from_str`;
  malformed entries are skipped; `EndpointInfo::to_pkarr_signed_packet`
  → `attrs.to_pkarr_signed_packet`. Conclusion: the serialization API for
  custom addresses is supported; the actual round-trip of concrete libp2p
  multiaddrs and sizes — P09 test.
- Source:
  `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh-dns/src/pkarr.rs` —
  `MAX_DNS_PACKET_SIZE = 1000`; `HEADER_SIZE = 104`
  (pubkey 32 + sig 64 + timestamp 8); `MAX_SIGNED_PACKET_SIZE = 1104`.
  Signed packet format: <pubkey32><signature64><timestamp8 BE><DNS>.
  The Mainline adapter puts `packet.encoded_packet()` (the DNS part
  ≤ 1000) into the MutableItem, with signature/key/seq separate — one must
  NOT require the whole signed packet to be ≤ 1000. Overflow during parsing
  → PacketTooLarge (from_txt_strings).
- Rule for us: on a serialization error the adapter logs and does NOT
  publish → choose up front a set of custom addresses that fits and observe
  publish failure, rather than silently assuming "2–3 addresses always fit".
- `from_parts_unchecked` in the resolver is not automatic proof that
  signature/freshness of the whole chain is verified: verification of
  n0-mainline and freshness are negative controls of P09, not unconditional
  trust.

- Signaling-only: the notion of a "negotiation-only path" is NOT found in
  the researched v1.3.0 API files; a production signaling-only gate is not
  found in them, but the categorical claim "iroh has none" must not be made —
  a full analysis of migration/prohibition code has not been done;
  absence of a confirmed gate = **requires a P03 experiment**
  (see `../verification/scenarios.md`).
  `PathSelection` selects paths for data; the v1.3.0 example shows operation
  purely on a custom transport, but exchanging
  NAT traversal candidates over the custom path with a switch to direct UDP
  is **unconfirmed**.
  Stopping `poll_send` after direct appears is NOT proof and NOT a resolution
  of the contract.
  If P03 shows impossibility — a stop condition for dependent stages
  (development.md 4.2); solution options go to the user.

## 3. libp2p 0.57.1 — relay v2, reservation, renewal

Read from the sources of tag v0.57.1 (`https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/relay/src/behaviour.rs`,
`https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/relay/src/priv_client.rs`,
`https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/relay/src/priv_client/handler.rs`):

- Default relay server limits (rust server): max_reservations=128,
  max_reservations_per_peer=4, reservation_duration=3600 s,
  max_circuits=16, max_circuits_per_peer=4, max_circuit_duration=120 s,
  max_circuit_bytes=131072 (128 KiB); rate limiters: 30 reservations/hour
  per peer, 60/hour per IP (and the same for circuits). The limits of PUBLIC
  Kubo/Amino nodes may differ and are NOT confirmed — do not assume a slot
  is available merely because the hop protocol is advertised
  (behaviour.rs `Config::default`).
- Client: reservation is initiated by `listen_on` on the address
  `/…/p2p/RELAY/p2p-circuit/p2p/SELF` (priv_client.rs poll → ListenReq →
  handler::In::Reserve); confirmation is the event
  `Event::ReservationReqAccepted { relay_peer_id, renewal, limit }`;
  renewal is signalled by the same event with `renewal: true`.
  Renewal (read from the source
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/protocols/relay/src/protocol/outbound_hop.rs`):
  `make_reservation` takes `reservation.expire` (unixsecs) from the wire,
  computes `remaining = expire − now` (checked_sub), then
  `renewal = remaining − remaining/4` and `Duration::from_secs` → `Delay`.
  BOTTOM LINE: the server reports the expiration; the CLIENT computes the
  renewal delay ≈ 3/4 of the remaining lifetime (remaining − floor(remaining/4)).
  The handler Accepted → Renewing mechanism remains as described.
- Opening streams: libp2p-stream 0.5.0-alpha
  (`https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/stream/src/control.rs`):
  `Control::open_stream(&mut self, peer: PeerId, protocol: StreamProtocol)
  -> Result<Stream, OpenStreamError>` — if there is no connection, it dials
  BY ITSELF (doc text: "In case we are currently not connected to the
  peer, we will attempt to make a new connection");
  `Control::accept(&mut self, protocol) -> Result<IncomingStreams,
  AlreadyRegistered>`; `OpenStreamError { UnsupportedProtocol, Io }`,
  `#[non_exhaustive]`; `Control` is Clone. Opening streams over
  a relayed connection is NOT forbidden by the code: in
  `https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/stream/src/behaviour.rs`
  (handle_established_inbound/outbound_connection) there is NO
  `is_relayed` check — streams work on any established connection,
  including relayed (read from the source). Additionally read:
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/protocols/stream/src/handler.rs`
  (listen_protocol and outbound `SubstreamProtocol::new`; neither `is_relayed`
  nor `allow_limited` is present) and
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/swarm/src/handler.rs`
  (`SubstreamProtocol`: upgrade/info/timeout, default 10 s, `with_timeout`;
  no separate allow_limited field). Static conclusion: the stream-opening
  mechanism has no restrictions on relayed connections at this level.
  Actual integration with a real relay (Kubo) and operability on
  truly limited connections — **requires a CI/P03 experiment**;
  do not claim that operability on all limited connections is proven.
- PeerId: `libp2p_identity::PublicKey::to_peer_id()` — a multihash wrapper,
  NOT the raw key bytes (see section 6).

## 4. yggdrasil-go v0.5.14 — core and FFI contract

Read from the sources of tag v0.5.14
(`https://github.com/yggdrasil-network/yggdrasil-go/blob/v0.5.14/src/core/core.go`):

- `core.New(cert *tls.Certificate, logger Logger, opts ...SetupOption)
  (*Core, error)`: a certificate with an ed25519.PrivateKey is required
  (otherwise an error); it generates a TLS config and
  `iwe.NewPacketConnWithPassword(secret,
  groupPassword, WithBloomTransform(SubnetForKey…),
  WithPeerMaxMessageSize(131070), WithPathNotify(…))`.
- Key-addressed datagrams: `ReadFrom(p []byte) (n, from net.Addr, err)`
  returns `iwt.Addr` = 32 bytes of the sender's public key;
  `WriteTo(p, addr)` accepts the same address; a sessionTraffic type byte
  is prepended internally. No TUN/TCP stack needed — confirmed.
- `MTU() uint64` = PacketConn.MTU() − 1, cap 65535. `Stop()` — graceful
  shutdown (phony.Block → cancel, links.shutdown, Close). `ReadFrom`
  is blocking → receiving must happen in a dedicated OS thread
  (rule 7 of CLAUDE.md).
  `SetPathNotify(func(ed25519.PublicKey))` — notification when a path to a
  key appears.
- Addressing from the key (read from the source
  `https://raw.githubusercontent.com/yggdrasil-network/yggdrasil-go/v0.5.14/src/address/address.go`):
  `AddrForKey` checks length 32, INVERTS all 256 bits of the pubkey,
  counts the number of leading ones up to the first zero; address byte 0
  = 0x02, byte 1 = the count of leading ones, the remaining 14 bytes =
  the subsequent bits of the inverted key after the leading ones and the
  first zero (truncation). THIS IS NOT A HASH. `GetKey` returns a partial
  key, not a full inversion of the pubkey; the Subnet prefix = 0x03. Do not
  claim invertibility of a Ygg-IPv6 into a full key. Test vectors are
  fixed at P04.
- FFI: the Go shim is built with `go build -buildmode=c-archive`.
  Static buildmode support is confirmed by reading
  `https://raw.githubusercontent.com/golang/go/go1.25.0/src/internal/platform/supported.go`:
  the `BuildModeSupported` function returns `true` for
  `-buildmode=c-archive` on windows (recognized arches) and linux/amd64.
  This is precisely static buildmode support; actual cross-language
  linking is a separate CI matter. Platform choice: on Windows — a
  compatible GNU/MinGW path: Rust `x86_64-pc-windows-gnu` + Go windows/amd64
  + gcc; an MSVC-ABI spike variant is a separate decision, MSVC
  compatibility must NOT be claimed now. The final choice is P02 via CI;
  do not silently exclude Windows. Linux: `x86_64-unknown-linux-gnu` +
  gcc/ld.
- cgo ownership (read
  `https://raw.githubusercontent.com/golang/go/go1.25.0/src/cmd/cgo/doc.go`,
  section Passing pointers): Go pointers are pinned for the duration of the
  call; C/Rust pointers must not be kept after return; do not store Go
  pointers in C memory without pinning; `cgo.Handle` — for an opaque
  identifier; `cgocheck=1` by default, `GOEXPERIMENT=cgocheck2` — CI only.
  These are rules, not proof of the whole wrapper. C.GoBytes copies; Go
  panics must not cross the ABI (recover at the boundary).
- Threading/lifecycle (read in ironwood
  `https://raw.githubusercontent.com/Arceliar/ironwood/d50055b11f5e/types/packetconn.go`
  — interface embeds net.PacketConn;
  `https://raw.githubusercontent.com/Arceliar/ironwood/d50055b11f5e/network/packetconn.go`
  — ReadFrom: select over closed/readDeadline/recv, Close closes closed
  under closeMutex;
  `https://raw.githubusercontent.com/Arceliar/ironwood/d50055b11f5e/encrypted/packetconn.go`
  — ReadFrom calls network.read() and waits on `<-network.readCh`,
  WriteTo checks closed/addr/MTU and copies the packet;
  `https://raw.githubusercontent.com/Arceliar/ironwood/d50055b11f5e/encrypted/network.go`
  — readloop, on an underlying ReadFrom error, closes closed (if
  IsClosed) and sends one error into readCh):
  serializing everything on a single queue, including the blocking recv,
  is NOT allowed — Stop/WriteTo would hang behind recv. Preliminary
  lifecycle contract: one receiving worker-thread for recv; a SEPARATE
  control/stop path (admission stop, no new operations); handle release
  after all calls have ceased and recv has finished. The exact safety of
  concurrent ReadFrom/Stop and handle passing is proven in P07
  by reading the sources and CI; a test does not replace the SAFETY
  justification. The Debug+Send+Sync requirements of CustomTransport (iroh)
  do not mean an unsafe impl on the Go Core: a thread-safe queue /
  opaque-handle adapter can be made without raw-pointer Send/Sync; do not
  promise the method without proof.
  go.mod confirmed:
  `https://raw.githubusercontent.com/yggdrasil-network/yggdrasil-go/v0.5.14/go.mod`
  (go 1.25.0, ironwood v0.0.0-20260613025018-d50055b11f5e); LICENSE —
  LGPLv3 with a special exception (static/dynamic linking of the
  Combined Work without Minimal Corresponding Source / Application Code
  per 4d/4e provided the rest of LGPL is observed; no legal warranties).
  Full LICENSE text:
  `https://raw.githubusercontent.com/yggdrasil-network/yggdrasil-go/v0.5.14/LICENSE`.

## 5. ktav 0.8.0 — syntax and API

Read from the README and Cargo.toml of tag v0.8.0
(`https://github.com/ktav-lang/rust/blob/v0.8.0/README.md`,
`https://raw.githubusercontent.com/ktav-lang/rust/v0.8.0/README.md`,
`https://raw.githubusercontent.com/ktav-lang/rust/v0.8.0/Cargo.toml`):

- Syntax: implicit root object; `key: value` (dots in keys =
  nesting; quotes disable it), `key:: value` — literal string;
  `##`-comments (full lines only); inline compounds only empty
  `{}` / `[]`; non-empty `{ ... }` / `[ ... ]` are multi-line, with the
  closing bracket on its own line; multi-line strings `( … )` (strip) and
  `(( … ))` (verbatim); booleans/null strictly lowercase; numbers are typed
  lexically (Integer/Float with canonicalization; `01234` — a string).
- API: `ktav::from_str/from_file` (serde Deserialize),
  `to_string/to_file`, `parse/parse_strict` (Value), `parse_events`
  (no tree), `format_str`, `render::render`. Errors:
  `Error::Structured(ErrorKind{…})` with span/path; variants:
  MissingSeparatorSpace, InvalidTypedScalar, DuplicateKey,
  KeyPathConflict, EmptyKey, InvalidKey, UnclosedCompound,
  UnbalancedBracket, InlineNonEmptyCompound, MissingSeparator,
  LossyScalar (strict), Other; `#[non_exhaustive]`. The existence of the
  `parse_strict` function and its behavior on numbers like `1.10`, as well
  as serde behavior on unknown fields, is to be checked against the real
  parser/serde API at P05; the existence of a function ≠ resolution of the
  user-number policy.
  The user requirement is ktav 0.8.*, without additional
  strict-mode surface; P05 will define the minimal schema without new
  modes. The README claims a serde round-trip,
  but the README does NOT explicitly describe the behavior on unknown
  fields — **unconfirmed, test at P05** (deny_unknown_fields/ignore — a
  schema decision); README contradictions must not be treated as proven.
- The read README v0.8.0 states the format does not support:
  inline non-empty compounds, anchors/aliases, includes, root arrays
  (do not claim a long-term guarantee of the format; verify against the
  actual API at P05).

## 6. Keys and addresses

One Ed25519 seed (32 bytes) → an ed25519 private key. The exact static
contract:

- iroh (read
  `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh-base/src/key.rs`):
  `SecretKey::from_bytes(&[u8;32])` via
  `ed25519_dalek::SigningKey::from_bytes`; `public()` → 32 bytes
  `verifying_key().to_bytes()`; `to_bytes() -> [u8;32]`;
  `EndpointId` = pubkey.
- Yggdrasil: address = `address.AddrForKey(pubkey)`, an address from the
  200::/7 range (algorithm — section 4; not a hash, invertibility into a
  full key must NOT be claimed).
- libp2p (read
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/identity/src/generated/keys.proto`):
  `PublicKey { Type = field 1 (enum Ed25519 = 1), Data = field 2 (bytes) }`;
  for a 32-byte key the protobuf = `08 01 12 20 || pubkey` (36 bytes).
  Read
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/identity/src/peer_id.rs`:
  identity multihash (code 0x00) if the protobuf ≤ 42 bytes;
  PeerId bytes = `00 24 08 01 12 20 || pubkey`; base58btc encoding.
  This is a static algorithm, read from the source; executing
  test vectors — P04/CI.
- pkarr: the record is signed with the same Ed25519 key; the format and the
  exact serialization sources are described in section 2.2. Signature
  checks and negative test vectors of the whole chain — P09.

Test vectors — P04; fix the formulas per the listed sources.

## 7. Open questions and stop conditions

- NAT traversal via custom transport + the ban of STREAM on signaling-only:
  unconfirmed, a blocking P03 experiment (stop conditions —
  development.md 4.2). A separate P03 matrix item: check the availability
  of an oracle mechanism (a test-only trace hook before encryption,
  or decoding captured traffic) — see
  `../verification/scenarios.md`, section 1.
- Limits of public Amino/Kubo relays and slot availability: unknown;
  depends on infrastructure; test on our own relay + a separate
  smoke test of the public network.
- c-archive windows/amd64 and linux/amd64: an early CI check (P02/P03);
  a blocker → a user decision, not silence.

The remaining real gates:

- NAT traversal + signaling-only (P03).
- Availability of decoded-frames/path-oracle + positive calibration (P03).
- Actual cross-language linking of c-archive (CI).
- SAFETY of concurrent ReadFrom/Stop (P07).
- Executing the test vectors (P04).
- The actual ktav parser/serde API and the configuration policy (P05).
- The actual multiaddr round-trip/budget and negative controls of Mainline
  verification (P09).
- DHT bootstrap and absence of n0 requests (P02/P09 + CI).
- Limits of public Amino/Kubo relays.
