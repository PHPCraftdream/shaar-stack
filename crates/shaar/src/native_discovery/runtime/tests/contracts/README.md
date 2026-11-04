# Native runtime tests — private seam proposal

Copyright 2026 PHPCraftdream; SPDX-License-Identifier: MIT OR Apache-2.0.

These tests remain intentionally unwired and uncompiled. Future attachment requires a reviewed private adapter in `native_discovery/runtime/test_support.rs`, included by `native_discovery/runtime/mod.rs` using `#[cfg(test)] mod test_support;`; neither file is created by this proposal. No support implementation, stub, or new SDK API is proposed. No policy insertion, caller-selected provenance, writable counters, simulated send/dial success, or public packet is proposed.

## Proposed observable test-support API

```rust
type TestResult<T, E> = Result<T, E>;
use crate::native_discovery::address::SnapshotError;
struct ClockSample { wall_unix_micros: i64, monotonic_micros: u64 }
struct TestOwner { /* real owner, actor JoinHandle, socket and charges */ }
struct Probe { /* owner-bound controls and read-only observations */ }
#[derive(Debug, Eq, PartialEq)] struct ClientProbeResult { responder_attempts: Vec<ResponderAttemptReceipt>, mode: ClientMode }
#[derive(Clone, Debug)] struct RequestHandle { /* owner command sender */ }
struct RequestTicket { operation_id: u64 }
struct TestClock { /* controlled clocks */ }
struct Snapshot { /* raw addresses; invalid inputs are constructible */ }
#[derive(Debug, Eq, PartialEq)] struct PublishAck { generation: u64 }
#[derive(Debug, Eq, PartialEq)] struct ResolveReceipt { peer: EndpointId, sequence: i64, address: SocketAddr, cache_expiry_monotonic_micros: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct QueryReceipt { operation_id: u64, query_id: u64, peer: EndpointId }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct RpcReceipt { operation_id: u64, query_id: u64, transaction_id: u32, expected_source: SocketAddr, runtime_destination: SocketAddr }
#[derive(Debug, Eq, PartialEq)] enum RpcOutcome { Accepted, RejectedUnexpectedTransaction }
#[derive(Debug, Eq, PartialEq)] struct RpcEvent { rpc: RpcReceipt, outcome: RpcOutcome }
#[derive(Debug, Eq, PartialEq)] struct IngressReceipt { event_id: u64, rpc: RpcReceipt, outcome: RpcOutcome }
struct OperationReceipt { operation_id: u64 }
struct MaintenanceReceipt { observed_at_monotonic_micros: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct QueryIngressReceipt { query_id: u64, destination: SocketAddr }
#[derive(Debug, Eq, PartialEq)] struct ResponderAttemptReceipt { query_id: u64, destination: SocketAddr }
#[derive(Debug, Eq, PartialEq)] struct ClientMode { hard_client_only: bool, adaptive_server_enabled: bool }
struct RetryReceipt { delay: Duration }
#[derive(Debug, Eq, PartialEq)] struct DialReceipt { operation_id: u64, peer: EndpointId, address: SocketAddr }
#[derive(Debug, Eq, PartialEq)] struct AdmissionReceipt { peer: EndpointId }
struct PutAttempt { operation_id: u64, attempt: u8, generation: u64, deadline_monotonic_micros: u64, signed_packet_bytes: Vec<u8> }
struct PutReceipt { operation_id: u64, attempt: u8, generation: u64, deadline_monotonic_micros: u64, destination: SocketAddr, signed_packet_bytes: Vec<u8> }
#[derive(Debug, Eq, PartialEq)] struct EgressReceipt { operation_id: u64, query_id: u64, referral_transaction_id: u32, destination: SocketAddr, outcome: EgressOutcome }
#[derive(Debug, Eq, PartialEq)] struct EventReceipt { operation_id: u64, query_id: Option<u64>, transaction_id: Option<u32>, generation: Option<u64>, destination: SocketAddr }
struct DatagramReceipt { source: SocketAddr, destination: SocketAddr, bytes: Vec<u8> }
#[derive(Debug, Eq, PartialEq)] struct CloseReceipt { actor_joined: bool, socket_dropped: bool }
struct PeerInspection { watermark: Option<i64>, winner_bytes: Option<Vec<u8>>, conflicted: bool, cache_expiry_monotonic_micros: Option<u64>, completed_network_queries: u64 }
struct PublisherInspection { active_generation: Option<u64> }
struct LimitInspection { active_operations: usize, queued_operations: usize, operation_charges: usize, actor_charges: usize, watermark_count: usize }
struct RuntimeInspection { pending_datagrams: usize, join_handle_retained: bool, socket_dropped: bool }
#[derive(Default)] struct BootstrapAudit { /* read-only actual branch counts */ }
#[derive(Debug)] enum FixtureError { Bind, Codec, UnexpectedPacket, Closed }
struct Barrier { /* owner-bound real barrier */ }
struct AdmissionBarrier { /* real admission gate */ }
struct CleanupBarrier { /* real cleanup gate */ }
struct QueryBarrier { /* actual query/RPC correlation and completion gate */ }
struct SendBarrier { /* real send gate */ }
struct FlushBarrier { /* real flush gate */ }
enum HoldPoint { Enqueue, Bootstrap }
enum PutReply { Accept, Reject }
#[derive(Debug, Eq, PartialEq)] enum EgressOutcome { Sent, BlockedOutsideFixture }
enum InvalidRecord { WrongKey, CorruptSignature, Oversize, Truncated, ByteFlipped, Stale, TooFarFuture, Empty }
#[derive(Debug, Eq, PartialEq)] enum ResolveError { EqualSequenceConflict, Replay, NoValidRecords }
#[derive(Debug, Eq, PartialEq)] enum RuntimeError { Deadline, Closed, Resolve(ResolveError), Capacity(CapacityError) }
#[derive(Debug, Eq, PartialEq)] enum PublishError { InvalidSnapshot, RetryExhausted, ClockFault }
#[derive(Debug, Eq, PartialEq)] enum BootstrapError { Invalid }
#[derive(Debug, Eq, PartialEq)] enum CapacityError { OperationsAndQueueFull, WatermarksFull }
#[derive(Debug, Eq, PartialEq)] enum CloseError { NotJoined }

impl TestOwner {
 async fn start(clock: ClockSample, fixture: Arc<UdpSocket>) -> TestResult<(Self, Probe), io::Error>;
 async fn bind_numeric(clock: ClockSample, fixture: Arc<UdpSocket>, endpoints: Vec<SocketAddr>, audit: &BootstrapAudit) -> TestResult<(Self, Probe), BootstrapError>;
 fn handle(&self) -> RequestHandle;
 fn publisher(&self) -> PublisherInspection;
 fn inspect(&self, peer: EndpointId) -> PeerInspection;
 fn limits(&self) -> LimitInspection;
 fn runtime(&self) -> RuntimeInspection;
 fn request_stop_out_of_band(&mut self);
 async fn close(&mut self) -> TestResult<CloseReceipt, CloseError>;
}
impl RequestHandle {
 async fn resolve(&self, peer: EndpointId) -> TestResult<ResolveReceipt, RuntimeError>;
 async fn resolve_until(&self, peer: EndpointId, deadline_monotonic_micros: u64) -> TestResult<ResolveReceipt, RuntimeError>;
 async fn resolve_record(&self, peer: EndpointId, bytes: Vec<u8>) -> TestResult<ResolveReceipt, RuntimeError>;
 async fn resolve_and_connect(&self, peer: EndpointId) -> TestResult<ResolveReceipt, RuntimeError>;
 async fn resolve_record_and_connect(&self, peer: EndpointId, bytes: Vec<u8>) -> TestResult<ResolveReceipt, RuntimeError>;
 async fn update(&self, snapshot: Option<Snapshot>) -> TestResult<PublishAck, PublishError>;
 async fn enqueue_resolve(&self, peer: EndpointId) -> TestResult<RequestTicket, CapacityError>;
}
impl RequestTicket { async fn cancel(self); }
impl Probe {
 fn clock(&self) -> TestClock;
 fn query(&self, peer: EndpointId) -> QueryBarrier;
 fn hold(&self, point: HoldPoint) -> Barrier;
 fn hold_admission(&self) -> AdmissionBarrier;
 fn hold_next_cleanup(&self) -> CleanupBarrier;
 fn flush(&self) -> FlushBarrier;
 fn put_send(&self, generation: u64) -> SendBarrier;
 fn put_send_next(&self) -> SendBarrier;
 fn put_sends(&self, count: usize) -> Vec<SendBarrier>;
 fn client_mode(&self) -> ClientMode;
 async fn wait_maintenance_observed(&self) -> MaintenanceReceipt;
 fn script_put_replies(&self, replies: Vec<PutReply>);
 async fn send_inbound_query(&self, socket: Arc<UdpSocket>) -> QueryIngressReceipt;
 async fn client_query_observation(&self, receipt: QueryIngressReceipt) -> ClientProbeResult;
 fn hold_next_publish_ack(&self) -> Barrier;
 async fn native_endpoint(&self, key: &SecretKey) -> TestResult<SocketAddr, FixtureError>;
 fn dials(&self) -> Vec<DialReceipt>;
 fn admissions(&self) -> Vec<AdmissionReceipt>;
 fn receipts(&self) -> Vec<EventReceipt>;
 fn put_receipts(&self) -> Vec<PutReceipt>;
 fn put_receipts_for_operation(&self, operation_id: u64) -> Vec<PutReceipt>;
 fn egress_receipts(&self) -> Vec<EgressReceipt>;
 fn owned_destinations(&self) -> Vec<SocketAddr>;
 fn start_audit(&self) -> BootstrapAudit;
 async fn wait_queued_operations(&self, count: usize);
 async fn wait_operation_admitted(&self, peer: EndpointId) -> OperationReceipt;
 async fn wait_generation_revoked(&self, generation: u64);
 async fn wait_generation_revoked_after_cancel(&self);
 async fn wait_outbox_drained(&self);
 async fn wait_put_attempt_finished(&self, operation_id: u64, attempt: u8);
 async fn retry_scheduled(&self, operation_id: u64) -> RetryReceipt;
 async fn publication_terminal(&self, operation_id: u64) -> Result<(), PublishError>;
 async fn next_signed_put(&self, generation: u64) -> PutReceipt;
 async fn wait_retry_budget_elapsed(&self, operation_id: u64, deadline_monotonic_micros: u64);
 async fn wait_stop_observed(&self);
 async fn close_started(&self);
 async fn wait_actor_joined(&self);
 async fn wait_socket_dropped(&self);
 async fn wait_cleanup_finished(&self);
 async fn replay_transaction(&self, rpc: RpcReceipt, bytes: Vec<u8>);
 async fn replay_cached_value(&self, peer: EndpointId, bytes: Vec<u8>);
 async fn replay_local_put(&self, peer: EndpointId, bytes: Vec<u8>);
 async fn inject_referral(&self, rpc: RpcReceipt, numeric: SocketAddr);
 async fn rebind(&self) -> io::Result<()>;
}
impl QueryBarrier {
 async fn entered(&self) -> QueryReceipt;
 async fn rpc(&self, index: usize) -> RpcReceipt;
 async fn rpc_events(&self) -> Vec<RpcEvent>;
 async fn deliver(&self, rpc: RpcReceipt, bytes: Vec<u8>);
 async fn duplicate(&self, rpc: RpcReceipt, bytes: Vec<u8>);
 async fn late_response(&self, rpc: RpcReceipt, bytes: Vec<u8>) -> Result<IngressReceipt, FixtureError>;
 async fn finish(&self);
 async fn release_correlated(&self, records: Vec<Vec<u8>>);
 async fn release_empty(&self);
 async fn release_without_response(&self); // gate release/cancellation acknowledgement only
}
impl Barrier { async fn entered(&self); async fn release(&self); }
impl AdmissionBarrier { async fn wait_active(&self, count: usize); async fn release_all(&self); }
impl CleanupBarrier { async fn entered(&self) -> OperationReceipt; async fn release(&self); }
impl FlushBarrier { async fn entered(&self); async fn release(&self); }
impl SendBarrier { async fn entered(&self) -> PutAttempt; async fn release(&self); }
impl BootstrapAudit { fn bind_attempts(&self) -> usize; fn hostname_resolution_calls(&self) -> usize; fn default_bootstrap_uses(&self) -> usize; }
impl Snapshot { fn new(addresses: Vec<SocketAddr>) -> Snapshot; fn contains_zero_port(&self) -> bool; }
impl PublisherInspection { fn active_generation(&self) -> Option<u64>; }
impl LimitInspection { fn operation_charge(&self, operation_id: u64) -> usize; }
impl TestClock { fn monotonic_micros(&self) -> u64; fn wall_unix_micros(&self) -> i64; async fn advance(&self, monotonic: Duration, wall_delta_micros: i64); async fn set_wall(&self, unix_micros: i64); }
```

No `InvalidRecord` test-support API is proposed; the enum is local to `runtime/tests/fixture.rs`. The fixture helper is `invalid_record(secret: &SecretKey, kind: InvalidRecord, wall_us: u64, address: SocketAddr) -> Vec<u8>` and uses the upstream timestamped signer for `Stale` (wall minus 300,000,001), `TooFarFuture` (wall plus 30,000,001), and `WrongKey` (separate indexed key); it mutates bytes for `CorruptSignature`, `ByteFlipped`, `Truncated`, `Oversize`, and `Empty`. Negative malformed-envelope cases use the direct SDK `resolve_record_and_connect` checked-record entry and a correctly-keyed native endpoint, not a fabricated KRPC mutable value; stale/future/wrong-key cases additionally parse as valid signed packets and assert exact timestamps. The `QueryReceipt` in the support API has logical operation/query identity only; actual transaction/source comes from `QueryBarrier::rpc(index)`.

The `owned_destinations()` snapshot is a read-only set of fixture-owned socket addresses, including the root and its two responders, captured before the operation. The production send guard's allowed set is established by owner configuration, not expanded by probe input. The hostile-referral assertion requires all actual sent egress destinations to belong to this snapshot and the separately bound hostile socket to remain `WouldBlock` after drain. `put_sends(count)` arms exactly `count` FIFO send gates (no implicit initial gate). Scripted replies are consumed in order; after the script is exhausted, the owned fixture returns its ordinary real Accept response. `PutAttempt` is the intended pre-send attempt event; each `DialReceipt` records the exact invocation immediately before SDK `Endpoint::connect`, including failed handshakes. Admission receipts separately prove successful TLS admission. Only actual-send `PutReceipt`s prove transmission. `resolve`/`resolve_until` are discovery-only; connect calls use the product private wrapper around `Endpoint::connect` and TLS admission. The positive test uses a separate per-key loopback QUIC endpoint bound with that `SecretKey`; `TestOwner::close` owns and joins its server/endpoint.

An `EgressReceipt` records `referral_transaction_id`, the transaction ID of the accepted RPC whose referral caused the guarded candidate attempt; it is provenance, not the outgoing candidate datagram's transaction ID. `operation_id` and `query_id` identify the owning operation/query. The attempted destination and actual send/blocked outcome are observed at the send boundary before I/O. `wait_outbox_drained()` does not wait for held work or advance future timers. Do not call it while a send or cleanup gate needed for the observed operation remains held; release such gates first. Query completion gates are distinct from send gates and may remain held while inspecting pre-completion state. It captures the current monotonic ingress sequence, acknowledges ingress/candidate scheduling/cancellations/timer dispatch through that sequence, then waits for empty outbox and send reservations. Query gate entry follows actual initial query send; `entered()` returns when that send allocated the query. The matching UDP datagram remains in the fixture socket until explicit receive; correlated release consumes it if not already observed, avoiding a competing socket reader. `replay_cached_value` uses the actual N cached-query delivery path, not policy injection. Send gates are armed before updates/ticks and ordered by operation/attempt; timestamps use completed actual-send receipts.

Query completion is counted only on actual query termination. Before `finish`, accepted values do not create a completed query or cache entry. Duplicate replay uses the old `RpcReceipt` (and old transaction) and the actual wire receive path. `release_without_response` is valid even while armed but not entered: it cancels/relinquishes the gate without I/O and does not mint network completion. It is idempotent after terminal stop. Cancellation and deadline tests need not hold a response; arm cleanup gates before task creation. Tests that capture an outstanding actual RPC before abort may send a late response, then release without response and observe cleanup and a stable drained outbox; cancellation may remove the query before that datagram is accepted. `wait_outbox_drained` does not release held work or wait for unreleased gates.

Generation update acknowledgement owns the generation switch and waits for old-generation revocation/drain, not sends belonging to the new generation. Initial acknowledgement may precede its first held send. Cancellation before acknowledgement revokes the generation; requester drop after acknowledgement does not. Clock advance waits for due timer dispatch registration, not held work, so a gate cannot deadlock time advancement.

The client-only case sends an actual N query packet from a separately owned UDP sender; `client_query_observation` waits for actor processing, stable-work barrier and due maintenance-timer processing, then returns actual guard state and actual responder-branch attempts. Assert sender `WouldBlock` and no attempt, then repeat after controlled 15-minute advance and observed maintenance; assert hard-client-only and adaptive-server-disabled. This exercises separate N client and responder guards, not a writable mode switch.

## Proposed N dependency bridge

Not implemented or established: N-source review is required to export `pub mod owned_fixture` from normal `n0/src/lib.rs`, implemented at `n0/src/owned_fixture.rs`; it is not `cfg(test)`-only. The SDK future `native_discovery/runtime/test_support.rs` is included by `native_discovery/runtime/mod.rs` using `#[cfg(test)] mod test_support;`. Neither SDK file is created here; no production SDK API or support stub is proposed.

The proposed typed codec bridge defines `RequestKind { FindNode, GetMutable, PutMutable, Ping }`, `RequestMetadata { transaction_id: u32, kind: RequestKind, target: Option<[u8; 20]>, put_token: Option<Vec<u8>>, value: Option<Vec<u8>>, public_key: Option<[u8; 32]>, sequence: Option<i64>, signature: Option<[u8; 64]> }`, `Referral { id: [u8; 20], address: SocketAddrV4 }`, and `decode_request(bytes: &[u8]) -> Result<RequestMetadata, FixtureCodecError>`, delegating to N decoding. GET and PUT request metadata are decoded from actual packets. Validate a PUT's target and echoed token against the GET advertisement; validate its value/key/sequence/signature against that actual witnessed signed PUT using the supported `iroh_dns::pkarr::SignedPacket::from_bytes` parser and identity, not presumed GET-advertised new value. `MutableReply<'a> { public_key: [u8; 32], signature: [u8; 64], sequence: i64, value: &'a [u8] }`; `FixtureResponse<'a> { Mutable { token: &'a [u8], record: MutableReply<'a>, nodes: &'a [Referral] }, NoValues { token: &'a [u8], nodes: &'a [Referral] }, PutAccepted, PutRejected { code: i32, description: &'a str } }`; and `encode_response(transaction_id: u32, responder_id: [u8; 20], response: FixtureResponse<'_>) -> Result<Vec<u8>, FixtureCodecError>` delegate response construction/encoding to N's single-Message codec. GET carries no token; the fixture advertises bounded opaque test bytes and the actor echoes its token in actual PUT. This checks consistency, not cryptographic security. `PutAccepted` maps to N `MessageType::Response(ResponseSpecific::Ping(PingResponseArguments { responder_id }))`; `PutRejected` maps to `MessageType::Error(ErrorSpecific { code, description: description.to_owned() })`; the reviewed N type has `description: String` (`common/messages.rs:43–47`). N's response handler accepts Ping and routes Error to the actual PUT query (`core/handle_response.rs:29–41`). Scripted `PutReply` is selected for the matched actual PUT and sends its actual same-transaction reply from the expected fixture socket. `wait_put_attempt_finished` observes actual N PUT-query response processing, not a pre-send attempt; `PutReceipt` records actual transmission. The retry publication fixture has one eligible writable storage peer in its publication-specific routing profile, while resolver fixtures exercise two GET peers; this creates no production filter/limit. No handwritten bencode or synthetic multi-value response is proposed.

`RequestMetadata` includes actual target, token, mutable value, public key, sequence, and signature fields, populated from the decoded request. `FixtureResponse`/`encode_response` are defined above and are the sole proposed response API.

`rpc(0)` and `rpc(1)` are the two actual query RPCs. `release_correlated(records)` handles them in index order: it sends each supplied record as a mutable response on its corresponding real RPC, then sends valid N no-values responses for every remaining still-outstanding RPC. It waits for each actual socket decision and the query's actual N terminal event; it advances no clock and uses no timeout. `release_empty()` is exactly the zero-record form. `finish()` checks the observed outstanding-RPC set and answers only still-outstanding RPCs with no-values; it does not resend accepted replies or synthesize completion. Root/bootstrap requests are separately handled from their actual packets and are not hidden query RPCs. `finish()` waits for actual N query terminal, not SDK caller/TLS completion, cache publication, or held cleanup; socket-decision receipts and query-terminal observation are separate events. The test must inspect post-terminal completion state only after joining the query caller. `IngressReceipt` is `#[derive(Debug, Eq, PartialEq)] struct IngressReceipt { event_id: u64, rpc: RpcReceipt, outcome: RpcOutcome }`; `late_response` returns `Result<IngressReceipt, FixtureError>` only after actual live-socket ingress decision.

`release_without_response()` acknowledges only applying barrier release/cancellation, including cancellation of an armed registration before query entry. It sends no UDP packet and waits for neither socket entry/flush nor actor cleanup. It cannot be used as successful completion for a live uncancelled query: outstanding RPCs remain real and must terminate by response or owner cancellation/deadline/stop. Once cancellation or stop is already signalled, the owner remains responsible for actual actor termination; held flush/cleanup work keeps charges until released and completed. Clock advance acknowledges due-timer dispatch registration, not held sends, flushes, or cleanup gates. `finish()` never advances clocks or substitutes a timeout for N query termination.

A narrowly reviewed proposed N `OwnedDht` constructor has the shape `fn owned_fixture::start(config: OwnedConfig, observer: tokio::sync::mpsc::Sender<SocketObservation>) -> Result<OwnedDht, StartError>`. `OwnedConfig` contains only numeric bootstrap endpoints, numeric bind address, and the existing hard-client-only mode; limits remain the existing production limits, not new knobs. It binds only supplied/fixture-owned sockets and returns the actor with immutable bounded observations. Each `SocketObservation` is emitted at N's actual socket boundary and contains `{ event_id: u64, query_id: Option<u64>, transaction_id: u32, source: SocketAddrV4, destination: SocketAddrV4, outcome: SocketOutcome }`, where outcomes are `Accepted`, `RejectedUnexpectedTransaction`, or `SendAttempt`. The owning DHT query handle supplies the actual query-ID mapping to SDK operation/query receipts; no caller chooses these IDs. Candidate-attempt events retain the accepted referral transaction as provenance, distinct from the outgoing transaction. The observer is drained without callbacks or registry-lock reentrancy and bounded within the existing RPC budget. The module, constructor, and observer are proposals requiring N-source review; none is claimed to exist.

Source aliases/provenance are recorded in `docs/architecture/native-mainline-runtime-plan.md` lines 9–15: repository root is P; A is supplied adapter 0.6.1 archive revision `0f5f547cc65514e4537d4e66f776319ea8e30a2e`; N source root is `../../.rush/downloads/native-mainline-212-1101-n0-01/source/n0-mainline-0.7.0`; C source root is `../../.rush/downloads/native-mainline-239-1101-codec-01/codec-source/iroh-dns-1.3.0`. The plan records the pinned archive hashes/checksums; adapter Git-archive versus registry equivalence remains unresolved. These references are not fresh verification. C public `EndpointInfo` methods: `iroh-dns/src/endpoint_info.rs:381,397,471`; crate-private attribute conversions: `iroh-dns/src/attrs.rs:82,97,160,179`. N u32 transaction parsing: `src/actor/socket.rs:369–394`. N private `Message`/codec are not currently cross-crate APIs; `owned_fixture` is a proposed normal-build repair pending review. A is not a product dependency. Repository CI pins Rust `1.99.1` in `.github/workflows/ci.yml:72`.

No independent known-answer vector is claimed. The product test-support seam is private under `native_discovery::runtime`; its N-source ingress hook remains proposed, not implemented. Retry policy is scheduled, not manually ticked/published; limits are 8 active operations and 16 queued; retry contract is <=3 attempts and same 10s operation deadline, jitter <=100ms then <=200ms. A scheduled 60s refresh starts a new operation; missed ticks coalesce. Cancellation signals; cleanup is separately observed. Five-second close failure retains owner/join/socket/charges until released work joins and socket rebind succeeds. Aggregate limits: 8 active operations, 16 queued; payload <=1104 bytes (DNS payload <=1000); 256 aggregate candidates and 256 visited; RPC 128 total/16 per operation including maintenance; outbox 128 datagrams, each <=2048 bytes; 8 result channels owner-wide, <=32 entries and <=65,536 bytes per operation (32*1104=35,328, tighter than the separate byte ceiling); 64 protected keys and 1104-byte full winner; <=4 addresses; cache TTL 30s and freshness/query immediate result <=300s. Aggregate feasibility, parser source paths, and normal dependency graph remain unproved. Sources are unwired/uncompiled; no build, tests, or readiness claim is made.
