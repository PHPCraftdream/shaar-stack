# Public SDK API (`shaar` crate)

The crate is `publish = false` and lives in this workspace. Add it as a path dependency of a crate in the same workspace (or with the same pinned lock). Items below are the `pub` surface of `crates/shaar/src/lib.rs`; signatures are taken from the source. The two binaries are the reference callers: `crates/shaar-server/src/main.rs`, `crates/shaar-client/src/main.rs`, and the public-API integration tests `crates/shaar/tests/sdk_network.rs`.

Cancellation: unless an item says otherwise, **dropping a future is not a clean shutdown**. Await the explicit `close`/`shutdown`/`stop` operations. Many futures are documented `cancel-safe: NO` in their doc comments.

## `shaar::identity`

| Item | Behaviour |
|---|---|
| `Identity::generate() -> Identity` | New random identity in memory. |
| `Identity::from_seed([u8; 32])` | For fixtures and explicit provisioning only; never derive seeds from passwords. The caller's buffer is zeroized. |
| `Identity::create_new(path).await -> Result<Identity, IdentityError>` | Creates the key file exclusively; never overwrites. |
| `Identity::load(path).await` | Loads an existing file; malformed, inaccessible or insecure-permission files are errors. |
| `Identity::load_or_create(path).await` | Loads, or creates only if the file did not exist when opened; under a race the loser gets an error, not a second identity. |
| `public_key_bytes() -> [u8; 32]` | Ed25519 public key. |
| `peer_id_bytes() -> [u8; 38]` | libp2p PeerId bytes. |
| `ygg_address() -> Ipv6Addr` | Key-derived Yggdrasil address (one-way). |

`IdentityError`: `AlreadyExists`, `Io(std::io::Error)`, `InvalidFormat`, `InsecurePermissions`, `NotARegularFile`. `Debug` output of `Identity` is redacted and there is no seed accessor. A complete key-creation program is [`examples/keygen.rs`](examples/keygen.rs).

## `shaar::config`

`ServerConfig::from_text(&str, &ServerOverrides)` and `ClientConfig::from_text(&str, &ClientOverrides)` parse and validate ktav text; `load_server`/`load_client` (and the `*_with_endpoint_overrides` variants) do the same from a file with a bounded asynchronous read. Getters: `ServerConfig::{target, bind, key_file, allowlist_path, fallback, network}`, `ClientConfig::{server_key_bytes, listen, server_address, key_file, fallback, network}`. `NetworkSettings` exposes `mainline()`, `signaling()` and `ygg()` (`MainlineNetwork`, `SignalingNetwork`, `YggNetwork`). `Fallback::{Signal, Standby}` (default `Standby`). `ConfigError::{Loading, Parsing, Validation}` with `ValidationKind`; its `Display` and `Debug` are identical and redacted. `MAX_CONFIG_BYTES` is 1 MiB. Override structs let a caller (for example a CLI) replace file values before validation; a typed override can repair an invalid file value. Fields and messages: [configuration.md](configuration.md).

## `shaar::network` (direct native layer)

- `ALPN = b"shaar/tcp/1"`.
- `Limits::new(sessions: usize)`: 1 to 32, else `NetworkError::InvalidLimits`; `Limits::default()` is 32. The slots are shared by outbound handshakes and returned sessions.
- `Allowlist::new(&[iroh_base::PublicKey])`: at most 256 input entries (`AllowlistTooLarge`), sorted and deduplicated; `Allowlist::default()` is empty and denies everyone. Note that `PublicKey` is the `iroh-base` type (pinned `=1.3.0`, feature `key`).
- `Endpoint::bind(&Identity, SocketAddr, Allowlist, Limits).await`: one native socket, no n0 services, no port mapping; the address must be usable unicast. `id()`, `local_addr()`.
- `Endpoint::connect(peer: PublicKey, SocketAddr).await -> Session`: pins the exact server key; success proves the TLS identity, not that a later TCP request will be accepted.
- `Endpoint::accept(&mut self).await -> Session`: returns only fully handshaken, allowlisted peers. Each started handshake has a 10 s deadline.
- `Endpoint::close(self).await`: waits for backend shutdown; sessions may still exist.
- `Session::peer_id()`, `closed().await`, `close(self)`.
- `Session::forward(&self, TcpStream).await -> ForwardStats`: client side. One local TCP socket and one QUIC stream; at most 16 concurrent calls (`ForwardError::Capacity` otherwise, no queue). No application byte is read before the server status succeeded.
- `Session::serve(&mut self, target: SocketAddr, stop: impl Future).await -> ServeReport`: server side. `target` must be loopback with a nonzero port (`InvalidTarget`); a peer can never choose host or port. At most 16 workers; `stop` closes the session, aborts and joins the workers.
- `ForwardStats { to_peer, from_peer }`, `ServeReport { completed, failed, cancelled }` (counters saturate).
- `NetworkError`: `InvalidLimits`, `AllowlistTooLarge`, `InvalidAddress`, `Capacity`, `Closed`, `Deadline`, `AccessDenied`, `PeerMismatch`, `Protocol`, `Bind`, `Connect`, `Handshake`, `Signaling`, `SignalingOperation`, `NativePath`. `ForwardError`: `InvalidTarget`, `Capacity`, `AccessDenied`, `PathUnavailable`, `TargetUnavailable`, `Protocol`, `Deadline`, `StreamReset`, `TaskFailure`, `Io`. Peer text is never parsed into a type.
- `SignaledEndpoint`, `bind_signaling`, `bind_signaling_with_discovery`, `DiscoveryConfig`, `DiscoveredRelay` are building blocks of the signaling layer; the composed roles below are the supported way to use them.

Wire protocol `shaar/tcp/1`: the client writes request byte 1, the server answers one status byte (0 target connected, 1 target unavailable, 2 invalid request), unknown values fail closed, setup is bounded by 10 s. Transport limits: 16 bidirectional streams, no unidirectional streams, no datagrams, 256 KiB per-stream and 1 MiB per-connection receive windows. TCP half-close is propagated per direction.

## `shaar::startup` (composed roles)

`ServerRole::new(ServerConfig, &Identity, Allowlist, Limits, RoleOptions)` and `ClientRole::new(ClientConfig, &Identity, Limits, RoleOptions)` validate options only and perform no I/O. Then, on either role:

1. `start().await`: preflight (needs the `network` object), Mainline/signaling/Yggdrasil/native startup; resumable if cancelled; a failed start keeps what it acquired so `shutdown()` can roll it back.
2. `run(&mut Pin<&mut impl Future<Output = ()>>).await`: serves until the supplied shutdown future completes (`Ok`) or a terminal error occurs (`Err(StartupError)`).
3. `shutdown().await`: joined, ordered close; call it after `run` returns on every path, including errors. Dropping a role is only a best-effort fallback.

`RoleOptions::default()` carries the path-policy tuning described in [operations.md](operations.md#path-modes). The roles are not `Send`. Server `Limits` of 32 and a client `Limits` of 1 mirror the binaries. `StartupError` variants are listed with their messages in [operations.md](operations.md#error-messages-and-recovery); they name stages and fields, never values.

The binaries wire exactly this sequence, plus signal handling and error printing, in `main.rs`. **Verified**: the real binaries in CI. **Unverified**: use of the roles from a third-party crate.
