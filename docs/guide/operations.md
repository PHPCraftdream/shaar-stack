# Operations: keys, startup, path modes, errors

Claims are tagged where it matters. **Verified** means exercised by tests that ran in GitHub CI (runs are listed in [limits-and-evidence.md](limits-and-evidence.md)). **Source** means read from the code and not separately exercised. **Unverified** means no evidence exists.

## Binaries

`shaar-server` and `shaar-client` are built by CI. A fresh checkout cannot run a plain `cargo build`: the manifests depend on pinned third-party sources that the CI recipes prepare under `target/` (`.github/actions/prepare-sources/action.yml`; CI pins toolchain 1.99.1). No packages, installers or release artifacts exist (non-goal of v1). **Unverified**: building on a machine outside the CI recipes.

## Keys

One 32-byte Ed25519 seed is one identity. The same seed yields the QUIC endpoint key, the libp2p PeerId and the Yggdrasil address (`Identity::ygg_address`), so anyone who knows the public key can link all four.

- File format: exactly 32 raw bytes. No text, no hex, no header. A file of any other size is rejected.
- The binaries only **load** keys. They cannot create a key and `shaar-client` never prints its own public key. Create keys with the public SDK: [`examples/keygen.rs`](examples/keygen.rs) is a complete program (`keygen create <file>` prints the 64-hex public key, `keygen show <file>` prints it again). It is compiled and executed verbatim by tests in `crates/shaar/tests/sdk_network.rs`. **Unverified**: building it as a separate crate outside the workspace.
- `create` never overwrites (`identity key file already exists`). On Unix the file is created with mode 0600 in one step; on Windows with an owner-only ACL before the first byte is written (exercised by the identity test suites in Linux and Windows CI).
- Loading rejects a non-regular file, a wrong size, and (Unix) any group/other permission bit or (Windows) an ACL that is not owner-only. A rejected key is never repaired, regenerated or overwritten. On other platforms only the type and size checks apply.
- Protect the parent directory yourself: the checks cover the file, not its directory. Back the key up: a lost seed is a lost identity, a leaked seed allows impersonation of that identity.

## Allowlist (server)

`allowlist_path` is a text file, one **client public key** per line, exactly 64 hexadecimal characters (either case). Blank lines and lines whose trimmed text starts with `#` are ignored. An empty file admits nobody. [`examples/allowlist.txt`](examples/allowlist.txt) is read verbatim by the production parser in a test (`crates/shaar-server/src/tests/allowlist.rs`).

- Limits: at most 256 entries and 16,896 bytes. **In the composed shape the effective limit is 16 distinct keys** (the entries double as the peer set of the signaling and Yggdrasil layers); 17 or more fail startup with `raw application-peer entries: N exceeds the composed startup bound of 16` (**Verified**: preflight test with 17 entries).
- The server's own key must not be in its allowlist in the composed shape (`identity role conflict: application identity collides with a distinct required role`).
- The file is read once at startup. Restart the server after editing it.
- Admission order: handshake authenticates the client key, the key is checked against the allowlist, and only then may a target TCP connection be opened. A key that is not listed never causes a target connection (**Verified** in both fallback modes for the composed server and for the direct-only server).
- Errors printed by the server: `could not read allowlist`, `allowlist file exceeds 16896 bytes`, `allowlist exceeds 256 entries`, `invalid allowlist key on line N` (N counts comments and blank lines; the key text is never printed).

## Startup

Prepare keys and configs ([configuration.md](configuration.md)), start the fixed target service, then the server, then the client.

### Direct-only shape (no `network` object)

```text
shaar-server --config server.ktav
shaar-client --config client.ktav
```

The server prints a notice that the configured fallback is not active, then one stdout line `bound=<ip:port> public_key=<64 hex>`. `bound=0.0.0.0:PORT` means "listening on all interfaces"; give the client a reachable host address with that PORT as `server_address`. The client prints `listening=<ip:port>` on stdout when its local listener is ready. Connect your application to that address. **Verified** end to end with real processes on loopback in CI (D1); not on any real network.

### Composed shape (`network` object)

Needs a Mainline bootstrap node, a libp2p relay and Yggdrasil peers that you provide ([configuration.md](configuration.md)). The server prints `shaar-server: composed startup: public_key=<hex> fallback=<mode>` on stderr and nothing on stdout: it publishes its signed record under that key and clients find it from the key alone. The client prints `shaar-client: composed startup: public_key=<hex> fallback=<mode> server_address=<hint|none>` on stderr. **The `public_key` in the client line is the pinned *server* key, not the client's own.** The composed client does not print its listening address. **Verified** with real processes against owned fixtures (DHT bootstrap, relay, Yggdrasil transit) in CI; **Unverified** against the public Mainline DHT, public relays or public Yggdrasil peers.

## Shutdown

Stop either binary with Ctrl-C (SIGINT); on Windows Ctrl-Break also works. **Source**: only these console signals are handled; SIGTERM is not, so a service manager should send SIGINT. A normal stop exits 0 (**Verified**: console shutdown and same-port rebinding in the direct-only shape; the composed role stops, releases its UDP/TCP ports and leaves the key file unchanged in both modes).

- Server: stops accepting, closes sessions and workers and joins them, then withdraws the DHT record, closes Mainline and the endpoint (composed order, **Source**).
- Client: aborts stream workers, drops the session and listener, closes the endpoint.
- Established TCP streams end with the shutdown.

## Path modes

`fallback` selects what the second and third networks may do. Native direct QUIC always has priority and is the only payload path in `signal`.

| | `signal` | `standby` (default) |
|---|---|---|
| Direct QUIC to the published or hinted address | tried first | tried first |
| libp2p relay | negotiation only; carries no application bytes | negotiation only; carries no application bytes |
| Yggdrasil | started control-only; never carries payload | may carry payload while the native path is unavailable |
| Direct path blocked | the client gives up after its attempt budget: the local connection ends without reply bytes, the client exits non-zero, the target sees no connection (fail closed) | payload moves to Yggdrasil; the target sees the same exact bytes |

**Verified** in the controlled namespace fixture (fork dispatch 43229756778): single NAT with Native data in both modes; double NAT with all forwarded UDP and relay TCP denied and only the owned Yggdrasil transit allowed: exact application bytes in `standby`, fail closed in `signal`. **Not established**: successful hole punching through arbitrary double NAT (the double-NAT case proves fallback, not punching), symmetric NAT or CGNAT behaviour, real home or mobile networks, the public Yggdrasil network.

Policy defaults (**Source**; not configurable from the files; the SDK exposes them through `RoleOptions`): a native attempt has 3 s; up to 6 attempts with a 500 ms backoff doubling to a 4 s cap; payload fails over after the native path has been down 2 s; it returns to native after native has been stable for 5 s. Only **new** TCP streams use a new route; an established stream ends with its connection and is never replayed or migrated. Standby requires `network.ygg.peers` on both sides, and the Yggdrasil transport only dials out to the configured peers (it opens no listening port).

## What the DHT record discloses

The server publishes one signed record under its own key in the Mainline DHT (**Source**, `crates/shaar/src/native_discovery`, `startup/resources/maintain.rs`). It contains only IP socket addresses reported by the native QUIC endpoint: at most 4 entries, port nonzero, not wildcard/multicast/broadcast, not in the Yggdrasil range, IPv6 only if it has no scope id and is not link-local; IPv4-mapped IPv6 is stored as IPv4. If the endpoint reports more than 4 addresses the snapshot is replaced by an empty one. Relay, libp2p and Yggdrasil addresses are rejected by the record profile and are never published. The record does not contain the allowlist, the target or any config value. Signed age is limited to 300 s, DNS TTL is 30 s, and the record is withdrawn during a normal shutdown.

Consequences for the operator: the record is public to everyone who can query the DHT and it reveals that the key is online and at which addresses. Loopback and private (RFC 1918) addresses are **not** filtered out by the record profile, so assume every unicast interface address of the host may appear. **Unverified**: the exact address set reported on real hosts, with port mapping disabled and the minimal net-report configuration. The key itself links the QUIC key, the PeerId and the Yggdrasil address. The system provides no anonymity (`docs/architecture/threat-model.md`). A client's DHT lookups and its direct dial expose the client's address to the DHT nodes it contacts and to the server (**Source**, not analysed further).

## Error messages and recovery

Messages are printed on stderr as `shaar-server: ...` / `shaar-client: ...`; exit status 1. Redaction: key bytes, peer URIs and upstream I/O text never appear.

| Message | Cause and action |
|---|---|
| `could not load configured identity key` (server) | Missing file, not a regular file, size not 32, or group/other-accessible permissions. The server hides the reason; check with `keygen show`. The client prints the specific reason (`identity key file must be exactly 32 raw bytes`, `identity key file permissions are too broad`, `identity key path is not a regular file`, `identity key file I/O error: ...`). |
| `configuration: ...` / client config error | See [configuration.md](configuration.md). Fix the named field and restart. |
| `endpoint bind failed: ...` (server, direct-only) | The `bind` address is unusable or taken (`a usable native unicast address is required`, `native endpoint bind failed`). |
| `server_address is required for direct-only operation without network settings` (client) | Add `server_address` or a `network` object. |
| `dial failed: handshake deadline exceeded` / `native peer connection failed` (client, direct-only) | The server is unreachable. The client retries up to 3 times (12 s each, 250 ms steps growing with each retry) and then reports; the local connection is closed and the next local connection dials again. |
| `peer is not allowed` / `authenticated peer does not match the pinned key` | The client key is not in the allowlist, or the key behind the address is not the pinned server key. Not retried, but a wrong pinned key can also appear as a generic connection failure. |
| `session admission limit reached` | The 32-session server cap (client: 1 session, 16 local stream workers) is full. |
| `forwarding stream limit reached` / `target TCP connection failed` | 16 streams per session are busy, or the server cannot reach `target`. Start or repair the target; new connections succeed afterwards (**Verified**: recovery after the target becomes available). |
| `composed startup: ...` followed by one of the lines below | Startup or run failure of the composed shape. Stages are named, values are not. |
| `composed startup requires the shared network settings; ...` | A role was started without a `network` object. |
| `identity role conflict: relay\|application\|service identity collides ...` | Your key equals the relay's key, the pinned server key (client), or an allowlisted peer (server). Use distinct keys. |
| `native endpoint/signaling bind failed`, `Mainline discovery runtime start failed`, `Yggdrasil start failed: ...`, `Yggdrasil payload endpoint construction failed`, `local listener bind failed` | A port is taken or unusable, or a peer URI was rejected by the Yggdrasil adapter (the message names the field, e.g. `invalid configuration: peers`). Free the port or fix the field. A failed start rolls back what it had acquired. |
| `relay reservation failed at startup` (server) | The pinned relay could not be reserved. Check `relay` and `relay_address` and that the relay is reachable. |
| `no usable path remained within the attempt budget` (client) | In `signal`, the direct path stayed unavailable for the whole budget; in `standby`, neither path became usable. The client exits; restart it after the network is restored. |
| `shutdown failed at the <stage> stage` | A cleanup stage reported an error; the message is the first error, the process still exits non-zero. |

Recovery behaviour (**Verified** with real processes and owned fixtures in CI): after the server is stopped and started again with the same key the running client reconnects and new connections forward exact bytes, in `signal` and `standby`; the native path being lost makes the client refresh its DHT lookup and recover onto a new native session; a client that loses its session in direct-only mode dials again for the next local connection. Existing TCP streams do not survive any of these events.
