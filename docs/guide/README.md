# Sha'ar Stack guide: from keys to a TCP connection

Sha'ar forwards one local TCP port of a client to one fixed loopback TCP service of a server. Both sides are identified by Ed25519 keys; the client pins the server key and the server admits only allowlisted client keys.

| Page | Content |
|---|---|
| [operations.md](operations.md) | Keys, allowlist, startup, shutdown, `signal` vs `standby`, what the DHT record discloses, errors and recovery |
| [configuration.md](configuration.md) | Every ktav 0.8 field, defaults, validation messages |
| [sdk-api.md](sdk-api.md) | Public SDK API |
| [limits-and-evidence.md](limits-and-evidence.md) | OS, NAT, relay, Yggdrasil and FFI limits; the checks that were actually run and what was not |
| [examples/](examples/) | Config files, allowlist and key program used below; each is exercised by a test |

Labels: **Verified** = exercised by tests that ran in GitHub CI; **Source** = read from the code only; **Unverified** = no evidence. Nothing in this guide has been run on a public network or on real home or mobile networks.

## Choose a shape

| | Direct-only | Composed |
|---|---|---|
| Config | no `network` object | with a `network` object |
| Client needs | server key **and** a numeric `server_address` | server key only |
| Finds the server by | the address you give | the Mainline DHT |
| Fallback | none (`fallback` is accepted but not active) | `signal` or `standby` |
| You must supply | a reachable address | DHT bootstrap node(s), a libp2p relay, Yggdrasil peers |
| Evidence | real processes on loopback in CI | real processes against owned fixtures in CI, controlled NAT and blockade matrix |

The direct-only shape is the simplest path and is described first.

## Quick start: direct-only

You need the `shaar-server` and `shaar-client` binaries (CI builds them; see [operations.md](operations.md#binaries)) and a program to create keys ([`examples/keygen.rs`](examples/keygen.rs), a tiny crate depending on `shaar`; the binaries cannot create keys).

1. **Keys.** Create one identity per side and note the printed public keys:

   ```text
   keygen create server.key     # prints SERVER_PUBLIC (64 hex)
   keygen create client.key     # prints CLIENT_PUBLIC (64 hex)
   ```

2. **Allowlist** on the server host: `allowed.txt` with one line, `CLIENT_PUBLIC` ([`examples/allowlist.txt`](examples/allowlist.txt) shows the format).
3. **Server config** `server.ktav` from [`examples/server-direct.ktav`](examples/server-direct.ktav): set `target` to your service, for example `127.0.0.1:8080`. Keep `key_file`, `allowlist_path` in the working directory or adjust them.
4. **Start the target service**, then the server: `shaar-server --config server.ktav`. It prints `bound=0.0.0.0:PORT public_key=SERVER_PUBLIC`.
5. **Client config** `client.ktav` from [`examples/client-direct.ktav`](examples/client-direct.ktav): set `server` to `SERVER_PUBLIC` and `server_address` to the server host's reachable IP and `PORT` (a numeric address; UDP must be allowed through any firewall).
6. **Start the client**: `shaar-client --config client.ktav`. It prints `listening=127.0.0.1:2222`.
7. **Connect** your application to `127.0.0.1:2222`. Its TCP stream is forwarded to the server's `target`. A client whose key is not in `allowed.txt` is refused and the target sees no connection.
8. **Stop** both with Ctrl-C.

If something fails, [operations.md](operations.md#error-messages-and-recovery) maps each message to a cause.

## Quick start: composed (key-only client)

Same keys and allowlist (at most 16 allowlisted clients in this shape). In addition you provide: 1 to 4 numeric IPv4 Mainline bootstrap nodes, the PeerId and numeric address of a libp2p relay, and 1 to 4 Yggdrasil peer URIs. No defaults exist; nothing public has been tried.

1. Server: [`examples/server-composed.ktav`](examples/server-composed.ktav) with your values, `fallback: standby` or `signal`. Start it; read `public_key=` from its stdout line `bound=<ip:port> public_key=<hex>` (also on its stderr startup line).
2. Client: [`examples/client-composed.ktav`](examples/client-composed.ktav) with `server: <that key>` and the same `network` section (no `server_address`). The client prints `listening=<ip:port>` on stdout once its local listener is bound (so `listen` may use port 0).
3. Start the client and connect to `listen`. With `standby` payload may fall back to Yggdrasil when direct QUIC is blocked; with `signal` it fails closed. Details and limits: [operations.md](operations.md#path-modes).

## Tests that keep this guide honest

`crates/shaar/src/config/guide_examples_tests.rs` loads the four `.ktav` examples verbatim and asserts their values and the quoted validation messages; `crates/shaar-server/src/tests/allowlist.rs` parses `allowlist.txt` with the production parser; `crates/shaar/tests/sdk_network.rs` compiles and runs `keygen.rs`. The CI impact map (`.github/ci/policy.py`) selects them when an example changes.
