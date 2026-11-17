# Operations: keys, startup, path modes, errors

Claims are tagged where it matters. **Verified** means exercised by tests that ran in GitHub CI (runs are listed in [limits-and-evidence.md](limits-and-evidence.md)). **Source** means read from the code and not separately exercised. **Unverified** means no evidence exists.

## Binaries

`shaar-server` and `shaar-client` are built by CI. A fresh checkout cannot run a plain `cargo build`: the manifests depend on pinned third-party sources that the CI recipes prepare under `target/` (`.github/actions/prepare-sources/action.yml`; CI pins toolchain 1.99.1). No packages, installers or release artifacts exist (non-goal of v1). **Unverified**: building on a machine outside the CI recipes.

## Keys

One 32-byte Ed25519 seed is one identity. The same seed yields the QUIC endpoint key, the libp2p PeerId and the Yggdrasil address (`Identity::ygg_address`), so anyone who knows the public key can link all four.

- File format: exactly 32 raw bytes. No text, no hex, no header. A file of any other size is rejected.
- The binaries can now also **create** keys: both binaries provision a `shaar.key` identity on first run (see [First run](#first-run)). `shaar-client` also prints its own public key in the first-run output. If you prefer explicit key files, create them with the public SDK: [`examples/keygen.rs`](examples/keygen.rs) is a complete program (`keygen create <file>` prints the 64-hex public key, `keygen show <file>` prints it again). It is compiled and executed verbatim by tests in `crates/shaar/tests/sdk_network.rs`. **Unverified**: building it as a separate crate outside the workspace.
- `create` never overwrites (`identity key file already exists`). On Unix the file is created with mode 0600 in one step; on Windows with an owner-only ACL before the first byte is written (exercised by the identity test suites in Linux and Windows CI).
- Loading rejects a non-regular file, a wrong size, and (Unix) any group/other permission bit or (Windows) an ACL that is not owner-only. A rejected key is never repaired, regenerated or overwritten. On other platforms only the type and size checks apply.
- The address key of the encrypted publication (`address_key_file`, see [What the DHT record discloses](#what-the-dht-record-discloses)) is a second secret of the same format: 32 random bytes, owner-only, loaded by the same checks. Create it with the same keygen program (`keygen create address.key`; the printed public key is meaningless for it) and give the same file to the Server and to every Client that may learn the address.
- Protect the parent directory yourself: the checks cover the file, not its directory. Back the key up: a lost seed is a lost identity, a leaked seed allows impersonation of that identity.

## Allowlist (server)

`allowlist_path` is a text file, one **client public key** per line, exactly 64 hexadecimal characters (either case). Blank lines and lines whose trimmed text starts with `#` are ignored. An empty file admits nobody. [`examples/allowlist.txt`](examples/allowlist.txt) is read verbatim by the production parser in a test (`crates/shaar-server/src/tests/allowlist.rs`).

- Limits: at most 256 entries and 16,896 bytes. **In the composed shape the effective limit is 16 distinct keys** (the entries double as the peer set of the signaling and Yggdrasil layers); 17 or more fail before any network I/O with ``invalid configuration value for field `allowlist_path` (TooMany): N distinct keys exceed the composed-shape limit of 16`` (duplicates count once). The bound is the signaling peer set size, not an arbitrary config choice; it is not raised here (**Verified**: Server binary tests for 16 and 17 keys, and a real-process case).
- The server's own key must not be in its allowlist in the composed shape (`identity role conflict: application identity collides with a distinct required role`).
- The file is read once at startup. Restart the server after editing it.
- Admission order: handshake authenticates the client key, the key is checked against the allowlist, and only then may a target TCP connection be opened. A key that is not listed never causes a target connection (**Verified** in both fallback modes for the composed server and for the direct-only server).
- Errors printed by the server: `could not read allowlist`, `allowlist file exceeds 16896 bytes`, `allowlist exceeds 256 entries`, `invalid allowlist key on line N` (N counts comments and blank lines; the key text is never printed).

## First run

Both binaries can now set themselves up with zero configuration. Label: **Source** — read from the code (`crates/shaar/src/identity/provision/` and the binaries' first-run tests; the ignored process case `process_smoke::startup::real_first_run_bootstrap_without_arguments` is run by CI's process-feedback job).

### CLI grammar

- `shaar-server` — provision only, no target: prints the next step and exits 1. A bare run never guesses the TCP forward target.
- `shaar-server <target>` — provision, then serve; the positional target overrides the config file value for that run (the file is untouched).
- `shaar-server --config <path.ktav>` — explicit config, as before. Mixing the forms is a usage error: `usage: shaar-server [--config <path.ktav> | <target>]`.
- `shaar-client` — if `./client.ktav` exists in the working directory it is used exactly as before (legacy behavior preserved); otherwise the client role is provisioned under the data directory and the next step is printed, exiting 1.
- `shaar-client <server-key> [server-address]` — provision once; the server key (and address, if given) are persisted into the generated `client.ktav` at first generation only; later positional values act as per-run overrides. With a key but no address the client exits 1 after printing `no server address configured` (direct-only needs the numeric address).
- `shaar-client --config <path>` — explicit config, as before. Usage: `usage: shaar-client [--config PATH] | [server-key [server-address]]`.

### Data directory

- Windows: `%LOCALAPPDATA%\shaar` — the machine-local profile, so the device key never roams to other machines or a file server. Unix: `$XDG_DATA_HOME/shaar` when `XDG_DATA_HOME` is non-empty and absolute, otherwise `$HOME/.local/share/shaar` (this works on macOS and on Termux/Android, which only set `HOME`).
- Only the environment variables `LOCALAPPDATA` (Windows) and `XDG_DATA_HOME` and `HOME` (Unix) are read (`APPDATA` is never read); none of them are set by default anywhere. If none is usable the binary fails with `first run: no per-user data directory: set ...`.
- The role directory (`server/` or `client/`) is created with owner-only permissions on Unix (`0o700`, recursive) at creation time. An **existing** directory is reused and its permissions are never silently changed. On Windows `create_dir_all` inherits the per-user profile ACL (no new FFI).

### Files created per role

| Role | Files |
|---|---|
| `shaar-server` | `server.ktav` (ktav 0.8 template **without** a `target:` line; comments explain that `target:` must be added), `shaar.key` (Ed25519 identity), `allowed.txt` (comment-only allowlist template; an empty allowlist denies everyone) |
| `shaar-client` | `client.ktav`, `shaar.key` (no allowlist file) |

`shaar.key` is created only if missing and never overwritten; on Unix it is created with mode 0600, on Windows with an owner-only ACL. Existing files are **never overwritten**: an existing key, config or allowlist is left byte-for-byte untouched and reported as `kept:`. Second runs are idempotent — same identity, `reused` directory. A key file that exists but is corrupt or has too-broad permissions is an error (never repaired, regenerated or overwritten). The generated configs are direct-only (no `network` object). See [configuration.md](configuration.md#generated-first-run-files) for the exact file shapes.

### Stdout contract

The readiness line is printed **first**, the operator block after it:

- `shaar-server <target>`: `bound=<ip:port> public_key=<hex>`, then the summary lines (`first run data directory: <dir> (created|reused)`, one `created:`/`kept:` line per file, `public_key=<64 lowercase hex>`), then `clients connect direct: give each client this public key and this machine's address with the bound port`, then either `allowlist <path>: empty - append each client's public key as one line, then restart the server to admit it` or `allowlist <path>: <N> client key(s) loaded; edits apply after a restart`, then `forward target: <target>`.
- `shaar-client <server-key> <server-address>`: `listening=<ip:port>` first, then the summary lines, then `your public key for the server allowlist: public_key=<own hex>`, `pinned server: public_key=<server hex> address=<addr>`, `add your key as one line to the server allowlist file, then restart the server`.
- Bare runs (`shaar-server`, `shaar-client` without a key, `shaar-client <key>` without an address) print only the summary block, the relevant `no ... configured` line and a `next step: ...` line, then a `first run: ...` error on **stderr** and exit status 1. With `--config` the binary behaves as before and does not provision the data directory.

### Allowlist restart rule

The allowlist is read once at startup. Append each client's public key as one line to `<data>/server/allowed.txt` and restart the server to admit the client; later edits also apply only after a restart.

### What the first run does not do today

The generated configs of the first-run forms are direct-only (no `network` object), and that is deliberate: **no default relay, bootstrap or Yggdrasil peers are invented** by the first run. The `init` subcommand ([Subcommands](#subcommands)) is the explicit way to get public defaults (never a relay), or `config network public` on an existing file. A first run therefore **does not publish a DHT record** and the client still needs the server's numeric address; `fallback` stays inactive. To find the server by key alone, write a `network` object yourself (Mainline bootstrap node(s) and Yggdrasil peers; the libp2p relay pair is optional since leaf L0 and is not needed for the DHT and Yggdrasil paths, see [configuration.md](configuration.md)). Hole punching is **not** part of this build: a composed client dials the published candidates directly and falls back to Yggdrasil, and no direct path through a NAT between two private networks has been observed on a public network.

## Subcommands

Both binaries have subcommands next to the first-run forms above. Clap answers only when the first argument is a subcommand name, `help`, `--help`, `-h`, `--version` or `-V`; every other invocation goes to the first-run parser, with its usage text and exit code unchanged. A subcommand that clap refuses prints clap's usage and exits with status 2; a failing operation prints `shaar-server: <message>` or `shaar-client: <message>` on stderr and exits with 1. Messages name fields and stages, never key material or rejected values.

Where the files are: `--config <path.ktav>` names the configuration file (the key and allowlist paths come from it); `--dir <base>` names the data directory instead (default: the per-user directory of [First run](#data-directory); the files are `<base>/server/` or `<base>/client/`). The two options exclude each other.

**shaar-server**

| Command | What it does |
|---|---|
| `init [--dir D] [--private]` | Creates the role directory, `shaar.key`, `server.ktav` and `allowed.txt` (existing files are kept), then prints the summary, `peer_id=`, `ygg_ip=`, the network note, the next step and `clients connect with this address: <public key>`. The generated file carries the public `network` object (Mainline bootstrap hosts `dht.libtorrent.org:25401` and `router.bittorrent.com:6881`, Yggdrasil peers `tcp://ygg-pa.incognet.io:8883` and `tcp://mo.us.ygg.triplebit.org:9000`, never a relay) unless `--private` is given. The file has no `target` yet. |
| `address` | Prints `public_key=`, `peer_id=` and `ygg_ip=` of the Server's key: the key is the address a Client needs. |
| `address-key new <path>` | Creates a 32-byte key file (owner-only, never overwrites) for `publish_address: encrypted`; give the same file to every Client that may learn the address. |
| `allow add <key>...`, `allow remove <key>...`, `allow list` | Edits or lists `allowed.txt`: comments stay, the old content is kept as `allowed.txt.bak`, the entry bounds of [Allowlist](#allowlist-server) apply. A running Server reads the file only at startup: restart it. `list` prints one key per line and `clients=<n>`. |
| `config show`, `config check` | `show` prints the file. `check` validates it with the rules of a file load (every required value present), the identity key and the allowlist file it names, and prints `ok: <path>` and the Server's `public_key=`. |
| `config set <key> <value>`, `config unset <key>`, `config network public\|private` | Edits one top-level setting (`target`, `bind`, `key_file`, `allowlist_path`, `fallback`, `publish_address`, `address_key_file`) or switches the `network` object. See *Editing a configuration* below. |
| `run [--config P \| --dir D] [TARGET]` | Serves exactly like `shaar-server --config P`, or like the first run of `D`; `TARGET` overrides `target` for this run. |

**shaar-client**

| Command | What it does |
|---|---|
| `init <server-key> [--address ip:port] [--dir D] [--private]` | Creates `shaar.key` and `client.ktav` pinned to the Server key (public `network` object unless `--private`; `--private` needs `--address`), then prints the summary, `your public key for the server allowlist: public_key=<own>`, `pinned server: ...` and the command to run on the Server: `shaar-server allow add <own>`. |
| `address` | Prints this Client's `public_key=`, `peer_id=` and `ygg_ip=`. |
| `connect [--config P \| --dir D]` | Runs the Client of that configuration (`listening=<ip:port>` first). Without the file it says to run `init` first. |
| `config show\|check\|set\|unset\|network` | As for the Server; the editable keys are `server`, `server_address`, `listen`, `key_file`, `fallback`, `address_key_file`. |

### Editing a configuration

`config set`, `config unset` and `config network` read the file, normalise it with `ktav::format_str` (every comment and grouping blank survives, compounds take their block form), change one top-level entry (a value is written as a literal string, `key:: value`; the next edit normalises the file again, which prints a value that cannot be mistaken for a number or a keyword as a plain `key: value`), and validate the result with the rules of the role. A result that would be invalid is refused with the field and kind of the file's own message and nothing is written, with one allowance: a file that still lacks its required `target` (Server) or `server` (Client) can be edited step by step; `config check` is the strict gate. The previous content is kept as `<file>.bak`; the new content is written through a temporary file and a rename. `config network public` replaces the `network` object by the public defaults and drops the comment header `init` wrote above it; `config network private` removes it.

Evidence for this section is stated in [limits-and-evidence.md](limits-and-evidence.md#sdk-and-command-line).

## Startup

With no arguments, both binaries now bootstrap themselves ([First run](#first-run)); the forms below still work unchanged. Prepare keys and configs ([configuration.md](configuration.md)), start the fixed target service, then the server, then the client.

### Direct-only shape (no `network` object)

```text
shaar-server --config server.ktav
shaar-client --config client.ktav
```

The server prints a notice that the configured fallback is not active, then one stdout line `bound=<ip:port> public_key=<64 hex>`. `bound=0.0.0.0:PORT` means "listening on all interfaces"; give the client a reachable host address with that PORT as `server_address`. The client prints `listening=<ip:port>` on stdout when its local listener is ready. Connect your application to that address. **Verified** end to end with real processes on loopback in CI (D1); not on any real network.

### Composed shape (`network` object)

Needs a Mainline bootstrap node and Yggdrasil peers that you provide; a libp2p relay is optional ([configuration.md](configuration.md)). With no relay fields the Server skips the relay reservation and the Client dials the direct candidates, then the Yggdrasil path. The server prints `shaar-server: composed startup: public_key=<hex> fallback=<mode>` on stderr, then (once started) the stdout line `bound=<ip:port> public_key=<hex>`; `bound=0.0.0.0:PORT` is the native UDP port on all IPv4 interfaces. It publishes its signed record under that key and clients find it from the key alone. The client prints `shaar-client: composed startup: public_key=<own hex> server=<pinned server hex> fallback=<mode> server_address=<hint|none>` on stderr, then the stdout line `listening=<ip:port>` once its local listener is bound. `public_key` is always the process's own key; the pinned server key is labelled `server`. **Verified** with real processes against owned fixtures (DHT bootstrap, relay, Yggdrasil transit) in CI, including the relay-less shape. **Observed once** on the public network without a relay: a single bounded smoke (fork run 43671098240, two separate GitHub-hosted runners, public Mainline bootstrap nodes and public Yggdrasil peers, key-only Client) completed one exact request/reply over the Yggdrasil standby path in under one second; the route was inferred at that time, not observed, and no direct path was attempted. This is an observation, not an acceptance of the end-to-end claim. A public libp2p relay was tried once and gave no reservation. Everything else on public networks stays **Unverified**.

## Shutdown

Stop either binary with Ctrl-C (SIGINT) or, on Unix, SIGTERM (the signal service managers send); on Windows Ctrl-Break also works. All use the same graceful path. A normal stop exits 0 (**Verified**: console shutdown and same-port rebinding in the direct-only shape; the composed role stops, releases its UDP/TCP ports and leaves the key file unchanged in both modes).

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

## Session observability lines (stable grammar)

This section is **Verified** by unit tests and real-process cases in CI (fork CI 43694473684, process feedback 43695774162, upstream CI 43696633747 at `aac9ddf`). A live public smoke with these lines has not run yet; until it does, the smoke harness falls back to inferring the route.

Both binaries print operator-facing lines on **stderr** with a fixed grammar (`crates/shaar/src/network/forwarding/observe.rs`). Lines carry only counts and typed tokens — never key material, addresses, or third-party data.

Client route line — printed once per successful dial (per route decision):

```text
shaar-client: route path=<P> candidates=record:<R>,hint:<H> resolve=<X> elapsed_ms=<MS>
```

Server route line — printed once per accepted session:

```text
shaar-server: route path=<P>
```

Session line — printed exactly once per reaped session, by either product:

```text
<shaar-server|shaar-client>: session path=<P> result=ok bytes_in=<N> bytes_out=<M>
<shaar-server|shaar-client>: session path=<P> result=error error=<TOKEN> bytes_in=0 bytes_out=0
```

Values:

- `path` P ∈ {`native`, `ygg-signal`, `ygg-standby`}. `ygg-signal` is reserved for future signal-mode negotiation routes and is not emitted today.
- `resolve` X ∈ {`found`, `not-found`, `timeout`, `cached`}: `found` = a fresh Mainline lookup returned addresses (the `record:` count is the taken candidate count, capped at the 4-candidate bound); `not-found` = the lookup completed with zero addresses; `timeout` = the lookup produced no answer in its budget (this also covers a resolver runtime failure — no answer is the observable fact); `cached` = no lookup happened for this decision (candidates were already carried: the configured hint or the retained list of an earlier resolve).
- The `ygg-standby` client route line carries the LAST native resolve observation of that dial cycle (the standby fallback never consults the record itself; with no native attempt yet it reports `cached` with zero counts).
- `elapsed_ms` measures the dial that produced the route (from its start to the established link), saturating at `u64::MAX`.
- `result=ok` means the session ended without a forwarding error: a completed/normal stop OR the peer's clean application close (`peer-closed` is never rendered as an error). `result=error` names the typed cause via `error` ∈ {`invalid-target`, `capacity`, `access-denied`, `path-unavailable`, `target-unavailable`, `protocol`, `deadline`, `stream-reset`, `task-failure`, `io`, `peer-closed`}; on error lines the byte counts are literal zeros (unknown).
- Classification rule: only the peer's APPLICATION-level close is a clean end; locally-closed teardown, transport failures and timeouts remain typed errors.
- `bytes_in`/`bytes_out` are totals over FULLY completed streams only: at the server, `bytes_in` counts bytes received from the peer (forwarded toward the target) and `bytes_out` the bytes sent back; cancelled or interrupted streams contribute nothing; a session that ended before any stream completed reports zeros.

Hole-punch diagnostics — tokens and counts only, never an address:

```text
shaar: <client|server> punch candidates=<N> outcome=<direct|fallback> reason=<direct|deadline|no-answer|closed|probe> elapsed_ms=<MS>
shaar: <client|server> punch ports own=<PORTS|-> peer=<PORTS|->
shaar: server punch offer candidates=<N> answer=<sent|none|refused>
shaar: reflexive window outcome=<skipped|empty|observed> lookup=<ok|incomplete|bounded|failed:<ERROR>> info=<some|none|failed> elapsed_ms=<MS>
shaar: reflexive window outcome=exposed elapsed_ms=<MS>
```

- A punch attempt names why it ended. `candidates` counts what this side offered; a side that does not yet know its public address offers none.
- `punch ports` lists the ports of the candidates this side offered (`own`) and of those the peer offered or answered (`peer`), comma separated and at most four per side, `-` for none; it never prints an address. A peer port that differs from the port the peer bound means a NAT rewrote the source port, which the candidate (public IP plus local QUIC port) cannot reach. The Client prints it when the Answer arrives, the Server when it answers an Offer.
- The same trace lines appear whichever channel carries the exchange: the Yggdrasil bridge control datagrams (no relay fields), or, with a pinned relay, the authenticated libp2p carrier link (leaf L4b). On the carrier link the punch messages are side-channel datagrams next to the QUIC packets; the relay still carries signaling only, never application data. With a relay the Client punches between bringing up the carrier link and the relay negotiation, using up to half of the remaining attempt, and falls through to the unchanged negotiation when no answer or probe succeeds.
- The Server answers an Offer only when it has candidates of its own; `answer=none` means it had none to answer with.
- One reflexive window is one lookup of the DHT address watcher. `lookup` says how the window's own lookup ended (`ok` completed; `incomplete` finished without a network answer; `bounded` hit the 10 s bound; `failed:<ERROR>` carried a typed error) and `info` what the DHT actor held afterwards (`some` an address, `none` no vote yet, `failed` the read did not finish). A completed lookup counts whatever it read; any other lookup still counts an address that another finished query already learned, and never counts "no vote" as evidence. `exposed` marks the first majority of two agreeing windows; only that majority is ever published in the record (`publish_address = plain`). The punch offers the address of the latest window that observed one as soon as it exists (a single DHT vote, never published) and switches to the majority once it is exposed, so a side can offer a candidate before two windows agree. One forged vote can therefore make a side offer a wrong IP; the peer then probes at most four candidates per attempt and one burst per interval.

Consumers: the public smoke harness (`.github/probes/public-smoke/`) reads these lines from the product stderr and fails a run whose observed path contradicts its expectation. Absence of the lines (older binaries) keeps the previous inferred wording.

## What the DHT record discloses

The server publishes one signed record under its own key in the Mainline DHT (**Source**, `crates/shaar/src/native_discovery`, `startup/resources/maintain.rs`). It contains only IP socket addresses reported by the native QUIC endpoint: at most 4 entries, port nonzero, not wildcard/multicast/broadcast, not in the Yggdrasil range, IPv6 only if it has no scope id and is not link-local; IPv4-mapped IPv6 is stored as IPv4. If the endpoint reports more than 4 addresses the snapshot is replaced by an empty one. Relay, libp2p and Yggdrasil addresses are rejected by the record profile and are never published. The record does not contain the allowlist, the target or any config value. Signed age is limited to 300 s, DNS TTL is 30 s, and the record is withdrawn during a normal shutdown.

Consequences for the operator: the record is public to everyone who can query the DHT and it reveals that the key is online and at which addresses. Loopback and private (RFC 1918) addresses are **not** filtered out by the record profile, so assume every unicast interface address of the host may appear. **Unverified**: the exact address set reported on real hosts, with port mapping disabled and the minimal net-report configuration. The key itself links the QUIC key, the PeerId and the Yggdrasil address. The system provides no anonymity (`docs/architecture/threat-model.md`). A client's DHT lookups and its direct dial expose the client's address to the DHT nodes it contacts and to the server (**Source**, not analysed further).

**Encrypted address (`publish_address: encrypted`).** The record then carries no plain address: the list that `plain` would publish (the snapshot and the voted public address, at most 4 entries) is sealed with ChaCha20-Poly1305 under a key derived by HKDF-SHA256 from the 32-byte `address_key_file`, a fresh random salt per publication, the Server key and the signed timestamp, and travels as one `user-data` value of the form `shaar1.<base64url>` (at most 245 characters, so exactly one key per Server). A passive DHT observer, a storage node or a crawler sees that a record exists, its size and its sequence number, but no address. The Client that was given the same key file (`address_key_file` in its config) opens the value and uses the addresses exactly like published ones; a Client without the key, or with a wrong key, gets no address from the record and keeps the rendezvous and Yggdrasil paths. A flipped byte, a changed Server key or a re-signed timestamp makes the value fail authentication and the record is rejected. What it does not hide: the existence of the record, the Yggdrasil address derived from the key, the IP seen by the Server's configured Yggdrasil peers, and the IP seen by any peer that connects directly. Rotation: write a new key file on the Server and give it to the clients; records already published stay readable by former holders until they expire (300 s). **Verified** in CI by unit, record-codec, publisher, configuration and start-up tests, and in the controlled namespace fixture by the pair `dnat-cone-encrypted-signal` and `-standby` (a sealed record stored, the Client holding the key opened it, direct path, APP exact). **Unverified**: any live run with a real DHT and real NATs.

## Error messages and recovery

Messages are printed on stderr as `shaar-server: ...` / `shaar-client: ...`; exit status 1. The first-run guidance lines (`no ... configured`, `next step: ...`) are the exception: they are printed on stdout and describe what to do next, not an error; only the accompanying `first run: ...` line goes to stderr. Redaction: key bytes, peer URIs and upstream I/O text never appear.

| Message | Cause and action |
|---|---|
| `first run: no per-user data directory: set ...` | None of `LOCALAPPDATA` (Windows) or `XDG_DATA_HOME` / `HOME` (Unix) is usable. Set one and retry. |
| `first run: ...` (other first-run provisioning errors) | The data directory or a file could not be provisioned (for example a corrupt key or too-broad key permissions; the key is never repaired, regenerated or overwritten). Fix the cause and retry; existing files are never overwritten. |
| `no forward target configured` / `next step: run shaar-server <target:port> or set target: in <config path>` | Bare `shaar-server`: it provisioned but has no forward target. Pass the target as a positional argument or add `target:` to the generated `server.ktav`. |
| `no server key configured` / `next step: run shaar-client <server-public-key> <server-address>` | Bare `shaar-client`: it provisioned but has no pinned server key. Run it again with the server's public key and address. |
| `no server address configured` / `next step: run shaar-client <hex> <server-address>` | `shaar-client <server-key>` without an address: direct-only needs the numeric server address. |
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
| `address key file could not be loaded` | `address_key_file` is missing, not a regular file, not exactly 32 bytes, or readable by group or others. Fix the file (the message never names the path). |
| `relay reservation failed at startup` (server) | The pinned relay could not be reserved. Check `relay` and `relay_address` and that the relay is reachable. |
| `no usable path remained within the attempt budget` (client) | In `signal`, the direct path stayed unavailable for the whole budget; in `standby`, neither path became usable. The client exits; restart it after the network is restored. |
| `shutdown failed at the <stage> stage` | A cleanup stage reported an error; the message is the first error, the process still exits non-zero. |

Recovery behaviour (**Verified** with real processes and owned fixtures in CI): after the server is stopped and started again with the same key the running client reconnects and new connections forward exact bytes, in `signal` and `standby`; the native path being lost makes the client refresh its DHT lookup and recover onto a new native session; a client that loses its session in direct-only mode dials again for the next local connection. Existing TCP streams do not survive any of these events.
