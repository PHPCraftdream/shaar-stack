# Configuration reference (ktav 0.8)

Both binaries read one ktav 0.8 file. Syntax notes that matter here:

- `key: value` is a plain scalar; `key:: value` is a literal string (needed when the value starts with `[`, for example an IPv6 socket address such as `bind:: [::1]:0`). The examples use `::` for file paths.
- `## text` starts a comment line. Objects use `{ ... }`, lists use `[ ... ]` with one entry per line.
- Unknown fields are rejected everywhere (`deny_unknown_fields`), also inside `network`. A file larger than 1 MiB (`MAX_CONFIG_BYTES`) is rejected before parsing.
- Relative `key_file` and `allowlist_path` values are resolved against the **process working directory**, not against the directory of the config file.

Every example below is a separate file in [`examples/`](examples/). The test module `crates/shaar/src/config/guide_examples_tests.rs` loads these files verbatim and checks the field values and the validation messages quoted on this page. Written and executed are separate facts: see [limits-and-evidence.md](limits-and-evidence.md) for the CI run.

## Two shapes of file

| Shape | Selected by | Examples |
|---|---|---|
| Direct-only (legacy) | no `network` object | [`server-direct.ktav`](examples/server-direct.ktav), [`client-direct.ktav`](examples/client-direct.ktav) |
| Composed (DHT, optional signaling relay, Yggdrasil) | a `network` object | [`server-composed.ktav`](examples/server-composed.ktav), [`client-composed.ktav`](examples/client-composed.ktav), [`server-composed-norelay.ktav`](examples/server-composed-norelay.ktav) |

Without `network` the binaries run direct-only and print that the configured `fallback` is not active. With `network` they run the composed startup. There is no silent switch between the two.

## Server fields

| Field | Required | Default | Rules |
|---|---|---|---|
| `target` | yes | none | Numeric loopback socket address, nonzero port. The only place the server ever connects to. DNS names are not accepted. |
| `bind` | no | `0.0.0.0:0` | Socket address of the direct QUIC endpoint (direct-only shape). Port 0 on an address that is not loopback takes the first free port of the endpoint's own key-ordered set of 100 ports (`shaar::network::ports`) and an OS-chosen port only when all of them are busy; an explicit port is used as given. **Rejected in the composed shape** (a file with `network` and a top-level `bind` fails validation with ``invalid configuration value for field `bind` (NotApplicable)``): the composed startup binds the native socket itself, IPv4 `0.0.0.0:0` (a port of the key-ordered set, as above) plus an optional IPv6 `[::]:0`, and prints the chosen port (see [operations.md](operations.md)). The nested `network.mainline.bind` and `network.signaling.bind` are separate fields. |
| `key_file` | no | `shaar.key` | Non-empty path of the raw 32-byte seed file. |
| `allowlist_path` | no | `allowed.txt` | Non-empty path of the allowlist (see [operations.md](operations.md)): at most 256 entries, and at most 16 distinct keys when `network` is present. |
| `fallback` | no | `standby` | `signal` or `standby`. See [operations.md](operations.md#path-modes). |
| `publish_address` | no | `off` | `off`, `plain` or `encrypted` (case sensitive); composed shape only. `off` publishes private addresses only, exactly as before. `plain` adds ONE entry to the DHT record: the public IP that the DHT nodes observed for this Server (a majority vote of BEP 42 observations) with the local QUIC port, so a Client behind a different NAT can try it directly. **`plain` makes the Server's public IP readable by anyone who looks up its key.** The vote is untrusted and is not authenticated: a wrong address costs a Client at most one bounded dial attempt, and addresses the record policy rejects (loopback, link-local, multicast, broadcast, wildcard) are never added. The record keeps its limit of 4 addresses: when it is already full, the last local address yields its slot. With no observation yet, the record is unchanged; a changed observation updates the record through the normal refresh. `encrypted` publishes the same list (the endpoint addresses and the voted public address) sealed: the record carries no plain address, only a ChaCha20-Poly1305 value under a key derived (HKDF-SHA256) from `address_key_file` and bound to the Server key and the signed timestamp. Only a Client that holds the same key file (`address_key_file` in its own config) learns the addresses; anyone else sees that a record exists, its size and its sequence number. A Client without the key, or with a wrong one, gets no address from the record and keeps the rendezvous and Yggdrasil paths. A Server holds exactly one key (the sealed value travels in the 245-character `user-data` attribute): the audience is whoever is given that file. |
| `address_key_file` | with `publish_address: encrypted` | none | Non-empty path of a raw 32-byte key file, in the identity key format and with the same owner-only permission checks (create it with the keygen example of [operations.md](operations.md#keys) and keep it out of version control). Required with `encrypted` and rejected with `off` or `plain`. It is read before any socket is opened; an unreadable file stops the start with `address key file could not be loaded`. |
| `network` | no | absent | Composed settings, see below. |

## Client fields

| Field | Required | Default | Rules |
|---|---|---|---|
| `server` | yes | none | Server public key, hex (64 characters) or base32, validated as an Ed25519 public key. This is the only locator in the composed shape. |
| `server_address` | direct-only: yes at runtime; composed: no | none | Numeric socket address: not wildcard, not multicast, not broadcast, port nonzero, and not the Yggdrasil-reserved `fd15:070a:510b::/48`. In the composed shape it is only an optional direct-address hint. |
| `listen` | no | `127.0.0.1:2222` | Loopback socket address of the local TCP listener. Port 0 is accepted by the parser; both shapes print the chosen address as `listening=<ip:port>` on stdout. |
| `key_file` | no | `shaar.key` | As for the server. |
| `fallback` | no | `standby` | As for the server. |
| `address_key_file` | no | none | Raw 32-byte key file that opens the Server's `encrypted` record (the same file the Server was given). Composed shape only: with no `network` object it is rejected (``NotApplicable``). Without it an encrypted record yields no address and the other paths are used. |
| `network` | no | absent | Composed settings, see below. |

## The `network` object (both roles)

If `network` is present, **all three sections are required** and are checked in this order: `mainline`, `signaling`, `ygg`.

| Field | Required | Default | Rules |
|---|---|---|---|
| `network.mainline.bind` | no | `0.0.0.0:0` | IPv4 socket address for the Mainline DHT UDP socket. |
| `network.mainline.bootstrap` | yes | none | 1 to 4 entries, each a numeric IPv4 `address:port` (not wildcard, multicast or broadcast) or a DNS `host:port` (letters, digits and inner hyphens, at most 63 bytes per label and 253 in all); port nonzero. Host names are resolved once when the composed role starts, within 5 s, and each contributes its first usable IPv4 address; if no entry is usable the start fails with ``no bootstrap host of `network.mainline.bootstrap` could be resolved``. The parser itself builds in no bootstrap node; files written by `init` carry public ones (below). |
| `network.mainline.pkarr_relays` | no | none | 0 to 4 public pkarr relay base URLs, each `https://` with a domain name and nothing after it (no user, path, query or fragment), or `http://` to a loopback IPv4 address for a local test relay; a repeated entry counts once. The Server additionally sends every signed record it publishes to each of them as one HTTPS `PUT` (a refresh at most once per 120 s per relay; a new record as soon as 40 s have passed since the previous request to that relay, the latest record wins, so at most 3 requests per relay in 106 s), on top of its own DHT publication and without ever delaying it; a relay does the DHT put from a well-connected host and reports how many nodes stored it, which matters for a Server on a mobile link. The Client ignores the key. Nothing is contacted unless entries are listed: examples are `https://pkarr.pubky.app`, `https://pkarr.pubky.org` and `https://relay.pkarr.org` (third-party services; the relays of n0 are not used). The relay sees the signed record, which is encrypted when `publish_address: encrypted` is set. |
| `network.signaling.bind` | no | `0.0.0.0:0` | Socket address of the libp2p signaling listener. |
| `network.signaling.relay` | no (together with `relay_address`) | none | libp2p PeerId (base58, usually starting `12D3KooW`) of the pinned relay node. The pair is optional: **both fields together or neither**; exactly one present fails validation naming the missing field. |
| `network.signaling.relay_address` | no (together with `relay`) | none | Numeric socket address of that relay (same rules as `server_address`). |
| `network.ygg.peers` | yes | none | 1 to 4 Yggdrasil peer URIs, scheme `tcp` or `tls`, non-empty host and an explicit nonzero port. Query options such as `key`, `priority`, `password`, `maxbackoff`, `sni` are checked structurally. Never echoed in diagnostics; they may carry secrets. |

The configuration parser provides no default relay, bootstrap node or Yggdrasil peer and contacts nothing. Files written by `init` (SDK: `identity::provision_with` with `NetworkChoice::Public`) carry the public bootstrap hosts `dht.libtorrent.org:25401` and `router.bittorrent.com:6881` and the public Yggdrasil peers `tcp://ygg-pa.incognet.io:8883` and `tcp://mo.us.ygg.triplebit.org:9000`, never a relay; `--private` (`NetworkChoice::Private`) and the legacy first run write direct-only files. Without the relay pair the composed startup runs without any relay connection: the Server publishes its record and serves through the DHT and Yggdrasil paths, and the Client dials the direct candidates first and then the Yggdrasil path; no relay negotiation phase exists. With Ygg peers configured, the Client additionally runs the bounded punch coordination over the Yggdrasil bridge control channel between its direct candidates and the Yggdrasil path, and the Server answers authenticated punch offers and fires bounded probe bursts; each side prints one stderr line per punch attempt (`punch candidates=<n> outcome=direct|fallback elapsed_ms=<ms>`). A configured relay is a libp2p relay node that you must supply; this repository ships no relay program.

## Validation order and error messages

Validation runs before any socket is opened. Syntax and unknown-field errors come first, then fields in the order of the tables (server: `target`, `bind`, `key_file`, `allowlist_path`, then `network`; `fallback` and `publish_address` are checked together with the merge). Messages never contain the rejected value, key material or unknown field names:

| Message | Meaning |
|---|---|
| ``invalid configuration value for field `target` (MissingRequired)`` | A required field is absent. |
| ``invalid configuration value for field `target` (NotLoopback)`` | `target` or `listen` is not a loopback address. |
| ``invalid configuration value for field `target` (InvalidPort)`` | `target` has port 0 (also bootstrap entries). |
| ``invalid configuration value for field `bind` (InvalidAddress)`` | Not a numeric socket address, or unusable (wildcard/multicast/broadcast/port 0 where forbidden). |
| ``invalid configuration value for field `bind` (NotApplicable)`` | A top-level `bind` is present together with a `network` object (composed server). Remove it. |
| ``invalid configuration value for field `server` (InvalidKey)`` | Not a valid hex/base32 Ed25519 public key; also an invalid relay PeerId (`network.signaling.relay`). |
| ``invalid configuration value for field `fallback` (InvalidEnum)`` | Not exactly `signal` or `standby` (case sensitive). |
| ``invalid configuration value for field `key_file` (EmptyPath)`` | Present but empty path (also `allowlist_path` and `address_key_file`). |
| ``invalid configuration value for field `publish_address` (InvalidEnum)`` | Not exactly `off`, `plain` or `encrypted` (case sensitive). |
| ``invalid configuration value for field `address_key_file` (MissingRequired)`` | `publish_address: encrypted` without a key file. |
| ``invalid configuration value for field `address_key_file` (NotApplicable)`` | A server key file with `off` or `plain`, or a client key file without a `network` object. |
| ``invalid configuration value for field `network.ygg.peers` (InvalidUri)`` | Unsupported scheme, missing host or port, port 0, malformed query. |
| ``invalid configuration value for field `network.mainline.bootstrap` (TooFew)`` / `(TooMany)` | List is empty / has more than 4 entries (also `network.ygg.peers`). |
| ``invalid configuration value for field `network.mainline.pkarr_relays` (InvalidUri)`` / `(TooMany)` | An entry is not an `https://` relay base URL as above / the list has more than 4 entries. |
| `configuration parse error (syntax, line N, offset M)` | ktav syntax error; location only. |
| `configuration parse error (schema)` | Unknown field or wrong value shape; no field name is reported. |
| `configuration file loading failed (Io)` / `(TooLarge)` / `(InvalidUtf8)` | The file cannot be opened/read, exceeds 1 MiB, or is not UTF-8. |

The server binary prefixes configuration errors with `shaar-server: configuration: `. A syntax/schema error is not attributed to a field; compare your file with the examples.

## Command line

| Binary | Invocation |
|---|---|
| `shaar-server` | `shaar-server` (provision only, prints the next step, exits 1) · `shaar-server <target>` (provision, then serve) · `shaar-server --config <path.ktav>`. Mixing the forms is a usage error: `usage: shaar-server [--config <path.ktav> | <target>]` and exit 1. |
| `shaar-client` | `shaar-client` (uses `./client.ktav` if it exists in the working directory, otherwise provisions `<data>/client/`) · `shaar-client <server-key> [server-address]` · `shaar-client --config <path>`. Other forms print `usage: shaar-client [--config PATH] | [server-key [server-address]]` and exit 1. |

Precedence: a positional `<target>` (server) or `<server-key>` / `<server-address>` (client) overrides the config file value **for that run only**; the config file is never rewritten by an override. The client persists the positional server key and address into its generated `client.ktav` at **first generation only** (as `server:: <hex>` / `server_address:: <addr>`); later positional values are again per-run overrides and the file is never rewritten afterwards. Without `--config`, an existing `./client.ktav` in the working directory wins over the data directory (legacy behavior preserved). The server's generated `server.ktav` has no `target:` line; the positional target fills the gap without touching the file. There are no environment variables, `--help` or logging flags.

### Generated first-run files

What the binaries **write** on first run (these are not example files; see [operations.md](operations.md#first-run)). Values use the `::` literal-string form so paths and hex keys always parse as strings.

Server `<data>/server/server.ktav` (note: no `target:` line — the comments explain that `target:` must be added, or a positional target can be given):

```text
## Sha'ar Server configuration (ktav 0.8), generated by the first run.
## The binary never rewrites this file; edit it freely.
## Set the local TCP service to forward to by adding one line, for example:
## target: 127.0.0.1:8080
## Or run: shaar-server 127.0.0.1:8080
key_file:: <path of shaar.key>
allowlist_path:: <path of allowed.txt>
```

Client `<data>/client/client.ktav` (`key_file::` always; `server::` and `server_address::` are written only when the corresponding positional arguments were given at first generation, and the file is never rewritten afterwards):

```text
## Sha'ar Client configuration (ktav 0.8), generated by the first run.
## The binary never rewrites this file; edit it freely.
## client: the server key pins the server; server_address is required today
## (direct-only first run); both may also be given on the command line.
key_file:: <path of shaar.key>
server:: <64 hex server public key>
server_address:: <server ip:port>
```

Server `<data>/server/allowed.txt` starts as a comment-only template (an empty allowlist denies everyone):

```text
## Sha'ar allowlist: one client public key per line (64 hex characters).
## Empty lines and lines starting with # are ignored.
## An empty allowlist denies every client.
## Append a client key as one line, then RESTART the server: the file is
## read once at startup.
```
