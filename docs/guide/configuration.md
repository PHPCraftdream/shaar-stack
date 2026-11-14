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
| `bind` | no | `0.0.0.0:0` | Socket address of the direct QUIC endpoint (direct-only shape). Port 0 lets the OS choose. **Rejected in the composed shape** (a file with `network` and a top-level `bind` fails validation with ``invalid configuration value for field `bind` (NotApplicable)``): the composed startup binds the native socket itself, IPv4 `0.0.0.0:0` plus an optional IPv6 `[::]:0`, and prints the chosen port (see [operations.md](operations.md)). The nested `network.mainline.bind` and `network.signaling.bind` are separate fields. |
| `key_file` | no | `shaar.key` | Non-empty path of the raw 32-byte seed file. |
| `allowlist_path` | no | `allowed.txt` | Non-empty path of the allowlist (see [operations.md](operations.md)): at most 256 entries, and at most 16 distinct keys when `network` is present. |
| `fallback` | no | `standby` | `signal` or `standby`. See [operations.md](operations.md#path-modes). |
| `network` | no | absent | Composed settings, see below. |

## Client fields

| Field | Required | Default | Rules |
|---|---|---|---|
| `server` | yes | none | Server public key, hex (64 characters) or base32, validated as an Ed25519 public key. This is the only locator in the composed shape. |
| `server_address` | direct-only: yes at runtime; composed: no | none | Numeric socket address: not wildcard, not multicast, not broadcast, port nonzero, and not the Yggdrasil-reserved `fd15:070a:510b::/48`. In the composed shape it is only an optional direct-address hint. |
| `listen` | no | `127.0.0.1:2222` | Loopback socket address of the local TCP listener. Port 0 is accepted by the parser; both shapes print the chosen address as `listening=<ip:port>` on stdout. |
| `key_file` | no | `shaar.key` | As for the server. |
| `fallback` | no | `standby` | As for the server. |
| `network` | no | absent | Composed settings, see below. |

## The `network` object (both roles)

If `network` is present, **all three sections are required** and are checked in this order: `mainline`, `signaling`, `ygg`.

| Field | Required | Default | Rules |
|---|---|---|---|
| `network.mainline.bind` | no | `0.0.0.0:0` | IPv4 socket address for the Mainline DHT UDP socket. |
| `network.mainline.bootstrap` | yes | none | 1 to 4 numeric IPv4 `address:port` entries; port nonzero; not wildcard, multicast or broadcast. DNS names are not accepted. No public bootstrap nodes are built in. |
| `network.signaling.bind` | no | `0.0.0.0:0` | Socket address of the libp2p signaling listener. |
| `network.signaling.relay` | no (together with `relay_address`) | none | libp2p PeerId (base58, usually starting `12D3KooW`) of the pinned relay node. The pair is optional: **both fields together or neither**; exactly one present fails validation naming the missing field. |
| `network.signaling.relay_address` | no (together with `relay`) | none | Numeric socket address of that relay (same rules as `server_address`). |
| `network.ygg.peers` | yes | none | 1 to 4 Yggdrasil peer URIs, scheme `tcp` or `tls`, non-empty host and an explicit nonzero port. Query options such as `key`, `priority`, `password`, `maxbackoff`, `sni` are checked structurally. Never echoed in diagnostics; they may carry secrets. |

No default relay, bootstrap node or Yggdrasil peer is provided or contacted by the SDK. Without the relay pair the composed startup runs without any relay connection: the Server publishes its record and serves through the DHT and Yggdrasil paths, and the Client dials the direct candidates first and then the Yggdrasil path; no relay negotiation phase exists. A configured relay is a libp2p relay node that you must supply; this repository ships no relay program.

## Validation order and error messages

Validation runs before any socket is opened. Syntax and unknown-field errors come first, then fields in the order of the tables (server: `target`, `bind`, `key_file`, `allowlist_path`, then `network`; `fallback` is checked together with the merge). Messages never contain the rejected value, key material or unknown field names:

| Message | Meaning |
|---|---|
| ``invalid configuration value for field `target` (MissingRequired)`` | A required field is absent. |
| ``invalid configuration value for field `target` (NotLoopback)`` | `target` or `listen` is not a loopback address. |
| ``invalid configuration value for field `target` (InvalidPort)`` | `target` has port 0 (also bootstrap entries). |
| ``invalid configuration value for field `bind` (InvalidAddress)`` | Not a numeric socket address, or unusable (wildcard/multicast/broadcast/port 0 where forbidden). |
| ``invalid configuration value for field `bind` (NotApplicable)`` | A top-level `bind` is present together with a `network` object (composed server). Remove it. |
| ``invalid configuration value for field `server` (InvalidKey)`` | Not a valid hex/base32 Ed25519 public key; also an invalid relay PeerId (`network.signaling.relay`). |
| ``invalid configuration value for field `fallback` (InvalidEnum)`` | Not exactly `signal` or `standby` (case sensitive). |
| ``invalid configuration value for field `key_file` (EmptyPath)`` | Present but empty path (also `allowlist_path`). |
| ``invalid configuration value for field `network.ygg.peers` (InvalidUri)`` | Unsupported scheme, missing host or port, port 0, malformed query. |
| ``invalid configuration value for field `network.mainline.bootstrap` (TooFew)`` / `(TooMany)` | List is empty / has more than 4 entries (also `network.ygg.peers`). |
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
