# Direct-only Server/Client quick start

This document describes the current `shaar-server` and `shaar-client` binaries. It is a direct-only operator guide, not a claim of complete production acceptance. Use ktav 0.8 syntax; both config schemas reject unknown fields. The examples use the scalar and socket-address forms present in `crates/shaar/tests/config.rs` and the ktav fixtures.

## 1. Server configuration

Save as `server.ktav`:

```ktav
## Forward accepted client streams only to this local TCP service.
target: 127.0.0.1:8080
## Bind the direct endpoint. Port 0 asks the OS to choose one.
bind: 0.0.0.0:0
key_file: "server.key"
allowlist_path: "allowed.txt"
fallback: signal
```

`target` is required and must be loopback with a nonzero port. `bind` defaults to `0.0.0.0:0`; a wildcard bind is not a client destination. The server prints the actual `bound=` socket and its `public_key=` after binding; the client does not print/export its own public key. Provide clients an independently reachable host address and that printed port (or configure a fixed bind port). Ensure firewall/NAT routing permits direct UDP/QUIC traffic to it. The server warns that signal negotiation is unsupported and connections are direct-only.

## 2. Server identity and client allowlist

The binaries only load existing keys; neither binary provides key generation or client-public-key export. Provision server and client seed files and their corresponding public keys out of band using a trusted, compatible external method. In particular, obtain the client public key for the server allowlist from that method; do not expect `shaar-client` to display it.

Identity files contain exactly 32 raw seed bytes; they are not text or hex. The identity API's exclusive creation operation never overwrites an existing file and sets restrictive permissions/ACLs on Unix and Windows. These platform-specific protections and permission validation do not apply on other platforms. Loading rejects non-regular files and wrong size everywhere; insecure-permission rejection is implemented on Unix and Windows only. Protect the parent directory as well; the key-file checks do not protect it. Back up the key securely: changing it changes the corresponding identity.

Create `allowed.txt` with one client **public key** per line as exactly 64 hexadecimal characters (upper- or lowercase accepted); blank lines and lines whose trimmed content starts with `#` are ignored. No key means no client is admitted. Maximum 256 entries and 16,896 bytes. Protect this file and its parent directory from unauthorized edits. After changing the allowlist, restart the server for the new entries to take effect. Do not put private seed material in this file.

## 3. Client configuration

Save as `client.ktav`, substituting the server's printed public key and an actual numeric address/port reachable from the client (the address below is deliberately illustrative, not a usable endpoint):

```ktav
server: "<server-public-key>"
server_address: "198.51.100.8:49152"
listen: 127.0.0.1:2222
key_file: "client.key"
fallback: signal
```

`server` is required and pins the expected server endpoint key. It accepts the iroh public-key textual representation: hex or base32, decoded and validated as a public key. Obtain the value from the trusted server operator; do not trust an unauthenticated address/key pairing. The client key file must already exist; the binary does not generate keys or export the corresponding client public key, so provision that identity and give its public key to the server operator out of band by a trusted compatible method. `server_address` is required by this direct-only binary and must be a numeric, usable socket address (not wildcard, multicast, broadcast or port zero); the IPv6 prefix `fd15:070a:510b::/48` is specifically excluded by validation. DNS names are not accepted. `listen` defaults to `127.0.0.1:2222` and must remain loopback. The client key file uses the same raw-seed format and platform-specific protection limitations described above.

## 4. Start and use

Start the target service on the server, then launch the server and client:

```text
shaar-server --config server.ktav
shaar-client --config client.ktav
```

The client also accepts no arguments, in which case it reads `client.ktav`. Connect a local application to `127.0.0.1:2222`; its TCP streams are forwarded through the authenticated direct session to the server's configured loopback `target`. The client retries failed dials up to three times with bounded timeouts/backoff; access-denied and peer-mismatch errors are not retried. A live session is reused. If it closes, workers for that session are retired and a later accepted local connection initiates a new dial. This is not a promise that existing streams survive reconnection.

## 5. Limits and transport restrictions

`fallback` accepts `signal` or `standby` and defaults to `standby`. For this direct-only server, explicitly select `signal`: `standby` causes server startup to fail. The client reports either setting and uses direct-only; `standby`/Ygg fallback is unavailable. Signal carries no application data and signaling negotiation is unsupported here. There is no relay/data fallback or guaranteed NAT traversal. Server admission is capped at 32 sessions; the client endpoint allows one session and accepts at most 16 concurrent local stream workers. The allowlist is checked before target forwarding. Expose only a target service you intend to make reachable by allowlisted clients.

## 6. Shutdown and security

Stop either process with Ctrl-C. The server stops accepting and drains active session tasks before closing its endpoint; the client aborts stream workers, drops its session/listener and closes its endpoint. The client listener does not authenticate local applications: any process able to reach it can use the client's authorized access. Restrict access to the host and its local network namespace accordingly. Keep key files private and out of logs/configs, use a trusted channel to distribute the server public key, and keep the allowlist to intended client keys. A compromised client key grants that identity allowlisted access; a compromised server seed permits server impersonation. Direct peer addresses expose network metadata; this setup does not provide anonymity, protect compromised hosts, or defend against volumetric denial of service.

## 7. Acceptance status

This guide documents source behavior and config syntax, not real-process acceptance. End-to-end acceptance for this operating setup remains pending; passing component CI does not establish production readiness. Earlier P03 evidence covers the scoped signaling-only and controlled NAT experiments; it does not establish this direct-only application's real-process acceptance or operation on every home or mobile network. See the path verification document for the evidence and its limits.

## Source references

- `crates/shaar/tests/config.rs` and `crates/shaar/tests/fixtures/{server,client}.ktav` — ktav syntax examples and parser cases.
- `crates/shaar/src/config/server.rs` and `crates/shaar/src/config/client.rs` — ktav fields, defaults, and validation.
- `crates/shaar/src/config/raw.rs` — fallback modes, address rules and excluded IPv6 prefix.
- `crates/shaar/src/identity/store.rs` — key format, platform-specific permission checks and exclusive creation.
- `crates/shaar-server/src/main.rs` and `crates/shaar-server/src/test_support.rs` — invocation, binding, admission, allowlist parsing and shutdown.
- `crates/shaar-client/src/main.rs` — CLI, direct dialing, stream/reconnect lifecycle and shutdown.
- `docs/verification/iroh-paths.md` — limitations of experimental acceptance evidence.
