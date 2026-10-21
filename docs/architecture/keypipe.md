# keypipe — key-based port forwarding without network interfaces

An architecture draft and code sketch. This is not a finished program: API names in iroh
(pre-1.0), rust-libp2p, and yggdrasil-go change from version to version, so everything
marked **⚠ verify** must be checked against the sources of the chosen versions.

> **STATUS (2026-10-22):** this is the original architectural draft. The
> Yggdrasil integration sections — the Go shim, `build.rs`, and the FFI sketch
> (section 11 and related roadmap items) — are **SUPERSEDED** by the native
> Rust backend decision (Revertron/Yggdrasil-ng, pinned commit
> c9a54f1587bb133a06072596484c972a336db0d2). The draft is kept as a historical
> sketch, not the current design; the current adapter contract lives in
> `docs/architecture/contracts.md` (section 4) and development plan stage P07.
> iroh/libp2p sketch claims remain unverified as before.

---

## 1. The idea

A device on the network is identified by a **key**, not an IP address. Nothing in the
system needs configuring: no TUN interfaces, no VPN routes, no open ports on the router,
no root required.

- The **server** keeps an internal service on `127.0.0.1` (SSH, web panel, bot) and
  "exposes" that port under its key.
- The **client** finds the server by key and opens a local port on its side. Everything
  that arrives at that port goes to the server's internal service.

```
  Client                                                      Server
  ssh -p 2222 127.0.0.1                                       sshd on 127.0.0.1:22
        │                                                            ▲
        ▼                                                            │
  [keypipe connect] ═══ QUIC + TLS, key-based authentication ═══ [keypipe listen]
   127.0.0.1:2222                                               --target 127.0.0.1:22
```

All the infrastructure belongs to communities, not companies: n0 infrastructure
(DNS and relay) in iroh is **disabled**.

---

## 2. One key — four addresses

All the systems used run on **Ed25519**. So a device has a single private key, and all
its addresses are derived from it:

| Where | Address | How it's derived |
|---|---|---|
| iroh | `EndpointId` | Public key |
| Mainline DHT (pkarr) | Record key | The same public key |
| Yggdrasil | Node address `200:…` and routing key | The same public key |
| libp2p | `PeerId` | The same public key |

An important corollary: **the server's Yggdrasil address is known to the client in
advance**, no lookup needed. So even if the DHT search fails, the path via Yggdrasil
remains.

---

## 3. Paths and their roles

Three functions are separated here: **discovery** (where you are), **signaling**
(agreeing on NAT traversal) and **data** (the traffic itself).

| Path | Infrastructure | Discovery | Signaling | Data |
|---|---|---|---|---|
| **Direct QUIC** (IPv6, IPv4, LAN, punched NAT) | None | — | — | ✅ Primary |
| **Mainline DHT** (pkarr) | BitTorrent, ~10M nodes | ✅ | ❌ | ❌ |
| **libp2p circuit relay v2** | Public IPFS Amino nodes (~25K) | ✅ (relay addresses) | ✅ | ❌ For traversal only |
| **Yggdrasil** (userspace) | Community public peers | Not needed: address = key | ✅ | ✅ Fallback |

### Why libp2p fits exactly for signaling

Public IPFS (Kubo) nodes by default act as **limited relays**
(circuit relay v2): connections through them are limited in time and volume
(on the order of a couple of minutes and ~100 KB — **⚠ verify** current Kubo limits).
That is too little for data transfer, but exactly right for exchanging address
candidates and punching NAT. That's what they were designed for.

### Why iroh does the punching, not libp2p

libp2p has its own NAT traversal (DCUtR), but it punches a hole for **the libp2p
socket**. We need a hole in the NAT for **the iroh UDP socket**, otherwise the direct
path goes to the wrong stack. So libp2p and Yggdrasil serve iroh only as a **channel**:
QUIC packets travel through them, and in newer versions iroh performs NAT traversal
inside the QUIC connection itself (multipath + QUIC NAT traversal), using any
already-working path as the negotiation channel.

---

## 4. How the connection is established

```
 Client                                                            Server
   │ 1. server key already known (config)                            │
   │                                                                 │ publishes to Mainline:
   │ 2. search in Mainline DHT ────────────────────────────────────► │  - its IP addresses
   │    gets IP addresses and libp2p relay addresses                 │  - libp2p relay addresses
   │                                                                 │
   │ 3. tries all paths in parallel:                                 │
   │    ├─ direct IP ───────────────────── (if available) ──────────►│
   │    ├─ libp2p relay ═══ /p2p/RELAY/p2p-circuit/p2p/SERVER ══════►│
   │    └─ Yggdrasil ═══ by server key, no lookup ══════════════════►│
   │                                                                 │
   │ 4. on the first working path: TLS handshake, verification       │
   │    of the client key against the allowlist                      │
   │                                                                 │
   │ 5. QUIC NAT traversal: candidate exchange over that path,       │
   │    simultaneous UDP packet sending → direct path                │
   │                                                                 │
   │ 6. data goes directly;                                          │
   │    libp2p relay closes by itself (limits);                      │
   │    Yggdrasil stays in reserve or is closed (mode below)         │
```

---

## 5. Path policy

**Priority for data:** direct QUIC → Yggdrasil → (libp2p relay — never for data).

**Fallback path modes** (the `--fallback` flag):

| Mode | libp2p relay | Yggdrasil |
|---|---|---|
| `signal` | Traversal only | Traversal only, then the path is closed |
| `standby` (default) | Traversal only | Traversal + reserve: data goes over it if there is no direct path or it disappeared |

**Nuance: NAT forgets holes.** If the direct path disappeared (network changed, the
router dropped its mappings), the fallback channels are needed again for a new
traversal. So even in `signal` mode the transports are not removed from the endpoint
but "go to sleep":
- libp2p: reconnects via relay when needed;
- Yggdrasil: the node stays on the network, the path is opened again on demand.

QUIC keepalive on the direct path (every ~15–25 s) keeps the NAT hole open.

---

## 6. Access and security

- **Key allowlist** on the server (`allowed.txt`): the primary access mechanism.
  Checked after the TLS handshake, where the client key has been cryptographically confirmed.
- **The internal service listens only on `127.0.0.1`.**
- The **key** is a single file with `0600` permissions.
- **Publicity.** The Mainline DHT record is visible to everyone: it contains the server's
  IP addresses and its libp2p relay addresses. If you don't want to publish your home IP,
  you can publish **only the libp2p relay addresses**: signaling goes through them, and
  Yggdrasil doesn't require a record at all. The direct path is then found at the
  traversal step.
- **Two layers of protection.** Authentication inside the service itself (SSH keys) remains.
- Intermediate nodes (IPFS relays, Yggdrasil peers) see only encrypted QUIC packets.

---

## 7. Project structure

```
keypipe/                         # cargo workspace
├── Cargo.toml
├── keypipe/                     # binaries
│   └── src/
│       ├── common.rs            # key, allowlist, endpoint, path policy
│       ├── server.rs
│       └── client.rs
├── iroh-yggdrasil/              # custom transport: Yggdrasil in userspace
│   ├── build.rs                 # builds the Go shim into a static library
│   ├── yggshim/                 # Go: thin wrapper over the yggdrasil-go core
│   │   ├── go.mod
│   │   └── shim.go
│   └── src/
│       ├── ffi.rs
│       └── lib.rs
└── iroh-libp2p/                 # custom transport: QUIC datagrams over a libp2p relay
    └── src/
        ├── swarm.rs
        └── lib.rs
```

### Root Cargo.toml

```toml
[workspace]
members = ["keypipe", "iroh-yggdrasil", "iroh-libp2p"]
resolver = "2"

[workspace.dependencies]
iroh   = { version = "0.97", features = ["discovery-pkarr-dht", "unstable-custom-transports"] } # ⚠ current
tokio  = { version = "1", features = ["full"] }
anyhow = "1"
bytes  = "1"
libp2p = { version = "0.55", features = ["tokio", "tcp", "quic", "noise", "yamux",
                                          "kad", "identify", "relay", "macros"] }        # ⚠ current
libp2p-stream = "0.3"                                                                      # ⚠ current
```

---

## 8. Shared code — `keypipe/src/common.rs`

```rust
use std::{collections::HashSet, fs, path::Path, sync::Arc};

use anyhow::{ensure, Context, Result};
use iroh::{
    discovery::dht::DhtDiscovery,                 // ⚠ in newer versions: address_lookup
    endpoint::{RecvStream, SendStream},
    Endpoint, EndpointId, RelayMode, SecretKey,
};
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub const ALPN: &[u8] = b"keypipe/tcp/0";
/// The other side sees a QUIC stream only after the first bytes.
pub const HANDSHAKE: &[u8; 5] = b"kpipe";

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum FallbackMode { Signal, Standby }

/// One key for everything: iroh, pkarr, Yggdrasil, libp2p.
pub fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let bytes: [u8; 32] = fs::read(path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let key = SecretKey::generate(&mut rand::rngs::OsRng);
    fs::write(path, key.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}

pub fn load_allowlist(path: &Path) -> Result<HashSet<EndpointId>> {
    fs::read_to_string(path)
        .context("failed to read the allowlist")?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.parse::<EndpointId>().context(format!("bad key: {l}")))
        .collect()
}

pub struct Net {
    pub endpoint: Endpoint,
    pub ygg: Arc<iroh_yggdrasil::YggTransport>,
    pub p2p: Arc<iroh_libp2p::Libp2pTransport>,
}

/// An Endpoint without n0 infrastructure, with two fallback transports.
pub async fn make_net(key: SecretKey, alpns: Vec<Vec<u8>>, mode: FallbackMode) -> Result<Net> {
    let seed = key.to_bytes(); // 32-byte Ed25519 seed — shared across all networks

    // Yggdrasil in userspace: public peers + LAN multicast.
    let ygg = Arc::new(iroh_yggdrasil::YggTransport::start(
        &seed,
        &[
            "tls://peer-1.example:443", // ⚠ take 3–5 peers from yggdrasil-network/public-peers
            "tls://peer-2.example:443",
        ],
    )?);

    // libp2p: entry into the IPFS Amino DHT, relay discovery, slot reservation.
    let p2p = Arc::new(iroh_libp2p::Libp2pTransport::start(&seed).await?);

    let endpoint = Endpoint::empty_builder(RelayMode::Disabled) // no n0 relay, no n0 DNS
        .secret_key(key)
        .discovery(DhtDiscovery::builder())                     // Mainline DHT
        .add_custom_transport(ygg.clone())                      // ⚠ verify the method name
        .add_custom_transport(p2p.clone())
        .path_selector(PathPolicy { mode })                     // ⚠ verify the path selection API
        .alpns(alpns)
        .bind()
        .await?;

    Ok(Net { endpoint, ygg, p2p })
}

/// Path policy: direct IP → Yggdrasil → libp2p (never for data).
/// ⚠ SKETCH: see the trait and path-selection context in iroh/examples/custom-transport.rs.
struct PathPolicy { mode: FallbackMode }

impl iroh::endpoint::transports::PathSelector for PathPolicy {
    fn rank(&self, path: &iroh::endpoint::transports::Addr) -> Option<u8> {
        use iroh::endpoint::transports::Addr;
        match path {
            Addr::Ip(_) => Some(0),                                         // always best
            Addr::Custom(a) if a.id() == iroh_yggdrasil::TRANSPORT_ID => match self.mode {
                FallbackMode::Standby => Some(1),                           // reserve for data
                FallbackMode::Signal  => None,                              // negotiation only
            },
            Addr::Custom(a) if a.id() == iroh_libp2p::TRANSPORT_ID => None, // negotiation only
            _ => None,
        }
    }
}

pub async fn pipe(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let up = async {
        tokio::io::copy(&mut tcp_r, &mut send).await?;
        send.finish()?;
        anyhow::Ok(())
    };
    let down = async {
        tokio::io::copy(&mut recv, &mut tcp_w).await?;
        tcp_w.shutdown().await?;
        anyhow::Ok(())
    };
    tokio::try_join!(up, down)?;
    Ok(())
}

pub async fn expect_handshake(recv: &mut RecvStream) -> Result<()> {
    let mut buf = [0u8; HANDSHAKE.len()];
    recv.read_exact(&mut buf).await?;
    ensure!(&buf == HANDSHAKE, "wrong handshake");
    Ok(())
}
```

**A note on "signaling only".** If a path is not eligible for data (`None` in the
policy), iroh may still use it during connection establishment and negotiation of the
direct path, but it does not send application data over it when a better path exists.
**⚠ Verify** that the chosen iroh version distinguishes a "path for negotiation" from
a "path for data". If it doesn't, the `signal` mode is implemented inside the transport
itself: once the connection observer (`conn` paths watcher) has seen a confirmed direct
path, the transport stops sending packets of that connection over the signaling path.

---

## 9. Server — `keypipe/src/server.rs`

```rust
mod common;

use std::{collections::HashSet, path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use iroh::{endpoint::Incoming, EndpointId};
use tokio::net::TcpStream;

use common::*;

#[derive(Parser)]
struct Args {
    /// Internal service, e.g. 127.0.0.1:22
    #[arg(long)]
    target: String,
    #[arg(long, default_value = "keypipe.key")]
    key: PathBuf,
    #[arg(long, default_value = "allowed.txt")]
    allow: PathBuf,
    #[arg(long, value_enum, default_value = "standby")]
    fallback: FallbackMode,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let key = load_or_create_key(&args.key)?;
    let allow = Arc::new(load_allowlist(&args.allow)?);
    let target = Arc::new(args.target);

    let net = make_net(key, vec![ALPN.to_vec()], args.fallback).await?;
    let ep = &net.endpoint;

    println!("keypipe-server");
    println!("  id:        {}", ep.id());
    println!("  yggdrasil: {}", net.ygg.address());           // 200:… — derived from the same key
    println!("  libp2p:    {}", net.p2p.peer_id());           // same key
    println!("  target:    {target}");

    // Nothing is published manually:
    // - DhtDiscovery publishes the endpoint addresses to Mainline and refreshes the record;
    // - the libp2p transport reports its relay addresses to iroh as CustomAddr,
    //   and they land in the same record (⚠ verify which address types get
    //   published; record size ≤ 1000 bytes → at most 2–3 relay addresses);
    // - the Yggdrasil address is not published at all: the client derives it from the key.

    while let Some(incoming) = ep.accept().await {
        let allow = allow.clone();
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, allow, target).await {
                eprintln!("connection: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_connection(
    incoming: Incoming,
    allow: Arc<HashSet<EndpointId>>,
    target: Arc<String>,
) -> Result<()> {
    let conn = incoming.await?;
    let peer = conn.remote_id();

    if !allow.contains(&peer) {
        eprintln!("denied: {peer}");
        conn.close(1u32.into(), b"forbidden");
        return Ok(());
    }
    println!("client connected: {peer}");

    while let Ok((send, mut recv)) = conn.accept_bi().await {
        let target = target.clone();
        tokio::spawn(async move {
            let res = async {
                expect_handshake(&mut recv).await?;
                let tcp = TcpStream::connect(target.as_str()).await?;
                pipe(tcp, send, recv).await
            }
            .await;
            if let Err(e) = res {
                eprintln!("stream: {e:#}");
            }
        });
    }
    println!("client disconnected: {peer}");
    Ok(())
}
```

---

## 10. Client — `keypipe/src/client.rs`

```rust
mod common;

use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use iroh::{endpoint::Connection, EndpointAddr, EndpointId};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Mutex};

use common::*;

#[derive(Parser)]
struct Args {
    /// Server key (EndpointId)
    #[arg(long)]
    server: EndpointId,
    #[arg(long, default_value = "127.0.0.1:2222")]
    listen: String,
    #[arg(long, default_value = "keypipe.key")]
    key: PathBuf,
    #[arg(long, value_enum, default_value = "standby")]
    fallback: FallbackMode,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let key = load_or_create_key(&args.key)?;
    let net = Arc::new(make_net(key, vec![], args.fallback).await?);

    println!("keypipe-client");
    println!("  my id: {}  ← add this to allowed.txt on the server", net.endpoint.id());

    let listener = TcpListener::bind(&args.listen).await?;
    println!("  listening: {} → {}", args.listen, args.server);

    let slot: Arc<Mutex<Option<Connection>>> = Arc::new(Mutex::new(None));

    loop {
        let (tcp, from) = listener.accept().await?;
        let net = net.clone();
        let slot = slot.clone();
        let server = args.server;

        tokio::spawn(async move {
            let res = async {
                let c = get_connection(&net, server, &slot).await?;
                let (mut send, recv) = c.open_bi().await?;
                send.write_all(HANDSHAKE).await?;
                pipe(tcp, send, recv).await
            }
            .await;
            if let Err(e) = res {
                eprintln!("{from}: {e:#}");
            }
        });
    }
}

async fn get_connection(
    net: &Net,
    server: EndpointId,
    slot: &Mutex<Option<Connection>>,
) -> Result<Connection> {
    let mut guard = slot.lock().await;
    if let Some(c) = guard.as_ref() {
        if c.close_reason().is_none() {
            return Ok(c.clone());
        }
    }

    // The server's Yggdrasil address is derived from its key — add it right away.
    // The other addresses (IP, libp2p relay) iroh will find in the Mainline DHT itself.
    let addr = EndpointAddr::new(server)
        .with_custom_addr(iroh_yggdrasil::addr_for(&server)); // ⚠ verify the API

    let c = net.endpoint.connect(addr, ALPN).await?;
    println!("connection established");
    *guard = Some(c.clone());
    Ok(c)
}
```

Running:

```bash
# server
keypipe-server --target 127.0.0.1:22

# client
keypipe-client --server <server_id>
ssh -p 2222 user@127.0.0.1
```

---

## 11. The `iroh-yggdrasil` transport

> **SUPERSEDED (2026-10-22):** the Go shim, `build.rs`, and FFI sketch below are
> superseded by the native Rust backend decision — see the STATUS note at the
> top of this document and section 11's replacement: the native adapter
> contract in `../architecture/contracts.md` section 4 and development plan P07.

### The idea

The yggdrasil-go core by itself works as a **packet conn addressed by public key**:
send a datagram to the node with key X, receive a datagram from the node with key Y.
IPv6, TUN, and the TCP stack are layers on top of it, and we don't need them. We take
only the core.

There is no mature Yggdrasil implementation in Rust, so the Go core is built into a
**static library** (`go build -buildmode=c-archive`) and linked into Rust. The result
is a single binary: no separate process, no TUN, no root.

### The Go shim — `iroh-yggdrasil/yggshim/shim.go`

```go
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"crypto/ed25519"
	"io"
	"net/url"
	"strings"
	"unsafe"

	iwt "github.com/Arceliar/ironwood/types"
	"github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

var node *core.Core

//export ygg_start
func ygg_start(seed *C.uint8_t, peers *C.char) C.int {
	sk := ed25519.NewKeyFromSeed(C.GoBytes(unsafe.Pointer(seed), 32))

	var opts []core.SetupOption
	for _, p := range strings.Split(C.GoString(peers), "\n") {
		if p == "" {
			continue
		}
		u, err := url.Parse(p)
		if err != nil {
			return -2
		}
		opts = append(opts, core.Peer{URI: u})
	}

	// ⚠ verify: in v0.5 core.New takes a TLS certificate
	// built from the node key (see config.NodeConfig in yggdrasil-go).
	cert, err := certFromKey(sk)
	if err != nil {
		return -3
	}
	n, err := core.New(cert, log.New(io.Discard, "", 0), opts...)
	if err != nil {
		return -1
	}
	node = n
	return 0
}

//export ygg_mtu
func ygg_mtu() C.int { return C.int(node.MTU()) }

//export ygg_send
func ygg_send(dst *C.uint8_t, buf *C.uint8_t, n C.int) C.int {
	key := ed25519.PublicKey(C.GoBytes(unsafe.Pointer(dst), 32))
	data := C.GoBytes(unsafe.Pointer(buf), n)
	if _, err := node.WriteTo(data, iwt.Addr(key)); err != nil {
		return -1
	}
	return n
}

// Blocking receive: Rust calls it on a separate thread.
//
//export ygg_recv
func ygg_recv(buf *C.uint8_t, capacity C.int, src *C.uint8_t) C.int {
	b := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(capacity))
	n, from, err := node.ReadFrom(b)
	if err != nil {
		return -1
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(src)), 32), from.(iwt.Addr))
	return C.int(n)
}

//export ygg_stop
func ygg_stop() { node.Stop() }

func main() {}
```

### Build — `iroh-yggdrasil/build.rs`

```rust
fn main() {
    let out = std::env::var("OUT_DIR").unwrap();
    let status = std::process::Command::new("go")
        .args(["build", "-buildmode=c-archive", "-o", &format!("{out}/libyggshim.a"), "."])
        .current_dir("yggshim")
        .status()
        .expect("Go must be installed");
    assert!(status.success());

    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static=yggshim");
    println!("cargo:rustc-link-lib=dylib=pthread"); // ⚠ on Linux; on macOS — frameworks
    println!("cargo:rerun-if-changed=yggshim");
}
```

### The Rust side — `iroh-yggdrasil/src/lib.rs`

```rust
mod ffi {
    use std::os::raw::{c_char, c_int};
    extern "C" {
        pub fn ygg_start(seed: *const u8, peers: *const c_char) -> c_int;
        pub fn ygg_mtu() -> c_int;
        pub fn ygg_send(dst: *const u8, buf: *const u8, n: c_int) -> c_int;
        pub fn ygg_recv(buf: *mut u8, cap: c_int, src: *mut u8) -> c_int;
        pub fn ygg_stop();
    }
}

use std::{ffi::CString, sync::Arc};
use bytes::Bytes;
use iroh::endpoint::transports::{CustomAddr /* , CustomTransport, CustomEndpoint, CustomSender */};
use tokio::sync::mpsc;

/// ⚠ reserve our own id in iroh/TRANSPORTS.md
pub const TRANSPORT_ID: u16 = 0x5947; // "YG"

/// A node's Yggdrasil address = its key, so it is derived without any lookup.
pub fn addr_for(id: &iroh::EndpointId) -> CustomAddr {
    CustomAddr::from_parts(TRANSPORT_ID, id.as_bytes())
}

pub struct YggTransport {
    rx: tokio::sync::Mutex<mpsc::Receiver<([u8; 32], Bytes)>>,
    mtu: usize,
    pubkey: [u8; 32],
}

impl YggTransport {
    pub fn start(seed: &[u8; 32], peers: &[&str]) -> anyhow::Result<Self> {
        let peers = CString::new(peers.join("\n"))?;
        anyhow::ensure!(unsafe { ffi::ygg_start(seed.as_ptr(), peers.as_ptr()) } == 0,
                        "failed to start Yggdrasil");
        let mtu = unsafe { ffi::ygg_mtu() } as usize;

        // Receive on a separate OS thread: ygg_recv is blocking.
        let (tx, rx) = mpsc::channel(1024);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; mtu];
            let mut src = [0u8; 32];
            loop {
                let n = unsafe { ffi::ygg_recv(buf.as_mut_ptr(), buf.len() as _, src.as_mut_ptr()) };
                if n < 0 { break; }
                if tx.blocking_send((src, Bytes::copy_from_slice(&buf[..n as usize]))).is_err() {
                    break;
                }
            }
        });

        let pubkey = ed25519_public_from_seed(seed);
        Ok(Self { rx: rx.into(), mtu, pubkey })
    }

    pub fn address(&self) -> std::net::Ipv6Addr { ygg_ipv6_from_key(&self.pubkey) }

    pub fn send(&self, dst: &[u8; 32], pkt: &[u8]) -> std::io::Result<()> {
        let r = unsafe { ffi::ygg_send(dst.as_ptr(), pkt.as_ptr(), pkt.len() as _) };
        if r < 0 { Err(std::io::ErrorKind::Other.into()) } else { Ok(()) }
    }
}

// ⚠ SKETCH of the trait implementations: signatures strictly per
// iroh/src/socket/transports/custom.rs and the Tor transport example.
//
// impl CustomTransport for YggTransport {
//     fn bind(self: Arc<Self>) -> io::Result<Box<dyn CustomEndpoint>> { … }
// }
// impl CustomEndpoint for YggEndpoint {
//     fn local_addrs(&self) -> … { [CustomAddr::from_parts(TRANSPORT_ID, &self.pubkey)] }
//     fn poll_recv(&mut self, cx, bufs, metas, src_addrs) -> Poll<io::Result<usize>> {
//         // take (src, pkt) from self.rx, src → CustomAddr::from_parts(TRANSPORT_ID, &src)
//     }
//     fn create_sender(&self) -> Arc<dyn CustomSender> { … }
// }
// impl CustomSender for YggSender {
//     fn poll_send(&self, cx, dst: &CustomAddr, transmit) -> Poll<io::Result<()>> {
//         // dst.data() → 32 bytes of key → self.send(...)
//     }
// }

impl Drop for YggTransport {
    fn drop(&mut self) { unsafe { ffi::ygg_stop() } }
}
```

---

## 12. The `iroh-libp2p` transport

### The idea

1. A libp2p node with the **same key** joins the **IPFS Amino DHT** (Kademlia,
   protocol `/ipfs/kad/1.0.0`).
2. The **server** finds public relay nodes (Kubo with relay v2), reserves a slot with
   2–3 of them, and obtains addresses of the form
   `/ip4/…/p2p/RELAY/p2p-circuit/p2p/SERVER`.
   These addresses go to iroh as `CustomAddr` and are published to Mainline.
3. The **client** connects to the server via the relay address.
4. Over that connection a stream is opened with protocol
   `/keypipe/dgram/1.0.0`, through which **iroh QUIC datagrams** travel in
   `[u16 length][data]` frames.
5. iroh performs the handshake and NAT traversal over this channel. The relay limits
   close the channel by themselves once it has served its purpose.

### `iroh-libp2p/src/swarm.rs`

```rust
use libp2p::{
    identify, identity, kad, noise, relay, swarm::NetworkBehaviour, tcp, yamux,
    Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};

pub const DGRAM_PROTO: StreamProtocol = StreamProtocol::new("/keypipe/dgram/1.0.0");
const AMINO: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    relay_client: relay::client::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    stream: libp2p_stream::Behaviour,
}

pub fn build(seed: &[u8; 32]) -> anyhow::Result<libp2p::Swarm<Behaviour>> {
    // The same Ed25519 key → the PeerId matches the iroh key.
    let key = identity::Keypair::ed25519_from_bytes(*seed)?;

    let swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            let peer_id = key.public().to_peer_id();
            let mut kad = kad::Behaviour::with_config(
                peer_id,
                kad::store::MemoryStore::new(peer_id),
                kad::Config::new(AMINO),
            );
            kad.set_mode(Some(kad::Mode::Client)); // we don't store other people's records
            Behaviour {
                relay_client,
                kad,
                identify: identify::Behaviour::new(identify::Config::new(
                    "/ipfs/id/1.0.0".into(),
                    key.public(),
                )),
                stream: libp2p_stream::Behaviour::new(),
            }
        })?
        .build();

    Ok(swarm)
}

/// Initial Amino nodes. These are IPFS nodes; after the first join the list of
/// discovered peers is cached to disk, and bootstrap is no longer needed.
pub const BOOTSTRAP: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    // + cache of previously discovered peers
];
```

### The logic (sketch) — `iroh-libp2p/src/lib.rs`

```rust
// SERVER
// 1. swarm.dial(BOOTSTRAP…), kad.bootstrap()
// 2. kad.get_closest_peers(random) → candidates; identify shows
//    who supports /libp2p/circuit/relay/0.2.0/hop
// 3. swarm.listen_on(relay_addr.with(Protocol::P2pCircuit)) for 2–3 relays
// 4. on the NewListenAddr event (reservation confirmed):
//      local_addrs ← CustomAddr::from_parts(TRANSPORT_ID, multiaddr.to_vec())
//    iroh will publish them to Mainline along with the other addresses
// 5. renew the reservations before they expire
//
// CLIENT
// 1. get the server's CustomAddr from the Mainline record (iroh does this itself)
// 2. poll_send to a new dst: swarm.dial(multiaddr) →
//    control.open_stream(server_peer, DGRAM_PROTO)
//
// BOTH SIDES
// - control.accept(DGRAM_PROTO) → incoming stream
// - datagram framing: [u16 BE length][QUIC packet]
// - stream ↔ CustomEndpoint::poll_recv / CustomSender::poll_send
//
// ⚠ IMPORTANT: by default libp2p does not open streams over limited
//   (relay) connections — this must be explicitly allowed for DGRAM_PROTO.
// ⚠ The stream is reliable and ordered, while QUIC expects unreliable datagrams —
//   for signaling this is acceptable (little data, short-lived channel).
```

---

## 13. Limitations and open questions

| Question | Risk | What to do |
|---|---|---|
| iroh API pre-1.0, custom transports marked unstable | Code breaks on upgrade | Pin the version, upgrade deliberately |
| Does iroh distinguish a "path for negotiation" from a "path for data" | The `signal` mode may require logic in the transport | Check the sources; the fallback option is described in section 8 |
| Does QUIC NAT traversal in iroh use custom paths as the negotiation channel | This is the key assumption of the whole scheme | **Check first**: prototype on the in-memory transport from the iroh example |
| The yggdrasil-go core as a packet conn by key | The core's internal APIs may change | Pin the yggdrasil-go version; verify raw datagrams get through |
| Relay limits in Kubo | If the limits are small, the handshake may not fit | Measure; if insufficient — several relays in parallel |
| Amino bootstrap via IPFS nodes | Initial entry depends on known addresses | Cache peers; add your own known nodes |
| Publicity of the Mainline record | Home IP becomes visible | Publish only libp2p relay addresses (section 6) |
| Go in the build *(SUPERSEDED in the intended native Rust architecture; the historical ABI sources remain pending removal — see go-abi.md)* | Requires a Go toolchain, increases binary size | Accept; in the future — a Rust implementation of the Yggdrasil protocol |

---

## 14. Roadmap

**Stage 0** (everything together, in risk-check order):

1. **Check the key assumption:** two iroh endpoints, relay disabled,
   in-memory custom transport from the iroh example → confirm that a direct path
   is punched through the custom channel and data migrates to it.
2. **`iroh-yggdrasil`:** Go shim + transport; two nodes behind different NATs
   connected only via Yggdrasil.
3. **`iroh-libp2p`:** join Amino, reserve relays, datagram channel;
   NAT traversal via an IPFS relay.
4. **`keypipe-server` / `keypipe-client`:** Mainline DHT, allowlist, path
   policy, `signal` / `standby` modes.
5. **Trials:** home ↔ mobile internet, home ↔ café, both behind NAT, no IPv6;
   disabling each path in turn.

**Next:** encrypting the DHT record, multiple exposed ports
(`--expose ssh=127.0.0.1:22 --expose web=127.0.0.1:8080`), systemd/OpenRC units,
a Rust implementation of the Yggdrasil protocol instead of the Go shim.
