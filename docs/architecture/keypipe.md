# keypipe — проброс портов по ключу без сетевых интерфейсов

Черновик архитектуры и эскиз кода. Это не готовая программа: имена API в iroh
(до 1.0), rust-libp2p и yggdrasil-go меняются от версии к версии, поэтому всё
помеченное **⚠ проверить** нужно сверить с исходниками выбранных версий.

---

## 1. Идея

Устройство в сети определяется **ключом**, а не IP-адресом. В системе ничего не
настраивается: нет TUN-интерфейсов, нет VPN-маршрутов, нет открытых портов на
роутере, не нужен root.

- **Сервер** держит внутренний сервис на `127.0.0.1` (SSH, веб-панель, бот) и
  «выставляет» этот порт под своим ключом.
- **Клиент** находит сервер по ключу и открывает у себя локальный порт. Всё, что
  приходит на этот порт, попадает во внутренний сервис сервера.

```
  Клиент                                                      Сервер
  ssh -p 2222 127.0.0.1                                       sshd на 127.0.0.1:22
        │                                                            ▲
        ▼                                                            │
  [keypipe connect] ═══ QUIC + TLS, аутентификация по ключам ═══ [keypipe listen]
   127.0.0.1:2222                                               --target 127.0.0.1:22
```

Вся инфраструктура принадлежит сообществам, а не компаниям: инфраструктура n0
(DNS и relay) в iroh **отключена**.

---

## 2. Один ключ — четыре адреса

Все используемые системы работают на **Ed25519**. Поэтому у устройства один
секретный ключ, а все адреса из него вычисляются:

| Где | Адрес | Как получается |
|---|---|---|
| iroh | `EndpointId` | Публичный ключ |
| Mainline DHT (pkarr) | Ключ записи | Тот же публичный ключ |
| Yggdrasil | Адрес узла `200:…` и ключ маршрутизации | Тот же публичный ключ |
| libp2p | `PeerId` | Тот же публичный ключ |

Важное следствие: **адрес сервера в Yggdrasil известен клиенту заранее**, его не
нужно искать. Значит, даже если поиск в DHT не сработал, путь через Yggdrasil
остаётся.

---

## 3. Пути и их роли

Здесь разделяются три функции: **поиск** (где ты), **сигнализация** (договориться
о пробивке NAT) и **данные** (сам трафик).

| Путь | Инфраструктура | Поиск | Сигнализация | Данные |
|---|---|---|---|---|
| **Прямой QUIC** (IPv6, IPv4, LAN, пробитый NAT) | Нет | — | — | ✅ Основной |
| **Mainline DHT** (pkarr) | BitTorrent, ~10 млн узлов | ✅ | ❌ | ❌ |
| **libp2p circuit relay v2** | Публичные узлы IPFS Amino (~25 тыс.) | ✅ (адреса relay) | ✅ | ❌ Только для пробивки |
| **Yggdrasil** (userspace) | Публичные пиры сообщества | Не нужен: адрес = ключ | ✅ | ✅ Запасной |

### Почему libp2p подходит именно для сигнализации

Публичные узлы IPFS (Kubo) по умолчанию работают как **ограниченные relay**
(circuit relay v2): соединение через них ограничено по времени и объёму
(порядка пары минут и ~100 КБ — **⚠ проверить** текущие лимиты Kubo). Для
передачи данных этого мало, а для обмена кандидатами адресов и пробивки NAT —
ровно то, что нужно. Они для этого и задуманы.

### Почему пробивает iroh, а не libp2p

У libp2p есть своя пробивка NAT (DCUtR), но она пробивает **сокет libp2p**.
Нам нужна дыра в NAT для **UDP-сокета iroh**, иначе прямой путь достанется не
тому стеку. Поэтому libp2p и Yggdrasil служат iroh только **каналом**: через них
идут QUIC-пакеты, а iroh в новых версиях выполняет обход NAT внутри самого
QUIC-соединения (multipath + QUIC NAT traversal), используя любой уже
работающий путь как канал согласования.

---

## 4. Как устанавливается соединение

```
 Клиент                                                            Сервер
   │ 1. ключ сервера уже известен (конфиг)                           │
   │                                                                 │ публикует в Mainline:
   │ 2. поиск в Mainline DHT ──────────────────────────────────────► │  - свои IP-адреса
   │    получает IP-адреса и relay-адреса libp2p                     │  - relay-адреса libp2p
   │                                                                 │
   │ 3. параллельно пробует все пути:                                │
   │    ├─ прямой IP ─────────────────────── (если доступен) ───────►│
   │    ├─ libp2p relay ═══ /p2p/RELAY/p2p-circuit/p2p/SERVER ══════►│
   │    └─ Yggdrasil ═══ по ключу сервера, без поиска ══════════════►│
   │                                                                 │
   │ 4. по первому заработавшему пути: TLS-рукопожатие, проверка     │
   │    ключа клиента по allowlist                                   │
   │                                                                 │
   │ 5. QUIC NAT traversal: обмен кандидатами по этому пути,         │
   │    одновременная отправка UDP-пакетов → прямой путь             │
   │                                                                 │
   │ 6. данные идут напрямую;                                        │
   │    libp2p relay закрывается сам (лимиты);                       │
   │    Yggdrasil остаётся в резерве или закрывается (режим ниже)    │
```

---

## 5. Политика путей

**Приоритет для данных:** прямой QUIC → Yggdrasil → (libp2p relay — никогда для
данных).

**Режимы запасных путей** (флаг `--fallback`):

| Режим | libp2p relay | Yggdrasil |
|---|---|---|
| `signal` | Только пробивка | Только пробивка, затем путь закрывается |
| `standby` (по умолчанию) | Только пробивка | Пробивка + резерв: данные идут по нему, если прямого пути нет или он пропал |

**Нюанс: NAT забывает дыры.** Если прямой путь пропал (сменилась сеть, роутер
сбросил отображения), запасные каналы снова нужны для новой пробивки. Поэтому
даже в режиме `signal` транспорты не удаляются из endpoint, а «засыпают»:
- libp2p: при необходимости заново подключается через relay;
- Yggdrasil: узел остаётся в сети, путь открывается снова по требованию.

QUIC keepalive на прямом пути (каждые ~15–25 с) держит дыру в NAT открытой.

---

## 6. Доступ и безопасность

- **Allowlist ключей** на сервере (`allowed.txt`): главный механизм доступа.
  Проверяется после TLS-рукопожатия, где ключ клиента подтверждён криптографически.
- **Внутренний сервис слушает только `127.0.0.1`.**
- **Ключ** — один файл с правами `0600`.
- **Публичность.** Запись в Mainline DHT видят все: в ней IP-адреса сервера и
  его relay-адреса libp2p. Если не хочется публиковать домашний IP, можно
  публиковать **только relay-адреса libp2p**: сигнализация через них, Yggdrasil
  вообще не требует записи. Прямой путь тогда найдётся на шаге пробивки.
- **Защита в два слоя.** Аутентификация в самом сервисе (SSH-ключи) остаётся.
- Промежуточные узлы (relay IPFS, пиры Yggdrasil) видят только зашифрованные
  QUIC-пакеты.

---

## 7. Структура проекта

```
keypipe/                         # cargo workspace
├── Cargo.toml
├── keypipe/                     # бинарники
│   └── src/
│       ├── common.rs            # ключ, allowlist, endpoint, политика путей
│       ├── server.rs
│       └── client.rs
├── iroh-yggdrasil/              # custom transport: Yggdrasil в userspace
│   ├── build.rs                 # собирает Go-прослойку в статическую библиотеку
│   ├── yggshim/                 # Go: тонкая обёртка над ядром yggdrasil-go
│   │   ├── go.mod
│   │   └── shim.go
│   └── src/
│       ├── ffi.rs
│       └── lib.rs
└── iroh-libp2p/                 # custom transport: QUIC-датаграммы через libp2p relay
    └── src/
        ├── swarm.rs
        └── lib.rs
```

### Корневой Cargo.toml

```toml
[workspace]
members = ["keypipe", "iroh-yggdrasil", "iroh-libp2p"]
resolver = "2"

[workspace.dependencies]
iroh   = { version = "0.97", features = ["discovery-pkarr-dht", "unstable-custom-transports"] } # ⚠ актуальная
tokio  = { version = "1", features = ["full"] }
anyhow = "1"
bytes  = "1"
libp2p = { version = "0.55", features = ["tokio", "tcp", "quic", "noise", "yamux",
                                          "kad", "identify", "relay", "macros"] }        # ⚠ актуальная
libp2p-stream = "0.3"                                                                      # ⚠ актуальная
```

---

## 8. Общий код — `keypipe/src/common.rs`

```rust
use std::{collections::HashSet, fs, path::Path, sync::Arc};

use anyhow::{ensure, Context, Result};
use iroh::{
    discovery::dht::DhtDiscovery,                 // ⚠ в новых версиях: address_lookup
    endpoint::{RecvStream, SendStream},
    Endpoint, EndpointId, RelayMode, SecretKey,
};
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub const ALPN: &[u8] = b"keypipe/tcp/0";
/// QUIC-поток виден другой стороне только после первых байтов.
pub const HANDSHAKE: &[u8; 5] = b"kpipe";

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum FallbackMode { Signal, Standby }

/// Один ключ на всё: iroh, pkarr, Yggdrasil, libp2p.
pub fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let bytes: [u8; 32] = fs::read(path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ключ должен быть 32 байта"))?;
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
        .context("не удалось прочитать allowlist")?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.parse::<EndpointId>().context(format!("плохой ключ: {l}")))
        .collect()
}

pub struct Net {
    pub endpoint: Endpoint,
    pub ygg: Arc<iroh_yggdrasil::YggTransport>,
    pub p2p: Arc<iroh_libp2p::Libp2pTransport>,
}

/// Endpoint без инфраструктуры n0, с двумя запасными транспортами.
pub async fn make_net(key: SecretKey, alpns: Vec<Vec<u8>>, mode: FallbackMode) -> Result<Net> {
    let seed = key.to_bytes(); // 32-байтовый seed Ed25519 — общий для всех сетей

    // Yggdrasil в userspace: публичные пиры + multicast в локальной сети.
    let ygg = Arc::new(iroh_yggdrasil::YggTransport::start(
        &seed,
        &[
            "tls://пир-1.example:443", // ⚠ взять 3–5 пиров из yggdrasil-network/public-peers
            "tls://пир-2.example:443",
        ],
    )?);

    // libp2p: вход в IPFS Amino DHT, поиск relay, резервирование слотов.
    let p2p = Arc::new(iroh_libp2p::Libp2pTransport::start(&seed).await?);

    let endpoint = Endpoint::empty_builder(RelayMode::Disabled) // без relay n0, без DNS n0
        .secret_key(key)
        .discovery(DhtDiscovery::builder())                     // Mainline DHT
        .add_custom_transport(ygg.clone())                      // ⚠ проверить имя метода
        .add_custom_transport(p2p.clone())
        .path_selector(PathPolicy { mode })                     // ⚠ проверить API выбора пути
        .alpns(alpns)
        .bind()
        .await?;

    Ok(Net { endpoint, ygg, p2p })
}

/// Политика путей: прямой IP → Yggdrasil → libp2p (никогда для данных).
/// ⚠ ЭСКИЗ: трейт и контекст выбора пути смотри в iroh/examples/custom-transport.rs.
struct PathPolicy { mode: FallbackMode }

impl iroh::endpoint::transports::PathSelector for PathPolicy {
    fn rank(&self, path: &iroh::endpoint::transports::Addr) -> Option<u8> {
        use iroh::endpoint::transports::Addr;
        match path {
            Addr::Ip(_) => Some(0),                                         // всегда лучший
            Addr::Custom(a) if a.id() == iroh_yggdrasil::TRANSPORT_ID => match self.mode {
                FallbackMode::Standby => Some(1),                           // резерв для данных
                FallbackMode::Signal  => None,                              // только согласование
            },
            Addr::Custom(a) if a.id() == iroh_libp2p::TRANSPORT_ID => None, // только согласование
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
    ensure!(&buf == HANDSHAKE, "неверное приветствие");
    Ok(())
}
```

**Замечание о «только для сигнализации».** Если путь недопустим для данных
(`None` в политике), iroh всё равно может использовать его на этапе
установления соединения и согласования прямого пути, но не отправляет по нему
данные приложения, когда есть путь лучше. **⚠ проверить**, что выбранная версия
iroh различает «путь для согласования» и «путь для данных». Если нет, режим
`signal` реализуется в самом транспорте: после того как наблюдатель за
соединением (`conn` paths watcher) увидел подтверждённый прямой путь,
транспорт перестаёт отправлять пакеты этого соединения.

---

## 9. Сервер — `keypipe/src/server.rs`

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
    /// Внутренний сервис, например 127.0.0.1:22
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
    println!("  yggdrasil: {}", net.ygg.address());           // 200:… — из того же ключа
    println!("  libp2p:    {}", net.p2p.peer_id());           // тот же ключ
    println!("  target:    {target}");

    // Ничего не публикуем вручную:
    // - DhtDiscovery публикует в Mainline адреса endpoint и обновляет запись;
    // - libp2p-транспорт сообщает iroh свои relay-адреса как CustomAddr,
    //   и они попадают в ту же запись (⚠ проверить, какие типы адресов
    //   публикуются; размер записи ≤ 1000 байт → не более 2–3 relay-адресов);
    // - Yggdrasil-адрес не публикуется вовсе: клиент вычисляет его из ключа.

    while let Some(incoming) = ep.accept().await {
        let allow = allow.clone();
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, allow, target).await {
                eprintln!("соединение: {e:#}");
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
        eprintln!("отказ: {peer}");
        conn.close(1u32.into(), b"forbidden");
        return Ok(());
    }
    println!("клиент подключён: {peer}");

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
                eprintln!("поток: {e:#}");
            }
        });
    }
    println!("клиент отключён: {peer}");
    Ok(())
}
```

---

## 10. Клиент — `keypipe/src/client.rs`

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
    /// Ключ (EndpointId) сервера
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
    println!("  мой id: {}  ← добавь в allowed.txt на сервере", net.endpoint.id());

    let listener = TcpListener::bind(&args.listen).await?;
    println!("  слушаю: {} → {}", args.listen, args.server);

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

    // Адрес сервера в Yggdrasil вычисляется из его ключа — добавляем сразу.
    // Остальные адреса (IP, relay libp2p) iroh найдёт в Mainline DHT сам.
    let addr = EndpointAddr::new(server)
        .with_custom_addr(iroh_yggdrasil::addr_for(&server)); // ⚠ проверить API

    let c = net.endpoint.connect(addr, ALPN).await?;
    println!("соединение установлено");
    *guard = Some(c.clone());
    Ok(c)
}
```

Запуск:

```bash
# сервер
keypipe-server --target 127.0.0.1:22

# клиент
keypipe-client --server <id_сервера>
ssh -p 2222 user@127.0.0.1
```

---

## 11. Транспорт `iroh-yggdrasil`

### Идея

Ядро yggdrasil-go само по себе работает как **packet conn с адресацией по
публичному ключу**: отправить датаграмму узлу с ключом X, получить датаграмму
от узла с ключом Y. IPv6, TUN и TCP-стек — это надстройки над ним, и они нам
не нужны. Берём только ядро.

Зрелой реализации Yggdrasil на Rust нет, поэтому ядро на Go собирается в
**статическую библиотеку** (`go build -buildmode=c-archive`) и линкуется в Rust.
На выходе один бинарник: без отдельного процесса, без TUN, без root.

### Go-прослойка — `iroh-yggdrasil/yggshim/shim.go`

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

	// ⚠ проверить: в v0.5 core.New принимает TLS-сертификат,
	// построенный из ключа узла (см. config.NodeConfig в yggdrasil-go).
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

// Блокирующий приём: Rust вызывает в отдельном потоке.
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

### Сборка — `iroh-yggdrasil/build.rs`

```rust
fn main() {
    let out = std::env::var("OUT_DIR").unwrap();
    let status = std::process::Command::new("go")
        .args(["build", "-buildmode=c-archive", "-o", &format!("{out}/libyggshim.a"), "."])
        .current_dir("yggshim")
        .status()
        .expect("нужен установленный Go");
    assert!(status.success());

    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static=yggshim");
    println!("cargo:rustc-link-lib=dylib=pthread"); // ⚠ на Linux; на macOS — фреймворки
    println!("cargo:rerun-if-changed=yggshim");
}
```

### Rust-часть — `iroh-yggdrasil/src/lib.rs`

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

/// ⚠ зарезервировать свой id в iroh/TRANSPORTS.md
pub const TRANSPORT_ID: u16 = 0x5947; // "YG"

/// Адрес узла в Yggdrasil = его ключ, поэтому вычисляется без поиска.
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
                        "не удалось запустить Yggdrasil");
        let mtu = unsafe { ffi::ygg_mtu() } as usize;

        // Приём в отдельном OS-потоке: ygg_recv блокирующий.
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

// ⚠ ЭСКИЗ реализации трейтов: сигнатуры строго по
// iroh/src/socket/transports/custom.rs и примеру транспорта Tor.
//
// impl CustomTransport for YggTransport {
//     fn bind(self: Arc<Self>) -> io::Result<Box<dyn CustomEndpoint>> { … }
// }
// impl CustomEndpoint for YggEndpoint {
//     fn local_addrs(&self) -> … { [CustomAddr::from_parts(TRANSPORT_ID, &self.pubkey)] }
//     fn poll_recv(&mut self, cx, bufs, metas, src_addrs) -> Poll<io::Result<usize>> {
//         // взять (src, pkt) из self.rx, src → CustomAddr::from_parts(TRANSPORT_ID, &src)
//     }
//     fn create_sender(&self) -> Arc<dyn CustomSender> { … }
// }
// impl CustomSender for YggSender {
//     fn poll_send(&self, cx, dst: &CustomAddr, transmit) -> Poll<io::Result<()>> {
//         // dst.data() → 32 байта ключа → self.send(...)
//     }
// }

impl Drop for YggTransport {
    fn drop(&mut self) { unsafe { ffi::ygg_stop() } }
}
```

---

## 12. Транспорт `iroh-libp2p`

### Идея

1. Узел libp2p с **тем же ключом** входит в **IPFS Amino DHT** (Kademlia,
   протокол `/ipfs/kad/1.0.0`).
2. **Сервер** находит публичные relay-узлы (Kubo с relay v2), резервирует у
   2–3 из них слот и получает адреса вида
   `/ip4/…/p2p/RELAY/p2p-circuit/p2p/SERVER`.
   Эти адреса уходят в iroh как `CustomAddr` и публикуются в Mainline.
3. **Клиент** подключается к серверу по relay-адресу.
4. По этому соединению открывается поток с протоколом
   `/keypipe/dgram/1.0.0`, через который идут **QUIC-датаграммы iroh** в
   кадрах `[u16 длина][данные]`.
5. iroh выполняет по этому каналу рукопожатие и пробивку NAT. Лимиты relay
   закрывают канал сами, когда он отработал.

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
    // Тот же Ed25519-ключ → PeerId совпадает с ключом iroh.
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
            kad.set_mode(Some(kad::Mode::Client)); // не храним чужие записи
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

/// Начальные узлы Amino. Это узлы IPFS; после первого входа список
/// найденных пиров кешируется на диск, и дальше bootstrap не нужен.
pub const BOOTSTRAP: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    // + кеш ранее найденных пиров
];
```

### Логика (эскиз) — `iroh-libp2p/src/lib.rs`

```rust
// СЕРВЕР
// 1. swarm.dial(BOOTSTRAP…), kad.bootstrap()
// 2. kad.get_closest_peers(random) → кандидаты; identify показывает,
//    кто поддерживает /libp2p/circuit/relay/0.2.0/hop
// 3. swarm.listen_on(relay_addr.with(Protocol::P2pCircuit)) для 2–3 relay
// 4. на событие NewListenAddr (резервирование подтверждено):
//      local_addrs ← CustomAddr::from_parts(TRANSPORT_ID, multiaddr.to_vec())
//    iroh опубликует их в Mainline вместе с остальными адресами
// 5. резервирования продлевать до истечения
//
// КЛИЕНТ
// 1. получить CustomAddr сервера из записи Mainline (iroh делает сам)
// 2. poll_send на новый dst: swarm.dial(multiaddr) →
//    control.open_stream(server_peer, DGRAM_PROTO)
//
// ОБЕ СТОРОНЫ
// - control.accept(DGRAM_PROTO) → входящий поток
// - кадрирование датаграмм: [u16 BE длина][пакет QUIC]
// - поток ↔ CustomEndpoint::poll_recv / CustomSender::poll_send
//
// ⚠ ВАЖНО: по умолчанию libp2p не открывает потоки поверх ограниченных
//   (relay) соединений — для DGRAM_PROTO это нужно явно разрешить.
// ⚠ Поток надёжный и упорядоченный, а QUIC ждёт ненадёжные датаграммы —
//   для сигнализации это приемлемо (данных мало, канал короткий).
```

---

## 13. Ограничения и открытые вопросы

| Вопрос | Риск | Что делать |
|---|---|---|
| API iroh до 1.0, custom transports помечены нестабильными | Код сломается при обновлении | Зафиксировать версию, обновлять осознанно |
| Различает ли iroh «путь для согласования» и «путь для данных» | Режим `signal` может потребовать логики в транспорте | Проверить в исходниках; запасной вариант описан в разделе 8 |
| Использует ли QUIC NAT traversal в iroh custom-пути как канал согласования | Это ключевое допущение всей схемы | **Проверить первым**: прототип на in-memory транспорте из примера iroh |
| Ядро yggdrasil-go как packet conn по ключу | Внутренние API ядра могут меняться | Зафиксировать версию yggdrasil-go; проверить, что сырые датаграммы доходят |
| Лимиты relay в Kubo | Если лимиты малы, рукопожатие может не уложиться | Измерить; при нехватке — несколько relay параллельно |
| Bootstrap Amino через узлы IPFS | Начальный вход зависит от известных адресов | Кешировать пиров; добавить свои известные узлы |
| Публичность записи в Mainline | Виден домашний IP | Публиковать только relay-адреса libp2p (раздел 6) |
| Go в сборке | Нужен тулчейн Go, растёт размер бинарника | Принять; в будущем — Rust-реализация протокола Yggdrasil |

---

## 14. Дорожная карта

**Этап 0** (всё вместе, но в порядке проверки рисков):

1. **Проверка ключевого допущения:** два iroh-endpoint, relay отключён,
   in-memory custom transport из примера iroh → убедиться, что прямой путь
   пробивается через custom-канал и данные переходят на него.
2. **`iroh-yggdrasil`:** Go-прослойка + транспорт; соединение двух узлов
   за разными NAT только через Yggdrasil.
3. **`iroh-libp2p`:** вход в Amino, резервирование relay, канал датаграмм;
   пробивка NAT через relay IPFS.
4. **`keypipe-server` / `keypipe-client`:** Mainline DHT, allowlist, политика
   путей, режимы `signal` / `standby`.
5. **Испытания:** дом ↔ мобильный интернет, дом ↔ кафе, оба за NAT, без IPv6;
   выключение каждого пути по очереди.

**Дальше:** шифрование записи в DHT, несколько выставленных портов
(`--expose ssh=127.0.0.1:22 --expose web=127.0.0.1:8080`), юниты
systemd/OpenRC, Rust-реализация протокола Yggdrasil вместо Go-прослойки.
