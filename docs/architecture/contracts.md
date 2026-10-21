# Внешние контракты Sha’ar Stack (P01)

Дата: 2026-10-21. Статус: исследование, реализация не начата.
Локальные сборки/тесты не выполнялись.

Каждый факт помечен уровнем достоверности:
- **прочитано в исходнике** — чтением исходников указанного тега/файла
  (с полным URL); без полного URL тега факт таковым не считается;
- **требует CI/P03-эксперимента** — подлежит обязательному запуску/эксперименту;
- **неподтверждено** — не проверено чтением и не проверено запуском;
  не использовать как основание контракта.

## 1. Первичный набор версий

- iroh **1.3.0** — метаданные версии подтверждены чтением Cargo.toml тега
  v1.3.0 (`https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/Cargo.toml`):
  `package.version = 1.3.0`, `edition = 2024`, `rust-version = 1.91`,
  лицензия MIT OR Apache-2.0; зависимости `noq`/`noq-proto`/`noq-udp`
  = 1.3.0; feature `qlog = ["noq/qlog"]`; присутствует feature
  `unstable-custom-transports`. Дата публикации на crates.io — не проверена.
  Первичный выбор; возраст не является доказательством стабильности.
  Свежайшая версия — 1.4.1, НЕ выбрана. Переход на 1.4.1 не выполнять
  без явного решения. Feature `unstable-custom-transports` обязателен.
- libp2p **0.57.1** (tag v0.57.1 =
  commit `2fed78f074af91e0c7440eedd08b8f898ad4a3fe`, MIT, MSRV 1.88,
  подтверждено `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/Cargo.toml`)
  + **libp2p-stream 0.5.0-alpha** (workspace-версия подтверждена
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/protocols/stream/Cargo.toml`);
  даты публикации crates.io не проверены. Совместимость подтверждена
  dependency-требованиями: оба требуют libp2p-core ^0.44.0 и
  libp2p-swarm ^0.48.0. Внимание: libp2p-stream 0.5.0-alpha — пре-релиз;
  альтернатива — libp2p 0.56.0 + libp2p-stream 0.4.0-alpha
  (решить на P02, после выбора не повышать).
- yggdrasil-go **v0.5.14** (tag, commit `422836eeb21a99790caa286aa63d493bbc4766d7`;
  go.mod требует go 1.25.0; зависимость Arceliar/ironwood pinned
  `d50055b11f5e` от 2026-06-13). Лицензия: **LGPLv3 со специальным
  исключением** — статическая линковка в Combined Work разрешена без
  раскрытия кода приложения при соблюдении LGPL (LICENSE, тег v0.5.14).
- ktav **0.8.0** (repo ktav-lang/rust, tag v0.8.0; метаданные подтверждены
  `https://raw.githubusercontent.com/ktav-lang/rust/v0.8.0/Cargo.toml`:
  version 0.8.0, spec-version 0.8.0, rust-version 1.71, MIT OR Apache-2.0;
  serde-native; дата публикации crates.io не проверена). Формат = Ktav spec
  0.8.0 (ktav-lang/spec).
- Toolchain: Rust stable >= 1.91 (MSRV iroh), Go >= 1.25.0.
  Целевые ОС: Windows (amd64) и Linux (amd64).

## 2. iroh 1.3.0 — custom transport, пути, отключение n0

Прочитано в исходнике тега v1.3.0:

- Трейты (`https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/socket/transports/custom.rs`):
  `CustomTransport: Debug + Send + Sync + 'static`:
  `fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>>`;
  `CustomEndpoint: Debug + Send + Sync + 'static`:
  `poll_recv(&mut self, cx: &mut Context, bufs: &mut [io::IoSliceMut<'_>],
  metas: &mut [noq_udp::RecvMeta], recv_infos: &mut [RecvInfo])
  -> Poll<io::Result<usize>>`,
  `watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>>`,
  `create_sender(&self) -> Arc<dyn CustomSender>`,
  `max_transmit_segments(&self) -> NonZeroUsize`
  (default `NonZeroUsize::MIN`);
  `CustomSender: Debug + Send + Sync + 'static`:
  `is_valid_send_addr(&self, &CustomAddr) -> bool`,
  `poll_send(&self, cx: &mut Context, dst: &CustomAddr,
  src: Option<&CustomAddr>, transmit: &Transmit<'_>)
  -> Poll<io::Result<()>>`. Экспорт только при feature
  `unstable-custom-transports`.
- Выбор пути: `PathSelector::select(&PathSelectionContext) -> PathSelection`
  (подтверждено в примере
  `https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/examples/custom-transport.rs`);
  трейты `PathSelector`/`PathSelectionContext`/`PathSelection` живут в
  `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/socket/remote_map/remote_state.rs`
  (внутренний модуль `socket/remote_map`, не `endpoint`).
  В `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/socket/biased_rtt_path_selector.rs`
  селектор по умолчанию для custom-транспорта — PRIMARY без RTT-bias,
  поэтому явная политика путей необходима (файл существует в дереве v1.3.0).
  `PathSelection::none()` означает отсутствие НОВОГО выбора пути,
  а НЕ запрет передачи данных по пути: правило «none → keep-current»
  видно в селекторе (текущий лучший путь сохраняется, `set` не
  вызывается). Местонахождение path_watcher подтверждено в дереве тега
  v1.3.0: `iroh/src/socket/remote_map/remote_state/path_watcher.rs` и
  `iroh/src/socket/biased_rtt_path_selector.rs`
  (`https://github.com/n0-computer/iroh/tree/v1.3.0/iroh/src/socket/remote_map/remote_state/`)
  — это местонахождение исходника, НЕ доказательство поведения;
  поведение — P03. Наблюдения `conn.paths()`,
  `path.is_selected()`, `path.rtt()` — из примера v1.3.0.
- TRANSPORTS.md существует и в v1.3.0, содержимое подтверждено чтением:
  `https://github.com/n0-computer/iroh/blob/v1.3.0/TRANSPORTS.md` —
  кастомные id адресов: 0x00–0x1F зарезервированы, 0x20 test,
  0x544F52 Tor (experimental), 0x424C45 BLE (reserved).
  Регистрация нового id — PR в iroh; локальный неспорный id допустим,
  риск коллизии.
- Отключение n0: пресеты (`https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/endpoint/presets.rs`):
  `Minimal` — только crypto provider, БЕЗ n0 lookup и релеев;
  `N0` — DNS publish/resolve iroh.link + default_relay_mode + crypto
  provider; `N0DisableRelay` — N0 + RelayMode::Disabled, ВНИМАНИЕ:
  оставляет n0 DNS lookup — для полного отключения n0 НЕ подходит.
  Пустой builder — «Creates an empty builder with no address lookup
  services, and [RelayMode::Disabled]»
  (`https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/endpoint.rs`).
  Правильный способ: `Endpoint::builder(presets::Minimal)` (или Empty +
  свой crypto_provider) и свои address_lookup/транспорты.
  `clear_ip_transports()` НЕ использовать для отключения n0:
  он снимает и нужный прямой UDP-путь.
- pkarr/Mainline: в крейте iroh 1.x mainline-DHT lookup НЕ входит
  (feature `address-lookup-pkarr-dht` существовал только в 0.98.x;
  в 1.x features его нет; n0_mainline используется в iroh-dns-server).
  Пресет N0 публикует/резолвит только в n0 DNS (pkarr relay).
  НО: `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/address_lookup.rs`
  прямо указывает, что Mainline-DHT Address Lookup живёт в отдельном
  крейте `iroh-mainline-address-lookup` (docs:
  `https://docs.rs/iroh-mainline-address-lookup`). По индексу crates.io
  (`https://index.crates.io/ir/oh/iroh-mainline-address-lookup`)
  существуют версии 0.5.0, 0.6.0, 0.6.1, `rust-version = 1.91`,
  обычная зависимость iroh ^1.0.0 (default-features = false) —
  совместимый кандидат с iroh 1.3. Существование крейта подтверждено;
  поиск репозитория на GitHub обычного repo не дал (только blinded-вариант),
  что НЕ доказывает отсутствие опубликованного крейта.

### 2.1. Mainline-адаптер — исследованный результат (источники прочитаны (по предоставленным URL))

Репозиторий: `https://github.com/n0-computer/iroh-address-lookups`,
тег `iroh-mainline-address-lookup-v0.6.1` = commit
`0f5f547cc65514e4537d4e66f776319ea8e30a2e`.
Источники:
`https://raw.githubusercontent.com/n0-computer/iroh-address-lookups/iroh-mainline-address-lookup-v0.6.1/iroh-mainline-address-lookup/Cargo.toml`,
`https://raw.githubusercontent.com/n0-computer/iroh-address-lookups/iroh-mainline-address-lookup-v0.6.1/iroh-mainline-address-lookup/README.md`,
`https://raw.githubusercontent.com/n0-computer/iroh-address-lookups/iroh-mainline-address-lookup-v0.6.1/iroh-mainline-address-lookup/src/lib.rs`.

- Cargo: version 0.6.1, MSRV 1.91, MIT OR Apache-2.0; iroh ^1.0.0
  (default-features = false), iroh-base ^1.0.0 (features key+relay),
  iroh-dns 1.0.0, n0-mainline 0.7. ПЕРВИЧНЫЙ выбор: адаптер 0.6.1 +
  iroh 1.3.0, без повышения iroh; совместимость подтверждена диапазонами
  зависимостей, фактическая компиляция — только CI.
- Builder API (прочитано в src/lib.rs): `DhtAddressLookup::builder()`,
  `.dht_builder(DhtBuilder)`, `.secret_key(SecretKey)`, `.ttl(u32)`,
  `.republish_delay(Duration)`, `.no_publish()`,
  `.addr_filter(AddrFilter)`, `.build() -> Result`; реализует
  `AddressLookupBuilder`, при подключении получает
  `endpoint.secret_key().clone()`. Дефолты: enable_publish = true,
  addr_filter = relay_only(), ttl = 30 c, republish = 3600 c;
  обновления заменяют `AbortOnDropHandle` задачи публикации,
  debounce 50 ms. Через `n0_mainline::Dht` —
  get_mutable_most_recent/put_mutable, БЕЗ обязательных n0 HTTP/DNS relay.
- ВАЖНО: `relay_only()` фильтрует `IROH TransportAddr::Relay`,
  а НЕ наши libp2p CustomAddr circuit-relay → нужен явный `AddrFilter`
  с допустимыми custom/IP адресами по политике; НЕ использовать
  `presets::N0` и не добавлять HTTP pkarr relay.
- Остаются gate: bootstrap DHT-инфраструктуры и фактическое отсутствие
  n0-сетевых запросов проверяются P02/P09 + CI; не заявлять полное
  свойство лишь из названия.

### 2.2. Custom-сериализация и бюджет (источники прочитаны (по предоставленным URL))

- Источник:
  `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh-dns/src/endpoint_info.rs` —
  `endpoint_info_to_attrs`: Relay → `relay=url`, Ip → `addr=socket`,
  Custom → `addr=CustomAddr::to_string`; `endpoint_info_from_attrs`
  пробует `SocketAddr::from_str`, иначе `CustomAddr::from_str`;
  malformed записи пропускаются; `EndpointInfo::to_pkarr_signed_packet`
  → `attrs.to_pkarr_signed_packet`. Вывод: API сериализации
  custom-адресов поддержан; фактический round-trip конкретных libp2p
  multiaddr и размеров — тест P09.
- Источник:
  `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh-dns/src/pkarr.rs` —
  `MAX_DNS_PACKET_SIZE = 1000`; `HEADER_SIZE = 104`
  (pubkey 32 + sig 64 + timestamp 8); `MAX_SIGNED_PACKET_SIZE = 1104`.
  Формат signed packet: <pubkey32><signature64><timestamp8 BE><DNS>.
  Mainline-адаптер кладёт в MutableItem `packet.encoded_packet()`
  (DNS-часть ≤ 1000), signature/key/seq отдельно — НЕЛЬЗЯ требовать
  весь signed packet ≤ 1000. Переполнение при разборе → PacketTooLarge
  (from_txt_strings).
- Правило для нас: при ошибке сериализации адаптер логирует и НЕ
  публикует → заранее выбирать помещающийся набор custom-адресов и
  наблюдать отказ публикации, а не молча считать «2–3 адреса всегда
  помещаются».
- `from_parts_unchecked` в резолвере не является автоматическим
  доказательством проверки подписи/свежести всей цепочки: верификация
  n0-mainline и freshness — негативные контролы P09, не безусловное
  доверие.

- Signaling-only: понятия «путь только для согласования» в
  исследованных файлах API v1.3.0 НЕ обнаружено; production-гейт
  signaling-only в них не найден, однако категорическое «в iroh его нет»
  не заявлять — полный анализ кода миграции/запрета ещё не выполнен;
  отсутствие подтверждённого гейта = **требует P03-эксперимента**
  (см. `../verification/scenarios.md`).
  `PathSelection` выбирает пути для данных; пример v1.3.0 показывает работу
  purely на custom transport, но обмен
  кандидатами NAT traversal через custom-путь с переходом на прямой UDP
  — **неподтверждено**.
  Остановка `poll_send` после появления direct — НЕ доказательство
  и НЕ решение контракта.
  Если P03 покажет невозможность — стоп-условие для зависимых этапов
  (development.md 4.2), варианты решения вынести пользователю.

## 3. libp2p 0.57.1 — relay v2, резервирование, продление

Прочитано в исходнике тега v0.57.1 (`https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/relay/src/behaviour.rs`,
`https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/relay/src/priv_client.rs`,
`https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/relay/src/priv_client/handler.rs`):

- Лимиты relay-сервера по умолчанию (rust-сервер): max_reservations=128,
  max_reservations_per_peer=4, reservation_duration=3600 c,
  max_circuits=16, max_circuits_per_peer=4, max_circuit_duration=120 c,
  max_circuit_bytes=131072 (128 KiB); rate limiters: 30 резерваций/час
  на peer, 60/час на IP (и то же для circuits). Лимиты ПУБЛИЧНЫХ
  Kubo/Amino-узлов могут отличаться и НЕ подтверждены — не считать, что
  слот доступен по факту объявления протокола hop
  (behaviour.rs `Config::default`).
- Клиент: резервирование инициируется `listen_on` на адресе
  `/…/p2p/RELAY/p2p-circuit/p2p/SELF` (priv_client.rs poll → ListenReq →
  handler::In::Reserve); подтверждение — событие
  `Event::ReservationReqAccepted { relay_peer_id, renewal, limit }`;
  продление фиксируется тем же событием с `renewal: true`.
  Продление (прочитано в исходнике
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/protocols/relay/src/protocol/outbound_hop.rs`):
  `make_reservation` получает из wire `reservation.expire` (unixsecs),
  вычисляет `remaining = expire − now` (checked_sub), затем
  `renewal = remaining − remaining/4` и `Duration::from_secs` → `Delay`.
  ИТОГ: сервер сообщает expiration; КЛИЕНТ вычисляет delay продления
  ≈ 3/4 остаточного срока (remaining − floor(remaining/4)).
  Механизм handler Accepted → Renewing остаётся как описано.
- Открытие потоков: libp2p-stream 0.5.0-alpha
  (`https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/stream/src/control.rs`):
  `Control::open_stream(&mut self, peer: PeerId, protocol: StreamProtocol)
  -> Result<Stream, OpenStreamError>` — при отсутствии соединения САМ
  делает dial (док-текст: «In case we are currently not connected to the
  peer, we will attempt to make a new connection»);
  `Control::accept(&mut self, protocol) -> Result<IncomingStreams,
  AlreadyRegistered>`; `OpenStreamError { UnsupportedProtocol, Io }`,
  `#[non_exhaustive]`; `Control` — Clone. Открытие потоков поверх
  relayed-соединения НЕ запрещено кодом: в
  `https://github.com/libp2p/rust-libp2p/blob/v0.57.1/protocols/stream/src/behaviour.rs`
  (handle_established_inbound/outbound_connection) НЕТ проверки
  `is_relayed` — потоки работают на любом установленном соединении,
  включая relayed (прочитано в исходнике). Дополнительно прочитаны
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/protocols/stream/src/handler.rs`
  (listen_protocol и outbound `SubstreamProtocol::new`; ни `is_relayed`,
  ни `allow_limited` нет) и
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/swarm/src/handler.rs`
  (`SubstreamProtocol`: upgrade/info/timeout, default 10 c, `with_timeout`;
  отдельного поля allow_limited нет). Статический вывод: механизм открытия
  потоков не имеет ограничений на relayed-соединения на этом уровне.
  Фактическая интеграция с реальным relay (Kubo) и работоспособность
  на truly limited connections — **требует CI/P03-эксперимента**;
  не заявлять, что работоспособность всех limited connections доказана.
- PeerId: `libp2p_identity::PublicKey::to_peer_id()` — multihash-обёртка,
  НЕ сырые байты ключа (см. раздел 6).

## 4. yggdrasil-go v0.5.14 — ядро и FFI-контракт

Прочитано в исходнике тега v0.5.14
(`https://github.com/yggdrasil-network/yggdrasil-go/blob/v0.5.14/src/core/core.go`):

- `core.New(cert *tls.Certificate, logger Logger, opts ...SetupOption)
  (*Core, error)`: обязателен сертификат с ed25519.PrivateKey (иначе
  ошибка); генерирует TLS-конфиг и `iwe.NewPacketConnWithPassword(secret,
  groupPassword, WithBloomTransform(SubnetForKey…),
  WithPeerMaxMessageSize(131070), WithPathNotify(…))`.
- Датаграммы по ключу: `ReadFrom(p []byte) (n, from net.Addr, err)`
  возвращает `iwt.Addr` = 32 байта публичного ключа отправителя;
  `WriteTo(p, addr)` принимает тот же адрес; внутрь добавляется байт типа
  sessionTraffic. TUN/TCP-стек не нужны — подтверждено.
- `MTU() uint64` = PacketConn.MTU() − 1, cap 65535. `Stop()` — штатное
  завершение (phony.Block → cancel, links.shutdown, Close). `ReadFrom`
  блокирующий → приём только в отдельном OS-потоке (правило 7 CLAUDE.md).
  `SetPathNotify(func(ed25519.PublicKey))` — уведомление о появлении пути
  к ключу.
- Адресация из ключа (прочитано в исходнике
  `https://raw.githubusercontent.com/yggdrasil-network/yggdrasil-go/v0.5.14/src/address/address.go`):
  `AddrForKey` проверяет длину 32, ИНВЕРТИРУЕТ все 256 бит pubkey,
  считает число ведущих единиц до первого нуля; байт 0 адреса = 0x02,
  байт 1 = счётчик ведущих единиц, остальные 14 байт = последующие
  биты инвертированного ключа после ведущих единиц и первого нуля
  (усечение). ЭТО НЕ ХЭШ. `GetKey` возвращает частичный ключ,
  не полную инверсию pubkey; префикс Subnet = 0x03. Обратимость
  Ygg-IPv6 в полный ключ НЕ заявлять. Тест-векторы фиксируются на P04.
- FFI: Go-прослойка собирается `go build -buildmode=c-archive`.
  Статическая поддержка buildmode подтверждена чтением
  `https://raw.githubusercontent.com/golang/go/go1.25.0/src/internal/platform/supported.go`:
  функция `BuildModeSupported` возвращает `true` для
  `-buildmode=c-archive` на windows (распознанные arch) и linux/amd64.
  Это именно статическая поддержка buildmode; фактическая cross-language
  линковка — отдельно CI. Платформенный выбор: на Windows — совместимый
  GNU/MinGW путь: Rust `x86_64-pc-windows-gnu` + Go windows/amd64 + gcc;
  вариант MSVC-ABI spike — отдельное решение, MSVC-совместимость
  сейчас НЕ заявлять. Окончательный выбор — P02 по CI;
  Windows молча не исключать. Linux: `x86_64-unknown-linux-gnu` +
  gcc/ld.
- Ownership cgo (прочитано
  `https://raw.githubusercontent.com/golang/go/go1.25.0/src/cmd/cgo/doc.go`,
  раздел Passing pointers): Go-указатель pin на время вызова;
  C/Rust-указатели не сохранять после возврата; не хранить Go-указатели
  в памяти C без pin; `cgo.Handle` — для непрозрачного идентификатора;
  `cgocheck=1` по умолчанию, `GOEXPERIMENT=cgocheck2` — только CI.
  Это правила, не proof всей обёртки. C.GoBytes копирует, паники Go
  не должны пересекать ABI (recover на границе).
- Threading/lifecycle (прочитано в ironwood
  `https://raw.githubusercontent.com/Arceliar/ironwood/d50055b11f5e/types/packetconn.go`
  — interface embeds net.PacketConn;
  `https://raw.githubusercontent.com/Arceliar/ironwood/d50055b11f5e/network/packetconn.go`
  — ReadFrom: select по closed/readDeadline/recv, Close закрывает closed
  под closeMutex;
  `https://raw.githubusercontent.com/Arceliar/ironwood/d50055b11f5e/encrypted/packetconn.go`
  — ReadFrom вызывает network.read() и ждёт `<-network.readCh`,
  WriteTo проверяет closed/addr/MTU и копирует пакет;
  `https://raw.githubusercontent.com/Arceliar/ironwood/d50055b11f5e/encrypted/network.go`
  — readloop при ошибке underlying ReadFrom закрывает closed (если
  IsClosed) и отправляет одну ошибку в readCh):
  сериализовать всё одной очередью, включая блокирующий recv, НЕЛЬЗЯ —
  Stop/WriteTo зависли бы за recv. Предварительный lifecycle-контракт:
  один приёмный worker-thread на recv; ОТДЕЛЬНЫЙ control/stop путь
  (admission stop, запрет новых операций); освобождение handle после
  прекращения всех вызовов и завершения recv. Точная безопасность
  конкурентных ReadFrom/Stop и передача handle доказываются в P07
  чтением исходников и CI; тест не заменяет SAFETY-обоснование.
  Требования Debug+Send+Sync у CustomTransport (iroh) не означают
  unsafe impl на Go Core: thread-safe очередь/opaque-handle адаптер
  можно сделать без raw-pointer Send/Sync, способ не обещать без proof.
  go.mod подтверждён:
  `https://raw.githubusercontent.com/yggdrasil-network/yggdrasil-go/v0.5.14/go.mod`
  (go 1.25.0, ironwood v0.0.0-20260613025018-d50055b11f5e); LICENSE —
  LGPLv3 со special exception (статическая/динамическая линковка
  Combined Work без Minimal Corresponding Source / Application Code
  по 4d/4e при соблюдении остальной LGPL; без юридических гарантий).
  Полный текст LICENSE:
  `https://raw.githubusercontent.com/yggdrasil-network/yggdrasil-go/v0.5.14/LICENSE`.

## 5. ktav 0.8.0 — синтаксис и API

Прочитано README и Cargo.toml тега v0.8.0
(`https://github.com/ktav-lang/rust/blob/v0.8.0/README.md`,
`https://raw.githubusercontent.com/ktav-lang/rust/v0.8.0/README.md`,
`https://raw.githubusercontent.com/ktav-lang/rust/v0.8.0/Cargo.toml`):

- Синтаксис: неявный корневой объект; `key: value` (точки в ключе =
  вложенность; кавычки отключают), `key:: value` — литеральная строка;
  `##`-комментарии (только полные строки); inline-компаунды только пустые
  `{}` / `[]`; непустые `{ ... }` / `[ ... ]` — многострочные, закрывающая
  скобка на своей строке; многострочные строки `( … )` (strip) и
  `(( … ))` (verbatim); booleans/null строго lowercase; числа типизируются
  лексически (Integer/Float с канонизацией; `01234` — строка).
- API: `ktav::from_str/from_file` (serde Deserialize),
  `to_string/to_file`, `parse/parse_strict` (Value), `parse_events`
  (без дерева), `format_str`, `render::render`. Ошибки:
  `Error::Structured(ErrorKind{…})` со span/path; варианты:
  MissingSeparatorSpace, InvalidTypedScalar, DuplicateKey,
  KeyPathConflict, EmptyKey, InvalidKey, UnclosedCompound,
  UnbalancedBracket, InlineNonEmptyCompound, MissingSeparator,
  LossyScalar (strict), Other; `#[non_exhaustive]`. Наличие функции
  `parse_strict` и её поведение на числах вида `1.10`, а также поведение
  serde при unknown-fields, проверяется по реальному parser/serde API
  в P05; наличие функции ≠ решение политики пользовательских чисел.
  Пользовательское требование — ktav 0.8.*, без дополнительной
  strict-mode surface; P05 определит минимальную схему без новых
  режимов. В README заявлен serde round-trip,
  но поведение при неизвестных полях в README явно НЕ описано —
  **неподтверждено, тест на P05** (deny_unknown_fields/ignore — решение
  схемы); противоречия README не считать доказанными.
- В прочитанном README v0.8.0 заявлено, что формат не поддерживает:
  inline непустые компаунды, якоря/алиасы, includes, корневые массивы
  (долгосрочную гарантию формата не заявлять; сверять с фактическим
  API на P05).

## 6. Ключи и адреса

Один Ed25519 seed (32 байта) → ed25519 приватный ключ. Точный статический
контракт:

- iroh (прочитано
  `https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh-base/src/key.rs`):
  `SecretKey::from_bytes(&[u8;32])` через
  `ed25519_dalek::SigningKey::from_bytes`; `public()` → 32 байта
  `verifying_key().to_bytes()`; `to_bytes() -> [u8;32]`;
  `EndpointId` = pubkey.
- Yggdrasil: адрес = `address.AddrForKey(pubkey)`, адрес из диапазона
  200::/7 (алгоритм — раздел 4; не хэш, обратимость в полный ключ
  НЕ заявлять).
- libp2p (прочитано
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/identity/src/generated/keys.proto`):
  `PublicKey { Type = field 1 (enum Ed25519 = 1), Data = field 2 (bytes) }`;
  для 32-байтного ключа protobuf = `08 01 12 20 || pubkey` (36 байт).
  Прочитано
  `https://raw.githubusercontent.com/libp2p/rust-libp2p/v0.57.1/identity/src/peer_id.rs`:
  identity multihash (code 0x00), если protobuf ≤ 42 байт;
  PeerId bytes = `00 24 08 01 12 20 || pubkey`; отображение base58btc.
  Это статический алгоритм, прочитано в исходнике; исполнение
  тест-векторов — P04/CI.
- pkarr: запись подписывается тем же Ed25519-ключом; формат и точные
  источники сериализации описаны в разделе 2.2. Проверки подписей
  и отрицательные тест-векторы всей цепочки — P09.

Тест-векторы — P04, зафиксировать формулы по указанным источникам.

## 7. Открытые вопросы и стоп-условия

- NAT traversal через custom transport + запрет STREAM на signaling-only:
  неподтверждено, блокирующий эксперимент P03 (условия остановки —
  development.md 4.2). Отдельный пункт матрицы P03: проверить
  доступность oracle-механизма (test-only trace-хук до шифрования
  или декодирование захваченного трафика) — см.
  `../verification/scenarios.md`, раздел 1.
- Лимиты публичных Amino/Kubo relay и наличие свободных слотов: неизвестно;
  зависит от инфраструктуры, тестировать на собственном relay + отдельный
  smoke публичной сети.
- c-archive windows/amd64 и linux/amd64: ранний CI-проверка (P02/P03);
  блокер → решение пользователя, не молча.

Реальные оставшиеся gate:

- NAT traversal + signaling-only (P03).
- Доступность decoded-frames/path-oracle + позитивная калибровка (P03).
- Фактическая cross-language линковка c-archive (CI).
- SAFETY конкурентных ReadFrom/Stop (P07).
- Исполнение тест-векторов (P04).
- Фактический parser/serde API ktav и политика конфигов (P05).
- Фактический round-trip multiaddr/бюджет и негативные контролы
  верификации Mainline (P09).
- Bootstrap DHT и отсутствие n0-запросов (P02/P09 + CI).
- Лимиты публичных Amino/Kubo.
