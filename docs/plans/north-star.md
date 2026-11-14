# North star

This file is the fixed goal of the project. It is imported by `CLAUDE.md`, so it is
loaded into every session and after every context compaction. Only the user changes
its scope; every change is recorded in the decision log below with date and quote.

## Goal

A device is identified by one Ed25519 key. Any device can reach a service on any
other device by that key alone: no IP address, no TUN or VPN, no root, no router
port forwarding, no n0 infrastructure. The aim is a very efficient solution built
from the strengths of four existing peer-to-peer networks, without Tor-style
anonymization overhead.

## End-to-end scenario (the measure of progress)

1. The server publishes a signed address record under its key in the Mainline DHT.
2. The client is configured with the server key only.
3. The client resolves the record and tries direct QUIC to the published addresses.
4. If direct paths fail, the client negotiates through libp2p (signaling only) and
   hole-punches; direct QUIC has data priority.
5. If UDP/QUIC is blocked, the client uses the Yggdrasil path derived from the same
   key. Yggdrasil carries negotiation in `signal` mode and payload fallback in
   `standby` mode.
6. The server checks the client key against its allowlist, then forwards the stream
   to one fixed internal TCP service. A disallowed client causes no target connection.

Every task must name the step it advances. A task that advances none is out of scope.

## Four networks, one key

| Network | Strength | Role |
|---|---|---|
| iroh / QUIC | Fast encrypted direct path, NAT hole punching, stream multiplexing | Primary data path |
| Mainline DHT | Large serverless network, lookup by key | Publish and resolve signed address records |
| libp2p (relay, Amino) | Mature signaling and relay machinery | Negotiation only; never application data |
| Yggdrasil | Global mesh, address derived from the key, works where UDP/QUIC is cut | Blockade resilience and DHT-failure fallback |

Each network covers another's weakness. The synergy is realized by path policy (P10):
find, negotiate, choose the fastest available path, fail over under blocking.

## Efficiency criteria (agreed with the user on 2026-11-05, balanced profile)

Measured in a controlled CI fixture, never on the public network; 95th percentile
unless stated.

- Time from "client knows the key" to the first forwarded byte on a direct path:
  at most 3 s with a known address, at most 10 s with a cold DHT lookup.
- Failover time to Yggdrasil under controlled blocking of direct paths: at most 10 s.
- Share of connections that end on the direct path when it is available: at least 95%.
- Bounded resource use per connection and per resolver (see the native Mainline
  contract).

## Non-goals of v1

UDP forwarding, multiple published services, a GUI, a single CLI replacing separate
Server and Client, DHT record encryption, system packages, automated release
publication, and torrent-style file sharing (future work over the finished channel).
An in-house Yggdrasil implementation is not permitted.

## Process principles

- Goal first: before each leaf, name the end-to-end scenario step it advances. Add
  no new proof mechanism or CI segment without a concrete uncovered failing case.
  Every ~10 tasks compare the TaskList with this goal.
- Three consecutive CI failures of one leaf: stop point-fix pushes. Review all
  causes together (feature contexts, paths, selectors, formatting, resources,
  oracle assumptions), make one reviewed repair commit and report it before CI
  resumes. A task change or context compaction does not reset the streak; only a
  real success does.
- Execution limits: no standalone local builds, tests, `cargo check`, unrelated
  project Python, unapproved dependency preparation, smoke runs, benchmarks or
  fake load. Locally only
  cargo fmt, cargo clippy, syntax checks and own stdlib DATA readers (`python -I`).
  Before each leaf push, run the exact CI formatting checks for the six owned
  workspace packages and the separate `shaar-ygg-core` manifest, plus
  `cargo clippy -p <affected-crate> --all-targets -- -D warnings` with the same
  features as CI, covering each affected crate and relevant feature context.
  The owner approved this boundary after actual `cargo fmt --all -- --check`
  exposed formatting differences in 34 pinned Ygg core files. Do not format,
  ignore or silently replace those verified upstream sources to obtain a green.
  The owner's 2026-11-10 permission covers dependency compilation and third-party
  `build.rs` execution required by clippy, not separate build/test/check commands.
  Use offline, locked resolution. The owner separately authorized pinned local
  source preparation for these checks, using existing CI prepare-only recipes
  with `python -I`, not test/check/fixture runners or lock generation. Registry
  acquisition is limited to its separately approved exact proposal and budgets;
  missing sources never authorize fallback URLs or version changes.
  Report local clippy separately from compilation/execution established in CI.
  Downloaded material is untrusted DATA in a new empty directory; never execute or
  import it as tools. Only checksum-verified dependencies explicitly authorized
  for clippy may be compiled by that check, including their required build.rs.
  Repeat this limit in every worker prompt and inspect execution evidence after
  the worker finishes. No new subagents without the user's explicit request.
- One owner and an ordered repository: at session entry verify HEAD, the latest
  checkpoint, live executors and the single repository owner; do not start work
  while another owner is active. Every dirty file has a custodian and a disposition;
  remove worktrees only after a verified transfer; keep no stray branches.
- Checkpoints are always committed and start with the distance to v1 (5-8 short
  bullets).
- Honest reports: distinguish written, compiled, executed in CI and accepted. A
  green CI does not prove case counts; compare selected with executed. Never
  synthesize license text. A tick, notification or cron is not user consent.
- Gates: public-network, Yggdrasil peers, legal and release actions need the user's
  separate permission for exact targets and budgets. Collect these decisions early
  and send them to the user as one package.

## Decision log

| Date | Decision | User words |
|---|---|---|
| 2026-11-14 | Platform scope extension: the products must be buildable in CI as command-line executables for Linux, Windows, macOS and Android, and a first run without any configuration must generate the Ed25519 key and the addresses, print them, and immediately start connecting and NAT traversal. Non-goals stay: no GUI, no APK or system packages, no release publication, no real-device claims without real-device evidence. Compiled and executed in CI are reported separately per platform. | "Нужно сделать чтобы можно было сделать билд под любую ОС (Android, linux, win, mac) - чтобы они просто запустили, получили/сгенерировали адреса/ключи и сразу занялись связью и проколом NAT" |
| 2026-11-14 | NAT traversal toolkit scope: no dedicated helper or relay server. Public (reflexive) address discovery and punch coordination must be assembled from the existing arsenal: the Mainline DHT, Yggdrasil, libp2p signaling (signaling only, never application data) and QUIC itself. This supersedes the owned-QAD-relay recommendation of the A5 proposal in [P13 controlled network](p13-controlled-network.md). Design, implementation leaves and verification in the existing namespace fixture (same disposable-runner, namespace-only scheme and bounds) are in scope; up to six further privileged matrix dispatches on SHAs with green ordinary CI are authorized for this work, with every other bound of the P13 contract unchanged. | "Сервер помощник - как раз и есть DHT и Yggdrasil - нужно собрать инструменты для прокола nat с помощью всего нашего арсенала" |
| 2026-11-14 | Licence work: the three remaining notice gaps (`base45`, `enum-assoc`, `if-watch`) may be researched on the web and in the packages' public GitHub repositories, and authentic upstream licence texts may be collected as inert DATA under the existing acquisition rules; text is never synthesized and unresolved gaps stay release blockers. Where a package offers `MIT OR Apache-2.0`, the engineer elects the Apache-2.0 option, and the provenance classes already recorded for `futures-bounded` and `ring` stand. This is an engineering decision made on the owner's delegation, not legal advice, and it grants no release authority. | "Погугли, посмотри их github"; "не знаю, подумай и реши сам, главное чтобы законно всё было." |
| 2026-11-14 | Authorize the P14 resource measurement in CI (`resource_measurement=true`, loopback only, release products, no public network) with the proposed budgets of [scenarios section 11.2](../verification/scenarios.md) as provisional ceilings to be tightened from measured values. Local commands that carry load run under `wnice -c 10 -m 10g` (10 % CPU, 10 GB memory), including delegated agents. | "Замеряй. Используй /win-nice capc 10, capm 10gb" |
| 2026-11-14 | Authorize the live-network smoke execution through the existing default-off contract: the engineer chooses a lawful public libp2p relay and the exact targets within the bounds already recorded (one run per dispatch, 120 s per process, no load testing, stop on any budget violation) and records them in the contract before dispatch. Public-peer contact beyond that contract, real devices and release stay gated. | "Пробуй всё, что нужно, друг" |
| 2026-11-12 | Close or honestly record the remaining open P13 rows (A2b, A5, A6, C5, C7 recovery, D2, D4, G2 signal) with the same disposable-runner, namespace-only scheme and no new network, sudo-scope, tool, package or product authority: sixteen further product cases in two new dispatch groups (`nat`, `faults`) selected by a closed workflow choice next to the unchanged `base` group, with the 64 MiB forwarded-traffic budget, the 20 min phase and the 16-descendant cap kept per dispatch, relay-full cases running three product processes (two fillers and the Server), and at most six dispatches on SHAs with green ordinary CI. Oracles encode the expected product behavior and are changed to an observed behavior only after a preserved failed run, never to force green. The exact bounds are in [P13 controlled network](p13-controlled-network.md). | "Все разрешения на работы с репами и скачиваниями - я выдаю"; "всё зеленое вливай" |
| 2026-11-12 | Extend the P13 privileged namespace matrix (same disposable-runner, namespace-only scheme; no new network, sudo-scope, tool or package authority) with LAN, runtime network-change failover and recovery, observed no-n0 counters, key denial over the Yggdrasil fallback, DHT-drop, total-outage and relay-denied cases, and re-split the 64 MiB forwarded-traffic budget as 2 MiB per router and case. The 20 min phase, 150 s per case and 16 descendants stay; at most four extension dispatches. The grant recorded in the next row and the instruction to merge green work are the authority; the exact bounds are in [P13 controlled network](p13-controlled-network.md). | "Все разрешения на работы с репами и скачиваниями - я выдаю"; "всё зеленое вливай" |
| 2026-11-12 | The user granted all permissions for repository work and downloads. This is recorded as stated; it does not by itself open the separately gated actions (public-network or Yggdrasil peer contact, real devices, legal clearance, release, version bumps, commit and push without an explicit request). | "Все разрешения на работы с репами и скачиваниями - я выдаю" |
| 2026-11-12 | Raise the P13 privileged namespace matrix dispatch cap to six, and validate every generated nft ruleset inside the dispatch (one throwaway owned namespace, before any case) because the runner restricts unprivileged user namespaces and ordinary CI cannot run `nft`. The contract bounds in [P13 controlled network](p13-controlled-network.md) are otherwise unchanged. | "Проверка внутри запуска (Recommended)" |
| 2026-11-11 | Authorize four exact pinned JNI macro LICENSE candidate GETs in proposal SHA-256 `dca3218e59f24108feedbc36fdb416c500792a35c5aee50b48ee1b3fadf457a7`: one request per URL, no redirects/retries/fallback/cloning, one connection, 64 KiB/object, 256 KiB total, 30 s/request and 5 min/pass. Inert DATA only; no execution/import, automatic applicability, OR election, legal clearance or release authority. All four requests completed HTTP 200, 24,380 bytes total; this acquisition budget is consumed. | "ок, разрешаю" |
| 2026-11-11 | Authorize an isolated NAT/UDP-blockade test network using sudo only on a disposable GitHub-hosted Linux runner, after fixing the scheme and enforceable bounds. The bounded contract is [P13 controlled network](p13-controlled-network.md): owned namespace-only addresses and fixtures, four normal-product cases, 20 min privileged phase, at most seven namespaces/16 live owned descendants and 64 MiB forwarded IP traffic; no host firewall/routes/sysctl changes, local sudo, TUN, public peers, package installation/download expansion, legal or release authority. Historical auto-triggered calibration workflows are not a substitute for this reviewed explicit execution path. | "ок, разрешаю" |
| 2026-11-10 | Permit a narrowly reviewed Native IP packet gate in the pinned Iroh source, enabled only by a separate SDK-test Cargo feature. Gate all Native IP ingress/egress, including discovered alternate routes and reconnects, while leaving Custom signaling/Ygg intact. Production keeps this feature off with no packet-hot-path branch or atomic overhead. Explicitly update provenance and source guards to disclose the test feature and prove feature-off/archive equivalence; never label modified source as unchanged. Reuse existing prepare-only recipes and local archives; no package/version/lock/download-budget changes, root, OS firewall or public-network authority. After three failed CIs, report one reviewed consolidated repair commit before CI resumes. | "Разрешить test-only gate (Recommended)" |
| 2026-11-10 | Temporarily verify candidates in isolated upstream CI topic branches while the testing remote's cooldown guard blocks pushes; never promote unverified develop or bypass the guard. A session alarm at 15:59 +01:00 restores future verification pushes to fork after its 15:57:38 cooldown, without cancelling existing CI. The duplicate testing task ref's blocked deletion remains an explicit operator cleanup obligation. This is not permanent CI rerouting or public-network/release authority. | "переключись на апстрим и поставь будильник вренуться обратно на форк" |
| 2026-11-10 | Permit at most 500 ppm relative wall/monotonic elapsed-time deficit after real Windows CI showed positive wall progress rejected for 2–1,952 microsecond cross-clock deficits. Preserve terminal observed wall rollback, invalid/backward monotonic brackets, stall and excessive-deficit rejection. Use adjacent and lifetime-anchor checks with exact integer comparison to prevent forward-credit and repeated-rounding bypasses; no public configuration or change to signed age/future limits. | "Разрешить 500 ppm" |
| 2026-11-10 | Keep the actual failed fmt-all receipt explicit: a preparation-only workspace boundary fixed discovery, then fmt-all found diffs in 34 pinned Ygg core files. Preserve their reviewed bytes and use the exact CI formatting boundary for owned packages and the separate core manifest, without ignore rules or upstream formatting patches. This supersedes the earlier literal fmt-all requirement. | "Сначала исправить --all"; after the 34-file evidence, "Принять границу CI" |
| 2026-11-10 | Authorize pinned local source preparation for fmt/clippy using existing CI prepare-only recipes. Separately approve registry proposal SHA-256 `00a252e01a61373fb541f7238de982fea16f25122daa161b381e69fbf8053ae5`: at most 465 exact index GETs and 533 exact locked archive GETs, reuse local archives first, one GET per URL, no redirects/retries/fallback, at most two connections, 30 s/request, 30 min/pass, 16 MiB/index object, 64 MiB/archive, 1 GiB total. No standalone build/test/check or additional network authority. | "нужно всё локально опдготовить, чтобы в ci было чему сростись"; "Разрешить этот набор" |
| 2026-11-10 | Allow local cargo fmt and cargo clippy before each leaf push with CI-equivalent features, including necessary clippy dependency compilation and third-party build.rs; no standalone build/test/check, dependency preparation/downloads, project Python, smoke, benchmarks or fake load. This supersedes the earlier blanket local Cargo ban. The owner answered the explicit build.rs coverage question with the permission quoted here. | "Локальный clippy и format - нужно ращрешить"; "разрешаю и clippy и форматирование" |
| 2026-10-31 | P07/Yggdrasil deferred beyond v1 | Superseded on 2026-11-04 |
| 2026-11-04 | Yggdrasil restored to v1; original architecture kept | "придерживаемся изначального плана" |
| 2026-11-04 | Controlled blockade resilience is mandatory for v1 | Recorded in `v1-focus.md` |
| 2026-11-04 | Checkpoints are always committed | "чекпоинты комитим всегда" |
| 2026-11-04 | Goal text lives in `CLAUDE.md` and is reloaded after compaction | "да, делай как ты говоришь" |
| 2026-11-04 | Replace base256emoji with base58 | "давай просто перейдем на base58" |
| 2026-11-04 | Authentic upstream license texts may be collected as isolated DATA for notices | "да" |
| 2026-11-04 | Pinned Yggdrasil-ng integration is approved after P09 | "да" |
| 2026-11-04 | Public smoke targets are chosen by the engineer; they must be legal and working, within agreed bounds | "нужно выбрать что-то - не важно, главное чтобы легально и чтобы работало" |
| 2026-11-05 | P10 efficiency criteria: balanced profile (first byte 3 s known / 10 s cold, failover 10 s, direct share 95%) | "Сбалансированный (Recommended)" |
| 2026-11-05 | MPL-2.0 is allowed narrowly, only for the pinned `ironwood` and `yggdrasil` packages, in the license check and report | "Узкое разрешение (Recommended)" |
| 2026-11-05 | Source availability of the modified MPL-2.0 files is met by this repository (patch hunks plus the pinned upstream revision); no further publication step | "так наша репа и есть способ их получить - ничего дополнительного делать не нужно" |
| 2026-11-09 | Group related work into bounded delivery passes following the audit; preserve acceptance order and failure history | "скорректируй план под аудит, сгруппируй смежные задачи, что их удобно было решать за один проход" |
| 2026-11-09 | Live-network smoke testing is authorized in principle; exact lawful targets/peers and enforceable budgets remain a pre-execution gate, without authorizing load testing or release | "смок тесты на живой сети разрешаю проводить" |
| 2026-11-09 | Authorize one inert-DATA acquisition pass for the 515 exact static.crates.io URLs in registry inventory SHA-256 `1aaca36c30203ecb73eebc8c73f1299c52e8b6161c27e3ec94a8e7a8c2aa347b`; one GET per URL, no redirects/retries/substitutions, 64 MiB/object, 1 GiB total, at most two concurrent requests, 30 s/request and 30 min/pass, stop on budget/checksum violation. No execution/import/build; raw GitHub candidates excluded. | "Разрешить ограниченный проход" |
| 2026-11-10 | Authorize nine exact pinned raw.githubusercontent.com LICENSE candidates in proposal SHA-256 `5a3d9d02e89b33df6c677268a44735c9770a4d7f8d92835718cb21798232dc6b`; 64 KiB/object, 576 KiB total, one concurrent connection, 30 s/request and 5 min/pass. No redirects, retries, fallback URLs, cloning or execution; availability/applicability not presumed. | "Разрешить 9 точных GET" |
