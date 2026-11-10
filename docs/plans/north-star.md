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
