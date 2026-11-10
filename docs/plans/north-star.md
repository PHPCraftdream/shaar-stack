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
- Execution limits: no local builds, tests, Cargo, project Python, dependency
  preparation, smoke runs, benchmarks or fake load; verification happens in GitHub
  CI. Locally only formatting, syntax checks and own stdlib DATA readers (`python -I`).
  Downloaded material is untrusted DATA in a new empty directory, never executed or
  imported. Repeat this limit in every worker prompt and inspect execution evidence
  after the worker finishes. No new subagents without the user's explicit request.
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
| 2026-11-09 | Authorize one inert-DATA acquisition pass for the 515 exact static.crates.io URLs in registry inventory SHA-256 `1aaca36c30203ecb73eebc8c73f1299c52e8b6161c27e3ec94a8e7a8c2aa347b`; one GET per URL, no redirects/retries/substitutions, 64 MiB/object, 1 GiB total, at most two concurrent requests, 30 s/request and 30 min/pass, stop on budget/checksum violation. No execution/import/build; raw GitHub candidates excluded. | "Разрешить ограниченный проход" |
| 2026-11-10 | Authorize nine exact pinned raw.githubusercontent.com LICENSE candidates in proposal SHA-256 `5a3d9d02e89b33df6c677268a44735c9770a4d7f8d92835718cb21798232dc6b`; 64 KiB/object, 576 KiB total, one concurrent connection, 30 s/request and 5 min/pass. No redirects, retries, fallback URLs, cloning or execution; availability/applicability not presumed. | "Разрешить 9 точных GET" |
