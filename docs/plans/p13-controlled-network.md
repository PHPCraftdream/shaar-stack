# P13 controlled NAT and UDP-blockade execution contract

Status: **executed and accepted for the twelve product cases and the three cleanup
controls** — the four original cases in fork workflow_dispatch run 43229756778 on
`ca6c04a`, and all twelve in the extension run 43245366525 on `17b711c`
(2026-11-12), phase status `pass`; see [Execution record](#execution-record-2026-11-12).
This is not full P13 acceptance: the open and gated rows are listed in the P13 report,
`docs/verification/scenarios.md` section 10.

## Authorization and fixed scope

On 2026-11-11 the user explicitly approved the two described actions with
“ок, разрешаю”: four exact pinned JNI license downloads, and an isolated Linux
GitHub CI test network using sudo only after its scheme and limits are fixed.
The license acquisition is separate; its four-request budget is now consumed.

This contract fixes the network scheme and tighter execution bounds below.
Permission covers disposable GitHub-hosted Ubuntu runners only. It does not cover
local sudo, TUN, host/router/firewall reconfiguration, public Yggdrasil or relay
peers, LAN/device/home/mobile tests, new package downloads, legal clearance or a
release. Production Server and Client remain unprivileged and keep one Ed25519
identity, key-only lookup, Native QUIC priority and signaling-only libp2p.

North-star steps: 4–5, with real step-6 fixed-target application bytes. This is
functional evidence, not another P10 efficiency campaign or a performance load.

## Topology and exact targets

Reuse the existing topology's address plan, invocation nonce, unique `sn<6-hex>`
resource prefix and ownership-based cleanup. Never reuse a previous case directory.

| Namespace role | Addresses | Purpose |
| --- | --- | --- |
| WAN | `203.0.113.10/24` | Owned DHT, relay and Ygg transit fixtures; Server in single-NAT cases |
| Router A | WAN `203.0.113.1/24`, LAN `10.0.1.1/24` | Client-side NAT and per-case packet controls |
| Client A | `10.0.1.2/24`, gateway `10.0.1.1` | Normal `shaar-client` |
| Router B | WAN `203.0.113.2/24`, LAN `10.0.2.1/24` | Server-side NAT in double-NAT cases |
| Server B | `10.0.2.2/24`, gateway `10.0.2.1` | Normal `shaar-server` in double-NAT cases |
| Off router/host | `203.0.113.3/24`, `10.0.3.1/24`, `10.0.3.2/24` | Existing forwarding-disabled calibration control only |

There are at most seven namespaces. The WAN bridge and every veth endpoint live
inside these namespaces after setup. The WAN namespace has no Internet/default
route or interface to the runner's primary network. Fixture ports are dynamically
allocated and recorded, never substituted with public services. Loopback TCP
fixed targets live in the same namespace as their Server; Client frontends are
loopback-only inside the Client namespace. Cross-namespace helpers are explicit
owned fixture processes, not exposed production control interfaces.

UDP MASQUERADE retains the existing translated-port range `41010–41020` on both
routers. TCP NAT must also be configured **inside router namespaces** for owned
relay/Ygg TCP connectivity; the old UDP-only calibration is insufficient for
this product path. Only router namespace forwarding sysctls may change. IPv6
forwarding is denied for this IPv4 topology, including the blockade cases, so it
cannot bypass the selected controls. This is not IPv6 NAT acceptance.

## Four product cases

All cases use normal CI-built binaries, secure provisioned test keys, actual
Server records and a Client configured with only the Server key. No fabricated
address record, synthetic public socket or production route hook is allowed.
Product policy, retry counts, idle timers and deadlines remain unchanged.

1. **Single NAT / signal / Native positive control.** Client A reaches a Server
   in WAN through Router A. Native UDP, owned DHT and signaling are available;
   router rules deny Ygg transit TCP. Require exact request/reply, half-close/EOF
   and the fixed target. Native data is established by path exclusion plus real
   NAT observations, not a plaintext guess from encrypted packet sizes.
2. **Single NAT / standby / unavailable Ygg.** Same network and exclusion as case
   1, with `standby`. Require Native APP success despite unavailable Ygg peers.
   A failure to start or serve is a defect, not permission to weaken the case.
3. **Double NAT / standby / UDP blockade.** Client A and Server B are behind
   distinct NATs. Router rules deny all forwarded Native UDP; Client relay TCP
   is also denied. Only the owned Ygg transit TCP path is available between the
   devices. Require a fresh exact fixed-target APP exchange and successful
   normal shutdown. Observe the installed matching rules and nonzero dropped
   UDP attempts; silent bootstraps alone do not establish UDP blockade.
4. **Double NAT / signal / fail closed.** Same controlled blockade and reachable
   Ygg transit as case 3, changing only the mode/identity fixture inputs needed
   for isolation. Require actual local TCP admission followed by terminal stream
   failure and normal CLI error exit, zero target accepts through child reaping,
   and successful Server shutdown. Timeout or a crashed child is not success.
   Case 3 is the positive connectivity control; absence of target traffic alone
   cannot prove that a working alternate path was forbidden to carry APP.

Case 3 proves fallback under controlled double NAT, **not successful Native
hole punching through arbitrary double NAT**. A later direct-double-NAT claim
requires its own observed mapping and data-path proof; do not manufacture it by
routing the private Server address across WAN or by forging the DHT record.
The approved historical `nat-peer` QUIC fixture is supporting calibration, not a
substitute for any normal-product case above.

## Extension cases (recorded 2026-11-12)

The extension reuses the same disposable-runner, namespace-only scheme, the same
normal products and the same dispatch job. It adds eight product cases and a
kernel-side observation of traffic to non-owned destinations; the four cases above
are unchanged. North-star steps: 3 (published address), 4–5 (path choice and
failover), 6 (allowlist denial), plus the "no n0" goal. Non-goals: new networks,
real devices, IPv6, NAT type variety, direct double-NAT punching, throughput.

Each case below names its observable acceptance criterion.

| Case | Row | Mode | Topology and rules | Acceptance (all exact) |
| --- | --- | --- | --- | --- |
| `lan-signal`, `lan-standby` | E1 | both | Client in the Router A namespace, Server in the Router B namespace; both are hosts on the owned `203.0.113.0/24` segment next to the DHT/relay/Ygg fixtures. Their router-side LAN interfaces are flushed after the calibrations so each host has exactly one address. No NAT, no forwarding on the path. Client Ygg dial blocked on its output hook so APP can only use Native | APP 61/61 bytes, target accepts 1, Client exit 0; the signed record lists exactly the Server's segment address `203.0.113.2`; on both routers forwarded quota bytes 0 and `udp_nat`, `tcp_nat`, `native_snat`, `native_drop` all 0; `lan_sent` and `lan_native` > 0 on both routers (Native UDP was sent and received on the segment) |
| `relay-denied-signal` | C4b | signal | Single NAT (Server in WAN); Client-side router denies relay TCP, allows Ygg transit, UDP open | APP 61/61, accepts 1, Client exit 0, `udp_nat` and `native_snat` > 0; `tcp_drop` is recorded, not required (the product may not dial a relay when the direct path works) |
| `failover-standby` | D2, D3 | standby | Single NAT, relay and Ygg transit open, UDP open at start. APP 1 over Native, then a runtime Native UDP block table (both routers, DHT exempt), then APP 2, then the block is lifted and a Ygg TCP block table is inserted, then APP 3 | APP 1: `native_snat` > 0 (Ygg is open, so Native carriage is policy plus counters, not exclusion). APP 2 succeeds within **10 s** of block insertion (north-star failover bound), exact bytes, `native_snat` growth during the block exactly 0, dropped Native UDP > 0, Ygg TCP packets grow. APP 3 succeeds within **40 s** of the block removal with Ygg blocked, so Native carried it by exclusion, and `native_snat` grows again. Target accepts 3, 183/183 bytes in total |
| `failover-signal` | D2 | signal | As above without recovery | APP 1 as above; after the block APP 2 fails closed (terminal EOF/reset, 0 reply bytes), `native_snat` growth 0, dropped Native UDP > 0, target accepts stay 1. The Client process stays alive (a lost path mid-session fails the stream, it does not end the Client; first dispatch evidence), so it is stopped by console interrupt and must exit 0 |
| `denied-blocked-standby` | G2 | standby | Double NAT, Native UDP blocked, Ygg only (the `blocked-standby` network) | Authorized Client first: APP 61/61, accepts 1, clean exit 0. Then a second Client with a different valid key: terminal EOF/reset, 0 reply bytes, target accepts still 1, second Client exits 1, Server stays up and stops cleanly |
| `dht-drop-signal` | C2 | signal | Single NAT; Client-side router drops UDP to the DHT socket (all queries) | Hypothesis "fail closed" was refuted by dispatch 1 (the fixed target saw an admission). Accepted oracle: APP 61/61, target accepts 1, Client exit 0, `dht_drop` > 0, `udp_nat` and `native_snat` > 0. In signal mode only Native can carry APP, so the Client reached the Server over Native after discovery without the DHT; `relay_tcp` shows the libp2p signaling traffic that supplied the candidates |
| `outage-standby` | C7 | standby | Double NAT, Native UDP blocked and Client-side relay and Ygg TCP both denied | Local admission then terminal failure, 0 reply bytes, target accepts 0, Client exit 1 on its own within the case bound |

Notes on the oracles.

- **LAN honesty.** The segment uses documentation-range addresses because the DHT
  fixture admits only `203.0.113.1/2/10` as query sources. It proves direct IPv4 Native
  over one shared L2 segment without NAT or forwarding, and that discovery finds the
  segment address. It does not prove RFC 1918 LAN address handling, multicast LAN
  discovery, Wi-Fi, or real devices.
- **Runtime blocks are separate tables** (`<prefix>_dnative`, `<prefix>_dygg`, forward
  hook priority -250, own named drop counter), inserted and deleted whole, so the
  verified product table stays immutable. Failover time is measured from the commit of
  the last router's insertion to the controller receiving APP 2's result, so it includes
  the APP worker's process start and is conservative. The recovery bound of 40 s is a
  fixture choice that fits the 90 s active window; it is not a north-star criterion.
- **Observed no-n0 (F1).** Every case installs, in both router namespaces, a counter-only
  `<prefix>_obs` table: forward and output hooks, counters for any destination outside
  `10.0.0.0/8`, `203.0.113.0/24` (which contains the `203.0.113.10/32` WAN host),
  loopback and link-scope multicast/broadcast, plus UDP/53 and TCP/443 to such
  destinations. Before each case the exact installed rules are proven live by known probes
  to TEST-NET-1 `192.0.2.77` (a destination no namespace routes or answers), then the
  table is reinstalled with zero counters. The case fails if any observation counter is
  nonzero at the end. Limits: IPv4 only (IPv6 forwarding is separately dropped and counted);
  products running in the WAN namespace have no route out at all, so their attempts are
  prevented rather than counted; traffic that never leaves a host namespace is not seen.
- **Rule dependencies.** `nft --check` of every generated ruleset (now 53: the 48 case
  tables, two calibration tables, the observation table and the two runtime-block tables)
  stays the first step of the dispatch.
- **Measured bounds.** Failover to Ygg took 7.0-7.1 s and Native recovery 13.1 s in
  the three dispatches that ran the standby failover case; signal-mode fail-closed took
  5.1 s. The 10 s bound is the north-star criterion; one run is not a 95th-percentile
  claim.

## Enforceable resource and lifetime bounds

- One Ubuntu job, one exact reviewed source SHA, cases sequentially; no fan-out.
- Job wall limit: 90 minutes including ordinary unprivileged pinned preparation
  and compilation. Privileged network phase: **20 minutes total**, with the final
  45 seconds reserved for forced owned cleanup. No arbitrary timeout increase.
- Each product case: 150 seconds including setup, at most 90 seconds of active
  functional work and up to 45 seconds of teardown. These are fixture bounds,
  not raised product deadlines or relaxed efficiency thresholds.
- At most 16 simultaneously live owned descendants including supervision and
  namespace wrappers. At most two product processes per case, eight application
  or infrastructure roles, and two concurrent transient setup commands. Admission
  must prevent exceeding the total; draining later is not a concurrency cap.
- At most 16 fresh APP transactions per case, at most two simultaneously active
  APP streams, and at most 64 KiB request plus 64 KiB reply per transaction. No
  throughput loop or artificial load. Retry only actual typed transient I/O
  failure under one absolute transaction-campaign deadline.
- Forwarded IP traffic: **64 MiB maximum across the privileged phase**. Re-split on
  2026-11-12 for twelve product cases: each product case receives 2 MiB per router
  (48 MiB maximum total); the live-failure and interruption controls receive 2 MiB per
  router each (8 MiB total); 8 MiB stays unallocated. The first run of the original four
  cases used 160,332 B in total, so 2 MiB per router and case keeps a margin of more
  than two orders of magnitude. Setup-failure controls start no traffic. Namespace-local
  kernel quotas must enforce these allocations; a quota hit is a recorded failure, not
  a passing blockade.
- The 150 s per-case ceiling is unchanged. Twelve cases at their ceiling would exceed
  the 20 minute phase, so the worst case no longer fits by arithmetic; the phase refuses
  to start a case whose ceiling plus the 45 s cleanup reserve no longer fits the
  remaining time, records that as a failure, and orders the slowest cases last. The
  observed duration of the original seven runs was 53.6 s in total.
- Metadata/capture artifacts: at most 64 MiB aggregate, bounded files and packet
  capture buffers. Never dump production secrets or unbounded packet streams.
- Setup-failure, live-child-failure and SIGTERM cleanup controls: at most 60
  seconds each, within the same privileged-phase budget. No automatic rerun.

## Privilege, tool and trigger gates

Compile and prepare the exact normal products **without sudo**, using the existing
reviewed pinned recipes and locks. Confirm product source/profile/executable/hash
provenance and that `shaar-native-gate` is OFF. Test-only upstream packet gating
must not be silently enabled in these normal products.

The root supervisor creates only its own prefixed namespaces/veth/rules and enters
namespaces for setup and observation. Drop to the runner's unprivileged identity
before launching product processes and ordinary fixture helpers. Provision keys
for that identity; root-created permissive keys cannot bypass the normal loader.
No TUN interface, host route, host firewall rule or host forwarding change.

Require preinstalled `ip`, `nft` (including namespace quota support), Python and
the existing capture/conntrack facilities. Record their versions and the runner
image. Missing tools or kernel capabilities fail preflight; **do not run apt,
rewrite mirrors, install packages or use a fallback download URL** under this
permission. An unavailable required tool is a concrete blocker to report.

All new privileged execution is explicit `workflow_dispatch` on a recorded exact
source revision, never a side effect of an ordinary source push or pull request.
Before implementing probe changes, audit the legacy auto-triggers: both
`nat-topology.yml` and `quic-nat.yml` match the topology subtree and contain sudo/
apt steps. They must not accidentally execute their old installation/calibration
jobs when this leaf is promoted. Keep privileged legacy jobs manual and separately
scoped; ordinary CI still checks syntax, ownership, bounds and oracle tests.

Reuse an existing workflow rather than creating an eighth workflow file. A new
product helper can live under `.github/probes/nat-topology/quic/product/` without
exceeding seven direct directory items. Split by resource ownership/responsibility;
existing `run.sh` and `fixture.py` are already near the 700-line limit. Update the
ordinary impact map for every new owned source; no unknown-path or empty-green
fallback. No new workflow, helper or test is executed by writing this document.

## Mandatory evidence and cleanup

Preserve raw evidence separately from the verifier's conclusions: actual source
SHA, normal product provenance, configs without secret key bytes, namespace and
PID identities, actual Server publication, observed NAT/conntrack tuples, rule
identity and drop/quota counters, local admission, exact APP assertions, terminal
outcomes and target accepts. Do not equate control bytes with application routes.

Calibration must establish that a live sender and live receiver observe the real
NAT translation and that a controlled drop actually prevents the intended path.
A test that reuses its own fabricated observations is not an independent oracle.

The supervisor owns every child handle and records TERM/KILL escalation, waits
and survivors. Normal cases require graceful product exit; failure cleanup does
not convert a failed functional case to success. Delete only resources created
by the nonce-bound invocation. Compare host firewall, routes, forwarding state,
interfaces and namespace inventory before/after; failed capture or any unexpected
change is itself failure. Cleanup controls must cover partial setup, live-child
failure and supervisor cancellation with bounded reaping and zero survivors.

Acceptance distinguishes written, compiled, executed, verified and delivered.
Preserve failed runs. Three consecutive leaf CI failures require one joint review
and one reported reviewed repair before more CI. Verify in fork; upstream receives
only the exact reviewed green SHA, then custody transfer and branch/worktree
cleanup. No skipped or permission-blocked applicable P13 row counts as passed.

## Execution record (2026-11-12)

- **Accepted:** fork workflow_dispatch run 43229756778 on `ca6c04a`, runner image
  20261101.186.1. All four product cases (`native-signal`, `native-standby`,
  `blocked-standby`, `blocked-signal`) and the three cleanup controls
  (`setup-failure`, `live-failure`, `interruption`) passed. Zero leftover
  namespaces, processes and interfaces; host firewall and `ip_forward` unchanged.
  Forwarded 160,332 B of the 64 MiB allocation; privileged phase 53.6 s of 20 min.
  The later `6e730b1` (merged to main as `1844247`; upstream develop CI 43231417573
  green) changes only the supervisor interrupt wait and was not re-dispatched.
- **Oracle deviation:** the runner has no conntrack procfs table or CLI (tool
  preflight run 43118324828). Native NAT admission is therefore established by
  named nftables counters (`udp_nat`, `native_snat`, `native_drop`) with exact rule
  identities, not by NAT/conntrack tuples as the mandatory-evidence section
  requested. No tuple is claimed. Case 3 stays a fallback result, not hole punching.
- **Amendments recorded on 2026-11-12** (decision log): the dispatch cap is raised
  to six, and nft syntax is checked inside the dispatch (all 18 generated rulesets
  in one throwaway owned namespace before any case) because the runner restricts
  unprivileged user namespaces, so ordinary CI cannot run `nft`.
- **Earlier failed dispatches (kept as evidence):** 43218411816 on `c265050` — the
  controller could not find the `cat` tool; 43220370261 on `9225dcc` — nft rejected a
  chain named `snat` (reserved word); 43227388578 on `0800aa4` — the product cases
  passed their functional oracles but strict verification demanded an identity for
  a short-lived APP child that is never sampled. Each was repaired in the following
  commit; none was retried blindly.
- **Not covered by this contract or its runs:** IPv6 NAT, other NAT types, direct
  double-NAT punching, interface or address switch and NAT rebinding, recovery after a
  total outage, RFC 1918 or device LANs, public and device scenarios. LAN (owned
  segment), observed no-n0, runtime Native loss and recovery, key denial over Ygg, DHT
  drop, total outage and relay-denied are covered by the extension (see above). The
  rest stay open or gated in `docs/verification/scenarios.md`.

## Extension execution record (2026-11-12)

Authority: the north-star decision-log row of 2026-11-12 (extension) and the user's
grant quoted there. Three of the at most four extension dispatches were used; each ran on
a SHA whose ordinary fork CI was green and whose in-dispatch `nft --check` of all 53
rulesets passed first. Evidence is preserved per dispatch under
`.rush/downloads/p13-rows-dispatchN-<runid>/` in the primary checkout (not committed).

| Dispatch | Run | Source SHA | Result |
| --- | --- | --- | --- |
| 1 | 43241277233 | `72db069` | fail: the four original cases and `relay-denied-signal`, `failover-standby`, `denied-blocked-standby`, `outage-standby` passed; `lan-*` failed (Server published an unreachable LAN-side candidate first, Client found no usable path), `failover-signal` and `dht-drop-signal` failed (Client stays alive after the stream fails; DHT-drop hypothesis wrong) |
| 2 | 43243607361 | `7f89780` | fail: all but `dht-drop-signal` passed (LAN works with one interface per host; signal cases expect a console stop); `dht-drop-signal` still used the fail-closed oracle |
| 3 | 43245366525 | `17b711c` | **pass**: 15 of 15 invocations (12 product cases, 3 cleanup controls), phase 185.2 s of 20 min, forwarded 582,967 B of the 64 MiB budget (largest router quota use 101,583 B of 2 MiB), zero leftover namespaces, host firewall and `ip_forward` unchanged, 269,150 B of artifacts |

Fixes between dispatches were test-harness only (worker treats a reset local stream as a
typed transient; LAN host isolation; signal-case expectations; C2 oracle) plus extra
diagnostics (`lan_sent` counters, neighbor and link dumps on failure). No product code
changed. A later documentation-only commit does not alter the executed source.
