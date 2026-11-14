# P13 controlled NAT and UDP-blockade execution contract

Status: **executed and accepted for the twelve base product cases and the three cleanup
controls** — the four original cases in fork workflow_dispatch run 43229756778 on
`ca6c04a`, all twelve in the extension run 43245366525 on `17b711c`, and again unchanged in
run 43262321962 on `31fd921` (2026-11-12), phase status `pass`; see
[Execution record](#execution-record-2026-11-12). The sixteen remaining-row cases ran in
the six dispatches recorded in [Remaining-row execution record](#remaining-row-execution-record-2026-11-12);
the last change of the branch head (the fixture punch control) was not dispatched.
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

## Remaining-row cases (recorded 2026-11-12)

This leaf closes or honestly records the remaining open rows of
`docs/verification/scenarios.md` section 10 with the same disposable-runner,
namespace-only scheme, normal products and dispatch job. It adds sixteen product
cases in two new dispatch groups; the twelve accepted cases are the unchanged `base`
group. North-star steps: 3 and 4 (hole punching after relay signaling), 5 (blockade
fallback), 6 (allowlist denial). Non-goals: new networks, real devices, throughput,
public peers, RFC 1918 or device LANs, NAT types other than the two below, product
changes. Written and syntax-checked here; the execution records below say what ran.

**Dispatch groups.** `workflow_dispatch` takes `controlled_network_group` (a closed
choice `base`, `nat`, `faults`, default `base`) and passes it to `phase.py --group`.
Every group runs its cases, then the same three cleanup controls, inside the same 20
minute phase; the 28 cases together would not fit, so a dispatch never runs more than
one group. Forwarded-traffic allocation per group: `base` 56 MiB (12 cases and two live
controls, as before), `nat` 48 MiB (10 cases), `faults` 32 MiB (6 cases); each product case
and live control keeps its own 2 MiB per router quota, so every group stays under 64 MiB.
The in-dispatch `nft --check` still runs first and now covers every generated ruleset
(all cases x 2 routers x {product, fault}, 2 quota probes, 2 NAT probes, the observation
table and 3 runtime blocks).

| Case | Row | Mode | Topology and rules | Acceptance (all exact) |
| --- | --- | --- | --- | --- |
| `dnat-cone-signal`, `dnat-cone-standby`, `dnat-cone-relay-signal`, `dnat-cone-relay-standby` | A5 | both | Client A behind Router A, Server B behind Router B, WAN segment shared. Both routers NAT UDP and TCP with plain `masquerade` (the kernel keeps the source port: endpoint-independent, port-preserving, cone-like). Native UDP allowed. Client-side router denies Ygg transit TCP (relay allowed), so APP cannot use Ygg. No private address is routed across the WAN and no record is forged. The `relay` variants drop the Client's DHT queries, so the Client has no direct candidate and must go through relay negotiation | Live NAT probe on both routers before the case: 3 of 3 datagrams from one fixed source port to three destinations keep the port; a fixture punch control is recorded. **Expectation after dispatch 43255837358 (the first version expected a punch and failed, preserved):** no direct path in either mode: terminal EOF/reset, 0 reply bytes, target accepts 0, Client exit 1, `peer_recv` 0 on both routers (no Native UDP reached the other router), `ygg_tcp` 0 on the Client-side router; relay variants additionally `dht_drop` > 0 and `relay_tcp` > 0 on the Client-side router (relay negotiation was reached) |
| `dnat-sym-signal`, `dnat-sym-standby` | A6 | both | Same topology; both routers use `masquerade fully-random` (a new random port per flow: not endpoint-independent, symmetric-like). Ygg and relay TCP allowed | Live NAT probe: 3 of 3 datagrams change the source port. Expectation: `signal` fails closed (terminal EOF/reset, 0 reply bytes, target accepts 0, Client exit 1); `standby` succeeds exactly through the Ygg fallback (accepts 1, exit 0, `ygg_tcp` > 0). Peer counters are recorded, not forced |
| `hole-signal`, `hole-standby` | D4 | both | Single NAT, Server in WAN, Ygg denied on the Client side so only Native can carry APP. APP 1, then Router A's WAN link is cycled down and up: masquerade drops every conntrack entry bound to that interface (no conntrack CLI is needed), and the default route is restored. Then APP 2 | APP 1 and APP 2 exact (2 accepts), APP 2 within **40 s** of the flush (fixture bound), `native_new` (new Native UDP flow admitted by the NAT chain) grows after the flush, which proves the old mapping was really gone; `hole_in` (UDP addressed to the router itself, i.e. no longer matching a mapping) is recorded |
| `switch-signal`, `switch-standby` | D2 | both | As above, Client binds wildcard sockets, NAT matches the whole `10.0.1.0/24`. APP 1, then the Client host moves from `10.0.1.2` to `10.0.1.3` on the same interface (old address deleted, new added, default route restored), then APP 2 | Same as `hole-*`; `native_new` growth proves a new NAT mapping from the new address |
| `relay-full-signal`, `relay-full-standby` | C5 | both | The owned relay allows two reservations. Two extra Servers (`filler1`, `filler2`, other identities, same normal binary) are started first and given 8 s to reserve (the reservation has no observable signal; a fixed bounded delay). Then the real Server starts. No Client | The real Server ends by itself with exit status 1 and the typed message `relay reservation failed at startup` within 70 s (finite, typed), fillers still alive, target accepts 0, fillers and WAN stop gracefully. Client-side exhaustion is not separately run: the Client reserves only after every direct candidate failed, so with the UDP/relay conditions of B1, B2, C4 and C4b its outcome is the already accepted one |
| `ipv6-signal`, `ipv6-standby` | A2b | both | As the LAN cases (Client and Server are hosts on the owned segment, no NAT, no forwarding), plus documentation-prefix IPv6 addresses `2001:db8:13::1` and `2001:db8:13::2` on the two segment hosts (router IPv6 forwarding stays denied). A runtime table drops IPv4 Native UDP between the two hosts for the whole case, and the Client is given the Server's published IPv6 candidate as its `server_address` hint. The first version had both families open and switched mid-session; it was not deterministic (dispatch 43257222340, preserved) | The signed record lists the Server's IPv6 address; APP exact (accepts 1) with Client exit 0, so only IPv6 Native UDP can have carried it; `lan6_native` and `lan6_sent` > 0 on both hosts, `lan_native` (IPv4 input) 0, `ipv6_drop` 0 (no forwarding), quota 0. The hint is an explicit exception to "Client configured with only the Server key": the key-only dial tries the published IPv4 candidate first and a silent candidate consumes the attempt |
| `denied-native-signal` | G2 | signal | Single NAT, Server in WAN, Native over the NAT, Ygg denied on the Client side | Authorized Client first (APP exact, accepts 1, exit 0); a second Client with a different valid key gets terminal EOF/reset, 0 reply bytes, target accepts stay 1, second Client exit 1, Server stays up and stops cleanly |
| `recover-standby` | C7 | standby | Single NAT, Server in WAN. Runtime tables block Native UDP (DHT exempt) and Ygg TCP before the first APP. APP 1 fails closed and the Client ends on its own (status 1). Both blocks are removed, a fresh Client (same key) starts, APP 2 | APP 1 terminal failure, 0 reply bytes, Client exit 1; both blocks dropped packets; APP 2 exact (accepts 1 in total) within **40 s** of the block removal (includes the fresh Client's start); final Client exits 0 |

Notes on the oracles.

- **NAT type honesty.** The live probe is an independent oracle for the mapping flavor on
  each router, run in a throwaway table with the same `masquerade` statement before the
  product table exists (same pattern as the quota probe). `cone` means "port-preserving,
  endpoint-independent for outgoing packets; Linux conntrack still filters inbound packets
  by the contacted address and port". It is not a claim about every home router.
  `fully-random` is symmetric-like for the purpose of this test, not a full NAT-type survey.
- **Nothing forces green.** A5 and A6 oracles encode the expectation of the case. If the
  product does not behave that way the dispatch fails and the execution record keeps the
  failure; the oracle is only changed afterwards to the observed behavior, with the failed
  run preserved and the finding written down. A5 went through exactly this: the first
  oracle (APP exact over a punched path) failed, and the cases now record the finding.
- **Fixture punch control.** For the cone cases the harness also lets two plain UDP sockets
  (20 datagrams each, 0.1 s apart, never echoing) punch through both routers using the
  public endpoints it knows. The outcome is recorded (`pass` or `fail` with receipts) and
  never decides a product verdict; a miss means the fixture could not show a punched path in
  that run.
- **Counters.** New named counters: `peer_sent` (translated Native UDP leaving a router toward
  the other router), `peer_recv` (the reverse direction, after de-translation), `native_out`
  (any translated non-DHT UDP leaving a router, including attempts toward unroutable
  addresses), `native_new` (new Native UDP flows seen by the NAT chain), `hole_in` (UDP
  addressed to the router's own WAN address), `lan6_native`/`lan6_sent` (IPv6 UDP between the
  two segment hosts, input and output hooks).
- **Mapping probe.** `masquerade` (cone) and `masquerade fully-random` are applied in a
  throwaway table with the same statement as the product rules; 3 datagrams from one fixed
  source port to three destinations must all keep the port (cone) or all change it (random).
- **Operations inside owned namespaces only.** Link down/up of a router WAN interface, delete
  and add of the Client host address, IPv6 address add on the two router WAN interfaces, and
  extra nft tables. No host state changes; forwarding sysctls stay as in the base contract.
- **Process count.** `relay-full-*` runs three product processes at once (two fillers and
  the real Server; no Client). The base text "at most two product processes per case" is
  amended for these two cases only; total owned children stay at most 16.
- **Dispatch budget.** At most six dispatches for these rows, each on a SHA with green ordinary
  CI; three consecutive failed dispatches stop incremental repair in favor of one reviewed
  consolidated repair.

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

## Remaining-row execution record (2026-11-12)

Authority: the north-star decision-log row of 2026-11-12 (remaining rows) and the user's
grants quoted there. All six allowed dispatches were used; evidence per dispatch is kept under
`.rush/downloads/p13-rows2-dispatchN-<runid>/` in the primary checkout (not committed). Every
dispatch ran `nft --check` of all generated rulesets first (112, later 120).

| Dispatch | Run | Source | Group | Result |
| --- | --- | --- | --- | --- |
| 1 | 43255837358 | `1d36cd5` | nat | fail: the two cone cases expected a punch and failed (finding); other six cases and three controls pass; phase 147.8 s, forwarded 301,560 B |
| 2 | 43257222340 | `1d36cd5` | faults | fail: `ipv6-*` only; `denied-native-signal`, `recover-standby`, `relay-full-*` and the controls pass; phase 176.6 s |
| 3 | 43258223283 | `6f7c0ce` | nat | pass: 10 cases and 3 controls; phase 221.7 s, forwarded 625,370 B of 48 MiB allocated. The fixture punch control looped without a bound here (about 50,000 datagrams per side in 2 s): a load defect, fixed afterwards |
| 4 | 43262304898 | `31fd921` | faults | pass: 6 cases and 3 controls; phase 137.9 s, forwarded 172,029 B of 32 MiB allocated |
| 5 | 43262313789 | `31fd921` | nat | fail: 8 of 10 cases and 3 controls pass; `dnat-cone-signal` and `dnat-cone-relay-signal` failed at the fixture punch control before any product started (fixture, not product) |
| 6 | 43262321962 | `31fd921` | base | pass: the twelve accepted cases and 3 controls; phase 203.5 s, forwarded 609,232 B of 56 MiB allocated |

Every group left zero leftover namespaces, unchanged host firewall and `ip_forward`, and
artifacts below 280 KB. Fixes between dispatches were harness-only; no product code changed.
After dispatch 5 the control became a recorded, non-decisive receipt and its probe table
gained an input-hook drop of unsolicited UDP to the router's own port (hypothesis: such a
packet otherwise creates a conntrack entry that takes the peer's preserved port). That change
is **not dispatched**; one nat-group dispatch is needed to verify it.

## Reflexive address source and hole punching without a helper server (design)

Status: **design, not implemented** (rewritten 2026-11-14). It answers the A5 finding
(scenarios.md §10.2, row A5): with a port-preserving cone NAT on each router and Yggdrasil
denied, neither product direction punches; the signed record lists only the Server's private
address, the Client spends its whole attempt budget on that silent candidate, and relay-first
negotiation still produces no direct path. This section changes no product code and no oracle.

**Superseded recommendation.** The earlier revision of this section recommended an owned
iroh-relay QAD server (its mechanisms M1 and R1) and, as an alternative, an own UDP reflector
(M5). Both are superseded by the **owner decision of 2026-11-14**: the public (reflexive)
address of a device and the coordination of a hole punch must come from what the products
already use — the Mainline DHT, Yggdrasil, libp2p signaling (signaling only, never application
data) and QUIC itself; there is **no dedicated helper or relay server**. The same day, the
first public smoke (run 43629141158) showed a public libp2p bootstrap used as the signaling
relay accepting TCP while the Server never completed its reservation (3 connections about 13 s
apart, then the harness stopped it on the relay-connection budget); public Yggdrasil peers and
DHT bootstrap nodes worked. The owner decided that **DHT and Yggdrasil are the only helper
infrastructure**, which adds relay-optional composed startup as an explicit early leaf (L0).
Still-valid evidence and mechanisms of the earlier revision are kept below (§1; the QUIC
observed-address mechanism M2 becomes D3; the counter logic in §4 is unchanged).

Claims are labeled: **read** = read in source or in a recorded run receipt; **inferred** =
derived from that reading, not separately proven; **unknown** = not establishable here.

References: `repo` = this repository. `iroh 1.3.0`, `noq-proto 1.3.0` and `iroh-relay 1.3.0`
are the pinned upstream sources. `n0-mainline 0.7.0` is the pinned source whose reviewed local
adapter (`.github/scripts/p2p/discovery/mainline/prepare.py` injecting `owner.rs`) is compiled
as `target/native-graph/n0-mainline-0.7.0` (workspace `Cargo.toml:26`). All are read from the
already-prepared local DATA (extracted crates.io bytes kept under the primary checkout's
`.rush/downloads`; CI preparation applies the reviewed `prepare.py`/`policy.py`/`runtime.py`
edits on top of exactly these bytes — the `replace()` anchors in those scripts prove the cited
lines exist in the prepared trees too).

### 1. What the products do today (read)

**Endpoint construction.** `bind_custom_shared` builds the native endpoint with
`iroh::Endpoint::builder(presets::Minimal)` (repo
`crates/shaar/src/network/admission/mod.rs:197`), `clear_ip_transports()` plus one explicit
`bind_addr` (`:200-202`), `PortmapperConfig::Disabled` (`:214`) and
`NetReportConfig::minimal()` (`:215`). The QUIC transport config (`:184-196`) sets filters,
windows and stream limits but never enables observed-address reporting. In pinned iroh,
`presets::Minimal` sets only the TLS crypto provider (`iroh 1.3.0
src/endpoint/presets.rs:57-79`), and the empty builder defaults to "no address lookup
services" with `RelayMode::Disabled` (`iroh 1.3.0 src/endpoint.rs:192`).

**Why nothing reflexive is learned.** iroh's net_report client — the only component that
derives reflexive addresses — skips entirely on an empty relay map (`iroh 1.3.0
src/socket.rs:794`), and its QAD probes additionally require IP transports
(`src/socket.rs:1036-1049`). The products configure no iroh relay, so
`update_direct_addresses` (`src/socket.rs:1801-1877`) can only ever merge `Portmapped`
entries (disabled), `Local` entries (bound/interface addresses) and `Config` entries
(explicitly injected). `watch_addr()` (`src/endpoint.rs:1289-1301`) is what the SDK publishes
from; with no relay it yields only local addresses (repo watcher:
`crates/shaar/src/network/admission/mod.rs:267-269`). For the A5 Server, bound to one
specific private address, the record lists exactly that entry.

**Publication.** Startup maintenance feeds the record publisher from the endpoint's address
watcher: `crates/shaar/src/startup/resources/start.rs:496` →
`crates/shaar/src/startup/resources/maintain.rs:269`, bounded to 4 `TransportAddr::Ip`
entries (`crates/shaar/src/startup/resources/mod.rs:39`;
`crates/shaar/src/native_discovery/address.rs:8,25-41` — `Relay`/`Custom` entries are
rejected, `:33-36`). The record carries bare socket addresses only; the reflexive/local
distinction is not serialized
(`crates/shaar/src/native_discovery/runtime/publisher.rs:168-185`, the `EndpointData` of
`TransportAddr::Ip` at `:180`).

**Candidate dialing and the ordering defect.** `NativeDialer::dial`
(`crates/shaar/src/startup/role/dialers.rs:150-201`) resolves the record into at most 4
candidates (`:27`, `:90-117`; resolve budget 5 s at `:30`) and dials them sequentially, each
under the full remaining attempt deadline (`:163`). A silently dropped candidate (unroutable
private address) neither errors nor completes: the timeout arm returns `Err(DialError)` and
ends the whole attempt (`:179`); `candidates.remove(0)` runs only for typed errors (`:177`),
and the list survives across policy attempts until observed loss (`:91-93`, `:206-211`), so
every retry burns on the same silent candidate. One native attempt is 3 s
(`crates/shaar/src/path/model.rs:83,99`), up to 6 attempts (`:102`), then the Client ends
with "no usable path remained within the attempt budget"
(`crates/shaar/src/startup/error.rs:71`) — matching the recorded 32.6 s A5 exit. Relay
negotiation (`dialers.rs:183-201`) sits after the candidate loop, so direct-first never
reaches it; relay-first (empty candidate list, DHT dropped) reaches it and did exchange
signaling (`relay_tcp` about 290-300 per router, scenarios.md §10.2 row A5).

**Rendezvous infrastructure today.** The libp2p carrier runs a relay client, a control
behavior and a request-response datagram protocol
(`crates/shaar-p2p/src/carrier/driver/mod.rs:99-103`; datagrams bounded to 1500 B,
`crates/shaar-p2p/src/packet.rs:7-28`; delivered only on authenticated, allowlisted
application connections, `driver/mod.rs:592-600`), with identify/kad control that hides
listen addrs and disables the address cache
(`crates/shaar-p2p/src/carrier/driver/runtime/protocols/mod.rs:59-66`); no native candidate
list is exchanged over signaling. `connect_via` mints a per-link synthetic `CustomAddr`
(`crates/shaar-p2p/src/bridge/mod.rs:74-81`) and the custom transport fabricates `RecvInfo`
sources from that minted address (`:178`), so a QUIC connection carried over the relay
observes synthetic addresses, never a NAT mapping. `native_ready` waits for any eligible
Native IP path on the connection (`crates/shaar/src/network/session.rs:31-47`; `native_ip`
admits every IPv4 address, `crates/shaar/src/network/admission/policy.rs:60-66`). The
Yggdrasil bridge pairs allowlisted peers by their 32-byte keys and carries bounded datagrams
plus a probe (`crates/shaar-ygg/src/bridge/mod.rs:204,264,273`), but the standby owner never
dials the Ygg side in signal mode (fallback dials 0, Ygg accepts 0 —
`crates/shaar/src/network/admission/ygg/standby_tests/forwarding.rs:345-395`;
`crates/shaar/src/startup/role/dialers.rs:268-287`).

**The relay is mandatory today.** The ktav schema requires both `network.signaling.relay`
and `network.signaling.relay_address`
(`crates/shaar/src/config/network/mod.rs:276-305`, `MissingRequired` at `:285-297`), the
Server retries relay reservations at startup and exits with `RelayReserve` when they fail
(`crates/shaar/src/startup/role/server.rs:420-434`, `:430`), and the Client dialer is
constructed with a validated relay address taken from the signaling settings
(`dialers.rs:53-59,124-135`). A zero-configuration first run therefore has no usable
signaling path when no relay is configured, and the public smoke above failed exactly at the
reservation step.

**Verdict on the probable cause.** Confirmed as the primary cause: neither endpoint has any
source of its own reflexive (NAT-mapped) UDP address, so the record cannot carry a dialable
public candidate and neither side can fire the first datagram toward the other's mapped
endpoint. The A5 relay-variant counters (`native_out` 7/8 with `peer_recv` 0 on both routers)
are consistent with both endpoints emitting translated Native UDP toward unusable
destinations — inferred; the exact targets are unknown (not logged by the harness).

### 2. Mechanisms without a helper server

**D1 — Mainline DHT as the reflexive-address source.** The pinned `n0-mainline 0.7.0`
already implements BEP 42 end to end: every KRPC response can carry the `ip` field, parsed
into `requester_ip: Option<SocketAddrV4>` (`src/common/messages.rs:25`, parse `:498-499`,
`bytes_to_sockaddr` `:807-818`, reply serialization `:273-274`); every response to an
iterative query casts a vote (`src/core/handle_response.rs:70-71` →
`src/core/iterative_query.rs:152-156`); the most-voted address wins (`best_address`,
`iterative_query.rs:129-141`); votes are collected from finished GET queries
(`src/core.rs:180-200`) and overwrite `public_address` after each query (`core.rs:388-389`).
The value is exposed: upstream `Dht::info()` (`src/dht.rs:172`) → `Info::public_address()`
(`src/actor/info.rs:35-37,76`), and the reviewed adapter exposes the same through the owned
API (`OwnedDhtHandle::info()`,
`.github/scripts/p2p/discovery/mainline/owner.rs:222-233`), which the products already hold
(`crates/shaar/src/native_discovery/runtime/owner/mod.rs:12,158,406`). So: parse yes, vote
yes, expose yes — the SDK only has to read it.

Reliability and caveats: `best_address` is a per-query majority with nondeterministic tie
breaking (HashMap iteration, `iterative_query.rs:133-139`); the "changed address → confirm by
pinging" branch is dead in this pinned version (the overwrite at `core.rs:389` precedes the
comparison at `:391-408`), so `firewalled()` (`actor/info.rs:43-45`, cleared only by the
self-ping path, `src/core/handle_request.rs:93-118`) must not gate any product decision —
read. Client-side votes arrive with the normal record resolve (a GET query); on the Server
side only GET queries vote and publication is a PUT (`core.rs:194-199`), so whether any
current Server operation yields fresh votes is **unknown** — L2 must add one bounded periodic
self-lookup (for example resolving the Server's own key) and measure freshness. The observed
address is the mapping of the **DHT socket**, which `OwnedDht::new` binds separately
(`owner.rs:469-485`; repo bind at
`crates/shaar/src/native_discovery/runtime/owner/mod.rs:191`) from the QUIC socket
(`admission/mod.rs:201-202`) — inferred from the socket topology, consistent with the
config surface (`bind: <ip>:0`, harness `runtime/configs.py:31-33`). What can safely be
derived: the **public IP** (a per-router property shared by sibling sockets — inferred); the
**port never directly** (it is the DHT socket's own port); the QUIC port only under a
port-preserving mapping (D2).

**D2 — The QUIC socket's external port.** Under port-preserving cone NAT the external port of
the QUIC socket equals its local port, which the product already knows (`local_addr`,
`admission/mod.rs:253-255`; `bound_sockets`, `:227-237`). The derived punch candidate is
therefore `(DHT-voted IP, QUIC local port)` — a guess that is wrong only when the port was
taken or the mapping is not port-preserving. Fixture flavors (read: `network.py:42` —
`range` maps to `:41010-41020`, `cone` preserves the source port, `random` is
`masquerade fully-random`; measured by `flows/natprobe.py:9-14` kept/moved counters and the
A5/A6 live probes: cone 3/3 kept, random 0/3): `cone` → candidate exact; `range` → an
11-port candidate set could be probed birthday-style, but a product cannot know a router's
configured range, so multi-port prediction is **out of scope**; `random` → prediction
impossible within any bounded budget, punch not attempted, today's behavior preserved (A6
stays fail closed). Probe bursts are the QUIC Initials themselves: the candidate list is
bounded (≤4), so the burst is bounded; no extra datagram protocol on the data path.

**D3 — QUIC observed-address frames between the endpoints (kept from M2).** Pinned noq-proto
implements draft-seemann-quic-address-discovery end to end (`src/address_discovery.rs`;
transport parameters `src/transport_parameters.rs:118,148,198`; `TransportConfig` toggles
default-off, `src/config/transport.rs:369-385,590`), and iroh tolerates but discards the
events (`src/socket/remote_map/remote_state.rs:635`). Useful on true UDP paths to verify a
punch in band and refresh mappings; over the custom transport the observed source is the
minted `CustomAddr` (`bridge/mod.rs:178`), so a consumer must filter by transport kind. No
new infrastructure; a secondary refinement, not the reflexive source.

**Explicitly out.** Owned-relay QAD (M1) and the own UDP reflector (M5): superseded — each is
a helper server. libp2p identify observed addresses (M3): over a relayed TCP circuit the view
is not a UDP mapping (kept as before). AutoNAT/DCUtR (M4): absent from `Cargo.lock` and
TCP-dial-back — not proposed. Portmapper (NAT-PMP/PCP/UPnP): forbidden by the project rules
and already disabled (`admission/mod.rs:214`). noq's n0 NAT-traversal frames
(`noq-proto 1.3.0 src/n0_nat_traversal.rs`) are unreferenced in pinned iroh — dead code for
this composition (read). The compile-witness dependency `iroh-mainline-address-lookup 0.6.1`
publishes self-declared endpoint data and does not consume `ip` votes
(`selected-source/iroh-mainline-address-lookup/src/lib.rs:265-356`; used only as a trait
witness, `.github/probes/native-graph/fixture/witness.rs:9,13,55`) — it stays a witness, not
a mechanism.

### 3. Recommended design (R1-R5)

**R1 — dial-ordering fix (first leaf).** In
`crates/shaar/src/startup/role/dialers.rs`: classify candidates (public/reflexive scope
first, private/local scope last — RFC 1918, CGNAT 100.64/10, loopback, link-local and the
synthetic fabric prefix count as "local"; inferred heuristic, the record carries no address
types), bound each candidate's `connect` to `min(remaining deadline, 1 s)` instead of the
whole attempt deadline (`:163`), drop a timed-out candidate from the list instead of ending
the attempt (`:179`), and keep typed-error handling (`:174-178`), the total budget, backoff
and the `Exhausted` exit (`model.rs:83,99,102`; `error.rs:71`) unchanged. With four
candidates the worst case spends about 4 s inside one attempt, so relay/punch negotiation is
reached within the same attempt instead of never. P10 interaction: the policy keeps owning
attempts and fallback; the slice only bounds work inside one attempt, so the first-byte
criterion (3 s with a known address — a good first candidate still connects immediately; a
silent first candidate costs its 1 s slice and the second candidate still lands inside 3 s)
and the 10 s failover criterion are not weakened.

**R2 — relay-optional composed startup (early leaf L0).** Parse the relay pair as optional:
`SignalingNetwork` carries the relay as `Option<(PeerId, SocketAddr)>` instead of required
fields (`config/network/mod.rs:128-152,276-305`); absent fields validate cleanly, present
fields behave byte-identically to today. With no relay: the Server skips reservation entirely
(`server.rs:420-434` — no attempts, no `RelayReserve`), the Client constructs `NativeDialer`
without a relay lease (`dialers.rs:124-135` skipped), and negotiation rides the Yggdrasil
bridge (R5). With a relay configured, nothing changes: the carrier keeps its relay client and
the signaling-only rule — the relayed carrier QUIC still never carries application data (C8
evidence stands; the publisher still rejects `Relay` entries, `address.rs:33-36`), so
optionality does not weaken signaling-only.

**R3 — DHT reflexive-IP exposure (read-only).** Extend the discovery runtime owner to poll
`OwnedDhtHandle::info()` (adapter `owner.rs:222-233`) and publish the voted public IP through
a bounded watcher; add one bounded periodic self-lookup so votes stay fresh (the Server has no
GET query today — D1); no record or wire change. The vote source is untrusted, so the value
is advisory input to R4/R5, never an address the product treats as authenticated.

**R4 — record-carried reflexive candidate (flagged, default-off).** The publisher may add
one extra entry `(voted IP, QUIC local port)` to the ≤4 record addresses
(`publisher.rs:168-185`; validation `address.rs:25-41` unchanged — still bare
`TransportAddr::Ip`), behind an explicit ktav flag; default-off keeps today's record bytes
exactly. Purpose: the cold-start path (north-star steps 3-4, 10 s cold criterion) needs a
dialable public candidate even when no rendezvous channel exists (A5 had Ygg denied), and it
alone suffices when the Server's NAT admits unsolicited inbound to its mapped endpoint; the
exchange (R5) covers stricter filtering. The disclosure trade-off (the site's public IP
becomes resolvable under the key) and the spoofing bound (wrong votes publish a wrong address
that cannot authenticate) are recorded in §6; the default is an owner decision.

**R5 — punch coordination over an authenticated rendezvous.** Channel: the Yggdrasil bridge
when Ygg peers are configured (datagrams bounded by the bridge queues,
`shaar-ygg/src/bridge/mod.rs:264`; peers allowlisted by 32-byte key, `:204`; the probe at
`:273` pre-measures RTT to size the timing window), else the relay carrier datagrams when a
relay is configured (≤1500 B, authenticated application connections only,
`shaar-p2p/src/carrier/driver/mod.rs:592-600`, send at `:417`). Message: one small typed
datagram `version | punch epoch | ≤4 candidate endpoints | flags`, well under the 1500 B
budget. Who initiates: only the authenticated dialing side (Client) on dial start and on
candidate change; the Server answers once with its own candidate set and starts its punch
burst on sending that reply, the Client on receiving it, so both mappings open within one RTT
plus a bounded jitter window; the Server never emits datagrams toward a candidate it did not
learn from an authenticated, allowlisted peer link (no unsolicited poking). Both sides then
fire a bounded burst of QUIC Initials at each other's candidates (iroh completes whichever
direction arrives first; a received Initial is answered from its observed source, so a
mapping-preserving Server needs no pre-knowledge of the Client endpoint — inferred). Timing:
exchanges ride the existing attempt cadence (≤6 attempts, `model.rs:102`), one exchange per
direction per attempt; per-candidate slices (R1) bound the punch wait; the whole punch stays
inside the native attempt, so direct-first priority and the 10 s failover envelope are
unchanged. Order inside one attempt: record candidates → exchange+punch (bounded) → relay
negotiation (if configured) → attempt ends; policy retries as today. Modes: in `signal` the
Ygg bridge carries only these control datagrams (payload stays Native; the bridge already
proves negotiation without sessions, `forwarding.rs:345-395`); in `standby` the Ygg payload
fallback is unchanged and policy returns payload to Native after the punch (existing
`stable_hold` semantics).

Security and bounds: peer-claimed endpoints are dial/punch targets only for
already-authenticated allowlisted peers and are **never published** — the record is fed only
by the local endpoint watcher chain (`admission/mod.rs:267-269` → `maintain.rs:269`) and R4
adds only locally derived values; a spoofed DHT vote worst case publishes a wrong candidate
that cannot complete a handshake (cert bound to the Server key) and costs one bounded slice;
amplification is bounded to one ≤1500 B exchange per direction per attempt plus ≤4 Initial
bursts per candidate set; allowlist checks precede any target connection (G1/G2 evidence
unchanged); binding of exchange datagrams to the authenticated link reuses the carrier/bridge
admission gates; resource caps: ≤4 candidates per message and record (`resources/mod.rs:39`,
`address.rs:8`), existing queue bounds unchanged, no per-packet allocations on the data path.
When the toolkit has no information (no votes, no exchange), candidates are exactly today's
record addresses and behavior degrades to today's outcomes (A5 fail closed in signal, A6
standby fallback).

Non-goals: no symmetric-NAT punching claim (random mappings stay fail closed / standby); no
public STUN, no n0, no helper or relay server, no router configuration, no new dependencies;
no IPv6 NAT acceptance; no change to Yggdrasil standby semantics; no product behavior change
when the reflexive sources are unavailable.

### 4. Test plan against the existing namespace harness

Oracles expected to flip once R1-R5 are implemented (each flip is a new hypothesis needing
its own executed evidence): `dnat-cone-signal`, `dnat-cone-relay-signal`,
`dnat-cone-standby`, `dnat-cone-relay-standby` (A5) expect a direct path — exact APP, target
accepts 1, Client exit 0, `peer_sent`/`peer_recv` > 0 on both routers, `ygg_tcp` 0 on the
Client-side router. The relay variants additionally keep `dht_drop` > 0 and `relay_tcp` > 0,
proving negotiation came from signaling, not the record; with R2 a new `dnat-cone-norelay-*`
case proves the punch with **no `network.signaling.*` relay fields at all** (rendezvous over
Ygg). `dnat-sym-signal`/`dnat-sym-standby` (A6) deliberately do NOT flip — they remain the
negative control. New negative guards: cone with DHT responses denied on the Client side must
fail closed again (proves the flip depends on the reflexive source, not harness accident);
`relay-absent-startup` (standby, no relay config): the Server starts, Ygg carries payload,
exit 0 — the L0 acceptance; a Server config that still names a relay must produce startup
behavior and counters identical to today (regression control).

Fixture changes: the owned Mainline fixture (bootstrap at `wan:dht`,
`runtime/configs.py:31-33`) must include the BEP 42 `ip` field in its KRPC responses and
report the per-peer observed addresses in its status output, so the oracle can assert what
each product learned; the in-process responder fixture
(`crates/shaar/src/native_discovery/runtime/tests/fixture/wire.rs`) is the unit-level seam
for vote-parsing tests. Touch points (no code written yet): case entries in
`runtime/phase.py` `GROUPS` (`:56-61`, `--group` at `:296`), roles in `flows/scenarios.py`
and `processes.py`, budgets in `contract.py`; `flows/` holds 6 items (one new module
allowed), `runtime/` holds 7 (must not grow). Every new owned source enters the ordinary
impact map (`.github/ci/policy.py`); the per-group 20-minute phase and 2 MiB/router quotas
are unchanged.

How counters prove direct data without relay or Yggdrasil payload: `peer_recv` > 0 on both
routers is the only counter that grows when translated Native UDP actually reaches the other
router (the A5 failure had `native_out` 7/8 with `peer_recv` 0); a direct-path oracle asserts
`peer_sent`/`peer_recv` growth consistent with the APP transaction on both routers together
with exact APP bytes and target accepts 1, while `ygg_tcp` 0 excludes the Ygg path. Relay
payload exclusion: payload over the relay would show as continued `relay_tcp` growth with
`peer_recv` static; the flipped oracles require `peer_recv` growth consistent with the APP
transaction, matching the accepted `dht-drop-signal` oracle pattern that reads `relay_tcp` as
signaling traffic. The fixture punch control stays recorded and non-decisive (its
un-dispatched amendment still needs its own dispatch).

### 5. Leaves, effort, parallelism

Each leaf has authored tests and ordinary CI; no local build/test per project rules.
Privileged = needs its own namespace dispatch grant (the six-dispatch remaining-row budget is
fully used; the punch-control amendment is still un-dispatched).

- **L1 (first) — dial ordering** (R1). Files: `crates/shaar/src/startup/role/dialers.rs` and
  its tests. Acceptance: with a record whose first candidate is silent and a second dialable,
  the dial reaches the second candidate inside one attempt, timed-out candidates are dropped
  from the list, and the Client exits through the unchanged `Exhausted` path when nothing
  works. Ordinary CI; effort S. Blocks L0 (same file) — run sequentially.
- **L0 (early) — relay-optional startup** (R2). Files:
  `crates/shaar/src/config/network/mod.rs`, `crates/shaar/src/startup/role/server.rs`,
  `crates/shaar/src/startup/role/dialers.rs`, startup resources wiring, config tests.
  Acceptance: a composed Server and Client with **no** `network.signaling.relay*` fields
  start, negotiate over Yggdrasil and complete the standby payload exchange; with the relay
  fields present, behavior is identical to today (the typed `RelayReserve` failure on a dead
  relay is preserved). Ordinary CI; effort M.
- **L2 — DHT reflexive exposure** (R3). Files:
  `crates/shaar/src/native_discovery/runtime/owner/mod.rs` plus seam/wiring tests (the
  `owner/` directory holds 7 items — extend existing files, add none). Acceptance: a fixture
  responder casting `ip` votes yields the majority address through the owner watcher, and one
  bounded self-lookup keeps it fresh. Ordinary CI; effort S-M. Independent of L1/L0 (disjoint
  files) — can run in a separate worktree in parallel.
- **L3 — record-carried reflexive candidate** (R4). Files:
  `crates/shaar/src/native_discovery/runtime/publisher.rs`,
  `crates/shaar/src/native_discovery/address.rs`, startup resources wiring, ktav flag tests.
  Acceptance: with the flag on and votes present, the record gains exactly one extra entry
  (voted IP, local QUIC port), still bounded to 4; with the flag off the record bytes equal
  today's. Ordinary CI for units; depends on L2; owner decision gate on the default.
- **L4 — punch coordination** (R5). Files: `crates/shaar/src/network/signaling/` extensions
  (7 items — extend, add none or restructure), `crates/shaar-ygg/src/bridge/` extensions
  (7 items — same constraint), `crates/shaar/src/startup/role/` wiring. Acceptance: two
  products behind double port-preserving cone NAT with the DHT denied and no relay configured
  exchange candidates over the Ygg bridge and complete an exact-APP exchange over Native with
  zero Ygg payload in signal mode. Units in ordinary CI; the namespace proof needs a
  privileged dispatch. Depends on L0 (no-relay path); independent of L3. Effort L.
- **L5 — harness**: DHT fixture `ip` votes plus observed-address reporting, the new cases and
  oracle flips (`flows/scenarios.py`, one new `flows/` module, `processes.py`,
  `runtime/phase.py`, `contract.py`, impact map). The fixture vote support is independent of
  product code and can start in parallel; the flipped oracles land only with L3/L4.
  Privileged dispatch; effort M-L.
- **L6 — verification dispatch**: operator-run, after a new dispatch grant; produces the
  receipts that move scenarios.md §10.2 rows A5/A6.

Parallel sets (disjoint file sets): {L2} ∥ {L1 → L0} ∥ {L5 fixture part}. L3 after L2; L4
after L0; L5 oracle flips and L6 last.

### 6. Honest limits and owner decisions

Not establishable without real devices: RFC 4787 mapping/filtering flavors beyond the two
conntrack mappings, port-overload and port-reuse behavior, hairpinning, CGNAT, mobile and
IPv6-only networks, real Mainline DHT vote reliability and latency (the fixture has one DHT
node — a single respondent, no majority), Windows/macOS behavior, and any 95th-percentile
timing claim (one dispatch run per case). The pinned vote pipeline has known softness: the
confirm-by-ping branch is dead (`core.rs:391-408`), tie breaking is nondeterministic, and
`firewalled()` must not be trusted; a wrong-but-consistent set of respondents can shift the
voted address, which the design bounds but does not eliminate.

Owner decisions still open (scope decisions are the owner's): (1) the default of R4 —
publish the reflexive guess in the signed record vs exchange-only, accepting the public-IP
disclosure trade-off; (2) a new privileged dispatch grant for the flipped oracles and the
punch cases, sequenced with the still-un-dispatched punch-control amendment; (3) whether the
periodic self-lookup (L2) and the punch probe bursts fit the efficiency budget (bounded: one
lookup per refresh window, ≤4 candidates per attempt); (4) the exact ktav field shape for the
R4 flag, reviewed together with the L0 schema change that makes the signaling relay pair
optional; (5) confirm that a punched direct path always outranks standby Yggdrasil payload
(north-star step 4) once a punch exists.
