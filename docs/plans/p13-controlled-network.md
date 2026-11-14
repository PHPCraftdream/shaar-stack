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

## Reflexive address source for double-NAT punching (proposal)

Status: **proposal, not implemented** (written 2026-11-14). It answers the A5 finding
(scenarios.md §10.2, row A5): with a port-preserving cone NAT on each router and Yggdrasil
denied, neither product direction punches; the signed record lists only the Server's private
address, the Client spends its whole attempt budget on that silent candidate, and relay-first
negotiation still produces no direct path. This section changes no product code and no oracle.
Claims are labeled: **read** = read in source or in a recorded run receipt; **inferred** =
derived from that reading, not separately proven; **unknown** = not establishable here.

References: `repo` = this repository. `iroh 1.3.0`, `noq-proto 1.3.0` and `iroh-relay 1.3.0`
are the pinned upstream sources, read from the already-prepared local DATA (extracted
crates.io bytes kept under the primary checkout's `.rush/downloads`; CI preparation applies
the reviewed `prepare.py`/`policy.py`/`runtime.py` edits on top of exactly these bytes — the
`replace()` anchors in those scripts prove the cited lines exist in the prepared trees too).

### 1. What the products do today (read)

**Endpoint construction.** `bind_custom_shared` builds the native endpoint with
`iroh::Endpoint::builder(presets::Minimal)` (repo `crates/shaar/src/network/admission/mod.rs:129`),
`clear_ip_transports()` plus one explicit `bind_addr` (`:132-133`), `PortmapperConfig::Disabled`
(`:146`) and `NetReportConfig::minimal()` (`:147`). The QUIC transport config (`:116-127`) sets
filters, windows and stream limits but never enables observed-address reporting. In pinned
iroh, `presets::Minimal` sets only the TLS crypto provider (`iroh 1.3.0 src/endpoint/presets.rs:57-79`),
and the empty builder defaults to "no address lookup services" with `RelayMode::Disabled`
(`iroh 1.3.0 src/endpoint.rs:192`).

**Why nothing reflexive is learned.** iroh's net_report client — the only component that
derives reflexive addresses — skips entirely on an empty relay map (`iroh 1.3.0
src/socket.rs:794`, "skipping net_report, empty RelayMap"), and its QAD probes additionally
require IP transports (`src/socket.rs:1036-1049`). The products configure no iroh relay, so
`update_direct_addresses` (`src/socket.rs:1801-1877`) can only ever merge `Portmapped` entries
(disabled), `Local` entries (bound/interface addresses, `:1881-1955`) and `Config` entries
(explicitly injected, `:1870-1872`). `watch_addr()` (`src/endpoint.rs:1289-1301`) is what the
SDK publishes from; with no relay it yields only local addresses. For the A5 Server, bound to
one specific private address, `collect_local_addresses` adds exactly that entry. This
confirms the recorded fact that the record lists only `10.0.2.2:<port>`.

**Publication.** Startup maintenance feeds the record publisher from the endpoint's address
watcher: `crates/shaar/src/startup/resources/start.rs:496` →
`crates/shaar/src/startup/resources/maintain.rs:269`, bounded to 4 `TransportAddr::Ip`
entries (`crates/shaar/src/startup/resources/mod.rs:39`;
`crates/shaar/src/native_discovery/address.rs:8,25-40` — `Relay`/`Custom` entries are
rejected, `:32-38`). Whatever iroh reports in `watch_addr()` therefore becomes the signed
Mainline record; a reflexive address would flow into the record with no publisher change.
The record carries bare socket addresses only — the reflexive/local distinction is not
serialized (`crates/shaar/src/native_discovery/runtime/publisher.rs:171-180`).

**Candidate dialing and the ordering defect.** `NativeDialer::dial`
(`crates/shaar/src/startup/role/dialers.rs:150-201`) resolves the record into at most 4
candidates (`:27`, `:90-117`; resolve budget 5 s at `:30`) and dials them sequentially, each
under the full remaining attempt deadline (`:163`). A silently dropped candidate (unroutable
private address) neither errors nor completes: the timeout arm returns `Err(DialError)` and
ends the whole attempt (`:179`); `candidates.remove(0)` runs only for typed errors (`:177`),
and the kept list survives across attempts (`:91-93`), so every retry burns on the same
silent candidate. One native attempt is 3 s (`crates/shaar/src/path/model.rs:83,99`), up to 6
attempts (`:102`), then the Client ends with "no usable path remained within the attempt
budget" (`crates/shaar/src/startup/error.rs:71`) — matching the recorded 32.6 s A5 exit.
Relay negotiation (`dialers.rs:183-201`) sits after the candidate loop, so direct-first never
reaches it; relay-first (empty candidate list, DHT dropped) reaches it and did exchange
signaling (`relay_tcp` about 290-300 per router, scenarios.md §10.2 row A5).

**What signaling exchanges today.** The libp2p carrier runs a relay client, a control
behavior and a request-response datagram protocol
(`crates/shaar-p2p/src/carrier/driver/mod.rs:99-103`). The control behavior runs identify and
kad with listen addrs hidden and the peer-address cache disabled
(`crates/shaar-p2p/src/carrier/driver/runtime/protocols/mod.rs:60-65`); no native candidate
list is exchanged over signaling. `connect_via` mints a per-link synthetic `CustomAddr`
(`crates/shaar-p2p/src/bridge/mod.rs:58,76-81`) and the custom transport fabricates `RecvInfo`
sources from that minted address (`:170-178`), so a QUIC connection carried over the relay
observes synthetic addresses, never a NAT mapping. `native_ready` waits for any eligible
Native IP path on the connection (`crates/shaar/src/network/session.rs:33-49`; `native_ip`
admits every IPv4 address, `crates/shaar/src/network/admission/policy.rs:60-66`).

**Verdict on the probable cause.** Confirmed as the primary cause: neither endpoint has any
source of its own reflexive (NAT-mapped) UDP address, so the record cannot carry a dialable
public candidate and neither side can fire the first datagram toward the other's mapped
endpoint. The A5 relay-variant counters (`native_out` 7/8 with `peer_recv` 0 on both routers)
are consistent with both endpoints emitting translated Native UDP toward unusable
destinations — inferred; the exact targets are unknown (not logged by the harness).

### 2. Mechanisms actually available in the pinned stack

For each mechanism: what it needs, whether it fits "libp2p is signaling only, never
application data", whether it needs infrastructure beyond an owned relay (no n0), and its
failure modes.

- **M1 — iroh net_report QAD against an owned iroh-relay.** Pinned iroh runs QAD probes
  (QUIC Address Discovery, draft-ietf-quic-address-discovery) as part of net_report whenever
  the relay map is non-empty (`iroh 1.3.0 src/socket.rs:794`); `NetReportConfig::minimal()`
  only disables the HTTPS and captive-portal probes, not QAD
  (`src/net_report.rs:88-121,115-121`). Probe results land in
  `update_direct_addresses` as `DirectAddrType::Qad` (`src/socket.rs:1832-1837`, plus the
  hard-NAT `Qad4LocalPort` guess `:1845-1862`) and then flow into `watch_addr()` → the
  Mainline record automatically. The server side of QAD exists in pinned `iroh-relay 1.3.0`
  (`src/quic.rs`: ALPN `"/iroh-qad/0"`, per-connection handler, self-signed TLS server cert;
  the crate archive is part of the authorized 2026-11-09 registry acquisition, record #187).
  Needs: one owned iroh-relay process on the WAN fixture host with a QUIC (UDP) port, and a
  product-side builder change (`relay_mode(RelayMode::Custom(map))` +
  `clear_relay_transports()`, `iroh 1.3.0 src/endpoint.rs:568-578,517-522` — inferred
  composition: the relay map keeps driving net_report while the relay transport is removed,
  so the iroh relay can never carry payload; must be verified in CI). No n0 infrastructure.
  Fits signaling-only libp2p (the iroh relay is not libp2p and carries only QAD control).
  Failure modes: relay unreachable → no report → record stays local-only (today's behavior);
  first report latency delays the record update (full report interval 5 min,
  `src/net_report.rs:132`, event-driven on network change); no STUN is involved.
- **M2 — QUIC observed-address reports between the two endpoints.** Pinned noq-proto
  implements draft-seemann-quic-address-discovery end to end: `src/address_discovery.rs`
  (roles, `OBSERVED_ADDRESS`), transport-parameter negotiation
  (`src/transport_parameters.rs:118,148,198`), and `TransportConfig`
  `send/receive_observed_address_reports` toggles, default disabled
  (`src/config/transport.rs:369-385,590`). iroh already tolerates the resulting
  `NoqPathEvent::ObservedAddr` events but discards them
  (`iroh 1.3.0 src/socket/remote_map/remote_state.rs:635`). Caveat (read): over the product's
  custom transport the observed source is the minted `CustomAddr`
  (`crates/shaar-p2p/src/bridge/mod.rs:170-178`), so reports on a relay-carried connection
  would carry synthetic addresses, not NAT mappings. The mechanism is useful on true UDP
  paths (verification of a punch, in-band refresh), not for creating one. No new
  infrastructure; fits signaling-only (frames ride inside the existing QUIC connection).
  Failure modes: none beyond frame bytes if enabled on IP paths; misleading synthetic
  addresses if consumed on custom paths — a consumer must filter by transport kind.
- **M3 — libp2p identify observed addresses.** libp2p-identify 0.48.0 is in the lock and the
  behavior is running (`crates/shaar-p2p/src/carrier/driver/runtime/protocols/mod.rs:60-65`),
  but over a circuit-relayed TCP connection the observed address is the TCP/circuit view,
  not a UDP mapping; the repository additionally hides listen addrs and caches nothing.
  Does not fit the goal (wrong address family and path); no changes recommended.
- **M4 — AutoNAT / DCUtR.** `libp2p-autonat` and `libp2p-dcutr` are absent from
  `Cargo.lock`; adding them is a new dependency (a separate permission per project rules) and
  both are TCP-dial-back mechanisms that never produce UDP mappings for QUIC. Not proposed.
- **M5 — external injection via `Endpoint::add_external_addr` / `Builder::external_addr`.**
  Pinned iroh exposes explicit injection (`iroh 1.3.0 src/endpoint.rs:660-664,1026-1033`) →
  `DirectAddrType::Config` (`src/socket.rs:1870-1872`) → record. Usable with a tiny owned UDP
  reflector fixture (request/reply "your address is X") instead of iroh-relay: less pinned
  code reused, but a new product protocol module (client, refresh policy, bounds) and config.
  An alternative to M1, not an addition; owner's choice.
- **M6 — client record + server-side resolve.** The Server could resolve the Client's own
  signed record and dial its reflexive address. No wire change, but the Client must publish
  (extra Mainline writes) and the Server gains a dial path it does not have today; M1/M5 are
  still needed for the Client to have a reflexive address to publish.
- **Explicitly out:** iroh portmapper (NAT-PMP/PCP/UPnP changes the router; forbidden by the
  project rules and already disabled, `crates/shaar/src/network/admission/mod.rs:146`);
  noq's n0 NAT traversal frames (`noq-proto 1.3.0 src/n0_nat_traversal.rs`,
  `AddAddress`/`ReachOut`) exist in the pinned source but are unreferenced anywhere in
  pinned iroh — dead code for this composition (read).

### 3. Recommended minimal design

R1 (**reflexive source**, M1): configure an owned-relay `RelayMode::Custom` map carrying only
the fixture relay, immediately followed by `clear_relay_transports()`; keep
`PortmapperConfig::Disabled` and `NetReportConfig::minimal()`. The record gains `Qad` IPv4
entries with no publisher or dialer data-shape change. Relay address and its TLS cert reach
the products through configuration (new optional ktav field — schema question, below);
the feature is default-off, so behavior without configuration is exactly today's.

R2 (**server-side poke**): on establishing a relay-negotiated custom link, the Server sends
one bounded native dial (existing `Endpoint::connect`) toward the Client's reflexive endpoint
learned via R3, with a short self-imposed deadline. Purpose: create Router B's outbound
mapping so the Client's concurrent Initial can traverse. The poke creates no target TCP
connection and passes through the unchanged allowlist admission.

R3 (**signaling exchange**): extend the carrier's authenticated link with one small typed
message carrying the sender's current UDP reflexive endpoints (at most 4, ~100 B, sent on
link establishment and on change). Receivers use peer endpoints only as dial/poke targets —
never for publication into the signer's own record (no poisoning). On the wire this rides
the existing request-response carrier channel; no Mainline record format change (still ≤4
`TransportAddr::Ip` entries).

R4 (**ordering fix**, the silent-first-candidate defect): in
`crates/shaar/src/startup/role/dialers.rs`, classify candidates (reflexive/public-scope
first, private/local last), and bound each non-reflexive candidate's connect to a fixed
slice (for example 1 s) instead of the whole attempt deadline, so a silent candidate can
neither consume the 3 s attempt nor block relay negotiation; remove a timed-out candidate
from the list. Total attempt budget, retry/backoff policy and the `Exhausted` exit path stay
unchanged. Scope classification is heuristic on the dialer side because the record does not
carry address types (read, §1): treat RFC 1918, CGNAT 100.64/10, loopback, link-local and
the synthetic fabric prefix as "local"; everything else as "reflexive".

Security considerations: peer-claimed reflexive addresses are used only as poke/dial targets
for already-authenticated, allowlisted keys, bounded to a few small datagrams per negotiation
(amplification bound: an attacker client can direct at most a handful of ≤1200 B pokes while
its own authenticated link is live); locally observed QAD/Config/Local addresses are the only
ones ever published; the reflexive address in the signed record exposes the site's public
mapping to anyone resolving the key (already the case for private addresses today — recorded
as a consideration, not a blocker); spoofed QAD replies are impossible unless the owned relay
is compromised (it is owner infrastructure); the iroh relay cannot carry payload
(`clear_relay_transports()` + the publisher's `Relay` rejection,
`crates/shaar/src/native_discovery/address.rs:32-38`), preserving "libp2p is signaling only"
and no n0.

Resource bounds: one extra fixture process per dispatch; net_report cadence 5 min full plus
event-driven runs (`iroh 1.3.0 src/net_report.rs:132-133`); at most 4 reflexive endpoints per
message and record; pokes bounded per negotiation; no per-packet allocations on the data path.

Non-goals: no symmetric-NAT punching claim (A6 stays fail-closed in signal mode: with
`masquerade fully-random` the reflector-observed mapping differs from the peer-directed
mapping); no public STUN, no n0, no router configuration, no new dependencies; no IPv6 NAT
acceptance; no change to Yggdrasil standby semantics; no product behavior change when the
reflexive source is unavailable (fail closed / standby fallback exactly as recorded today).

### 4. Test plan against the existing namespace harness

Existing cases whose oracles flip once R1-R4 are implemented (each flip is a new hypothesis
needing its own executed evidence — see the dispatch question below):

- `dnat-cone-signal`, `dnat-cone-relay-signal` (A5): expect a direct path — exact APP, target
  accepts 1, Client exit 0, `peer_sent`/`peer_recv` > 0 on both routers, `ygg_tcp` 0 on the
  Client-side router. The relay variants additionally keep `dht_drop` > 0 and
  `relay_tcp` > 0, proving the punch came from relay negotiation (R3), not from the record.
- `dnat-cone-standby`, `dnat-cone-relay-standby` (A5): same direct-path oracle with
  `ygg_tcp` 0, so standby also proves the punch rather than the Yggdrasil fallback.
- `dnat-sym-signal` / `dnat-sym-standby` (A6): deliberately NOT flipped — they remain the
  negative control showing symmetric-like mapping still fails closed / falls back.

New cases needed:
- `dnat-cone-noqad-signal` (regression guard): QAD fixture UDP denied on the Client side;
  the whole case must reproduce today's recorded fail-closed outcome (exit 1, `peer_recv` 0).
  This proves the flipped oracles depend on the reflexive source, not on harness accident.
- `dnat-cone-reflx-only-standby` (R3 proof): QAD denied on the Server side, so the record
  has no dialable candidate; the Client advertises its reflexive endpoint over signaling and
  the Server's poke (R2) opens the server-side mapping. Punch must still complete.
- Optional: `dnat-sym-reflx-signal` — symmetric mapping with the feature on, expected still
  fail closed (guards against over-claiming).

How counters prove direct data without relay or Yggdrasil payload: `peer_recv` > 0 on both
routers is the only counter that grows when translated Native UDP actually reaches the other
router (the A5 failure had `native_out` 7/8 with `peer_recv` 0); direct-path acceptance
therefore asserts `peer_sent`/`peer_recv` > 0 on both routers together with exact APP bytes
and target accepts 1, while `ygg_tcp` 0 excludes the Ygg path. Relay payload exclusion: the
relay is libp2p TCP, so payload over it would show as continued `relay_tcp` growth with
`peer_recv` static; the flipped oracles require `peer_recv` growth consistent with the APP
transaction, matching the accepted `dht-drop-signal` oracle pattern that reads `relay_tcp`
as signaling traffic. The fixture punch control stays recorded and non-decisive
(this document's §Remaining-row notes, dispatch-5 amendment still un-dispatched).

Harness touch points (no code written yet): case definitions and fixtures live under
`.github/probes/nat-topology/quic/product/` — new role wiring in `flows/scenarios.py` and
`processes.py`, case entries in `runtime/phase.py` `GROUPS` (`:56-61`, `--group` at `:296`),
budgets in `contract.py`; a new QAD relay role likely needs one new module in `flows/` (6
items today — the 7-item directory limit allows exactly one more; `runtime/` is already at
7 items and must not grow). Every new owned source must enter the ordinary impact map
(`.github/ci/policy.py`). The per-group 20-minute phase and 2 MiB/router quotas are
unchanged; a new dispatch group (or an amended `nat` group) fits only if case count stays
within the existing arithmetic noted in this file's dispatch-group section.

### 5. Effort, risks, and what cannot be established here

Effort estimate in leaves (each leaf with authored tests and ordinary CI; no local
build/test per project rules): L1 — SDK: owned-relay QAD wiring (config field, builder
change, default-off, unit tests); L2 — SDK: dialer ordering fix R4 with candidate
classification tests; L3 — SDK: carrier reflexive-endpoint exchange R3 plus server poke R2
with tests; L4 — harness: QAD relay fixture role, new cases, impact map; L5 — oracle flips
and the first verification dispatch. Order L2 early: it is independent of R1-R3 and alone
fixes the "relay negotiation never reached" defect (signal mode would fail closed faster and
reach negotiation), but cannot produce a punch by itself.

Risks: the `relay_mode` + `clear_relay_transports` composition (R1) is inferred from source,
not executed — net_report may still require the relay transport in some path; iroh-relay TLS
cert distribution to products needs a config decision; QAD latency may delay the first
record publication (the 3 s known-address criterion applies to dialing, not to record
freshness; the cold-lookup 10 s criterion bounds the first useful record); OBSERVED_ADDRESS
events over custom transports carry synthetic addresses and must be filtered by transport
kind; Linux conntrack `masquerade` is not every home router (this file's NAT-type honesty
note), and the fixture punch control itself missed 2 of 4 cases in one dispatch for
unestablished reasons.

Not establishable without real devices: home-router NAT flavors beyond the two conntrack
mappings (port-restricted, full cone per RFC 4787 classes), CGNAT, real Mainline DHT and
relay latencies, Windows/macOS behavior (the namespace harness is Linux-only), and 95th
percentile timing claims (one dispatch run per case is one run).

Open questions for the project owner (scope decisions are the owner's):
1. Dispatch authority: the remaining-row budget of six dispatches is fully used (this file's
   execution records). Flipping A5-derived oracles and adding the new cases needs a new
   explicit dispatch grant; the still-un-dispatched punch-control amendment should be
   sequenced with it.
2. Config surface: an optional owned-QAD-relay address + TLS certificate in the ktav 0.8.*
   schema — allowed, and which field shape?
3. M1 (iroh-relay QAD, maximal reuse of pinned code) vs M5 (own UDP reflector +
   `add_external_addr`, minimal trusted-code surface but a new small protocol) — owner's
   preference.
4. Should the Client also publish its own reflexive record (M6) as a signaling-free
   alternative for the server-side poke, accepting extra Mainline writes?
5. Confirm standby policy wording: when a punched direct path exists, standby mode still
   prefers it over Yggdrasil (north-star step 4), with Yggdrasil kept as fallback only.
