# P13 controlled NAT and UDP-blockade execution contract

Status: **executed and accepted for the four product cases and the three cleanup
controls** — fork workflow_dispatch run 43229756778 on `ca6c04a` (2026-11-12),
phase status `pass`; see [Execution record](#execution-record-2026-11-12). This is
not full P13 acceptance: the open and gated rows are listed in the P13 report,
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
- Forwarded IP traffic: **64 MiB maximum across the privileged phase**. Product
  cases receive 7 MiB per router per case (56 MiB maximum total); live-failure and
  interruption controls receive 2 MiB per router each (8 MiB total). Setup-failure
  controls start no traffic. Namespace-local kernel quotas must enforce these
  allocations; a quota hit is a recorded failure, not a passing blockade.
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
- **Not covered by this contract or its run:** LAN, network change, IPv6 NAT,
  other NAT types, direct double-NAT punching, observed zero n0 contact, public and
  device scenarios. They stay open or gated in `docs/verification/scenarios.md`.
