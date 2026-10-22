# NAT Topology Calibration Probe (P03)

CI-only calibration fixture. It demonstrates, on a disposable GitHub-hosted
runner, that UDP flows are address+port translated by MASQUERADE in an
isolated network-namespace topology, and that matched-wrong / wrong-port /
no-forwarding cases are genuinely refused.

**Honesty note:** this is a *calibration* probe for NAT topology evidence. It
makes no claim about production TUN behavior and acquires root ONLY inside
the CI job (via `sudo`) on a throwaway runner to build network namespaces.
It never touches host firewall rules, routes, or `ip_forward`; host network
state is captured before the run and verified unchanged after cleanup
(any drift is a hard failure). Runtime verification happens ONLY in GitHub
CI — nothing in this probe has been executed locally. Calibration passed in
[run 39781462112](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39781462112)
at `733351a`, including normal, setup-failure, fixture-failure and SIGTERM
cases. Downloaded JSON artifacts confirmed both observed NAT tuples and
clean teardown with unchanged host state. This does not test QUIC traversal,
signaling-only STREAM exclusion, or migration, and does not close P03.

## Files

| File | Purpose |
|---|---|
| `run.sh` | builds the topology, exports `FIXTURE_CONFIG`, guarantees cleanup |
| `fixture.py` | orchestrator + responder/sender child roles (stdlib only) |
| `ctparse.py` | conntrack line parser (`conntrack -L` and `/proc` formats) |
| `childman.py` | child roles + tracked-subprocess wrapper; also the CI JSON validators and ROOT `supervise-interrupt` supervisor (CLI via `checks/selftest.py`) |
| `checks/selftest.py` | CI-only parser/oracle/lifecycle tests and validator CLI entry point |
| `checks/supervisor.py` | CI-only signal-mask, handler-restoration and owned-child reaping regressions |
| `out/case-<name>-<ts>/` | per-invocation runtime evidence (created during the run) |

## Topology

```
host-a (10.0.1.2) -- rtr-a (NAT, MASQUERADE --to-ports 41010-41020) --+
host-b (10.0.2.2) -- rtr-b (NAT, MASQUERADE --to-ports 41010-41020) --+-- wan bridge (203.0.113.10, responders)
host-off (10.0.3.2) -- rtr-off (ip_forward=0, NEGATIVE control) ------+
```

All three router WAN ends are enslaved to a bridge inside the `wan`
namespace (which itself neither bridges nor forwards), so 203.0.113.10 is a
true shared L2 segment: responder echoes ARP-flood the bridge and reach
every router's translated source. All namespace names carry a unique
per-invocation prefix `sn<6-hex>`; only resources created by the invocation
are tracked and deleted. Every veth endpoint moved into a namespace is
explicitly brought up there (including all three WAN ends behind the bridge).

## Per-invocation evidence directories

The workflow invokes `run.sh [--fault-inject-*] RUN_DIR NONCE` where `RUN_DIR`
is a fresh, unique per-case directory strictly inside `out/` (run.sh resolves
it against the probe directory, refuses `out/` itself or any path escaping
it, and fails if the directory already exists) and `NONCE` is a random per-
run hex token recorded in the run's artifacts. Each invocation writes every
artifact into that directory (setup log, host state snapshots, canonical
firewall snapshots, `prefix.txt`, `nonce.txt`, `run.pid`, `ns-removal.txt`,
`child-termination.txt`, `cleanup-evidence.json`, per-child `records/`
including the `children_started` phase marker, and `evidence.json` written
by `fixture.py`). Nothing under `out/` is reused between invocations.
`cleanup-evidence.json` records the case phase and reason (for injected
setups: phase `setup-injected` with the exact injected reason and the
created-namespace count) plus the original exit code, so the workflow's
strict validators can prove each case's identity and outcome; the phase
marker carries the nonce so it can be attributed to its own run.
`FIXTURE_CONFIG` carries the invocation directory and five unique per-run
16-byte-hex random `tokens` (`a`, `b`, `wrong`, `tuple`, `off`) — no
fixed-token assumptions anywhere.

## Deterministic translated ports (why the port assertion is sound)

Senders BIND a known private source port before sending (host-a `40001`,
host-b `40002`, outside the translated range). MASQUERADE is configured with a **fixed
port range** (`iptables ... -p udp -j MASQUERADE --to-ports 41010-41020`,
or nft `meta l4proto udp masquerade to :41010-41020`). Port-preserving NAT
is therefore
overridden: the observed source port MUST land in 41010-41020 and MUST
differ from the local port. If only a firewall without port-range MASQUERADE
is available, the fixture fails loudly rather than weakening the oracle.

## Controls

- **cal-a / cal-b (positive):** the SENDER sends through NAT and validates
  the SERVER endpoint: its own socket receives an exact-echo reply from
  `wan_ip:cal_port` with the exact expected payload. The RESPONDER
  independently observes the translated source (router WAN IP + translated
  port in 41010-41020), and that observation is correlated to the exact
  conntrack REPLY tuple (REPLIED entry, both tuples).
- **wrong-token:** unknown token still traverses NAT; the responder must
  record >=2 datagrams positively marked `known=false` for that token (and
  none marked known), with a REPLIED conntrack entry — transport worked,
  matching correctly refused.
- **wrong-tuple:** datagrams to a *different* WAN port are received by a
  sink responder bound there and never by the calibration responder. No
  conntrack/UNREPLIED requirement (ICMP/expiry may delete entries).
- **fwd-off:** sender through `rtr-off` (`ip_forward=0`, read back and
  verified) "succeeds" locally (rc 0, sent>0) but the responder-off records
  ZERO datagrams. The SAME shared echo-validating sender code runs here as
  on every path — the oracle is that it must observe ZERO VALID echoes
  (replies==0: any exact echo from the server endpoint would fail the
  control) — and rtr-off shows no REPLIED entry.

Positive-control observations are two DISTINCT observations, both required:
a sender-validated server echo (the sender's own socket receives the exact
reply), and a receiver-observed NAT source (the responder record shows the
translated WAN source address/port), correlated to the conntrack REPLY
tuple. Neither alone can stand in for the other. The negative controls have
different observation shapes (wrong-token/wrong-tuple: responder-side only;
fwd-off: sender sent>0 + ZERO valid echoes, replies==0).

Every control requires live processes: a READY handshake file, sender
returncode 0 and sent>0. No control can pass because a responder or sender
failed to run.

## Lifecycle & evidence

- `run.sh` tracks child PIDs and terminates them on EXIT/INT/TERM; the
  fixture terminates children GRACEFULLY first (cooperative STOP file,
  bounded wait) before escalating TERM→KILL, and classifies every outcome:
  preexisting unexpected child exits, survivors/wait errors, and TERM/KILL
  escalation on the NORMAL path are failures, while escalation during
  abnormal teardown (injected failure / interruption) is expected and
  recorded. Before deleting each tracked namespace it also terminates the
  concrete PIDs reported by `ip netns pids` (bounded TERM→wait→KILL). No
  process-name kills; survivors mark cleanup as failed; cleanup-evidence
  encoding uses a real JSON serializer (quotes/backslashes round-trip) and
  a serializer failure fails the run without masking the original error.
- `fixture.py` wraps every subprocess; `subprocess.run` calls always have a
  finite timeout and their returncodes are checked.
- `evidence.json` is written in a `finally` block (raw
  conntrack lines + parsed tuples + per-control verdicts); per-child stderr
  is kept under the invocation directory's `records/`; `run.sh` emits
  `cleanup-evidence.json` in the same directory (tracked namespaces, per-
  namespace process kills, removal results, remaining-namespace check, host
  ip_forward/firewall before/after with capture status) and exits nonzero
  if verification fails. The workflow re-checks these JSONs with the
  strict `checks/selftest.py` validators (typed assertions, no textual grep).
- Firewall comparison is canonical: both snapshots have comment lines,
  per-rule byte/packet counters (`[N:M]`) and blank lines stripped before
  comparison; a failed firewall/ip_forward capture is itself a failure,
  never a comparable value. Host rules are never modified.

## Failure injection (opt-in, CI checks only)

- `--fault-inject-setup`: aborts setup at a late stage with the exact
  signature phase=`setup-injected`, reason=`injected setup failure after
  three namespaces`, after EXACTLY wan/host-a/host-b exist; a generic
  namespace failure produces a different signature and cannot pass the
  injected-case validator.
- `--fault-inject-fixture`: full setup proceeds, then `FIXTURE_FAULT_INJECT=1`
  makes `fixture.py` deliberately fail after its children have started
  (after it writes the `records/children_started` phase marker); `run.sh`
  propagates the env and the orchestrator's exit status.
- interruption: the workflow uses the ROOT Python supervisor
  (`sudo python3 -I checks/selftest.py supervise-interrupt RUN_SH CASE_DIR NONCE`,
  implemented in `childman.py`), which owns the run.sh process via
  `Popen`, waits bounded for the nonce-tagged phase marker, verifies the
  responder PIDs are live descendants of the owned run.sh, re-checks
  process identity (no PID reuse), sends SIGTERM via `Popen.send_signal`
  (never pid files), requires exit 143, always reaps the owned process,
  and validates the case's cleanup/evidence JSON.

## Running (CI only)

`sudo -E env PATH="$PATH" bash run.sh RUN_DIR NONCE` from this directory
(RUN_DIR strictly inside `out/`, NONCE safe hex). Do not run it on a
developer machine; the workflow (`.github/workflows/nat-topology.yml`)
runs `python3 checks/selftest.py -v` first, then the fixture (normal,
`--fault-inject-setup`, `--fault-inject-fixture`, and interruption cases,
each in its own per-case directory), validating every case with the strict
`checks/selftest.py` validators / supervisor, and always uploads `out/` as
artifacts.

## Authored real-QUIC extension (runtime unverified)

The separate `.github/workflows/quic-nat.yml` builds the reviewed, detached Rust
`nat-peer` helper and opts into `quic/run.py` by setting `FIXTURE_QUIC_BINARY`.
Without that explicit variable, `run.sh` still runs the accepted UDP calibration.
`FIXTURE_QUIC_CASE` selects `positive`, `blocked`, or `wrong-tuple`. QUIC cases
require a 32-hex-byte nonce. Namespace creation, host-state checks, failure flags
and cleanup remain owned by the same `run.sh`; no native fixture runs locally.

Two real peer processes bind native UDP at private ports 40001/40002, while a
separate custom UDP relay in the WAN namespace bootstraps authenticated QUIC.
Both peers must prove queued payload non-delivery and live control before GO.
Only then do they publish the configured public candidates through iroh's normal
address-update API. No explicit `open_path` fixture hook is used. UPnP/PCP/NAT-PMP
and optional public net-report probes are disabled. The candidate addresses and
translated ports are controlled fixture inputs, not an address-discovery proof.

Additional outbound-only MASQUERADE rules force native source ports to
41010/41020. There is no DNAT/port-forward rule. A bounded WAN tcpdump capture
records actual post-NAT UDP tuples and ciphertext; tshark extracts raw UDP payload,
without decrypting QUIC. Segmentation/GRO is disabled only on owned veth devices.
The existing exact-ciphertext oracle requires zero custom STREAM/DATAGRAM frames,
positive native frames in each direction for the positive case, zero native app
frames for negative cases, and no unobserved application payload. Replied conntrack
entries must match the private and independently observed translated native tuples.

`blocked` drops only native-source UDP on both owned routers, keeping custom
control alive; nonzero drop counters are mandatory. `wrong-tuple` advertises a
wrong native public port and requires observed attempts to that wrong port.
Both peers must remain alive through every negative observation. Setup failure,
live-peer fixture failure and owned-process SIGTERM/reaping cases are also wired
into CI. Pure parser/rejection checks live in `quic/checks.py`.

All new two-NAT cases are authored but **not yet runtime accepted**. They do not
establish production libp2p/Yggdrasil deployment, autonomous discovery, selected
custom-transport authorization, or P03 completion.
