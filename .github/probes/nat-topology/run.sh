#!/usr/bin/env bash
# P03 NAT topology calibration fixture bootstrap (CI-only).
#
# Must run as root on a disposable runner (the workflow elevates via sudo).
# Creates an isolated set of uniquely-named network namespaces, hands the full
# topology to fixture.py via the FIXTURE_CONFIG env var, and guarantees
# cleanup: ONLY resources created by this invocation are tracked and removed,
# and host ip_forward / firewall state is captured before the run and
# verified unchanged after cleanup (any change is a hard failure).
# This script NEVER modifies host firewall rules, routes or ip_forward.
#
# Invocation contract:
#   run.sh [--fault-inject-setup | --fault-inject-fixture] RUN_DIR NONCE
# RUN_DIR is the per-case invocation dir; it must NOT exist yet (mkdir
# without -p, so an existing dir aborts the run loudly before anything
# else). NONCE is a unique invocation token string. All per-run artifacts
# live under RUN_DIR.
#
# Opt-in flags (workflow failure-injection checks only):
#   --fault-inject-setup    aborts setup at a LATE stage after some
#                           namespaces were created, to prove partial-failure
#                           cleanup removes exactly what was created.
#   --fault-inject-fixture  runs the full setup, then exports
#                           FIXTURE_FAULT_INJECT=1 so fixture.py deliberately
#                           fails AFTER its children started; run.sh only
#                           propagates the env and the orchestrator's exit
#                           status.
set -eu -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "usage: run.sh [--fault-inject-setup | --fault-inject-fixture] RUN_DIR NONCE" >&2
}

FAULT_INJECT_SETUP=0
FAULT_INJECT_FIXTURE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --fault-inject-setup)   FAULT_INJECT_SETUP=1; shift ;;
    --fault-inject-fixture) FAULT_INJECT_FIXTURE=1; shift ;;
    -h|--help)              usage; exit 0 ;;
    --)                     shift; break ;;
    --*)                    echo "unknown flag: $1" >&2; usage; exit 2 ;;
    *)                      break ;;
  esac
done
if [ $# -ne 2 ]; then
  echo "error: expected exactly two positional arguments: RUN_DIR NONCE" >&2
  usage
  exit 2
fi
RUN_DIR="$1"
NONCE="$2"

# NONCE must be safe hex (it is embedded in config/JSON artifacts).
case "$NONCE" in
  ""|*[!0-9a-fA-F]*)
    echo "error: NONCE must be non-empty lowercase/uppercase hex" >&2; usage; exit 2 ;;
esac

# RUN_DIR must resolve STRICTLY inside HERE/out (never HERE/out itself, no
# '..' components, no symlink escapes). Resolution via python pathlib runs
# BEFORE any mkdir, so existing symlink ancestors cannot smuggle the path
# out of out/. The leaf is then created exclusively.
RUN_DIR_ABS="$(RUN_DIR="$RUN_DIR" HERE="$HERE" python3 -I -c '
import os, sys
from pathlib import Path
here = Path(os.environ["HERE"]).resolve()
cand = Path(os.environ["RUN_DIR"])
if not cand.is_absolute():
    cand = Path.cwd() / cand
if ".." in cand.parts:
    sys.stderr.write("error: RUN_DIR contains .. components\n")
    sys.exit(2)
out = here / "out"
res = cand.resolve(strict=False)
if res == out or out not in res.parents:
    sys.stderr.write("error: RUN_DIR must resolve strictly inside %s\n" % out)
    sys.exit(2)
sys.stdout.write(str(res))
')" || { echo "error: invalid RUN_DIR" >&2; exit 2; }
RUN_DIR="$RUN_DIR_ABS"
mkdir -p "$(dirname "$RUN_DIR")"
mkdir "$RUN_DIR" || { echo "error: RUN_DIR already exists: $RUN_DIR" >&2; exit 2; }
mkdir "$RUN_DIR/records"
printf '%s' "$NONCE" > "$RUN_DIR/nonce.txt"

# Unique 6-hex prefix so concurrent/previous invocations cannot collide.
RUN_ID="$(printf '%06x' "$(( ((RANDOM * 32768 + $$) ^ $(date +%s%N)) & 0xFFFFFF ))")"
PREFIX="sn${RUN_ID}"

# Unique per-run tokens (16 random bytes hex each): no fixed-token assumption.
TOK_A="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
TOK_B="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
TOK_WRONG="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
TOK_TUPLE="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
TOK_OFF="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"

# Network namespace names (unique per invocation).
NS_WAN="${PREFIX}-wan";   NS_A="${PREFIX}-host-a";  NS_B="${PREFIX}-host-b"
NS_RA="${PREFIX}-rtr-a";  NS_RB="${PREFIX}-rtr-b"
NS_HOFF="${PREFIX}-host-off"; NS_ROFF="${PREFIX}-rtr-off"
# Shared-L2 bridge inside the WAN namespace: all three router WAN ends are
# enslaved to it so responder echoes ARP-flood to rtr-a/rtr-b/rtr-off alike
# (the wan namespace itself neither bridges nor forwards).
BR_WAN="${PREFIX}br"

# Host-side veth names: <=15 chars, unique; both ends are moved into their
# namespaces immediately after creation. No generic eth0/wan0/lan0 here.
IF_W0="${PREFIX}w0"; IF_RA0="${PREFIX}ra0"
IF_W1="${PREFIX}w1"; IF_RB0="${PREFIX}rb0"
IF_W2="${PREFIX}w2"; IF_RO0="${PREFIX}ro0"
IF_HA="${PREFIX}ha"; IF_RA1="${PREFIX}ra1"
IF_HB="${PREFIX}hb"; IF_RB1="${PREFIX}rb1"
IF_HO="${PREFIX}ho"; IF_RO1="${PREFIX}ro1"

NS_CREATED=()       # only namespaces successfully created by THIS run
HOST_IFS=()         # every host-ns interface name this run created
CHILD_PIDS=()       # real child PIDs; never process-name kills
NS_PIDS_KILLED=()   # PIDs found via `ip netns pids` and terminated
NS_PIDS_LEFT=()     # PIDs that survived TERM+KILL (cleanup failure)
CLEANUP_ERRORS=()   # human-readable cleanup verification failures
INTERFACE_SURVIVORS=()  # tracked host ifaces still present after cleanup
CLEANUP_FAILED=0
CAPTURE_FAILED=0
HOST_FWD_BEFORE="unknown"
FW_RAW=""
SETUP_PHASE="normal"
SETUP_REASON=""
ORIG_RC=0       # exit status of the run body, preserved across cleanup
EV_SER_FAILED=0 # cleanup-evidence JSON serializer status

exec > >(tee -a "$RUN_DIR/setup.log") 2>&1

# --- helpers ----------------------------------------------------------------

die() { echo "FATAL: $*" >&2; exit 1; }

# JSON encoding via python (stdlib): quotes/backslashes/newlines round-trip
# correctly, unlike shell-ad-hoc quoting. Never import fixture modules here.
json_str() { # $1 -> JSON string literal
  python3 -I -c 'import json,sys; sys.stdout.write(json.dumps(sys.argv[1]))' "$1"
}
json_arr() { # argv -> JSON array of strings
  python3 -I -c 'import json,sys; sys.stdout.write(json.dumps(sys.argv[1:]))' "$@"
}
json_int() { # $1 -> JSON number (validated)
  case "$1" in
    ''|*[!0-9-]*) json_str "$1" ;;
    *)            printf '%s' "$1" ;;
  esac
}

# Capture a firewall ruleset in the PARENT shell with explicit status.
# Sets the global FW_RAW; any failure (command error or empty output) is
# reported by a nonzero return -- NEVER by a sentinel value.
fw_capture() { # $1 = stderr log file
  if command -v iptables-save >/dev/null 2>&1; then
    FW_RAW="$(iptables-save 2>"$1")" || return 1
  elif command -v nft >/dev/null 2>&1; then
    FW_RAW="$(nft list ruleset 2>"$1")" || return 1
  else
    echo "no firewall tool (iptables-save/nft) available" > "$1"
    return 1
  fi
  [ -n "$FW_RAW" ] || return 1
}

# Canonicalize a ruleset string in the parent shell, writing directly to the
# target file: strip comment lines, per-rule byte/packet counters (including
# end-of-line counters with no trailing space) and blank lines.
fw_canon() { # raw target_file ; returns nonzero if target is empty
  printf '%s\n' "$1" \
    | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]([[:space:]]|$)//g' \
    | grep -v '^[[:space:]]*$' > "$2" || true
  [ -s "$2" ]
}

addns() { # track ONLY successful creations
  local ns="$1"
  if ip netns add "$ns"; then
    NS_CREATED+=("$ns")
    echo "created netns ${ns}"
  else
    echo "FAILED to create netns ${ns}" >&2
    exit 1  # EXIT trap cleans up only the tracked namespaces
  fi
}

mkveth() { # he peer nsa nsb: create both ends in host ns, move out at once
  local he="$1" peer="$2" nsa="$3" nsb="$4"
  if ! ip link add "$he" type veth peer name "$peer" 2>/dev/null; then
    echo "FAILED to create veth ${he}/${peer}" >&2
    exit 1
  fi
  # Only track after creation actually succeeded; these exact unique names
  # are ours, so a failed move lets us delete our own pair.
  HOST_IFS+=("$he")
  HOST_IFS+=("$peer")
  if ! ip link set "$he" netns "$nsa" || ! ip link set "$peer" netns "$nsb"; then
    echo "FAILED to move veth ends ${he}/${peer}; deleting our orphaned pair" >&2
    if ip link del "$he" 2>/dev/null; then
      echo "deleted orphaned veth end ${he}"
    else
      echo "veth end ${he} not present in host ns (already moved to ${nsa})"
    fi
    if ip link del "$peer" 2>/dev/null; then
      echo "deleted orphaned veth end ${peer}"
    else
      echo "veth end ${peer} not present in host ns (already moved to ${nsb})"
    fi
    exit 1  # EXIT trap removes whatever was tracked so far
  fi
  echo "created veth ${he} <-> ${peer}"
}

setup_nat() { # ns wan_if lan_subnet  -- MASQUERADE with a FIXED port range
  local ns="$1" wif="$2" subnet="$3"
  local log="$RUN_DIR/setup-iptables-${ns}.log"
  if ip netns exec "$ns" iptables -t nat -A POSTROUTING -o "$wif" \
      -s "$subnet" -p udp -j MASQUERADE --to-ports 41010-41020 2>"$log"; then
    echo "iptables MASQUERADE --to-ports 41010-41020 (udp) configured in ${ns}"
    return 0
  fi
  log="$RUN_DIR/setup-nft-${ns}.log"
  if ip netns exec "$ns" nft add table ip nat 2>"$log" \
     && printf 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; policy accept ; }\nadd rule ip nat postrouting oifname "%s" ip saddr %s meta l4proto udp masquerade to :41010-41020\n' "$wif" "$subnet" \
        | ip netns exec "$ns" nft -f - 2>>"$log"; then
    echo "nft masquerade to :41010-41020 (udp) configured in ${ns}"
    return 0
  fi
  # Never weaken the oracle: fixed-range NAT is mandatory (defect 6).
  die "neither iptables nor nft with port-range MASQUERADE available in ${ns} (see ${log})"
}

cleanup() {
  local pid ns rif remain pids alive out
  local ip_forward_changed=false fw_canonical_changed=false
  {
    echo "=== namespace process termination (ip netns pids based) ==="
  } > "$RUN_DIR/child-termination.txt"
  # Bounded per-PID termination: TERM, bounded wait, KILL, wait.
  for pid in "${CHILD_PIDS[@]:-}"; do
    [ -n "$pid" ] || continue
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      # 30s budget: the fixture orchestrator's finally gracefully stops its
      # children (STOP -> bounded wait, up to ~9s) before it can exit; a
      # 2.5s budget would KILL it mid-cleanup and orphan its children.
      for _ in $(seq 1 120); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.25
      done
      if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
      fi
      wait "$pid" 2>/dev/null || true
      echo "child ${pid}: terminated" >> "$RUN_DIR/child-termination.txt"
    else
      echo "child ${pid}: already-exited" >> "$RUN_DIR/child-termination.txt"
    fi
  done
  # Remove only namespaces this run actually created. Before each deletion,
  # terminate the concrete PIDs living in that namespace (obtained via
  # `ip netns pids`; no stale pid files and no process-name kills).
  # The loop runs in the parent shell; CLEANUP_FAILED must survive it.
  for ns in "${NS_CREATED[@]:-}"; do
    [ -n "$ns" ] || continue
    pids=""
    if ! pids="$(ip netns pids "$ns" 2>/dev/null)"; then
      CLEANUP_FAILED=1
      CLEANUP_ERRORS+=("ip netns pids ${ns} failed during cleanup")
    fi
    for pid in $pids; do
      echo "netns ${ns}: pid ${pid}: TERM" >> "$RUN_DIR/child-termination.txt"
      kill -TERM "$pid" 2>/dev/null || true
      alive=1
      for _ in $(seq 1 10); do # ~2.5s bounded wait
        kill -0 "$pid" 2>/dev/null || { alive=0; break; }
        sleep 0.25
      done
      if [ "$alive" = "1" ]; then
        echo "netns ${ns}: pid ${pid}: KILL" >> "$RUN_DIR/child-termination.txt"
        kill -KILL "$pid" 2>/dev/null || true
        sleep 0.25
        if kill -0 "$pid" 2>/dev/null; then
          wait "$pid" 2>/dev/null || true
        fi
        if kill -0 "$pid" 2>/dev/null; then
          echo "netns ${ns}: pid ${pid}: STILL-ALIVE" >> "$RUN_DIR/child-termination.txt"
          NS_PIDS_LEFT+=("$pid")
          CLEANUP_FAILED=1
          CLEANUP_ERRORS+=("pid ${pid} in netns ${ns} survived TERM+KILL")
        fi
      fi
      if [ "$alive" = "0" ] || ! kill -0 "$pid" 2>/dev/null; then
        NS_PIDS_KILLED+=("$pid")
        echo "netns ${ns}: pid ${pid}: terminated" >> "$RUN_DIR/child-termination.txt"
      fi
    done
    if ip netns del "$ns" 2>>"$RUN_DIR/ns-removal.txt"; then
      echo "${ns}: removed" >> "$RUN_DIR/ns-removal.txt"
      echo "${ns}: removed"
    else
      echo "${ns}: REMOVE-FAILED" >> "$RUN_DIR/ns-removal.txt"
      echo "${ns}: REMOVE-FAILED"
      CLEANUP_FAILED=1
      CLEANUP_ERRORS+=("ip netns del ${ns} failed")
    fi
  done
  # Remove any tracked host interfaces still present (exact names only).
  for rif in "${HOST_IFS[@]:-}"; do
    [ -n "$rif" ] || continue
    if ip link del "$rif" 2>/dev/null; then
      echo "removed leftover host interface ${rif}"
    fi
  done
  # Namespace removal verification: a failing `ip netns list` is itself a
  # verification failure, not an empty result.
  if ! out="$(ip netns list 2>/dev/null)"; then
    remain="unknown"
    CLEANUP_FAILED=1
    CLEANUP_ERRORS+=("ip netns list failed during cleanup verification")
  else
    remain="$(printf '%s\n' "$out" | grep -c "^${PREFIX}-" || true)"
    [ "${remain}" = "0" ] || CLEANUP_FAILED=1
  fi
  # Host state capture AFTER cleanup, canonicalized for comparison, with
  # explicit status in the parent shell (no sentinel values).
  if ! fwd_after="$(sysctl -n net.ipv4.ip_forward 2>"$RUN_DIR/ip-forward-after.err")" \
     || [ -z "$fwd_after" ]; then
    fwd_after="unknown"
    CAPTURE_FAILED=1
    CLEANUP_ERRORS+=("host ip_forward read after cleanup failed")
  fi
  if ! fw_capture "$RUN_DIR/host-fw-capture-after.err"; then
    CAPTURE_FAILED=1
    CLEANUP_ERRORS+=("host firewall capture after cleanup failed (see host-fw-capture-after.err)")
  fi
  if ! fw_canon "$FW_RAW" "$RUN_DIR/host-fw-after.canonical.txt"; then
    CAPTURE_FAILED=1
    CLEANUP_ERRORS+=("host firewall canonical snapshot after cleanup is empty")
  fi
  if [ "$CAPTURE_FAILED" != "0" ]; then
    CLEANUP_FAILED=1
  fi
  if [ "$(cat "$RUN_DIR/host-fw-before.canonical.txt")" \
      != "$(cat "$RUN_DIR/host-fw-after.canonical.txt")" ]; then
    fw_canonical_changed=true
  fi
  if [ "$fwd_after" != "$HOST_FWD_BEFORE" ]; then
    ip_forward_changed=true
  fi
  if [ "$fw_canonical_changed" = "true" ] || [ "$ip_forward_changed" = "true" ]; then
    CLEANUP_FAILED=1
  fi
  # Interface survivors: tracked host ifaces still present after the
  # removal loop. `ip link show` failure means gone, unless it failed for a
  # reason other than the interface being absent.
  for rif in "${HOST_IFS[@]:-}"; do
    [ -n "$rif" ] || continue
    if out="$(ip link show dev "$rif" 2>&1)"; then
      INTERFACE_SURVIVORS+=("$rif")
      CLEANUP_FAILED=1
      CLEANUP_ERRORS+=("host interface ${rif} still present after cleanup")
    else
      case "$out" in
        *"does not exist"*|*"Cannot find"*|*"No such"*|*"not found"*) : ;;
        *)
          CLEANUP_FAILED=1
          CLEANUP_ERRORS+=("ip link show ${rif} failed unexpectedly: ${out}")
          ;;
      esac
    fi
  done
  # cleanup-evidence.json: ONE python stdlib serializer fed values via env
  # (no shell interpolation into JSON; quotes/backslashes round-trip).
  NS_COUNT="${#NS_CREATED[@]}"
  local tmp_json="$RUN_DIR/cleanup-evidence.json.tmp"
  if ! NS_CREATEDjoined="$(json_arr ${NS_CREATED[@]+"${NS_CREATED[@]}"})" \
     || ! HOST_IFSjoined="$(json_arr ${HOST_IFS[@]+"${HOST_IFS[@]}"})" \
     || ! NS_KILLEDjoined="$(json_arr ${NS_PIDS_KILLED[@]+"${NS_PIDS_KILLED[@]}"})" \
     || ! NS_LEFTjoined="$(json_arr ${NS_PIDS_LEFT[@]+"${NS_PIDS_LEFT[@]}"})" \
     || ! IF_SURVjoined="$(json_arr ${INTERFACE_SURVIVORS[@]+"${INTERFACE_SURVIVORS[@]}"})" \
     || ! ERRSjoined="$(json_arr ${CLEANUP_ERRORS[@]+"${CLEANUP_ERRORS[@]}"})"; then
    EV_SER_FAILED=1
  fi
  if [ "$EV_SER_FAILED" = "0" ]; then
    if RUN_DIR="$RUN_DIR" PREFIX="$PREFIX" NONCE="$NONCE" \
         PHASE="$SETUP_PHASE" REASON="$SETUP_REASON" \
         NS_COUNT="$NS_COUNT" ORIG_RC="$ORIG_RC" \
         NS_CREATEDjoined="$NS_CREATEDjoined" HOST_IFSjoined="$HOST_IFSjoined" \
         NS_KILLEDjoined="$NS_KILLEDjoined" NS_LEFTjoined="$NS_LEFTjoined" \
         IF_SURVjoined="$IF_SURVjoined" ERRSjoined="$ERRSjoined" \
         REMAIN="$remain" FWD_BEFORE="$HOST_FWD_BEFORE" FWD_AFTER="$fwd_after" \
         CAPTURE_FAILED="$CAPTURE_FAILED" \
         FW_CANON_CHANGED="$fw_canonical_changed" \
         IP_FWD_CHANGED="$ip_forward_changed" \
         FW_CHANGED="$( [ "$fw_canonical_changed" = "true" ] || [ "$ip_forward_changed" = "true" ] && echo true || echo false )" \
         CLEANUP_FAILED="$CLEANUP_FAILED" \
         FAULT_SETUP="$FAULT_INJECT_SETUP" FAULT_FIXTURE="$FAULT_INJECT_FIXTURE" \
         TERMLOG="$RUN_DIR/child-termination.txt" \
         python3 -I -c '
import json, os
e = os.environ
def b(v): return v == "1" or v == "true"
cfg = {
  "prefix": e["PREFIX"],
  "nonce": e["NONCE"],
  "phase": e["PHASE"],
  "reason": e["REASON"],
  "namespaces_created_count": int(e["NS_COUNT"]),
  "namespaces_created": json.loads(e["NS_CREATEDjoined"]),
  "host_ifaces_created": json.loads(e["HOST_IFSjoined"]),
  "namespaces_remaining": e["REMAIN"],
  "namespace_processes_killed": [int(p) for p in json.loads(e["NS_KILLEDjoined"])],
  "namespace_processes_left": [int(p) for p in json.loads(e["NS_LEFTjoined"])],
  "interface_survivors": json.loads(e["IF_SURVjoined"]),
  "cleanup_errors": json.loads(e["ERRSjoined"]),
  "host_ip_forward_before": e["FWD_BEFORE"],
  "host_ip_forward_after": e["FWD_AFTER"],
  "host_fw_capture_ok": e["CAPTURE_FAILED"] == "0",
  "host_fw_canonical_changed": b(e["FW_CANON_CHANGED"]),
  "host_ip_forward_changed": b(e["IP_FWD_CHANGED"]),
  "host_firewall_changed": b(e["FW_CHANGED"]),
  "child_termination_log": e["TERMLOG"],
  "cleanup_failed": b(e["CLEANUP_FAILED"]),
  "fault_inject_setup": e["FAULT_SETUP"] == "1",
  "fault_inject_fixture": e["FAULT_FIXTURE"] == "1",
  "original_exit_code": int(e["ORIG_RC"]),
}
with open(os.path.join(e["RUN_DIR"], "cleanup-evidence.json.tmp"), "w",
          encoding="utf-8") as fh:
    json.dump(cfg, fh, indent=2, sort_keys=True)
' && mv "$tmp_json" "$RUN_DIR/cleanup-evidence.json"; then
      :  # serializer succeeded
    else
      EV_SER_FAILED=1
      echo "FATAL: cleanup-evidence serializer failed" >&2
    fi
  fi
  # Cleanup or evidence-serializer failures MUST fail the run, but the
  # ORIGINAL failing exit status (e.g. 143 from the TERM trap) must not be
  # masked by a generic 1: preserve it whenever it is nonzero.
  trap - EXIT
  if [ "$ORIG_RC" != "0" ]; then
    exit "$ORIG_RC"
  fi
  if [ "$CLEANUP_FAILED" != "0" ] || [ "$EV_SER_FAILED" != "0" ]; then
    exit 1
  fi
  exit 0
}

trap 'ORIG_RC=$?; cleanup' EXIT
trap 'exit 143' INT TERM  # EXIT trap performs cleanup; exit code is nonzero
printf '%s' "$$" > "$RUN_DIR/run.pid"  # diagnostic-only pid record for evidence; the workflow supervisor signals its OWN Popen and never reads this file

# --- host state capture (BEFORE anything happens; we change nothing) --------
# Explicit status in the parent shell; failures are recorded, never masked
# with sentinel values, and still produce cleanup evidence later.
if ! HOST_FWD_BEFORE="$(sysctl -n net.ipv4.ip_forward 2>"$RUN_DIR/ip-forward-before.err")" \
   || [ -z "$HOST_FWD_BEFORE" ]; then
  HOST_FWD_BEFORE="unknown"
  CAPTURE_FAILED=1
fi
if ! fw_capture "$RUN_DIR/host-fw-capture-before.err"; then
  CAPTURE_FAILED=1
fi
if ! fw_canon "$FW_RAW" "$RUN_DIR/host-fw-before.canonical.txt"; then
  CAPTURE_FAILED=1
fi
{
  echo "host_net_state_before"
  echo "ip_forward=${HOST_FWD_BEFORE}"
  if [ -n "$FW_RAW" ]; then echo "$FW_RAW"; fi
} > "$RUN_DIR/host-net-before.txt"

printf '%s' "$PREFIX" > "$RUN_DIR/prefix.txt"

# --- preflight ----------------------------------------------------------------
[ "$(id -u)" = "0" ] || die "must run as root (CI elevates via sudo)"
command -v ip >/dev/null 2>&1 || die "ip(8) not available"
command -v python3 >/dev/null 2>&1 || die "python3 not available"
command -v iptables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1 \
  || die "need iptables or nft"

# --- topology (documentation-range IPs, fixture-only) --------------------------
WAN_IP="203.0.113.10"; RA_WAN="203.0.113.1"; RB_WAN="203.0.113.2"
RO_WAN="203.0.113.3"
A_IP="10.0.1.2"; B_IP="10.0.2.2"; OFF_IP="10.0.3.2"

addns "$NS_WAN"
addns "$NS_A"
addns "$NS_B"
# Exact late-setup injection: ONLY immediately after exactly the three
# namespaces wan/host-a/host-b were created, with an explicit phase/reason
# recorded for the cleanup evidence. A generic namespace failure elsewhere
# must NOT produce this exact injected signature.
if [ "$FAULT_INJECT_SETUP" = "1" ]; then
  if [ "${#NS_CREATED[@]}" -eq 3 ] \
     && [ "${NS_CREATED[0]}" = "$NS_WAN" ] \
     && [ "${NS_CREATED[1]}" = "$NS_A" ] \
     && [ "${NS_CREATED[2]}" = "$NS_B" ]; then
    SETUP_PHASE="setup-injected"
    SETUP_REASON="injected setup failure after three namespaces"
    echo "fault injection: $SETUP_REASON (wan/host-a/host-b exist)"
    exit 1  # EXIT trap must remove exactly the 3 created namespaces
  fi
  # Wrong creation state for injection: fail with the generic signature so
  # the setup-fault validator cannot mistake it for the injected case.
  echo "fault injection precondition failed (created != wan/host-a/host-b)" >&2
  exit 1
fi
addns "$NS_RA"
addns "$NS_RB"
addns "$NS_HOFF"
addns "$NS_ROFF"

mkveth "$IF_W0" "$IF_RA0" "$NS_WAN" "$NS_RA"
mkveth "$IF_W1" "$IF_RB0" "$NS_WAN" "$NS_RB"
mkveth "$IF_W2" "$IF_RO0" "$NS_WAN" "$NS_ROFF"
mkveth "$IF_HA" "$IF_RA1" "$NS_A" "$NS_RA"
mkveth "$IF_HB" "$IF_RB1" "$NS_B" "$NS_RB"
mkveth "$IF_HO" "$IF_RO1" "$NS_HOFF" "$NS_ROFF"

# wan segment: one shared L2 bridge carrying all three router WAN ends so
# that replies reach rtr-b/rtr-off without depending on wan-ns forwarding.
ip -n "$NS_WAN" link add "$BR_WAN" type bridge
ip -n "$NS_WAN" link set "$BR_WAN" up
ip -n "$NS_WAN" link set "$IF_W0" master "$BR_WAN"
ip -n "$NS_WAN" link set "$IF_W1" master "$BR_WAN"
ip -n "$NS_WAN" link set "$IF_W2" master "$BR_WAN"
ip -n "$NS_WAN" addr add "$WAN_IP"/24 dev "$BR_WAN"
# ALL owned endpoints in the wan namespace are brought up exactly once.
ip -n "$NS_WAN" link set "$IF_W0" up
ip -n "$NS_WAN" link set "$IF_W1" up
ip -n "$NS_WAN" link set "$IF_W2" up
ip -n "$NS_RA" addr add "$RA_WAN"/24 dev "$IF_RA0"
ip -n "$NS_RA" link set "$IF_RA0" up
ip -n "$NS_RB" addr add "$RB_WAN"/24 dev "$IF_RB0"
ip -n "$NS_RB" link set "$IF_RB0" up
ip -n "$NS_ROFF" addr add "$RO_WAN"/24 dev "$IF_RO0"
ip -n "$NS_ROFF" link set "$IF_RO0" up
# lan segments
ip -n "$NS_RA" addr add 10.0.1.1/24 dev "$IF_RA1"
ip -n "$NS_RA" link set "$IF_RA1" up
ip -n "$NS_RB" addr add 10.0.2.1/24 dev "$IF_RB1"
ip -n "$NS_RB" link set "$IF_RB1" up
ip -n "$NS_ROFF" addr add 10.0.3.1/24 dev "$IF_RO1"
ip -n "$NS_ROFF" link set "$IF_RO1" up
ip -n "$NS_A" addr add "$A_IP"/24 dev "$IF_HA"
ip -n "$NS_A" link set "$IF_HA" up
ip -n "$NS_B" addr add "$B_IP"/24 dev "$IF_HB"
ip -n "$NS_B" link set "$IF_HB" up
ip -n "$NS_HOFF" addr add "$OFF_IP"/24 dev "$IF_HO"
ip -n "$NS_HOFF" link set "$IF_HO" up
# loopbacks up + default routes toward each host's router
for ns in "$NS_WAN" "$NS_A" "$NS_B" "$NS_RA" "$NS_RB" "$NS_HOFF" "$NS_ROFF"; do
  ip -n "$ns" link set lo up
done
ip -n "$NS_A" route add default via 10.0.1.1
ip -n "$NS_B" route add default via 10.0.2.1
ip -n "$NS_HOFF" route add default via 10.0.3.1
ip -n "$NS_RA" route add default via "$WAN_IP"
ip -n "$NS_RB" route add default via "$WAN_IP"
ip -n "$NS_ROFF" route add default via "$WAN_IP"

# Forwarding: ON only in the NAT routers; EXPLICITLY verified OFF in rtr-off.
ip netns exec "$NS_RA" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$NS_RB" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$NS_ROFF" sysctl -q -w net.ipv4.ip_forward=0
[ "$(ip netns exec "$NS_ROFF" sysctl -n net.ipv4.ip_forward)" = "0" ] \
  || die "rtr-off ip_forward readback is not 0"

setup_nat "$NS_RA" "$IF_RA0" 10.0.1.0/24
setup_nat "$NS_RB" "$IF_RB0" 10.0.2.0/24

# --- hand the full topology to fixture.py (no hardcoded names there) -----------
# FIXTURE_CONFIG is built by a python stdlib serializer from env values, so
# tokens/paths/names are JSON-encoded properly (quotes/backslashes safe).
FIXTURE_CONFIG="$(RUN_DIR="$RUN_DIR" NONCE="$NONCE" PREFIX="$PREFIX" \
  TOK_A="$TOK_A" TOK_B="$TOK_B" TOK_WRONG="$TOK_WRONG" TOK_TUPLE="$TOK_TUPLE" TOK_OFF="$TOK_OFF" \
  NS_WAN="$NS_WAN" NS_A="$NS_A" NS_B="$NS_B" NS_RA="$NS_RA" NS_RB="$NS_RB" \
  NS_HOFF="$NS_HOFF" NS_ROFF="$NS_ROFF" \
  WAN_IP="$WAN_IP" RA_WAN="$RA_WAN" RB_WAN="$RB_WAN" RO_WAN="$RO_WAN" \
  A_IP="$A_IP" B_IP="$B_IP" OFF_IP="$OFF_IP" RUN_PID="$$" \
  python3 -I -c '
import json, os
e = os.environ
cfg = {
  "prefix": e["PREFIX"],
  "run_pid": int(e["RUN_PID"]),
  "nonce": e["NONCE"],
  "out_dir": e["RUN_DIR"],
  "tokens": {"a": e["TOK_A"], "b": e["TOK_B"], "wrong": e["TOK_WRONG"],
             "tuple": e["TOK_TUPLE"], "off": e["TOK_OFF"]},
  "ns": {"wan": e["NS_WAN"], "host_a": e["NS_A"], "host_b": e["NS_B"],
         "rtr_a": e["NS_RA"], "rtr_b": e["NS_RB"],
         "host_off": e["NS_HOFF"], "rtr_off": e["NS_ROFF"]},
  "ip": {"wan": e["WAN_IP"], "rtr_a_wan": e["RA_WAN"],
         "rtr_b_wan": e["RB_WAN"], "rtr_off_wan": e["RO_WAN"],
         "host_a": e["A_IP"], "host_b": e["B_IP"], "host_off": e["OFF_IP"]},
  "port": {"cal": 41000, "tuple": 41001, "off": 41002,
           "src_a": 40001, "src_b": 40002, "src_off": 40003,
           "src_wrong": 40011, "src_tuple": 40012},
  "translated_ports": [41010, 41020],
}
print(json.dumps(cfg))
')"
export FIXTURE_CONFIG
if [ "$FAULT_INJECT_FIXTURE" = "1" ]; then
  # fixture.py deliberately fails AFTER its children started (phase marker
  # RUN_DIR/records/children_started is written by fixture.py; run.sh does
  # not wait for it — the workflow does).
  export FIXTURE_FAULT_INJECT="1"
fi

if [ "$FAULT_INJECT_SETUP" = "1" ]; then
  die "fault injection mode should have exited during setup"
fi

python3 "$HERE/fixture.py" orchestrator &
CHILD_PIDS+=("$!")
RC=0
wait "${CHILD_PIDS[0]}" || RC=$?  # -e must not abort before we record RC
CHILD_PIDS=()  # The child is reaped; its PID must not be signaled again.
echo "fixture orchestrator exit: ${RC}"
exit "$RC"
