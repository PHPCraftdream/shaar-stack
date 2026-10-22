#!/usr/bin/env python3
"""P03 NAT topology calibration orchestrator (CI-only, root, netns sandbox).

Topology (built by run.sh; ALL parameters arrive ONLY via FIXTURE_CONFIG —
no namespace, IP, port or token is hardcoded here):
  host-a -- rtr-a (MASQUERADE --to-ports) -+
  host-b -- rtr-b (MASQUERADE --to-ports) -+-- wan (responders)
  host-off -- rtr-off (ip_forward=0, NEGATIVE control) +

Controls (each requires live processes: READY handshake + sender rc==0
+ sent>0; none may pass because a responder or sender failed to run):
  cal-a / cal-b  positive per-host, ONE verdict per host: sender echo OK and
                 observed reply source == server endpoint wan_ip:cal_port
                 (the sender cannot see the translated port), responder
                 recorded a known record with post-NAT src == the host's
                 router WAN IP and a valid translated port, and conntrack
                 shows the EXACT translation tuple (ctparse.find_translation
                 with that observed port).
  wrong-token    unknown token still traverses NAT; responder records it
                 known=false with a REPLIED conntrack entry.
  wrong-tuple    datagrams to a DIFFERENT wan port reach a sink responder
                 and never the cal responder (no conntrack requirement).
  fwd-off        through rtr-off (ip_forward=0): sent>0, replies==0,
                 responder-off records ZERO datagrams, no REPLIED entry.

All per-run artifacts live under cfg["out_dir"]/records/ so concurrent runs
never share paths. Evidence is written LAST in a FINALLY block (SIGTERM/
SIGINT are converted to SystemExit so finally runs); every spawned child is
reaped there too.
"""

import json
import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import childman  # noqa: E402
import ctparse  # noqa: E402
from childman import echo_ok, expected_echo_payload  # noqa: E402,F401

READY_WAIT_S = 10.0
STOP_WAIT_S = 8.0
CMD_TIMEOUT_S = 15.0
ECHO_WAIT_S = 2.0
SEND_COUNT = 3
NEG_COUNT = 2


# Pure helper (imported and unit-tested by selftest.py; no side effects).
# expected_echo_payload / echo_ok live in childman and are re-exported above.

def translated_port_ok(port, local_port, lo, hi):
    """Observed post-NAT port must differ from the bound local port AND fall
    inside the configured --to-ports range. Sound because MASQUERADE is
    configured with a fixed range, which overrides port preservation."""
    return port != local_port and lo <= port <= hi


# Orchestrator plumbing.

def load_config():
    raw = os.environ.get("FIXTURE_CONFIG", "")
    if not raw:
        raise SystemExit("FIXTURE_CONFIG env var missing (run via run.sh)")
    return json.loads(raw)


def new_check():
    return {"status": "fail", "reasons": []}


def check(cond, ctrl, msg):
    if not cond:
        ctrl["reasons"].append(msg)
    return bool(cond)


def seal(ctrl):
    ctrl["status"] = "pass" if not ctrl["reasons"] else "fail"
    return ctrl


def run_cmd(cmd, rec_dir, name, timeout=CMD_TIMEOUT_S):
    """Finite timeout; stderr captured; returncode ALWAYS caller-checked."""
    stderr_path = os.path.join(rec_dir, name + ".stderr.txt")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        rc, out, err = proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        rc = 124
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        err = "TIMEOUT after %ss" % timeout
    try:
        with open(stderr_path, "w", encoding="utf-8") as fh:
            fh.write(err)
    except OSError:
        pass
    return rc, out, err


def spawn_child(cfg, rec_dir, ns_key, role_args, name, ev, all_children):
    stderr_fh = open(os.path.join(rec_dir, name + ".stderr.txt"), "w",
                     encoding="utf-8")
    cmd = ["ip", "netns", "exec", cfg["ns"][ns_key],
           sys.executable or "python3",
           os.path.join(HERE, "fixture.py")] + role_args
    # Responder children never write stdout; give them DEVNULL so a full
    # pipe can never block them. Senders print a JSON summary -> PIPE.
    stdout = (subprocess.PIPE if role_args and role_args[0] == "sender"
              else subprocess.DEVNULL)
    proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr_fh,
                            text=True)
    base = os.path.join(rec_dir, name)
    ev["children"][name] = {"pid": proc.pid, "ns": cfg["ns"][ns_key]}
    child = childman.Child(name, proc, stderr_fh,
                           base + ".stop", base + ".results.json")
    all_children.append(child)  # EVERY child is reaped in the final finally
    return child


def wait_ready(path, child, ctrl):
    """Bounded monotonic wait for a responder READY file."""
    deadline = time.monotonic() + READY_WAIT_S
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return True
        if child.proc.poll() is not None:
            break
        time.sleep(0.05)
    check(False, ctrl, "responder %s never became READY" % child.name)
    check(child.proc.poll() is None, ctrl,
          "responder %s exited early rc=%s" % (child.name, child.proc.poll()))
    return False


def collect_conntrack(cfg, ev, rec_dir, rtr_key, name):
    """Prefer the conntrack CLI inside the router ns; fall back to
    /proc/net/nf_conntrack; record which source was used."""
    ns = cfg["ns"][rtr_key]
    rc, out, _ = run_cmd(["ip", "netns", "exec", ns, "conntrack", "-L",
                          "-p", "udp"], rec_dir, name)
    if rc == 0:
        lines, source = out.splitlines(), "conntrack-cli"
    else:
        rc2, out2, _ = run_cmd(["ip", "netns", "exec", ns, "cat",
                                "/proc/net/nf_conntrack"],
                               rec_dir, name + "-proc")
        lines = out2.splitlines() if rc2 == 0 else []
        source = "proc-net-nf_conntrack" if rc2 == 0 else "unavailable"
    ev["conntrack"][rtr_key] = {
        "source": source,
        "raw": lines,
        "parsed": [p for p in (ctparse.parse_line(l) for l in lines) if p],
    }
    return ev["conntrack"][rtr_key]


def sender_summary(ctrl, rc, out, label):
    """Parse a sender child's JSON summary; a failed sender process marks the
    control FAILED instead of being silently ignored."""
    check(rc == 0, ctrl, "%s sender rc=%s" % (label, rc))
    summary = None
    if out:
        try:
            summary = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            check(False, ctrl, "%s sender summary not parseable" % label)
    if summary is None:
        ctrl["reasons"].append("%s sender produced no summary (process "
                               "failed to run?)" % label)
    return summary


def responder_records(child):
    results = child.read_results()
    if not results or "records" not in results:
        return None
    return results["records"]


# Sender stage: runs while ALL responders are alive. For the positive
# controls the sender may only assert what IT can observe: the echo comes
# from the SERVER endpoint (wan_ip:cal_port). The translated port is judged
# from responder records + conntrack, never from the sender's view.

def sender_stage(cfg, ev, rec_dir, all_children, name, ns_key, src_ip,
                 src_port, dst_ip, dst_port, token, count=SEND_COUNT):
    """Run one sender child to completion and check its JSON summary
    (sent>0; rc==0 and a parseable summary are enforced by sender_summary)."""
    ctrl = new_check()
    child = spawn_child(cfg, rec_dir, ns_key,
                        ["sender", name, src_ip, str(src_port), dst_ip,
                         str(dst_port), token, str(count)],
                        name, ev, all_children)
    try:
        out, rc = child.communicate(timeout=STOP_WAIT_S + ECHO_WAIT_S * count)
    finally:
        child.terminate()
    summary = sender_summary(ctrl, rc, out, name)
    if summary is not None:
        check(summary.get("sent", 0) > 0, ctrl,
              "%s sender sent nothing (transport broken?)" % name)
    # Normal-path escalation (the child had to be TERM/KILLed) is a failure:
    # cooperative STOP must suffice while everything works.
    check(not child.escalated, ctrl,
          "%s sender needed TERM/KILL escalation (normal path must use "
          "cooperative stop only)" % name)
    return ctrl, summary


# Positive sender stage: the sender may only assert what IT can observe —
# the echo comes from the SERVER endpoint (wan_ip:cal_port). The translated
# port is judged from responder records + conntrack, never the sender view.

def stage_positive(cfg, ev, rec_dir, all_children, host_key, src_port, token):
    """Returns the sender-stage control plus metadata for the later
    record/conntrack oracle (kept in one 'cal-<host>' control)."""
    label = "cal-" + host_key.split("_")[-1]
    wan_ip = cfg["ip"]["wan"]
    cal_port = cfg["port"]["cal"]
    ctrl, summary = sender_stage(
        cfg, ev, rec_dir, all_children, label, host_key,
        cfg["ip"][host_key], src_port, wan_ip, cal_port, token)
    if summary is not None:
        check(summary.get("errors", 1) == 0, ctrl, "sender had OSError sends")
        check(summary.get("replies", 0) > 0, ctrl,
              "no exact echo replies received")
        check(summary.get("mismatches", 0) == 0, ctrl,
              "echo payload mismatches observed")
        observed_ip = summary.get("observed_ip")
        observed_port = summary.get("observed_port")
        check(observed_ip == wan_ip, ctrl,
              "observed source ip %r != server (wan) ip %r"
              % (observed_ip, wan_ip))
        check(observed_port == cal_port, ctrl,
              "observed source port %r != server port %r (the sender can "
              "only ever see the un-translated server endpoint)"
              % (observed_port, cal_port))
    return {"label": label, "ctrl": ctrl, "host_key": host_key,
            "src_port": src_port, "token": token}


# Oracles over responder records + conntrack evidence.

def oracle_cal(cfg, ev, positive, cal_records):
    """One control per positive host covering all three observations:
    sender echo (reasons already on ctrl), the responder-recorded NAT
    tuple, and the EXACT conntrack translation tuple."""
    ctrl = positive["ctrl"]
    token = positive["token"]
    host_key = positive["host_key"]
    src_port = positive["src_port"]
    label = positive["label"]
    rtr_key = "rtr_" + host_key.split("_")[-1]
    rtr_wan_ip = cfg["ip"]["rtr_%s_wan" % host_key.split("_")[-1]]
    wan_ip = cfg["ip"]["wan"]
    cal_port = cfg["port"]["cal"]
    lo, hi = cfg["translated_ports"]
    if cal_records is None:
        ctrl["reasons"].append("cal responder produced no records")
        return seal(ctrl)
    got = [r for r in cal_records if r["token"] == token]
    check(len(got) >= 1, ctrl,
          "%s: responder never recorded %r" % (label, token))
    check(all(r["known"] is True for r in got), ctrl,
          "%s: %r not positively marked known" % (label, token))
    # The NAT tuple is ONLY knowable from the responder side: the post-NAT
    # source must be the host's router WAN IP with a valid translated port.
    matched = [r for r in got
               if r["known"] is True and r["src"][0] == rtr_wan_ip
               and translated_port_ok(r["src"][1], src_port, lo, hi)]
    check(bool(matched), ctrl,
          "%s: no known %r record with post-NAT src == %s and translated "
          "port in [%d,%d]" % (label, token, rtr_wan_ip, lo, hi))
    if not matched:
        return seal(ctrl)
    xlated_port = matched[0]["src"][1]
    ct = ev["conntrack"].get(rtr_key)
    if not ct or ct["source"] == "unavailable":
        ctrl["reasons"].append("no conntrack evidence from %s" % rtr_key)
        return seal(ctrl)
    entry = ctparse.find_translation(
        ct["raw"], cfg["ip"][host_key], src_port, wan_ip, cal_port,
        wan_ip, cal_port, rtr_wan_ip, xlated_port)
    if entry is None:
        ctrl["reasons"].append(
            "%s: no REPLIED MASQUERADE translation in %s with the EXACT "
            "observed tuple (orig %s:%d -> %s:%d, reply.src %s:%d, "
            "reply.dst %s:%d)" % (label, rtr_key, cfg["ip"][host_key],
                                  src_port, wan_ip, cal_port, wan_ip,
                                  cal_port, rtr_wan_ip, xlated_port))
    else:
        ev["conntrack"][rtr_key]["translation_" + label] = entry
    return seal(ctrl)


def oracle_wrong_token(cfg, ev, cal_records):
    ctrl = new_check()
    wrong_token = cfg["tokens"]["wrong"]
    if cal_records is None:
        ctrl["reasons"].append("cal responder produced no records")
    else:
        got = [r for r in cal_records if r["token"] == wrong_token]
        unknown = [r for r in got if r["known"] is False]
        check(len(unknown) >= NEG_COUNT, ctrl,
              "responder saw %d positively-unknown wrong-token datagrams, "
              "need >=%d" % (len(unknown), NEG_COUNT))
        check(not any(r["known"] is True for r in got),
              ctrl, "wrong token was accepted as known")
    ct = ev["conntrack"].get("rtr_a")
    if not ct or ct["source"] == "unavailable":
        ctrl["reasons"].append("no conntrack evidence from rtr-a")
    else:
        check(ctparse.has_replied_entry(ct["raw"], cfg["ip"]["host_a"],
                                        cfg["port"]["src_wrong"],
                                        cfg["ip"]["wan"],
                                        cfg["port"]["cal"]), ctrl,
              "no REPLIED conntrack entry for the wrong-token flow in rtr-a")
    return seal(ctrl)


def oracle_wrong_tuple(cfg, ev, sink_records, cal_records):
    ctrl = new_check()
    tuple_token = cfg["tokens"]["tuple"]
    if sink_records is None:
        ctrl["reasons"].append("sink responder produced no records")
    else:
        got = [r for r in sink_records if r["token"] == tuple_token]
        check(len(got) >= NEG_COUNT, ctrl,
              "sink received %d tok_tuple datagrams, need >=%d"
              % (len(got), NEG_COUNT))
    if cal_records is None:
        ctrl["reasons"].append("cal responder produced no records")
    else:
        check(not any(r["token"] == tuple_token for r in cal_records),
              ctrl, "calibration responder saw tok_tuple (port confusion)")
    # Deliberately NO conntrack requirement (ICMP may delete entries);
    # the oracle is sink receipt + no calibration match.
    return seal(ctrl)


def oracle_fwd_off(cfg, ev, off_records, off_ready_ok):
    ctrl = new_check()
    if not off_ready_ok:
        ctrl["reasons"].append("responder-off was not READY (cannot pass)")
    if off_records is None:
        ctrl["reasons"].append("responder-off produced no records")
    else:
        check(len(off_records) == 0, ctrl,
              "responder-off recorded %d datagrams, expected 0"
              % len(off_records))
    ct = ev["conntrack"].get("rtr_off")
    if not ct or ct["source"] == "unavailable":
        ctrl["reasons"].append("no conntrack evidence from rtr-off")
    else:
        check(not ctparse.has_replied_entry(ct["raw"], cfg["ip"]["host_off"],
                                            cfg["port"]["src_off"],
                                            cfg["ip"]["wan"],
                                            cfg["port"]["off"]), ctrl,
              "rtr-off shows a REPLIED/translated entry for the fwd-off flow")
    return seal(ctrl)


# Orchestrator main.

def write_evidence(ev, out_dir):
    """Best-evidence writer LAST in finally; never masks the original error.
    Returns True on success so the caller can fail the run if the evidence
    could not be written (a missing/failed write must never look like a
    successful normal run)."""
    try:
        tmp = os.path.join(out_dir, "evidence.json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(ev, fh, indent=2, sort_keys=True, default=str)
        os.replace(tmp, os.path.join(out_dir, "evidence.json"))
        return True
    except Exception as exc:  # noqa: BLE001 - evidence write must not mask
        try:
            sys.stderr.write("evidence write failed: %r\n" % (exc,))
        except OSError:
            pass
        return False


def cleanup_children(all_children, ev, escalation_expected=False):
    """Reap every spawned child (responders AND senders) on ANY exit path.

    Classification (defect: cleanup outcomes were indistinguishable):
      - preexisting unexpected nonzero child exit            -> failure
      - TERM/KILL escalation while escalation_expected       -> expected
        (abnormal teardown: injected failure or SIGTERM path)
      - TERM/KILL escalation on the NORMAL path              -> failure
      - survivor / wait error                                -> failure (always)
    """
    ev["child_cleanup"] = []
    ev["child_cleanup_errors"] = []
    for child in all_children:
        try:
            if child.proc.poll() is None:
                rc = child.terminate()
            else:
                rc = child.proc.returncode
            ev["child_cleanup"].append({
                "name": child.name,
                "action": child.action,
                "rc": rc,
                "error": child.error,
                "termination_requested": child.termination_requested,
                "escalated": child.escalated,
            })
            if child.proc.poll() is None:
                ev["child_cleanup_errors"].append(
                    {"name": child.name, "why": "still running after "
                                                 "terminate", "rc": rc})
            elif child.wait_error is not None:
                ev["child_cleanup_errors"].append(
                    {"name": child.name,
                     "why": "survived: %s" % child.wait_error, "rc": rc})
            elif child.error is not None:
                ev["child_cleanup_errors"].append(
                    {"name": child.name,
                     "why": "termination error: %s" % child.error, "rc": rc})
            elif rc not in (0, None):
                if child.escalated and escalation_expected:
                    # Intentional TERM/KILL during abnormal cleanup: the
                    # child never got to exit cooperatively because the
                    # orchestrator itself is failing/interrupted.
                    pass
                else:
                    why = ("escalated to TERM/KILL on the normal path"
                           if child.escalated
                           else "unexpected nonzero child exit")
                    ev["child_cleanup_errors"].append(
                        {"name": child.name, "why": why, "rc": rc})
        except Exception as exc:  # noqa: BLE001 - cleanup must complete
            ev["child_cleanup_errors"].append(
                {"name": child.name, "why": repr(exc)})


def orchestrator():
    # Default SIGTERM handling would kill the process WITHOUT running the
    # finally block, losing evidence in the interruption check. Convert
    # SIGTERM/SIGINT to SystemExit so finally runs. Child modes: no handlers.
    def _term_to_exit(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, _term_to_exit)
    signal.signal(signal.SIGINT, _term_to_exit)
    cfg = load_config()
    out_dir = cfg["out_dir"]
    rec_dir = os.path.join(out_dir, "records")
    os.makedirs(rec_dir, exist_ok=True)
    all_children = []
    ev = {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
          "controls": {}, "children": {}, "conntrack": {},
          "config": cfg}
    try:
        # 1) Start all responders, wait for READY (bounded).
        responders = {}
        ready_ok = {}
        for rec_name, tokens, port_key in (
                ("responder_cal",
                 "%s,%s" % (cfg["tokens"]["a"], cfg["tokens"]["b"]), "cal"),
                ("responder_sink", cfg["tokens"]["tuple"], "tuple"),
                ("responder_off", cfg["tokens"]["off"], "off")):
            base = os.path.join(rec_dir, rec_name)
            child = spawn_child(cfg, rec_dir, "wan",
                                ["responder", rec_name, cfg["ip"]["wan"],
                                 str(cfg["port"][port_key]),
                                 base + ".ready", base + ".stop",
                                 base + ".results.json", tokens],
                                rec_name, ev, all_children)
            responders[rec_name] = child
        for rec_name, child in responders.items():
            ctrl = new_check()
            ready_ok[rec_name] = wait_ready(
                os.path.join(rec_dir, rec_name + ".ready"), child, ctrl)
            if not ready_ok[rec_name]:
                ev["controls"]["ready_" + rec_name] = seal(ctrl)

        # Readiness gate: the marker may only be published when EVERY
        # responder is READY and still live; otherwise fail loudly.
        gate = new_check()
        for rec_name, child in responders.items():
            ready = ready_ok.get(rec_name, False)
            poll = child.proc.poll()
            if not ready:
                gate["reasons"].append(
                    "%s not READY" % rec_name)
            if poll is not None:
                gate["reasons"].append(
                    "%s not live (poll()=%s)" % (rec_name, poll))
        if gate["reasons"]:
            ev["controls"]["children-ready"] = seal(gate)
            raise RuntimeError("children not all ready/live; refusing to "
                               "publish children_started")
        # Phase marker: children are up; a later marker proves stages ran.
        marker = {"nonce": cfg["nonce"],
                  "pids": {name: child.proc.pid
                           for name, child in responders.items()}}
        # Atomic write (tmp + os.replace): the supervisor polls for this
        # file's existence and parses it as JSON, so it must never be
        # observed half-written.
        marker_path = os.path.join(rec_dir, "children_started")
        with open(marker_path + ".tmp", "w", encoding="utf-8") as fh:
            fh.write(json.dumps(marker) + "\n")
        os.replace(marker_path + ".tmp", marker_path)

        # Deterministic fault injection: exercises the finally cleanup path
        # with live children (opt-in via env).
        if os.environ.get("FIXTURE_FAULT_INJECT") == "1":
            raise RuntimeError("injected fixture failure after children "
                               "started")

        # 2) All senders run while every responder is alive.
        positives = [
            stage_positive(cfg, ev, rec_dir, all_children, "host_a",
                           cfg["port"]["src_a"], cfg["tokens"]["a"]),
            stage_positive(cfg, ev, rec_dir, all_children, "host_b",
                           cfg["port"]["src_b"], cfg["tokens"]["b"]),
        ]
        # Negative sender stages: paths/tokens from config; the wrong-token
        # stage checks port sanity, fwd-off adds its own ip_forward checks.
        wt_ctrl, _ = sender_stage(
            cfg, ev, rec_dir, all_children, "wrong-token", "host_a",
            cfg["ip"]["host_a"], cfg["port"]["src_wrong"], cfg["ip"]["wan"],
            cfg["port"]["cal"], cfg["tokens"]["wrong"])
        ev["controls"]["wrong-token"] = seal(wt_ctrl)
        tuple_ctrl = new_check()
        check(cfg["port"]["tuple"] != cfg["port"]["cal"], tuple_ctrl,
              "sink port must differ from calibration port")
        tuple_sender_ctrl, tuple_summary = sender_stage(
            cfg, ev, rec_dir, all_children, "wrong-tuple", "host_b",
            cfg["ip"]["host_b"], cfg["port"]["src_tuple"], cfg["ip"]["wan"],
            cfg["port"]["tuple"], cfg["tokens"]["tuple"])
        # The wrong-tuple verdict must incorporate the sender's outcome.
        tuple_ctrl["reasons"].extend(tuple_sender_ctrl["reasons"])
        ev["controls"]["wrong-tuple"] = seal(tuple_ctrl)
        off_ctrl, off_summary = sender_stage(
            cfg, ev, rec_dir, all_children, "fwd-off", "host_off",
            cfg["ip"]["host_off"], cfg["port"]["src_off"], cfg["ip"]["wan"],
            cfg["port"]["off"], cfg["tokens"]["off"])
        if off_summary is not None:
            check(off_summary.get("replies", 0) == 0, off_ctrl,
                  "fwd-off sender received replies despite ip_forward=0")
        ev["controls"]["fwd-off-sender"] = seal(off_ctrl)

        # 3) Stop responders (bounded), collect final records.
        records = {}
        for rec_name, child in responders.items():
            child.request_stop()
        for rec_name, child in responders.items():
            child.communicate(timeout=STOP_WAIT_S)
            child.terminate()
            records[rec_name] = responder_records(child)
            rec_ctrl = new_check()
            if records[rec_name] is None:
                rec_ctrl["reasons"].append(
                    "%s produced no records" % rec_name)
            elif child.term_result not in (0, None):
                rec_ctrl["reasons"].append(
                    "%s terminated rc=%s" % (rec_name, child.term_result))
            if child.escalated:
                # Normal path: cooperative STOP must suffice; escalation
                # here means a responder hung or ignored STOP.
                rec_ctrl["reasons"].append(
                    "%s needed TERM/KILL escalation on the normal path"
                    % rec_name)
            if rec_ctrl["reasons"]:
                ev["controls"]["records_" + rec_name] = seal(rec_ctrl)
        off_records = records.get("responder_off")
        cal_records = records.get("responder_cal")

        # 4) Conntrack evidence (raw + parsed) from each router.
        for rtr_key in ("rtr_a", "rtr_b", "rtr_off"):
            collect_conntrack(cfg, ev, rec_dir, rtr_key,
                              "conntrack-" + rtr_key)

        # 5) Final record/conntrack oracles. cal-a / cal-b each merge the
        # sender stage, the responder-recorded NAT tuple and the exact
        # conntrack tuple into ONE verdict.
        for positive in positives:
            ev["controls"][positive["label"]] = oracle_cal(
                cfg, ev, positive, cal_records)
        ev["controls"]["wrong-token-records"] = oracle_wrong_token(
            cfg, ev, cal_records)
        ev["controls"]["wrong-tuple-records"] = oracle_wrong_tuple(
            cfg, ev, records.get("responder_sink"), cal_records)
        ev["controls"]["fwd-off"] = oracle_fwd_off(cfg, ev, off_records,
                                                   ready_ok.get(
                                                       "responder_off",
                                                       False))
        # Roll up the fwd-off sender stage into the fwd-off verdict.
        if ev["controls"]["fwd-off-sender"]["status"] != "pass":
            ev["controls"]["fwd-off"]["reasons"].extend(
                ev["controls"]["fwd-off-sender"]["reasons"])
            ev["controls"]["fwd-off"]["status"] = "fail"

        failed = sorted(k for k, v in ev["controls"].items()
                        if v.get("status") != "pass")
        ev["failed_controls"] = failed
        ev["status"] = "pass" if not failed else "fail"
    except SystemExit as exc:
        # Signal conversion / config errors: record the interruption as an
        # EXPLICIT failing control (reason + code) so the evidence shows it,
        # then let finally run and the code propagate.
        ev["interruption"] = {"reason": "SystemExit", "code": repr(exc.code)}
        ev["status"] = "fail"
        ctrl = new_check()
        ctrl["reasons"].append("interrupted: reason=%s code=%r"
                               % ("SystemExit", exc.code))
        ev["controls"]["interrupted"] = seal(ctrl)
        if "interrupted" not in ev.setdefault("failed_controls", []):
            ev["failed_controls"].append("interrupted")
        raise
    except Exception as exc:  # noqa: BLE001 - record, then cleanup in finally
        ev["exception"] = repr(exc)
        ev["status"] = "fail"
        ctrl = new_check()
        ctrl["reasons"].append("orchestrator raised: %r" % (exc,))
        ev.setdefault("failed_controls", []).append("orchestrator-exception")
        ev["controls"]["orchestrator-exception"] = seal(ctrl)
    finally:
        # Child reaping FIRST, then evidence — on normal exit, exception and
        # SIGTERM alike. TERM/KILL escalation is EXPECTED only on the
        # abnormal paths (injected failure / interruption); it is a failure
        # on the normal path.
        ok_written = False
        abnormal = bool(ev.get("exception") or ev.get("interruption"))
        try:
            cleanup_children(all_children, ev,
                             escalation_expected=abnormal)
        except Exception as exc:  # noqa: BLE001
            ev["child_cleanup_errors"] = ev.get("child_cleanup_errors", [])
            ev["child_cleanup_errors"].append({"name": "*", "why": repr(exc)})
        # Cleanup failures must ALWAYS fail the run with an explicit control.
        cleanup_errors = ev.get("child_cleanup_errors") or []
        if cleanup_errors:
            ev["status"] = "fail"
            ctl = ev["controls"].get("child-cleanup")
            if not isinstance(ctl, dict):
                ctl = {"status": "fail", "reasons": []}
                ev["controls"]["child-cleanup"] = ctl
            ctl["status"] = "fail"
            ctl["reasons"].extend(repr(e) for e in cleanup_errors)
        # ALWAYS union failed_controls from every control (interrupt and
        # exception paths already added theirs); status reflects the union.
        ev["failed_controls"] = sorted(
            k for k, v in ev["controls"].items()
            if isinstance(v, dict) and v.get("status") != "pass")
        if ev["failed_controls"] or "status" not in ev:
            ev["status"] = "fail"
        ok_written = write_evidence(ev, out_dir)
    if ev.get("status") != "pass" or not ok_written:
        sys.stderr.write("FAILED controls: %s\n"
                         % ", ".join(ev.get("failed_controls", ["unknown"])))
        return 1
    return 0


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(
            "usage: fixture.py orchestrator|responder|sender ...\n")
        return 2
    if argv[1] == "responder":
        childman.run_responder(argv[2:])
        return 0
    if argv[1] == "sender":
        childman.run_sender(argv[2:])
        return 0
    if argv[1] == "orchestrator":
        return orchestrator()
    sys.stderr.write("unknown role %r\n" % argv[1])
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
