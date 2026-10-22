"""Child process code for the P03 NAT topology fixture.

Two concerns, both config-free so they can be unit-tested standalone:
  - the responder/sender ROLE entry points (invoked via `ip netns exec`,
    all paths arriving as absolute argv strings), and
  - the tracked-subprocess wrapper used by the orchestrator: bounded
    TERM/KILL termination, cooperative STOP-file requests, result reading.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time

RESP_MAX_PACKETS = 200
RESP_DEADLINE_S = 90.0  # must exceed the worst-case sum of all sender stages
ECHO_WAIT_S = 2.0  # bounded per-datagram echo wait


# Pure echo-validation helpers (also re-exported by fixture.py for the
# selftest; no side effects, no config).

def expected_echo_payload(token, seq):
    return "ECHO|%s|%s" % (token, seq)


def echo_ok(payload, src_ip, src_port, exp_ip, exp_port, token, seq):
    """A reply counts ONLY if byte-for-byte exact and sourced from the
    responder's ip:port; anything else is a mismatch/foreign packet."""
    if (src_ip, src_port) != (exp_ip, exp_port):
        return False
    return payload == expected_echo_payload(token, seq)


# Child role entry points.

def run_responder(args):
    """args: name bind_ip port ready_file stop_file results_file tokens_csv.
    Binds, writes a READY file, then loops with short recv timeouts until an
    overall monotonic deadline, a STOP file, or RESP_MAX_PACKETS."""
    name, bind_ip, port_s, ready_file, stop_file, results_file, tokens_csv = args
    port = int(port_s)
    expected = set(t for t in tokens_csv.split(",") if t)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, port))
    sock.settimeout(0.2)
    with open(ready_file, "w", encoding="utf-8") as fh:
        fh.write("ready\n")
    deadline = time.monotonic() + RESP_DEADLINE_S
    records = []
    while len(records) < RESP_MAX_PACKETS and time.monotonic() < deadline:
        if os.path.exists(stop_file):
            break
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        text = data.decode("utf-8", errors="replace")
        token, _, seq = text.partition("|")
        records.append({"token": token, "seq": seq,
                        "src": [addr[0], addr[1]],
                        "known": token in expected})
        # Echo everything so NAT entries become REPLIED and senders can
        # validate exact payloads; unknown tokens are only marked unknown.
        try:
            sock.sendto(expected_echo_payload(token, seq)
                        .encode("utf-8"), addr)
        except OSError:
            pass
    sock.close()
    tmp = results_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"name": name, "records": records}, fh)
    os.replace(tmp, results_file)


def run_sender(args):
    """args: name bind_ip src_port dst_ip dst_port token count.
    Binds the known private source port, sends N datagrams, validates every
    echo exactly. Prints a JSON summary on stdout; exit code is 0 even when
    no replies arrive (callers judge the control from the summary)."""
    name, bind_ip, src_port_s, dst_ip, dst_port_s, token, count_s = args
    src_port, dst_port, count = int(src_port_s), int(dst_port_s), int(count_s)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, src_port))
    sock.settimeout(0.2)
    sent = replies = mismatches = foreign = errors = 0
    observed_ip = observed_port = None
    for seq in range(count):
        payload = "%s|%d" % (token, seq)
        try:
            sock.sendto(payload.encode("utf-8"), (dst_ip, dst_port))
            sent += 1  # an OSError must never count as sent
        except OSError:
            errors += 1
            continue
        send_deadline = time.monotonic() + ECHO_WAIT_S
        while time.monotonic() < send_deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            except OSError:
                break
            text = data.decode("utf-8", errors="replace")
            if echo_ok(text, addr[0], addr[1], dst_ip, dst_port, token, seq):
                replies += 1
                if observed_ip is None:
                    observed_ip, observed_port = addr[0], addr[1]
                break
            if (addr[0], addr[1]) == (dst_ip, dst_port):
                mismatches += 1
            else:
                foreign += 1
        time.sleep(0.05)
    sock.close()
    print(json.dumps({"name": name, "sent": sent, "replies": replies,
                      "mismatches": mismatches, "foreign": foreign,
                      "errors": errors, "observed_ip": observed_ip,
                      "observed_port": observed_port}))


# Tracked subprocess wrapper.


class Child:
    """Tracked subprocess with graceful-then-escalating termination.

    Termination order: cooperative STOP request -> bounded wait -> TERM ->
    bounded wait -> KILL -> bounded wait. Every outcome is recorded (action,
    rc, error, termination_requested, escalated) so the orchestrator can
    classify: preexisting unexpected nonzero exits are failures, TERM/KILL
    during abnormal teardown is expected, survivors/wait errors are
    failures, and ANY escalation on the normal path is a failure.
    """

    GRACEFUL_WAIT_S = 3.0  # bounded cooperative wait after STOP request
    TERM_WAIT_S = 5.0      # bounded wait after SIGTERM
    KILL_WAIT_S = 5.0      # bounded wait after SIGKILL

    def __init__(self, name, proc, stderr_fh, stop_file, results_file):
        self.name = name
        self.proc = proc
        self.stderr_fh = stderr_fh
        self.stop_file = stop_file
        self.results_file = results_file
        self.term_result = None
        self.wait_error = None  # set if the process survived TERM+KILL
        self.termination_requested = False
        self.escalated = False  # True if TERM or KILL was needed
        self.action = "none"   # none|stop|term|kill
        self.error = None      # repr of the last termination error, if any

    def communicate(self, timeout):
        try:
            out, _ = self.proc.communicate(timeout=timeout)
            return out, self.proc.returncode
        except subprocess.TimeoutExpired:
            self.request_stop()
            self.terminate()
            return None, self.proc.returncode

    def request_stop(self):
        self.termination_requested = True
        try:
            with open(self.stop_file, "w", encoding="utf-8") as fh:
                fh.write("stop\n")
        except OSError as exc:
            self.error = repr(exc)

    def _bounded_wait(self, timeout):
        try:
            self.proc.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def terminate(self):
        """STOP -> bounded graceful wait -> TERM -> bounded wait -> KILL.
        Always reaps; a survivor is recorded, never raised (so terminate()
        stays usable inside except/cleanup paths)."""
        if self.proc.poll() is None:
            self.termination_requested = True
            self.request_stop()
            if not self._bounded_wait(self.GRACEFUL_WAIT_S):
                self.escalated = True
                self.action = "term"
                try:
                    self.proc.terminate()
                except OSError as exc:
                    self.error = repr(exc)
                if not self._bounded_wait(self.TERM_WAIT_S):
                    self.action = "kill"
                    try:
                        self.proc.kill()
                    except OSError as exc:
                        self.error = repr(exc)
                    if not self._bounded_wait(self.KILL_WAIT_S):
                        self.wait_error = "survived TERM+KILL"
            else:
                self.action = "stop"
        self.term_result = self.proc.returncode
        try:
            self.stderr_fh.close()
        except OSError:
            pass
        return self.term_result

    def read_results(self):
        try:
            with open(self.results_file, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None


# ---------------------------------------------------------------------------
# CI-only JSON validators + ROOT interruption supervisor (CLI subcommands
# used by nat-topology.yml via `python3 -I selftest.py <mode>`, which
# re-exports them; selftest keeps the tests). Strict json.load + type
# checks, never textual grep, so wrong-typed values fail. Not used by the
# orchestrator runtime; placing them here avoids import cycles.
# ---------------------------------------------------------------------------

SETUP_REASON = "injected setup failure after three namespaces"

# Per-case cleanup expectations: exact injection flags, phase, reason.
CASES = {
    "normal": {"setup": False, "fix": False, "phase": "normal", "reason": "", "count": None},
    "setup-fault": {"setup": True, "fix": False, "phase": "setup-injected", "reason": SETUP_REASON, "count": 3},
    "fixture-fault": {"setup": False, "fix": True, "phase": "normal", "reason": "", "count": None},
    "interrupt": {"setup": False, "fix": False, "phase": "normal", "reason": "", "count": None},
}

def _die(msg):
    sys.stderr.write("childman validator: %s\n" % msg)
    sys.exit(2)

def _load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        _die("%s: cannot load JSON: %s" % (path, exc))
    if not isinstance(data, dict):
        _die("%s: top-level JSON is not an object" % path)
    return data

def _req_bool(obj, path, key, expected):
    v = obj.get(key)
    if not isinstance(v, bool) or v is not expected:
        _die("%s: %s must be boolean %s (got %r)" % (path, key, expected, v))

def _req_empty_list(obj, path, key):
    v = obj.get(key)
    if not isinstance(v, list) or v != []:
        _die("%s: %s must be an empty list (got %r)" % (path, key, v))

def _req_eq(obj, path, key, expected):
    if obj.get(key) != expected:
        _die("%s: %s must be %r (got %r)" % (path, key, expected, obj.get(key)))

def _flags(argv, bare_flags, valued_flags):
    """Parse optional positional PATH, then ALLOWED --FLAG / --OPT VAL.
    Unknown and duplicate options are rejected."""
    path = None
    opts = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            if a in bare_flags:
                if a in opts:
                    _die("duplicate option: %s" % a)
                opts[a] = True
            elif a in valued_flags:
                if a in opts:
                    _die("duplicate option: %s" % a)
                i += 1
                if i >= len(argv):
                    _die("%s requires a value" % a)
                opts[a] = argv[i]
            else:
                _die("unknown option: %s" % a)
        elif path is None:
            path = a
        else:
            _die("unexpected positional argument: %s" % a)
        i += 1
    return path, opts

def validate_cleanup(argv):
    """validate-cleanup CLEANUP_JSON [--expect-cleanup-failed true|false]
    [--nonce NONCE] [--case normal|setup-fault|fixture-fault|interrupt]"""
    path, opts = _flags(argv, set(),
                        {"--expect-cleanup-failed", "--nonce", "--case"})
    if path is None:
        _die("usage: validate-cleanup CLEANUP_JSON [--expect-cleanup-failed "
             "true|false] [--nonce N] [--case C]")
    exp = opts.get("--expect-cleanup-failed")
    if exp is not None and exp not in ("true", "false"):
        _die("--expect-cleanup-failed requires true|false")
    nonce = opts.get("--nonce")
    case = opts.get("--case")
    if case is not None and case not in CASES:
        _die("--case requires one of %s" % ", ".join(sorted(CASES)))
    obj = _load_json(path)
    _req_bool(obj, path, "cleanup_failed", exp == "true")
    _req_empty_list(obj, path, "namespace_processes_left")
    _req_empty_list(obj, path, "interface_survivors")
    _req_empty_list(obj, path, "cleanup_errors")
    _req_bool(obj, path, "host_fw_capture_ok", True)
    _req_bool(obj, path, "host_fw_canonical_changed", False)
    _req_bool(obj, path, "host_ip_forward_changed", False)
    _req_bool(obj, path, "host_firewall_changed", False)
    _req_eq(obj, path, "namespaces_remaining", "0")
    if nonce is not None:
        _req_eq(obj, path, "nonce", nonce)
    if case is not None:
        want = CASES[case]
        # Strict boolean checks of BOTH injection flags, no numeric fakes.
        _req_bool(obj, path, "fault_inject_setup", want["setup"])
        _req_bool(obj, path, "fault_inject_fixture", want["fix"])
        _req_eq(obj, path, "phase", want["phase"])
        _req_eq(obj, path, "reason", want["reason"])
        count = obj.get("namespaces_created_count")
        if want["count"] is not None:
            created = obj.get("namespaces_created")
            if (count != want["count"] or not isinstance(created, list)
                    or len(created) != want["count"]):
                _die("%s: namespaces_created must be a list of EXACTLY %d "
                     "entries with count %d (got count=%r created=%r)"
                     % (path, want["count"], want["count"], count, created))
            # Exact list: prefix-derived -wan/-host-a/-host-b, NO extras.
            pfx = None
            for n in created:
                if isinstance(n, str) and n.endswith("-wan"):
                    pfx = n[:-len("-wan")]
            expected = sorted([pfx + "-wan", pfx + "-host-a",
                               pfx + "-host-b"]) if pfx else None
            if expected is None or sorted(created) != expected:
                _die("%s: created namespaces must be exactly "
                     "<prefix>-wan/-host-a/-host-b (got %r)"
                     % (path, created))
    return 0

def _check_phase_obj(data, nonce, label):
    """Shared children_started marker checks (nonce + >=3 positive pids)."""
    if not isinstance(data, dict):
        _die("%s: top-level JSON is not an object" % label)
    if data.get("nonce") != nonce:
        _die("%s: nonce mismatch: expected %r, got %r"
             % (label, nonce, data.get("nonce")))
    pids = data.get("pids")
    if not isinstance(pids, dict) or len(pids) < 3:
        _die("%s: pids must be a dict with >=3 entries (got %r)" % (label, pids))
    for name, pid in pids.items():
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            _die("%s: pid %r must be an int > 0 (got %r)" % (label, name, pid))
    return pids

def validate_phase(argv):
    """validate-phase PHASE_JSON|- NONCE  ('-' reads one JSON line from stdin)"""
    if len(argv) != 2:
        _die("usage: validate-phase PHASE_JSON|- NONCE")
    src, nonce = argv
    try:
        if src == "-":
            data = json.load(sys.stdin)
        else:
            with open(src, "r", encoding="utf-8") as fh:
                data = json.load(fh)
    except (OSError, ValueError) as exc:
        _die("phase marker: cannot load JSON: %s" % exc)
    _check_phase_obj(data, nonce, "phase marker")
    return 0

def validate_evidence(argv):
    """validate-evidence EVIDENCE_JSON --expect-status fail|pass
    [--expect-exception-substr SUBSTR] [--expect-interrupted] [--nonce N]"""
    path, opts = _flags(argv, {"--expect-interrupted"},
                        {"--expect-status", "--expect-exception-substr",
                         "--nonce"})
    if path is None:
        _die("usage: validate-evidence EVIDENCE_JSON --expect-status "
             "fail|pass [--expect-exception-substr S] [--expect-interrupted] "
             "[--nonce N]")
    expect_status = opts.get("--expect-status")
    if expect_status not in ("fail", "pass"):
        _die("--expect-status fail|pass is required")
    expect_sub = opts.get("--expect-exception-substr")
    expect_interrupted = "--expect-interrupted" in opts
    nonce = opts.get("--nonce")
    obj = _load_json(path)
    _req_eq(obj, path, "status", expect_status)
    failed = obj.get("failed_controls")
    if expect_status == "pass":
        if not isinstance(failed, list) or failed != []:
            _die("%s: passing evidence must have failed_controls == [] "
                 "(got %r)" % (path, failed))
    else:
        if (not isinstance(failed, list) or not failed
                or not all(isinstance(s, str) for s in failed)):
            _die("%s: failed_controls must be a non-empty list of strings "
                 "(got %r)" % (path, failed))
    if expect_sub is not None:
        exc = obj.get("exception")
        if not isinstance(exc, str) or expect_sub not in exc:
            _die("%s: exception must be a string containing %r (got %r)"
                 % (path, expect_sub, exc))
    if expect_interrupted:
        if "exception" in obj:
            _die("%s: exception must be absent on the interruption path" % path)
        itr = obj.get("interruption")
        if (not isinstance(itr, dict) or itr.get("reason") != "SystemExit"
                or itr.get("code") != "143"):
            _die("%s: interruption must record reason=SystemExit code=\"143\" "
                 "(got %r)" % (path, itr))
        ctrls = obj.get("controls")
        if (not isinstance(ctrls, dict)
                or not isinstance(ctrls.get("interrupted"), dict)
                or ctrls["interrupted"].get("status") != "fail"):
            _die("%s: controls.interrupted must be a failing control" % path)
        if not isinstance(failed, list) or "interrupted" not in failed:
            _die("%s: failed_controls must include 'interrupted'" % path)
    if nonce is not None:
        cfg = obj.get("config")
        cfg_nonce = cfg.get("nonce") if isinstance(cfg, dict) else None
        if cfg_nonce != nonce:
            _die("%s: config nonce mismatch: expected %r, got %r"
                 % (path, nonce, cfg_nonce))
    _req_empty_list(obj, path, "child_cleanup_errors")
    cc = obj.get("child_cleanup")
    if not isinstance(cc, list) or not cc:
        _die("%s: child_cleanup must be a non-empty list (got %r)"
             % (path, cc))
    for e in cc:
        if (not isinstance(e, dict) or not isinstance(e.get("rc"), int)
                or isinstance(e.get("rc"), bool)
                or e.get("error") is not None):
            _die("%s: child_cleanup entries must carry an integer rc and a "
                 "null error (got %r)" % (path, e))
    return 0

# Root-owned interruption supervisor (replaces any shell TERM/pid loop).

def _proc_identity(pid):
    """(ppid, starttime) from /proc/PID/stat: fields after the last ')'
    start at the state field (index 0), so ppid is index 1, starttime 19."""
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8") as fh:
            s = fh.read()
    except OSError as exc:
        _die("cannot read /proc/%d/stat: %s" % (pid, exc))
    rest = s[s.rindex(")") + 2:].split()
    if len(rest) < 20:
        _die("/proc/%d/stat too short" % pid)
    if rest[0] == "Z":
        _die("/proc/%d is a zombie" % pid)
    return int(rest[1]), int(rest[19])

def _descendants(root_pid):
    """Set of all live descendant PIDs of root_pid by walking /proc PPIDs."""
    parents = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry, "r", encoding="utf-8") as fh:
                s = fh.read()
            rest = s[s.rindex(")") + 2:].split()
            parents[int(entry)] = int(rest[1])
        except (OSError, ValueError, IndexError):
            continue
    live = set()
    for pid in parents:
        cur, hops = pid, 0
        while cur in parents and hops < 4096:
            cur = parents[cur]
            if cur == root_pid:
                live.add(pid)
                break
            hops += 1
    return live

# Scoped SIGTERM/SIGINT handling for the ROOT supervisor: signals are never
# delivered to arbitrary processes; the scope only controls THIS process's
# handling so cancellation unwinds into the finally reaper and repeated
# signals cannot interrupt the final bounded reap.

class term_signal_scope(object):
    """Context manager over SIGTERM/SIGINT handling for this process only.

    mode="exit": handler raises SystemExit(128+signum) so an in-flight
    supervision unwinds into the finally reaper.
    mode="defer": handler only counts signals (used inside the final reaper
    so repeated TERM/INT cannot interrupt it).
    On entry the signals are ALSO blocked via pthread_sigmask (no window
    between spawn and handler installation); on exit the ORIGINAL handlers
    are restored BEFORE the mask is unblocked, on all paths."""

    SIGNALS = (signal.SIGTERM, signal.SIGINT)

    def __init__(self, signal_mod=signal, mode="exit"):
        self._sig = signal_mod
        self.mode = mode
        self.triggered = []
        self._prev = {}
        self._pre_mask = None   # mask BEFORE blocking (child restore source)
        self.unblocked = False

    def _handler(self, signum, frame):
        self.triggered.append(signum)
        if self.mode == "exit":
            raise SystemExit(128 + signum)

    def __enter__(self):
        # pthread_sigmask returns the PREVIOUS mask; keep it for both the
        # child-side restore and our own unblock.
        self._pre_mask = self._sig.pthread_sigmask(self._sig.SIG_BLOCK,
                                                   self.SIGNALS)
        for s in self.SIGNALS:
            self._prev[s] = self._sig.signal(s, self._handler)
        return self

    def restore_child_mask(self):
        """preexec_fn hook: runs in the forked child BEFORE exec to undo the
        parent's SIGTERM/SIGINT mask block — otherwise the spawned run.sh
        would inherit the blocked mask and never receive SIGTERM. Safe only
        because this supervisor is a SINGLE-THREADED CI helper on Linux
        (preexec_fn is unsupported in multi-threaded processes); the hook
        only calls signal.pthread_sigmask(SIG_SETMASK, saved)."""
        if self._pre_mask is not None:
            self._sig.pthread_sigmask(self._sig.SIG_SETMASK, self._pre_mask)

    def unblock(self):
        """Restore the ORIGINAL pre-block mask while KEEPING the scope's
        handlers: after ownership is established a signal raises (exit mode)
        or is merely counted (defer mode) instead of killing us."""
        if not self.unblocked:
            self._sig.pthread_sigmask(self._sig.SIG_SETMASK, self._pre_mask)
            self.unblocked = True

    def __exit__(self, *exc):
        # Restore handlers while delivery is blocked, then restore the mask.
        self._sig.pthread_sigmask(self._sig.SIG_BLOCK, self.SIGNALS)
        try:
            for s, h in self._prev.items():
                self._sig.signal(s, h)
        finally:
            self._sig.pthread_sigmask(self._sig.SIG_SETMASK, self._pre_mask)
        return False


def supervise_interrupt(argv):
    """supervise-interrupt RUN_SH CASE_DIR NONCE [PHASE_TIMEOUT_S]
    ROOT only. Owns run.sh via Popen, waits bounded for the nonce-tagged
    children marker, verifies marker PIDs are live descendants, checks
    identity (no PID reuse), SIGTERMs via send_signal, requires rc 143,
    validates cleanup+evidence; always reaps in finally."""
    if len(argv) < 3 or len(argv) > 4:
        _die("usage: supervise-interrupt RUN_SH CASE_DIR NONCE "
             "[PHASE_TIMEOUT_S]")
    run_sh = os.path.abspath(argv[0])
    casedir = os.path.abspath(argv[1])
    nonce = argv[2]
    phase_timeout = float(argv[3]) if len(argv) == 4 else 40.0
    if not os.path.isfile(run_sh):
        _die("run.sh not found: %s" % run_sh)
    if os.getuid() != 0:
        _die("supervisor must run as root (workflow elevates via sudo)")
    if os.path.exists(casedir):
        _die("case dir already exists (run.sh would refuse): %s" % casedir)
    # Scoped signal handling: handlers installed and TERM/INT BLOCKED before
    # spawn, so there is no window where the child exists but a signal could
    # kill us without unwinding into the reaper. Spawn failure restores.
    body = term_signal_scope(signal, mode="exit")
    body.__enter__()
    try:
        # preexec_fn (single-threaded supervisor, Linux CI): the forked
        # child restores the pre-block mask before exec so run.sh can
        # receive SIGTERM normally.
        proc = subprocess.Popen(["bash", run_sh, casedir, nonce],
                                preexec_fn=body.restore_child_mask)
    except BaseException:
        body.__exit__(*sys.exc_info())
        raise
    survivor = None
    try:
        # Child is owned: unblock while KEEPING our handlers — TERM/INT now
        # convert to SystemExit and unwind into the finally reaper.
        body.unblock()
        # Identity is captured INSIDE try so any /proc read failure still
        # goes through the finally reaper.
        ident = _proc_identity(proc.pid)
        marker = os.path.join(casedir, "records", "children_started")
        deadline = time.monotonic() + phase_timeout
        while not os.path.exists(marker) and time.monotonic() < deadline:
            if proc.poll() is not None:
                _die("run.sh exited rc=%s before children started"
                     % proc.returncode)
            time.sleep(0.25)
        if not os.path.exists(marker):
            _die("children_started never appeared in %s" % casedir)
        with open(marker, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        pids = _check_phase_obj(data, nonce, "phase marker")
        # Marker PIDs must be live descendants of OUR run.sh process; their
        # start identities are captured for a re-check right before TERM.
        live = _descendants(proc.pid)
        idents = {}
        for name, pid in pids.items():
            if pid not in live:
                _die("phase pid %s (%s) is not a live descendant of the "
                     "owned run.sh pid %d" % (pid, name, proc.pid))
            idents[pid] = _proc_identity(pid)
        # Immediately before the signal: run.sh alive, still root, its own
        # identity unchanged (no PID reuse), and every marked child still a
        # live descendant with the SAME identity. Signal via the owned
        # Popen, never a pid file.
        live = _descendants(proc.pid)
        if (proc.poll() is not None or os.getuid() != 0
                or _proc_identity(proc.pid) != ident
                or any(pid not in live or _proc_identity(pid) != idents[pid]
                       for pid in idents)):
            _die("run.sh or marked children changed identity/liveness "
                 "before TERM (refusing to signal)")
        proc.send_signal(signal.SIGTERM)
        try:
            rc = proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            _die("run.sh did not exit within 90s of SIGTERM")
        if rc != 143:
            _die("interrupted run exited %r, expected 143" % rc)
        validate_cleanup([os.path.join(casedir, "cleanup-evidence.json"),
                          "--case", "interrupt", "--nonce", nonce])
        validate_evidence([os.path.join(casedir, "evidence.json"),
                           "--expect-status", "fail",
                           "--expect-interrupted", "--nonce", nonce])
        return 0
    finally:
        # Keep the same installed handlers, but defer signals during reaping.
        # There is no intermediate restoration of exit-raising handlers.
        body.mode = "defer"
        try:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    try:
                        proc.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=60)
                except Exception as exc:  # noqa: BLE001 - retain original error
                    survivor = "final reap error: %r" % (exc,)
            if proc.poll() is None:
                survivor = "run.sh pid %d survived final TERM+KILL" % proc.pid
        finally:
            body.__exit__(None, None, None)
        if survivor is not None:
            sys.stderr.write("supervisor: %s\n" % survivor)
            if sys.exc_info()[0] is None:
                raise RuntimeError(survivor)


VALIDATORS = {
    "validate-cleanup": validate_cleanup,
    "validate-phase": validate_phase,
    "validate-evidence": validate_evidence,
    "supervise-interrupt": supervise_interrupt,
}
