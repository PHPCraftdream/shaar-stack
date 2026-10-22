"""Privileged Linux CI-only QUIC proof in the topology owned by run.sh."""
import json
import os
from pathlib import Path
import signal
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import childman  # noqa: E402
import ctparse  # noqa: E402
import core  # noqa: E402
from capture import Capture  # noqa: E402


def interrupted(_signum, _frame):
    raise SystemExit(143)


def main():
    cfg = json.loads(os.environ["FIXTURE_CONFIG"])
    root = Path(cfg["out_dir"]).resolve(strict=True)
    binary = Path(cfg["quic_binary"]).resolve(strict=True)
    kind = cfg["quic_case"]
    if not binary.is_file() or not os.access(binary, os.X_OK) or kind not in ("positive", "blocked", "wrong-tuple"):
        raise ValueError("invalid QUIC binary/case")
    if len(cfg["nonce"]) != 32:
        raise ValueError("QUIC cases require a 32-hex-byte public nonce")
    cfg["helper_uid"] = int(os.environ.get("SUDO_UID", "0"))
    cfg["helper_gid"] = int(os.environ.get("SUDO_GID", "0"))
    if cfg["helper_uid"] <= 0 or cfg["helper_gid"] <= 0:
        raise ValueError("QUIC proof requires an unprivileged sudo caller")
    os.chown(root, cfg["helper_uid"], cfg["helper_gid"])
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    children = []
    ev = {"config": cfg, "status": "fail", "controls": {}, "failed_controls": ["incomplete"],
          "child_cleanup": [], "child_cleanup_errors": []}
    try:
        core.configure(cfg, root, kind)
        capture = Capture(cfg, root, childman.Child)
        children.append(capture.child)
        capture.ready()
        base = {"case_dir": str(root), "nonce": cfg["nonce"]}
        relay_address = f'{cfg["ip"]["wan"]}:{cfg["port"]["cal"]}'
        relay = core.spawn(cfg, root, binary, "wan", "relay", dict(base, role="relay", bind=relay_address), children, childman.Child)
        core.wait_files([root / "relay-ready.json"], children)
        peers = []
        for side, ns in enumerate(("host_a", "host_b")):
            host = cfg["ip"][ns]
            external_port = cfg["translated_ports"][side] + (1 if kind == "wrong-tuple" and side == 1 else 0)
            peer = dict(base, role="peer", side=side, relay=relay_address,
                        bind=f'{host}:{cfg["port"][("src_wrong", "src_tuple")[side]]}',
                        native_bind=f'{host}:{cfg["port"][("src_a", "src_b")[side]]}',
                        external_addr=f'{cfg["ip"][("rtr_a_wan", "rtr_b_wan")[side]]}:{external_port}',
                        expect_native=kind == "positive")
            peers.append(core.spawn(cfg, root, binary, ns, f"peer-{side}", peer, children, childman.Child))
        ready = core.wait_files([root / f"peer-{side}-ready.json" for side in range(2)], children)
        if not all(report["tls_complete"] is True and report["queued_bytes"] == 8 and report["premature_payload"] is False for report in ready):
            raise ValueError("real TLS/queued-negative phase failed")
        identities = {child.name: core.unprivileged(child.proc.pid, cfg["helper_uid"]) for child in [relay, *peers]}
        marker = {"nonce": cfg["nonce"], "pids": {child.name: child.proc.pid for child in children}}
        core.atomic(root / "records/children_started", marker)
        ev["controls"]["custom-bootstrap"] = {"status": "pass", "process_identities": identities}
        if os.environ.get("FIXTURE_FAULT_INJECT") == "1":
            raise RuntimeError("injected fixture failure after both real QUIC peers became ready")
        if os.environ.get("FIXTURE_QUIC_HOLD_READY") == "1":
            core.hold_ready_for_interrupt()
        (root / "GO").touch(exist_ok=False)
        observed = core.wait_files([root / f"peer-{side}-observed.json" for side in range(2)], children)
        if not all(report["native_delivered"] is (kind == "positive") for report in observed):
            raise ValueError("unexpected native observation")
        # Snapshot replied NAT state while both real peer sockets remain alive.
        conntrack = core.conntrack_snapshot(cfg, root)
        # Keep capture active until both endpoint drivers have closed and flushed qlogs.
        (root / "STOP").touch(exist_ok=False)
        for peer in peers:
            core.finish(peer)
        # The stop helper must originate in the WAN namespace, which owns the relay.
        stop_config = root / "stop-config.json"
        core.atomic(stop_config, dict(base, role="stop", relay=relay_address))
        core.run(cfg, "wan", [binary, stop_config], root / "records/stop.log")
        core.finish(relay)
        rows = capture.finish()
        translations = core.snapshot(cfg, root, kind, ctparse, rows, conntrack)
        core.atomic(root / "native-expectation.json", {"expected": kind == "positive"})
        core.helper(cfg, binary, root, "verify", relay_address)
        proof = json.loads((root / "verified.json").read_text(encoding="utf-8"))
        if proof.get("status") != "pass" or len(proof.get("directions", [])) != 2:
            raise ValueError("ciphertext correlation failed")
        ev["controls"]["native-case"] = {"status": "pass", "kind": kind, "translations": translations,
                                            "wan_datagrams": len(rows), "proof": proof}
        ev["status"], ev["failed_controls"] = "pass", []
    except SystemExit as error:
        ev["interruption"] = {"reason": "SystemExit", "code": str(error.code)}
        ev["controls"]["interrupted"] = {"status": "fail"}
        ev["failed_controls"] = ["interrupted"]
        raise
    except BaseException as error:
        ev["exception"] = str(error)
        ev["controls"]["exception"] = {"status": "fail"}
        ev["failed_controls"] = ["exception"]
        ev["diagnostic_errors"] = core.failure_snapshot(cfg, root)
        raise
    finally:
        normal = ev["status"] == "pass"
        for child in children:
            try:
                rc = child.terminate()
                failure = child.error or child.wait_error
                if rc is None or (normal and (rc != 0 or child.escalated)):
                    failure = failure or "unexpected child exit/escalation"
                ev["child_cleanup"].append({"name": child.name, "rc": rc, "error": failure,
                                             "action": child.action, "escalated": child.escalated})
                if failure:
                    ev["child_cleanup_errors"].append(child.name + ": " + str(failure))
            except BaseException as error:
                ev["child_cleanup_errors"].append(child.name + ": " + str(error))
        if ev["child_cleanup_errors"]:
            ev["status"] = "fail"
            ev["failed_controls"].append("child-cleanup")
        core.atomic(root / "evidence.json", ev)
    if ev["status"] != "pass":
        raise RuntimeError("QUIC proof cleanup failed")
    print(json.dumps(ev))


if __name__ == "__main__":
    main()
