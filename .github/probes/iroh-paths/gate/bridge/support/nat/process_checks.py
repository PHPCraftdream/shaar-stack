"""CI-only supervised three-process control-link proof; never run on developer hosts."""
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import time


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream)


def wait_files(paths, children, seconds=40):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for name, process, _, _ in children:
            if process.poll() is not None:
                raise RuntimeError(f"{name} exited before its readiness phase: {process.returncode}")
        if all(path.is_file() for path in paths):
            return [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        time.sleep(0.05)
    raise TimeoutError("owned process readiness deadline")


def run(binary, config, root, name, children):
    config_path = root / f"{name}-config.json"
    write_json(config_path, config)
    stdout = (root / f"{name}.stdout").open("xb")
    stderr = (root / f"{name}.stderr").open("xb")
    try:
        process = subprocess.Popen([str(binary), str(config_path)], stdout=stdout, stderr=stderr)
    except BaseException:
        stdout.close()
        stderr.close()
        raise
    children.append((name, process, stdout, stderr))
    return process


def finish(process, name):
    code = process.wait(timeout=15)
    if code != 0:
        raise RuntimeError(f"{name} returned {code}; inspect its stderr artifact")


class InjectedFault(Exception):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fault-after-ready", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    nonce = secrets.token_hex(16)  # Public per-case correlation marker, not an authentication key.
    base = {"case_dir": str(root), "nonce": nonce}
    children = []
    evidence = {"status": "fail", "cleanup_failed": False}
    try:
        relay = run(binary, dict(base, role="relay", bind="127.0.0.1:0"), root, "relay", children)
        ready = wait_files([root / "relay-ready.json"], children)[0]
        address = ready["address"]
        peers = [run(binary, dict(base, role="peer", relay=address, bind="127.0.0.1:0", side=side),
                     root, f"peer-{side}", children) for side in range(2)]
        ready = wait_files([root / f"peer-{side}-ready.json" for side in range(2)], children)
        for side, report in enumerate(ready):
            assert report["side"] == side and report["tls_complete"] is True
            assert report["queued_bytes"] == 8 and report["premature_payload"] is False
        if args.fault_after_ready:
            raise InjectedFault("exact injected failure after both real peer readiness reports")
        (root / "GO").touch(exist_ok=False)
        observed = wait_files([root / f"peer-{side}-observed.json" for side in range(2)], children)
        assert all(report["native_delivered"] is False for report in observed)
        (root / "STOP").touch(exist_ok=False)
        for side, process in enumerate(peers):
            finish(process, f"peer-{side}")
            report = json.loads((root / f"peer-{side}-report.json").read_text(encoding="utf-8"))
            assert report["status"] == "pass" and report["side"] == side
            assert report["custom_sent"] > 0 and report["custom_received"] > 0
            assert report["native_delivered"] is False
        # Stop only after both owned peers exited and flushed their complete traces.
        stop = run(binary, dict(base, role="stop", relay=address), root, "stop", children)
        finish(stop, "relay stop")
        finish(relay, "relay")
        verifier = run(binary, dict(base, role="verify"), root, "verify", children)
        finish(verifier, "ciphertext verifier")
        proof = json.loads((root / "verified.json").read_text(encoding="utf-8"))
        assert proof["status"] == "pass" and len(proof["directions"]) == 2
        for direction in proof["directions"]:
            assert direction["captured_packets"] > 0
            assert direction["stream_frames"] == 0 and direction["datagram_frames"] == 0
        evidence.update(status="pass", proof=proof)
    except InjectedFault as error:
        evidence.update(status="expected-fault", phase="both-peers-ready", reason=str(error))
    finally:
        outcomes = []
        for name, process, stdout, stderr in children:
            forced = False
            try:
                if process.poll() is None:
                    forced = True
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                if process.poll() is None:
                    evidence["cleanup_failed"] = True
                if forced and evidence["status"] == "pass":
                    evidence["cleanup_failed"] = True
                outcomes.append({"name": name, "pid": process.pid, "code": process.returncode, "forced": forced})
            except BaseException as error:
                evidence["cleanup_failed"] = True
                outcomes.append({"name": name, "error": str(error)})
            finally:
                stdout.close()
                stderr.close()
        evidence["children"] = outcomes
        write_json(root / "process-evidence.json", evidence)
    if evidence["cleanup_failed"]:
        raise RuntimeError("owned process cleanup failed")
    if args.fault_after_ready:
        assert evidence["status"] == "expected-fault" and evidence["phase"] == "both-peers-ready"
        assert len(evidence["children"]) == 3
        assert all(child.get("code") is not None for child in evidence["children"])
    else:
        assert evidence["status"] == "pass"
    print(json.dumps(evidence))


if __name__ == "__main__":
    main()
