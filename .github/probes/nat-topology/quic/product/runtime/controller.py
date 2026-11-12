"""Root controller for one product case, started by run.sh inside the topology it owns and cleans up."""

import json
import os
from pathlib import Path
import signal
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import case as runcase  # noqa: E402
import contract  # noqa: E402
import kernel  # noqa: E402
import preflight  # noqa: E402
import processes  # noqa: E402

TOOLS = ("ip", "nft", "setpriv", "sysctl", "cat")
SCOPE = "controlled-product-case-evidence"


def interrupted(_signum, _frame):
    # Installed before any child exists, so children never inherit an ignored SIGINT from a background job.
    raise SystemExit(143)


def find_tools():
    found = {name: preflight.trusted_tool(name) for name in TOOLS}
    missing = [name for name, path in found.items() if path is None]
    contract.require(not missing, "required preinstalled tools missing: " + ", ".join(missing))
    result = {name: str(path) for name, path in found.items()}
    result["python"] = str(Path(sys.executable).resolve(strict=True))
    return result


def verify_products(manifest, source):
    products = contract.validate_manifest(manifest, source)
    for name, product in products.items():
        path = Path(product["executable"])
        contract.require(path.is_file() and os.access(path, os.X_OK), "product executable missing: " + name)
        contract.require(contract.file_digest(path) == product["sha256"] and path.stat().st_size == product["bytes"],
                         "product executable differs from the verified manifest: " + name)
    return products


def prepare(root, uid, gid):
    (root / "logs").mkdir()
    work = root / "work"
    work.mkdir(mode=0o700)
    (work / "keys").mkdir(mode=0o700)
    for path in (work, work / "keys"):
        os.chown(path, uid, gid)
    return root / "logs"


def hold_for_interrupt():
    def expired(_signum, _frame):
        raise TimeoutError("interrupt supervisor did not signal the held live phase")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(60)
    try:
        signal.pause()
        raise RuntimeError("held phase resumed without termination")
    finally:
        signal.alarm(0)


def make_hook(fault, hold):
    def after_live():
        if fault:
            raise RuntimeError("injected fixture failure after live products")
        if hold:
            hold_for_interrupt()
    return after_live


def child_report(supervisor, spec, passed):
    entries, errors = [], []
    for child in supervisor.children:
        expected = spec["client_exit"] if child.name == "client" else 0
        failure = None
        if passed and (child.returncode != expected or child.signals):
            failure = f"unexpected exit {child.returncode} or escalation {child.signals}"
        entries.append({"name": child.name, "rc": child.returncode, "error": failure, "signals": child.signals})
        if failure:
            errors.append(child.name + ": " + failure)
    return entries, errors


def diagnostics(cfg, tools, root):
    """Bounded failure snapshots; their own failures are recorded, never hidden."""
    found = []
    deadline = time.monotonic() + 8
    for router in ("rtr_a", "rtr_b"):
        try:
            text = json.dumps(kernel.snapshot(cfg, tools, router, deadline))
            (root / f"failure-nft-{router}.json").write_text(text[:contract.MAX_REPORT], encoding="utf-8")
            lines = kernel.conntrack_lines(cfg, tools, router, deadline)
            (root / f"failure-conntrack-{router}.txt").write_text("\n".join(lines[:256]) + "\n", encoding="utf-8")
        except Exception as error:  # noqa: BLE001 - diagnostics must not mask the original failure
            found.append(f"{router}: {str(error)[:200]}")
    return found


def main():
    cfg = json.loads(os.environ["FIXTURE_CONFIG"])
    source, case = os.environ["FIXTURE_PRODUCT_SOURCE"], os.environ["FIXTURE_PRODUCT_CASE"]
    cfg["helper_uid"], cfg["helper_gid"] = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
    root = contract.validate_config(cfg, source, case)
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    fault, hold = os.environ.get("FIXTURE_FAULT_INJECT") == "1", os.environ.get("FIXTURE_PRODUCT_HOLD") == "1"
    purpose = "fault" if fault or hold else "product"
    started = time.monotonic()
    ev = {"schema": 1, "scope": SCOPE, "case": case, "purpose": purpose, "source_revision": source,
          "config": {key: value for key, value in cfg.items() if key != "tokens"}, "status": "fail",
          "controls": {}, "failed_controls": ["incomplete"], "child_cleanup": [], "child_cleanup_errors": []}
    supervisor, run, tools = None, None, None
    try:
        manifest = contract.bounded_json(os.environ["FIXTURE_PRODUCT_MANIFEST"])
        products = verify_products(manifest, source)
        ev["products"] = {name: {key: product[key] for key in ("sha256", "bytes", "executable")} for name, product in products.items()}
        ev["normal_native_gate_enabled"] = manifest["normal_native_gate_enabled"]
        tools = find_tools()
        logs = prepare(root, cfg["helper_uid"], cfg["helper_gid"])
        supervisor = processes.Supervisor(logs, started + contract.CASE_SECONDS - contract.CLEANUP_RESERVE)
        run = runcase.Run(cfg, root, case, products, tools, supervisor, purpose, started)
        run.run(make_hook(fault, hold))
        ev["status"], ev["failed_controls"] = "pass", []
    except SystemExit as error:
        ev["interruption"] = {"reason": "SystemExit", "code": str(error.code)}
        ev["controls"]["interrupted"] = {"status": "fail"}
        ev["failed_controls"] = ["interrupted"]
        raise
    except BaseException as error:
        ev["exception"] = f"{type(error).__name__}: {error}"[:2000]
        ev["controls"]["exception"] = {"status": "fail"}
        ev["failed_controls"] = ["exception"]
        if tools is not None and run is not None:
            ev["diagnostic_errors"] = diagnostics(cfg, tools, root)
        raise
    finally:
        # Reaping failures turn a pass into a failure; they never convert a failure into a pass.
        passed = ev["status"] == "pass"
        if supervisor is not None:
            ev["supervisor_errors"] = supervisor.close()
            ev["child_cleanup"], ev["child_cleanup_errors"] = child_report(supervisor, contract.CASES[case], passed)
            ev["child_cleanup_errors"] += [item["error"] for item in ev["supervisor_errors"]]
        for key in (root / "work" / "keys").glob("*.key"):
            key.unlink()
        ev["case_result"] = run.ev if run is not None else None
        ev["elapsed_seconds"] = time.monotonic() - started
        if ev["child_cleanup_errors"]:
            ev["status"] = "fail"
            ev["failed_controls"] = ev["failed_controls"] + ["child-cleanup"]
        runcase.atomic(root / "evidence.json", ev)
    if ev["status"] != "pass":
        raise RuntimeError("product case child cleanup failed")
    print(json.dumps({"case": case, "status": "pass", "elapsed_seconds": ev["elapsed_seconds"]}))


if __name__ == "__main__":
    main()
