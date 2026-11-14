"""Root driver for the bounded privileged phase: one dispatch group of product cases plus three cleanup controls."""

import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
TOPOLOGY = HERE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "flows"))
sys.path.insert(0, str(TOPOLOGY))
import verdicts  # noqa: E402
import childman  # noqa: E402
import contract  # noqa: E402
import dynamic  # noqa: E402
import kernel  # noqa: E402
import natprobe  # noqa: E402
import network  # noqa: E402
import observe  # noqa: E402
import preflight  # noqa: E402

ARTIFACT_BYTES = 64 * 1024 * 1024
CONTROL_SECONDS = 60
# (name, kind, case, run.sh flags); order keeps cheap cleanup proof ahead of product traffic and the slowest cases last.
PLAN = (
    ("setup-failure", "setup-fault", "native-signal", ("--fault-inject-setup",)),
    ("native-signal", "product", "native-signal", ()),
    ("native-standby", "product", "native-standby", ()),
    ("blocked-standby", "product", "blocked-standby", ()),
    ("blocked-signal", "product", "blocked-signal", ()),
    ("lan-signal", "product", "lan-signal", ()),
    ("lan-standby", "product", "lan-standby", ()),
    ("relay-denied-signal", "product", "relay-denied-signal", ()),
    ("failover-standby", "product", "failover-standby", ()),
    ("failover-signal", "product", "failover-signal", ()),
    ("denied-blocked-standby", "product", "denied-blocked-standby", ()),
    ("dht-drop-signal", "product", "dht-drop-signal", ()),
    ("outage-standby", "product", "outage-standby", ()),
    ("live-failure", "fixture-fault", "native-signal", ("--fault-inject-fixture",)),
    ("interruption", "interrupt", "native-signal", ()),
)


def product(name):
    return (name, "product", name, ())


# Dispatch groups (selected by --group): the 12 accepted cases, and two groups for the remaining P13 rows. The cases of all
# groups together would not fit the 20 minute phase, so each dispatch runs one group with the same three cleanup controls.
NAT_CASES = ("dnat-cone-signal", "dnat-cone-standby", "dnat-cone-relay-signal", "dnat-cone-relay-standby", "dnat-sym-signal", "dnat-sym-standby",
             "hole-signal", "hole-standby", "switch-signal", "switch-standby")
FAULT_CASES = ("ipv6-signal", "ipv6-standby", "denied-native-signal", "recover-standby", "relay-full-signal", "relay-full-standby")
GROUPS = {"base": PLAN,
          "nat": (PLAN[0], *map(product, NAT_CASES), *PLAN[-2:]),
          "faults": (PLAN[0], *map(product, FAULT_CASES), *PLAN[-2:])}


def allocated(plan):
    """Each product case and each live-traffic control gets its own pair of per-router kernel quotas."""
    products = sum(1 for entry in plan if entry[1] == "product")
    live = sum(1 for entry in plan if entry[1] in ("fixture-fault", "interrupt"))
    return products * 2 * contract.PRODUCT_QUOTA + live * 2 * contract.FAULT_QUOTA


PRODUCTS = sum(1 for entry in PLAN if entry[1] == "product")
ALLOCATED_BYTES = allocated(PLAN)
BASE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def interrupted(_signum, _frame):
    raise SystemExit(143)


def guarded(check, *args):
    """childman validators exit the process on failure; convert that into a recorded result."""
    try:
        check(list(args))
        return None
    except SystemExit as error:
        return f"validator rejected evidence (exit {error.code})"


def verify_product_case(ev, case, source, nonce):
    """Strict conclusions over raw controller evidence; never trusts a bare exit status."""
    spec = contract.CASES[case]
    result = ev.get("case_result") or {}
    contract.require(ev.get("status") == "pass" and ev.get("case") == case and ev.get("purpose") == "product"
                     and ev.get("source_revision") == source and ev.get("config", {}).get("nonce") == nonce,
                     "controller evidence is not a passing record of this exact case")
    contract.require(ev.get("normal_native_gate_enabled") is False, "normal product test gate must remain OFF")
    contract.require(len(result.get("quota_calibration", [])) == 2
                     and all(item["passed"] >= 1 and item["dropped"] >= 1 for item in result["quota_calibration"]),
                     "kernel quota enforcement was not proven live")
    kernel_report = result.get("kernel", {})
    contract.require(set(kernel_report) == {"rtr_a", "rtr_b"}
                     and all(0 <= item["quota_used"] < network.QUOTAS["product"] for item in kernel_report.values()),
                     "router quota receipts missing or exhausted")
    observed = result.get("observations", {})
    contract.require(observed.get("target", {}).get("accepts") == spec["target_accepts"]
                     and result.get("client_exit") == contract.final_client_exit(spec), "target accepts or Client exit differ")
    uid = ev["config"]["helper_uid"]
    contract.require(set(contract.identity_roles(spec)) <= set(result.get("identities", {}))
                     and all(item["uid"] == uid and item["capabilities"] == 0 for item in result["identities"].values()),
                     "every owned child must have a verified unprivileged identity")
    counters = {router: item["counters"] for router, item in kernel_report.items()}
    verdicts.verify_class(spec, result, counters)
    return {"forwarded_bytes": result["forwarded_bytes"], "active_seconds": result["active_seconds"]}


def run_script(script, flags, casedir, nonce, env, seconds):
    """Own run.sh through one Popen; bounded wait, TERM then KILL, always reaped."""
    process = subprocess.Popen(["bash", str(script), *flags, str(casedir), nonce], env=env, stdin=subprocess.DEVNULL)
    notes = []
    try:
        code = process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        notes.append("case deadline: TERM")
        process.send_signal(signal.SIGTERM)
        try:
            code = process.wait(timeout=contract.CLEANUP_RESERVE)
        except subprocess.TimeoutExpired:
            notes.append("cleanup deadline: KILL")
            process.kill()
            code = process.wait(timeout=10)
        notes.append("timed out")
    except BaseException:
        process.terminate()
        try:
            process.wait(timeout=contract.CLEANUP_RESERVE)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        raise
    return code, notes


def invoke(entry, out, source, env, seconds):
    name, kind, case, flags = entry
    casedir = out / f"{name}-{time.time_ns()}"
    nonce = secrets.token_hex(16)
    script = TOPOLOGY / "run.sh"
    environment = {**env, "FIXTURE_PRODUCT_CASE": case}
    record = {"name": name, "kind": kind, "case": case, "casedir": str(casedir), "nonce": nonce, "problems": []}
    started = time.monotonic()
    if kind == "interrupt":
        os.environ.update(environment, FIXTURE_PRODUCT_HOLD="1")
        try:
            problem = guarded(childman.supervise_interrupt, str(script), str(casedir), nonce, "35")
        finally:
            os.environ.pop("FIXTURE_PRODUCT_HOLD", None)
        record["exit_code"] = 143 if problem is None else None
        if problem:
            record["problems"].append(problem)
    else:
        code, notes = run_script(script, flags, casedir, nonce, environment, seconds)
        record.update(exit_code=code, notes=notes)
        record["problems"] += notes
        failing = kind != "product"
        if (code != 0) != failing:
            record["problems"].append(f"unexpected run.sh exit status {code}")
        cleanup = casedir / "cleanup-evidence.json"
        label = "normal" if kind == "product" else kind
        record["problems"] += [p for p in (guarded(childman.validate_cleanup, str(cleanup), "--case", label, "--nonce", nonce),) if p]
        evidence = casedir / "evidence.json"
        if kind == "product":
            problem = guarded(childman.validate_evidence, str(evidence), "--expect-status", "pass", "--nonce", nonce)
            if problem is None:
                try:
                    record["verified"] = verify_product_case(contract.bounded_json(evidence, 1024 * 1024), case, source, nonce)
                except (ValueError, KeyError, TypeError, OSError) as error:
                    problem = "strict product verification: " + str(error)[:300]
            if problem:
                record["problems"].append(problem)
        elif kind == "fixture-fault":
            for check, args in ((childman.validate_phase, (str(casedir / "records/children_started"), nonce)),
                                (childman.validate_evidence, (str(evidence), "--expect-status", "fail", "--nonce", nonce,
                                                              "--expect-exception-substr", "injected fixture failure"))):
                problem = guarded(check, *args)
                if problem:
                    record["problems"].append(problem)
    record["elapsed_seconds"] = time.monotonic() - started
    record["status"] = "pass" if not record["problems"] else "fail"
    return record


def tree_bytes(path):
    return sum(item.stat().st_size for item in Path(path).rglob("*") if item.is_file() and not item.is_symlink())


def namespaces(tools):
    deadline = time.monotonic() + 10
    return sorted(kernel.checked([tools["ip"], "netns", "list"], deadline, what="namespace inventory").decode().split("\n"))


def precheck_rulesets(prefix):
    """Every generated ruleset: cases x 2 routers x {product, fault}, both calibration tables, NAT probes, observation and dynamic blocks."""
    ports = {"dht": 42001, "relay": 42002, "transit": 42003}
    found = [(f"{case}/{router}/{purpose}", network.rules(prefix, router, case, ports, purpose))
             for case in sorted(contract.CASES) for router in ("rtr_a", "rtr_b") for purpose in ("product", "fault")]
    found += [(f"calibration/{host}", kernel.probe_rules(prefix, contract.IPS[host])[1]) for host in ("host_a", "host_b")]
    found += [(f"natprobe/{flavor}", natprobe.rules(prefix, flavor, contract.IPS["host_a"], contract.IPS["rtr_a_wan"]))
              for flavor in sorted(natprobe.STATEMENTS)]
    found.append(("observation", observe.rules(prefix)))
    found += [(f"dynamic/{kind}", dynamic.rules(prefix, kind, ports)) for kind in dynamic.KINDS]
    return found


def syntax_precheck(tools, prefix):
    """Dry-run every ruleset with the real nft inside one throwaway owned namespace; first rejection aborts."""
    deadline = time.monotonic() + 60
    name = prefix + "-chk"
    result = {"namespace": name, "checks": [], "namespace_removed": False, "status": "fail"}
    kernel.checked([tools["ip"], "netns", "add", name], deadline, what="syntax pre-check namespace")
    try:
        for label, text in precheck_rulesets(prefix):
            code, _out, err = kernel.run_tool([tools["ip"], "netns", "exec", name, tools["nft"], "--check", "--file", "-"],
                                              deadline, text.encode("ascii"))
            result["checks"].append({"ruleset": label, "rc": code, "error": err.decode("utf-8", errors="replace")[:400]})
            if code != 0:
                result["aborted_at"] = label
                break
    finally:
        kernel.checked([tools["ip"], "netns", "del", name], time.monotonic() + 20, what="syntax pre-check namespace removal")
        result["namespace_removed"] = True
    result["status"] = "pass" if len(result["checks"]) == len(precheck_rulesets(prefix)) and all(
        item["rc"] == 0 for item in result["checks"]) else "fail"
    return result


def run_precheck(summary, tools):
    """Record the pre-check outcome; any failure (including setup errors) means no case may start."""
    try:
        summary["syntax_precheck"] = syntax_precheck(tools, "sn" + secrets.token_hex(3))
    except (RuntimeError, ValueError, TimeoutError, OSError) as error:
        summary["syntax_precheck"] = {"status": "fail", "error": str(error)[:400]}
    return summary["syntax_precheck"]["status"] == "pass"


def phase(source, manifest_path, out, group="base"):
    started = time.monotonic()
    end = started + contract.PHASE_SECONDS
    plan = GROUPS[group]
    manifest = contract.bounded_json(manifest_path)
    products = contract.validate_manifest(manifest, source)
    ip = preflight.trusted_tool("ip")
    contract.require(ip is not None, "ip tool missing")
    nft = preflight.trusted_tool("nft")
    contract.require(nft is not None, "nft tool missing")
    tools = {"ip": str(ip), "nft": str(nft)}
    uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
    contract.require(os.geteuid() == 0 and uid > 0 and gid > 0, "phase requires a sudo caller with an unprivileged identity")
    env = {"PATH": BASE_PATH, "LANG": "C", "LC_ALL": "C", "SUDO_UID": str(uid), "SUDO_GID": str(gid),
           "FIXTURE_PRODUCT_SOURCE": source, "FIXTURE_PRODUCT_MANIFEST": str(Path(manifest_path).resolve())}
    out.mkdir(exist_ok=True)
    summary = {"schema": 1, "scope": "controlled-product-matrix-phase", "source_revision": source,
               "runner_image": os.environ.get("ImageVersion", "unknown")[:200], "group": group, "allocated_forward_bytes": allocated(plan),
               "products": {name: item["sha256"] for name, item in products.items()}, "invocations": [], "status": "fail"}
    summary["namespaces_before"] = namespaces(tools)
    try:
        for entry in plan if run_precheck(summary, tools) else ():
            budget = CONTROL_SECONDS if entry[1] != "product" else contract.CASE_SECONDS
            remaining = end - time.monotonic() - contract.CLEANUP_RESERVE
            if remaining < budget:
                summary["invocations"].append({"name": entry[0], "status": "fail", "problems": ["privileged phase budget exhausted"]})
                break
            record = invoke(entry, out, source, env, budget)
            summary["invocations"].append(record)
            if any("survived" in item or "still present" in item for item in record["problems"]):
                break  # leftovers: stop before creating more owned resources
    finally:
        summary["namespaces_after"] = namespaces(tools)
        summary["artifact_bytes"] = tree_bytes(out)
        summary["elapsed_seconds"] = time.monotonic() - started
        summary["forwarded_bytes_observed"] = sum(item.get("verified", {}).get("forwarded_bytes", 0) for item in summary["invocations"])
        complete = [item["name"] for item in summary["invocations"]] == [entry[0] for entry in plan]
        summary["status"] = "pass" if (complete and summary.get("syntax_precheck", {}).get("status") == "pass" and all(item["status"] == "pass" for item in summary["invocations"])
                                       and summary["namespaces_before"] == summary["namespaces_after"]
                                       and summary["artifact_bytes"] <= ARTIFACT_BYTES
                                       and summary["elapsed_seconds"] <= contract.PHASE_SECONDS) else "fail"
        (out / "phase-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--group", choices=sorted(GROUPS), default="base")
    arguments = parser.parse_args()
    contract.require(contract.hex_value(arguments.source, 40), "source must be the exact reviewed commit SHA")
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    summary = phase(arguments.source, arguments.manifest, TOPOLOGY / "out", arguments.group)
    print(json.dumps({"status": summary["status"], "invocations": {item["name"]: item["status"] for item in summary["invocations"]}}))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
