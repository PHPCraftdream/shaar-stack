"""CI-only source prerequisite; no real-carrier decoded-frame acceptance is claimed here."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location("carrier_frame_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wire():
    graph = load("wire_graph", HERE / "graph.py")
    instrument = load("wire_instrument", HERE / "instrument.py")
    runner = load("wire_runner", REPO / ".github/ci/run.py")
    label = os.environ.get("GITHUB_RUN_ID", "manual") + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", label):
        raise ValueError("invalid frame fixture run label")
    directory = REPO / "target" / ("carrier-frame-wire-" + label)
    directory.mkdir(parents=True, exist_ok=False)
    records = []
    original_environment = {key: os.environ.get(key) for key in (
        "SHAAR_CARRIER_FRAME_TRACE", "SHAAR_CARRIER_FRAME_POLICY", "SSLKEYLOGFILE"
    )}
    original_root = runner.ROOT
    try:
        product = graph.metadata(REPO)
        for name, allowed in (("strict", False), ("allow-all", True)):
            root = directory / name
            copied, paths = graph.copy_product(REPO, product, root)
            record = {"variant": name, "status": "preparing", "product": copied}
            records.append(record)
            record["observation_delta"] = graph.observation_reference(REPO, root)
            reference = graph.metadata(root)
            record["reference_graph"] = graph.verify_reference(REPO, product, reference)
            lock = (root / "Cargo.lock").read_bytes()
            selected = {package["name"]: Path(package["manifest_path"]).resolve().parent
                        for package in reference["packages"] if package.get("source") is None}
            record["packet_identity"] = instrument.packet_identity(REPO, selected["noq-proto"])
            record["native_helpers"] = instrument.native_helpers(REPO, selected["iroh"])
            record["workspace_hooks"] = instrument.workspace(REPO, root, HERE / "scenario.rs", allowed)
            actual = graph.metadata(root)
            record["graph"] = graph.verify_variant(reference, actual, root, lock, selected)
            trace = root / "target/frame-traces"
            trace.mkdir(parents=True, exist_ok=False)
            os.environ["SHAAR_CARRIER_FRAME_TRACE"] = str(trace)
            os.environ["SHAAR_CARRIER_FRAME_POLICY"] = name
            os.environ.pop("SSLKEYLOGFILE", None)
            runner.ROOT = root
            record["status"] = "wire-tests-pending"
            (directory / "receipt.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
            runner.tests([{"package": "shaar", "kind": "lib", "name": "shaar",
                           "filters": ["carrier_frame_fixture::"]}])
            record["tests"] = json.loads((root / "target/ci-selected/receipt.json").read_text(encoding="utf-8"))
            if (len(record["tests"]) != 1 or not record["tests"][0].get("executed")
                    or any(item.get("ignored_not_executed") for item in record["tests"])):
                raise ValueError("wire run did not execute selected non-ignored cases")
            executed = set(record["tests"][0]["executed"])
            prefix = "network::signaling::endpoint::tests::carrier_frame_fixture::"
            if not any(name == prefix + "carrier_frames_actual_relay_bootstrap_and_payload_policy"
                       for name in executed):
                raise ValueError("mandatory carrier scenario did not execute")
            if not any(name.startswith(prefix + "wire_oracle::tests::") for name in executed):
                raise ValueError("mandatory wire oracle controls did not execute")
            if not any(name.startswith(prefix + "supplement_controls::") for name in executed):
                raise ValueError("supplemental controls did not execute")
            graph.verify_variant(reference, graph.metadata(root), root, lock, selected)
            if copied["product_source_sha256"] != graph.shared(REPO).selected_hashes(REPO, paths):
                raise ValueError("product changed while running real-carrier frame case")
            record["status"] = "passed-bootstrap-phase-only"
            (directory / "receipt.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        print("Real-carrier strict/allow-all bootstrap phase passed; native loss/reconnect acceptance remains pending.", flush=True)
    except BaseException as error:
        if records:
            records[-1]["status"] = "failed"
            records[-1]["error"] = str(error)
        raise
    finally:
        (directory / "receipt.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        for key, value in original_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        runner.ROOT = original_root
        subprocess.run(["git", "diff", "--exit-code", "--", "Cargo.lock", "Cargo.toml", "crates"], cwd=REPO, check=True)


def main():
    if sys.argv[1:] == ["--wire"]:
        return wire()
    if sys.argv[1:]:
        raise ValueError("unknown frame proof scope")
    graph = load("graph", HERE / "graph.py")
    instrument = load("instrument", HERE / "instrument.py")
    runner = load("runner", REPO / ".github/ci/run.py")
    label = os.environ.get("GITHUB_RUN_ID", "manual") + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", label):
        raise ValueError("invalid frame fixture run label")
    directory = REPO / "target" / ("carrier-frame-source-" + label)
    directory.mkdir(parents=True, exist_ok=False)
    root = directory / "workspace"
    lock = (REPO / "Cargo.lock").read_bytes()
    product = graph.metadata(REPO)
    copied, paths = graph.copy_product(REPO, product, root)
    selected = {}
    for package in product["packages"]:
        if package.get("source") is None:
            original = Path(package["manifest_path"]).resolve().parent
            original.relative_to(REPO)
            if package["name"] in selected:
                raise ValueError("ambiguous copied path package")
            selected[package["name"]] = root / original.relative_to(REPO)
    record = {"scope": "source-contracts-only", "status": "preparing", "product": copied}
    receipt_path = directory / "receipt.json"
    try:
        record["packet_identity"] = instrument.packet_identity(REPO, selected["noq-proto"])
        record["native_helpers"] = instrument.native_helpers(REPO, selected["iroh"])
        record["observer"] = instrument.observer(REPO, root)
        actual = graph.metadata(root)
        record["graph"] = graph.verify_variant(product, actual, root, lock, selected)
        record["instrumented_source_sha256"] = graph.shared(REPO).hashes(root)
        record["status"] = "compiled-tests-pending"
        receipt_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        runner.ROOT = root
        runner.tests([{"package": "shaar-p2p", "kind": "lib", "name": "shaar_p2p",
                       "filters": ["carrier_frame_probe::tests::"]}])
        record["tests"] = json.loads((root / "target/ci-selected/receipt.json").read_text(encoding="utf-8"))
        if not record["tests"] or any(item.get("ignored_not_executed") for item in record["tests"]):
            raise ValueError("source contracts cannot use ignored cases as coverage")
        after = graph.metadata(root)
        graph.verify_variant(product, after, root, lock, selected)
        if copied["product_source_sha256"] != graph.shared(REPO).selected_hashes(REPO, paths):
            raise ValueError("product changed while running frame source contracts")
        record["status"] = "passed-source-contracts-only"
        print("Frame source prerequisite passed; real carrier frame exclusion remains unverified.", flush=True)
    except BaseException as error:
        record["status"] = "failed"
        record["error"] = str(error)
        raise
    finally:
        receipt_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        subprocess.run(["git", "diff", "--exit-code", "--", "Cargo.lock", "Cargo.toml", "crates"], cwd=REPO, check=True)


if __name__ == "__main__":
    main()
