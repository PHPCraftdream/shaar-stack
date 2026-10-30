"""CI-only source prerequisite; no real-carrier decoded-frame acceptance is claimed here."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location("carrier_frame_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
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
