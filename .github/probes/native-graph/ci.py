# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""CI runner for native graph candidate resolution and verification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fixture"))
import evidence
import graph
import prepare

ROOT = HERE.parents[2]
ARCHIVE_DIR = ROOT / "target/native-graph-archives"
DESTINATION = ROOT / "target/native-graph"
RECEIPT = DESTINATION / "ci-receipt.json"
CONSUMER = ROOT / "target/native-graph-consumer"
LOGS = DESTINATION / "logs"
COMMANDS: list[dict] = []


MAX_FAILURE_DIAGNOSTIC = 16_384


def _output_bytes(output: str | bytes | None) -> bytes:
    if output is None:
        return b""
    return output if isinstance(output, bytes) else output.encode("utf-8")


def run(argv: list[str], *, cwd: Path = ROOT, log_name: str) -> tuple[str, int]:
    try:
        result = subprocess.run(argv, cwd=cwd, check=False,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_bytes = _output_bytes(result.stdout)
        stderr_bytes = _output_bytes(result.stderr)
        code = result.returncode
    except Exception as error:
        COMMANDS.append({"argv": argv, "cwd": str(cwd), "exit_code": -1,
                         "error": f"{type(error).__name__}: {error}"})
        stdout_bytes = b""
        stderr_bytes = f"{type(error).__name__}: {error}".encode("utf-8")
        code = -1
    LOGS.mkdir(parents=True, exist_ok=True)
    stdout_path = LOGS / log_name
    stderr_path = LOGS / (log_name + ".stderr")
    stdout_path.write_bytes(stdout_bytes)
    stderr_path.write_bytes(stderr_bytes)
    record = {"argv": argv, "cwd": str(cwd), "exit_code": code,
              "stdout_log": log_name, "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
              "stderr_log": log_name + ".stderr", "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest()}
    COMMANDS.append(record)
    if code:
        diagnostic = stderr_bytes[:MAX_FAILURE_DIAGNOSTIC].decode("utf-8", errors="replace")
        truncation = "\n[stderr diagnostic truncated; full stderr preserved in raw artifact]" if len(stderr_bytes) > MAX_FAILURE_DIAGNOSTIC else ""
        sys.stderr.write(f"command failed (exit {code}): {argv!r}\ncwd: {cwd}\nstderr artifact: {stderr_path}\n{diagnostic}{truncation}\n")
    return stdout_bytes.decode("utf-8", errors="replace"), code


def checked(argv: list[str], *, cwd: Path = ROOT, log_name: str) -> str:
    stdout, code = run(argv, cwd=cwd, log_name=log_name)
    if code:
        raise RuntimeError(f"command failed ({code}): {argv}")
    return stdout


def archive_args() -> dict[str, Path]:
    names = {"adapter": "adapter-source.tar.gz", "mainline": "n0-mainline-0.7.0.crate", "future": "n0-future-0.3.2.crate",
             "bencode": "serde_bencode-0.2.4.crate", "dns": "iroh-dns-1.3.0.crate",
             "multibase": "multibase-0.9.3.crate"}
    paths = {name: ARCHIVE_DIR / filename for name, filename in names.items()}
    missing = [str(path) for path in paths.values() if not path.is_file() or path.is_symlink()]
    if missing:
        raise ValueError(f"required archives missing or linked: {missing}")
    return paths


def feature_comparison():
    return evidence.run(ROOT, archive_args(), prepare, graph,
                        lambda argv, cwd, env=None: subprocess.run(argv, cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False))


def ensure_sources() -> None:
    archives = archive_args()
    if DESTINATION.exists():
        prepare.verify_all(archives, DESTINATION)
    else:
        prepare.prepare_all(archives, DESTINATION)


def save_receipt(receipt: dict) -> None:
    DESTINATION.mkdir(parents=True, exist_ok=True)
    receipt["commands"] = list(COMMANDS)
    RECEIPT.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


def resolve_candidate() -> dict:
    COMMANDS.clear()
    before = graph.read_lock(ROOT / "Cargo.lock")
    try:
        graph.audit_product_workspace(tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8")))
        ensure_sources()
        (DESTINATION / "Cargo.before.lock").write_bytes(before)
        metadata_text, code = run(["cargo", "metadata", "--format-version", "1"], cwd=ROOT, log_name="candidate-resolution.json")
        after = graph.read_lock(ROOT / "Cargo.lock")
        (DESTINATION / "Cargo.candidate.lock").write_bytes(after)
        if code:
            raise RuntimeError(f"cargo metadata resolution failed ({code})")
        graph.audit_product_metadata(json.loads(metadata_text), ROOT)
        graph.audit_candidate_metadata(json.loads(metadata_text), ROOT)
        delta = graph.audit_lock_delta(before, after)
        receipt = {"mode": "candidate-resolution-not-acceptance", "accepted": False,
                   "before_sha256": hashlib.sha256(before).hexdigest(),
                   "after_sha256": hashlib.sha256(after).hexdigest(), "delta": delta}
        receipt["verification_status"] = "deferred-to-verify-locked"
        save_receipt(receipt)
        return receipt
    except Exception as error:
        save_receipt({"mode": "candidate-resolution-failed", "accepted": False,
                      "audit_error": str(error), "lock_after": graph.read_lock(ROOT / "Cargo.lock").decode("utf-8", errors="replace")})
        raise


def patches_from_root() -> dict[str, str]:
    root_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    output: dict[str, str] = {}
    for package, config in root_manifest.get("patch", {}).get("crates-io", {}).items():
        path = config.get("path")
        if path is None:
            raise ValueError(f"isolated consumer cannot copy non-path patch {package}")
        target = (ROOT / path).resolve()
        if not target.is_dir():
            raise ValueError(f"patch source missing: {package}: {target}")
        output[package] = str(target).replace("\\", "/")
    return output


def consumer_manifest() -> str:
    patch_lines = [f'{name} = {{ path = "{path}" }}' for name, path in sorted(patches_from_root().items())]
    return ("[workspace]\nresolver = \"3\"\n\n[package]\nname = \"native-graph-normal-consumer\"\n"
            "version = \"0.0.0\"\nedition = \"2024\"\nlicense = \"MIT OR Apache-2.0\"\n\n"
            "[lib]\npath = \"src/lib.rs\"\n\n[dependencies]\n"
            f'shaar = {{ path = "{(ROOT / "crates/shaar").as_posix()}" }}\n\n'
            "[patch.crates-io]\n" + "\n".join(patch_lines) + "\n")


def normal_projection_lock() -> tuple[Path, dict]:
    if CONSUMER.exists():
        shutil.rmtree(CONSUMER)
    CONSUMER.mkdir(parents=True)
    (CONSUMER / "Cargo.toml").write_text(consumer_manifest(), encoding="utf-8")
    (CONSUMER / "src").mkdir()
    (CONSUMER / "src/lib.rs").write_text("#![forbid(unsafe_code)]\nuse shaar as _;\n", encoding="utf-8")
    product_lock = graph.read_lock(ROOT / "Cargo.lock")
    (CONSUMER / "Cargo.lock").write_bytes(product_lock)
    _, code = run(["cargo", "metadata", "--manifest-path", str(CONSUMER / "Cargo.toml"),
                   "--format-version", "1"], cwd=CONSUMER, log_name="normal-consumer-resolution.json")
    if code:
        raise RuntimeError(f"consumer lock projection resolution failed ({code})")
    projected = graph.read_lock(CONSUMER / "Cargo.lock")
    product_records = [record for record in COMMANDS if record.get("stdout_log") == "product-metadata.json"]
    consumer_records = [record for record in COMMANDS if record.get("stdout_log") == "normal-consumer-resolution.json"]
    if len(product_records) != 1 or len(consumer_records) != 1:
        raise ValueError("missing/duplicate projection metadata receipts")
    context = graph.build_projection_context(
        (LOGS / "product-metadata.json").read_bytes(),
        (LOGS / "normal-consumer-resolution.json").read_bytes(),
        product_record=product_records[0],
        consumer_record=consumer_records[0],
        product_argv=["cargo", "metadata", "--locked", "--format-version", "1"],
        consumer_argv=["cargo", "metadata", "--manifest-path", str(CONSUMER / "Cargo.toml"), "--format-version", "1"],
        product_cwd=ROOT,
        consumer_cwd=CONSUMER,
        product_root_manifest=ROOT / "Cargo.toml",
        future_archive=ARCHIVE_DIR / "n0-future-0.3.2.crate",
        bencode_archive=ARCHIVE_DIR / "serde_bencode-0.2.4.crate",
    )
    delta = graph.audit_consumer_lock(product_lock, projected, projection_context=context)
    (DESTINATION / "normal-consumer.projection.json").write_text(json.dumps(delta, indent=2) + "\n", encoding="utf-8")
    return CONSUMER / "Cargo.lock", delta


def verify_future_dev() -> dict:
    """Test the prepared future crate's native dev graph in a disposable copy."""
    source = DESTINATION / "n0-future-0.3.2"
    copy = ROOT / "target/native-graph-future-dev"
    if copy.exists() or copy.is_symlink():
        shutil.rmtree(copy)
    source_inventory = prepare.inventory(source)
    prepared_manifest = (source / "Cargo.toml").read_bytes()
    archived_lock = graph.read_lock(source / "Cargo.lock")
    shutil.copytree(source, copy)
    copy_manifest_path = copy / "Cargo.toml"
    prefix = b'[workspace]\nresolver = "3"\n\n'
    expected_manifest = prefix + prepared_manifest
    copy_manifest_path.write_bytes(expected_manifest)
    lock_path = copy / "Cargo.lock"
    if graph.read_lock(lock_path) != archived_lock:
        raise ValueError('future archived dev lock mismatch')
    manifest = tomllib.loads(copy_manifest_path.read_text(encoding="utf-8"))
    package = manifest.get("package", {})
    if (package.get("name"), package.get("version")) != ("n0-future", "0.3.2"):
        raise ValueError("future dev copy package identity mismatch")
    target = prepare.FUTURE_TARGET
    normal = manifest.get("target", {}).get(target, {}).get("dependencies", {}).get("tokio")
    dev = manifest.get("target", {}).get(target, {}).get("dev-dependencies", {}).get("tokio")
    if (not isinstance(normal, dict) or sorted(normal.get("features", [])) != ["macros", "rt", "time"]
            or not isinstance(dev, dict) or dev.get("features") != ["test-util"]):
        raise ValueError("future native Tokio normal/dev declarations mismatch")
    copy_inventory = prepare.inventory(copy)
    manifest_names = ("Cargo.toml", "Cargo.lock")
    source_filtered = {name: digest for name, digest in source_inventory.items() if name not in manifest_names}
    if {name: digest for name, digest in copy_inventory.items() if name not in manifest_names} != source_filtered:
        raise ValueError("future dev copy inventory differs before metadata")

    def guard_copy() -> None:
        if copy_manifest_path.read_bytes() != expected_manifest:
            raise ValueError("future dev copy manifest changed")
        if graph.read_lock(lock_path) != archived_lock:
            raise ValueError("future dev lock changed")
        if prepare.inventory(source) != source_inventory:
            raise ValueError("prepared future source inventory changed")
        current_copy = prepare.inventory(copy)
        current_filtered = {name: digest for name, digest in current_copy.items() if name not in manifest_names}
        if current_filtered != source_filtered:
            raise ValueError("future dev copy inventory changed")

    guard_copy()
    metadata_text = checked(["cargo", "metadata", "--locked", "--manifest-path", str(copy_manifest_path), "--format-version", "1"],
                            cwd=copy, log_name="future-dev-metadata.json")
    if graph.read_lock(lock_path) != archived_lock:
        raise ValueError("future dev lock changed during metadata")
    guard_copy()
    metadata = json.loads(metadata_text)
    lock_data = tomllib.loads(archived_lock.decode("utf-8"))
    lock_index = {}
    for entry in lock_data.get("package", []):
        key = (entry.get("name"), entry.get("version"), entry.get("source"))
        if key in lock_index:
            raise ValueError(f"duplicate package in future archived dev lock: {key}")
        lock_index[key] = entry
    expected_root_key = ("n0-future", "0.3.2", None)
    if expected_root_key not in lock_index:
        raise ValueError("future archived dev lock root package missing")
    expected_tokio_key = ("tokio", "1.48.0", "registry+https://github.com/rust-lang/crates.io-index")
    tokio_lock = lock_index.get(expected_tokio_key)
    expected_tokio_checksum = "ff360e02eab121e0bc37a2d3b4d4dc622e6eda3a8e5253d5435ecf5bd4c68408"
    if tokio_lock is None or tokio_lock.get("checksum") != expected_tokio_checksum:
        raise ValueError("future archived dev lock Tokio identity/checksum mismatch")
    for entry in lock_index.values():
        if entry.get("name") == "tokio" and entry.get("source", "").startswith("registry+"):
            if (entry.get("version"), entry.get("source")) != expected_tokio_key[1:]:
                raise ValueError("unexpected registry Tokio in future archived dev lock")
    metadata_packages = metadata.get("packages", [])
    package_index = {}
    for item in metadata_packages:
        package_id = item.get("id")
        if not isinstance(package_id, str) or package_id in package_index:
            raise ValueError(f"future metadata package ID missing/duplicate: {package_id}")
        package_index[package_id] = item
    for item in metadata_packages:
        name = item.get("name")
        if name == "n0-future":
            if item.get("source") is not None or Path(item.get("manifest_path", "")).resolve() != copy_manifest_path.resolve():
                raise ValueError("future metadata root source/manifest mismatch")
            continue
        package_source = item.get("source")
        key = (name, item.get("version"), package_source)
        if not isinstance(package_source, str) or not package_source.startswith("registry+"):
            raise ValueError(f"non-registry package in future dev metadata: {key}")
        locked = lock_index.get(key)
        checksum = locked.get("checksum") if locked else None
        if locked is None or not isinstance(checksum, str) or len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum):
            raise ValueError(f"future metadata package missing exact checksummed lock entry: {key}")
    metadata_tokios = [item for item in metadata_packages if item.get("name") == "tokio"]
    if (len(metadata_tokios) != 1 or metadata_tokios[0].get("version") != "1.48.0"
            or metadata_tokios[0].get("source") != expected_tokio_key[2]):
        raise ValueError("future metadata Tokio identity mismatch")
    packages = [item for item in metadata_packages
                if item.get("name") == "n0-future" and item.get("version") == "0.3.2"]
    if len(packages) != 1:
        raise ValueError("future dev metadata package identity mismatch")
    metadata_tokio = [dep for dep in packages[0].get("dependencies", [])
                      if dep.get("name") == "tokio" and dep.get("target") == target]
    if (len(metadata_tokio) != 2 or
            {dep.get("kind"): sorted(dep.get("features", [])) for dep in metadata_tokio} !=
            {None: ["macros", "rt", "time"], "dev": ["test-util"]}):
        raise ValueError("future metadata native Tokio dependency graph mismatch")
    for dep in metadata_tokio:
        if dep.get("req") != "^1.28" or dep.get("source") != expected_tokio_key[2]:
            raise ValueError("future metadata native Tokio requirement/source mismatch")
    nodes = metadata.get("resolve", {}).get("nodes", [])
    node_index = {}
    for node in nodes:
        node_id = node.get("id")
        if not isinstance(node_id, str) or node_id in node_index:
            raise ValueError(f"future metadata resolve node ID missing/duplicate: {node_id}")
        node_index[node_id] = node
    if set(node_index) != set(package_index):
        raise ValueError("future metadata package/node IDs mismatch")
    for node in nodes:
        owner = package_index[node["id"]]
        owner_key = (owner.get("name"), owner.get("version"), owner.get("source"))
        locked_owner = lock_index.get(owner_key)
        if locked_owner is None:
            raise ValueError(f"future metadata resolve owner absent from archived lock: {owner_key}")
        for edge in node.get("deps", []):
            target_package = package_index.get(edge.get("pkg"))
            if target_package is None:
                raise ValueError(f"future metadata resolve target ID unknown: {edge.get('pkg')}")
            target_key = (target_package.get("name"), target_package.get("version"), target_package.get("source"))
            candidates = []
            for dependency in locked_owner.get("dependencies", []):
                fields = dependency.split()
                if not fields or fields[0] != target_key[0]:
                    continue
                if len(fields) >= 2 and fields[1] != target_key[1]:
                    continue
                if len(fields) >= 3 and " ".join(fields[2:]).strip("()") != (target_key[2] or ""):
                    continue
                candidates.append(dependency)
            if not candidates:
                raise ValueError(f"future metadata resolve edge absent from archived lock: {owner_key} -> {target_key}")
    root_id = metadata.get("resolve", {}).get("root")
    if root_id != packages[0].get("id") or metadata.get("workspace_members") != [root_id]:
        raise ValueError('future dev metadata root binding mismatch')
    root_node = node_index.get(root_id)
    tokio_node = node_index.get(metadata_tokios[0].get("id"))
    if root_node is None or tokio_node is None:
        raise ValueError("future dev metadata resolve nodes missing root/Tokio")
    tokio_edges = [edge for edge in root_node.get("deps", [])
                   if edge.get("pkg") == metadata_tokios[0].get("id")]
    if len(tokio_edges) != 1:
        raise ValueError("future dev metadata root-to-Tokio edge missing/duplicate")
    edge_kinds = tokio_edges[0].get("dep_kinds", [])
    if not any(kind.get("kind") is None for kind in edge_kinds) or not any(
            kind.get("kind") == "dev" and kind.get("target") == target for kind in edge_kinds):
        raise ValueError("future dev metadata root-to-Tokio dependency kinds mismatch")
    if not {"test-util", "rt", "time", "macros"}.issubset(set(tokio_node.get("features", []))):
        raise ValueError("future dev metadata Tokio node features mismatch")
    dev_tokio = {"version": tokio_lock["version"], "source": expected_tokio_key[2],
                 "checksum": tokio_lock["checksum"]}
    dev_lock_before = hashlib.sha256(archived_lock).hexdigest()
    checked(["cargo", "test", "--locked", "--manifest-path", str(copy_manifest_path), "--lib",
             "--target-dir", str(ROOT / "target/native-graph-future-dev-build")],
            cwd=copy, log_name="future-dev-test-lib.log")
    guard_copy()
    checked(["cargo", "test", "--locked", "--manifest-path", str(copy_manifest_path), "--doc",
             "--target-dir", str(ROOT / "target/native-graph-future-dev-build")],
            cwd=copy, log_name="future-dev-test-doc.log")
    guard_copy()
    after_lock = graph.read_lock(lock_path)
    after_lock_hash = hashlib.sha256(after_lock).hexdigest()
    if after_lock != archived_lock:
        raise ValueError("future dev lock changed during locked tests")
    current = prepare.inventory(source)
    if current != source_inventory:
        raise ValueError("prepared future source inventory changed")
    copy_hashes = prepare.inventory(copy)
    copy_after_filtered = {name: digest for name, digest in copy_hashes.items() if name not in manifest_names}
    if copy_after_filtered != source_filtered:
        raise ValueError("future dev copy inventory changed during metadata/tests")
    return {"source": str(source), "copy": str(copy),
            "prepared_manifest_sha256": hashlib.sha256(prepared_manifest).hexdigest(),
            "copy_manifest_sha256": hashlib.sha256(copy_manifest_path.read_bytes()).hexdigest(),
            "manifest_change": "standalone workspace resolver=3 only",
            "manifest_change_prefix_hex": prefix.hex(),
            "dev_tokio": dev_tokio,
            "dev_lock_sha256_before": dev_lock_before,
            "dev_lock_sha256_after": after_lock_hash,
            "source_inventory_unchanged": True,
            "copy_inventory_excluding_manifests_unchanged": True,
            "source_inventory_sha256": hashlib.sha256(json.dumps(source_inventory, sort_keys=True).encode()).hexdigest(),
            "copy_inventory_sha256": hashlib.sha256(json.dumps(copy_hashes, sort_keys=True).encode()).hexdigest(),
            "metadata_sha256": hashlib.sha256((LOGS / "future-dev-metadata.json").read_bytes()).hexdigest(),
            "commands": [record.copy() for record in COMMANDS
                         if record.get("stdout_log") in {"future-dev-metadata.json", "future-dev-test-lib.log", "future-dev-test-doc.log"}]}


def verify_locked() -> dict:
    COMMANDS.clear()
    try:
        graph.audit_product_workspace(tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8")))
        ensure_sources()
        (DESTINATION / "Cargo.product.lock").write_bytes(graph.read_lock(ROOT / "Cargo.lock"))
        for argv, cwd, name in (
            (["cargo", "build", "--locked", "-p", "shaar", "--lib"], ROOT, "sdk-build.log"),
            (["cargo", "metadata", "--locked", "--format-version", "1"], ROOT, "product-metadata.json"),
            ([sys.executable, "-I", "-m", "unittest", "discover", "-s", str(HERE), "-p", "test_*.py"], ROOT, "native-graph-tests.log"),
            ([sys.executable, "-I", "-m", "unittest", "discover", "-s", str(HERE / "fixture"), "-p", "test_*.py"], ROOT, "native-graph-fixture-tests.log"),
            ([sys.executable, "-I", "-m", "unittest", "discover", "-s", str(HERE.parent / "native-graph-multibase"), "-p", "test_*.py"], ROOT, "native-graph-multibase-tests.log"),
        ):
            output = checked(argv, cwd=cwd, log_name=name)
            if name == "product-metadata.json":
                graph.audit_product_metadata(json.loads(output), ROOT)
        inventory = checked(["cargo", "test", "--locked", "-p", "shaar", "--test", "native_graph_witness", "--", "--list"],
                            log_name="witness-inventory.log")
        cases = sorted(line.split(": test", 1)[0] for line in inventory.splitlines() if line.endswith(": test"))
        if not cases:
            raise ValueError("native graph witness selected zero runnable tests")
        witness_results = []
        for index, case in enumerate(cases):
            output = checked(["cargo", "test", "--locked", "-p", "shaar", "--test", "native_graph_witness", "--", "--exact", case],
                             log_name=f"witness-{index}.log")
            if f"test {case} ... ok" not in output:
                raise ValueError(f"witness did not report pass: {case}")
            witness_results.append({"case": case, "log_sha256": hashlib.sha256(output.encode()).hexdigest()})
        consumer_lock, projection = normal_projection_lock()
        metadata_text = checked(["cargo", "metadata", "--locked", "--manifest-path", str(CONSUMER / "Cargo.toml"),
                                 "--format-version", "1"], cwd=CONSUMER, log_name="normal-consumer-metadata.json")
        metadata = json.loads(metadata_text)
        graph.audit_normal_metadata(metadata, ROOT, normal_consumer=True)
        normal_tree = checked(["cargo", "tree", "--locked", "--manifest-path", str(CONSUMER / "Cargo.toml"),
                               "--edges", "normal,features"], cwd=CONSUMER,
                              log_name="normal-consumer-tree.txt")
        feature_sha = graph.normal_feature_receipt(metadata, ROOT, normal_tree, normal_consumer=True)
        checked(["cargo", "build", "--locked", "--manifest-path", str(CONSUMER / "Cargo.toml")],
                cwd=CONSUMER, log_name="normal-consumer-build.log")
        future_dev = verify_future_dev()
        comparison = feature_comparison()
        receipt = {"mode": "locked-product-and-isolated-normal-consumer", "accepted": False,
                   "platform": os.environ.get("RUNNER_OS", sys.platform),
                   "product_lock_sha256": hashlib.sha256(graph.read_lock(ROOT / "Cargo.lock")).hexdigest(),
                   "consumer_lock_sha256": hashlib.sha256(graph.read_lock(consumer_lock)).hexdigest(),
                   "consumer_projection": projection, "normal_metadata_sha256": hashlib.sha256(metadata_text.encode()).hexdigest(),
                   "normal_feature_receipt_sha256": feature_sha, "witness_cases": witness_results,
                   "normal_package_features": {package_id: sorted(features)
                       for package_id, features in graph.audit_normal_metadata(metadata, ROOT, normal_consumer=True)["normal_features"].items()},
                   "dev_only_projection_removals": projection["removed_projection_packages"],
                   "future_dev": future_dev}
        receipt["normal_feature_comparison"] = comparison
        receipt["accepted"] = True
        save_receipt(receipt)
        return receipt
    except Exception as error:
        save_receipt({"mode": "locked-verification-failed", "accepted": False, "error": str(error)})
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("resolve", "verify"))
    args = parser.parse_args()
    result = resolve_candidate() if args.mode == "resolve" else verify_locked()
    print(json.dumps(result, indent=2))


class AuxiliaryProbeShapeTests(prepare.AuxiliaryProbeShapeTests):
    def test_all_known_auxiliary_probe_shapes_and_rejections(self):
        host = 'x86_64-unknown-linux-gnu'
        target = Path('/tmp/aux').resolve()
        registry = 'registry+https://github.com/rust-lang/crates.io-index'
        cases = (
            ('proc-macro2', '1.0.107', '985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9', 'src/probe/proc_macro_span.rs', '--cfg=procmacro2_build_probe', '2021', 'proc_macro2', 1, 'host'),
            ('proc-macro2', '1.0.107', '985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9', 'src/probe/proc_macro_span_location.rs', '--cfg=procmacro2_build_probe', '2021', 'proc_macro2', 0, 'host'),
            ('proc-macro2', '1.0.107', '985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9', 'src/probe/proc_macro_span_file.rs', '--cfg=procmacro2_build_probe', '2021', 'proc_macro2', 0, 'host'),
            ('thiserror', '1.0.69', 'b6aaf5339b578ea85b50e080feb250a3e8ae8cfcdff9a461c9ec2904bc923f52', 'build/probe.rs', None, '2018', 'thiserror', 1, 'target'),
            ('thiserror', '2.0.21', '09e52cb86a36cede5cb101bf8908837b3e4c6e5e59fe7fd85c23fb56200d189e', 'build/probe.rs', None, '2018', 'thiserror', 1, 'target'),
            ('anyhow', '1.0.104', '330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470', 'src/nightly.rs', '--cfg=anyhow_build_probe', '2018', 'anyhow', 1, 'host'),
        )
        for index, (name, version, checksum, source, cfg, edition, crate, code, context) in enumerate(cases):
            with self.subTest(name=name, version=version):
                manifest = (Path('/registry').resolve() / f'{name}-{version}')
                build_root = target / host / 'debug/build' if name == 'thiserror' else target / 'debug/build'
                build = build_root / f'{name}-abc123'
                out = str(build / 'out/probe')
                args = ([cfg] if cfg else []) + [f'--edition={edition}', f'--crate-name={crate}', '--crate-type=lib', '--cap-lints=allow', '--emit=dep-info,metadata', '--out-dir', out, source, '--target', host]
                outputs = [str(Path(out) / f'lib{crate}.rmeta'), str(Path(out) / f'{crate}.d')] if code == 0 else []
                snapshots = [{'output': p, 'snapshot': str(target / f'capture/snapshots-{index}/{n}')}
                             for n, p in enumerate(outputs)]
                raw = {'package_name': name, 'package_version': version, 'kind': 'compile', 'exit_code': code, 'launch_error': None, 'manifest_dir': str(manifest), 'cwd': str(manifest), 'args': args, 'outputs': outputs, 'snapshots': snapshots}
                package = {'id': f'pkg-{index}', 'name': name, 'version': version, 'source': registry, 'manifest_path': str(manifest / 'Cargo.toml'), 'targets': [{'kind': ['custom-build'], 'src_path': str(manifest / 'build.rs')}]}
                checksums = {package['id']: checksum}
                result = prepare.auxiliary_probe_shape(raw, target, host, [package], checksums)
                self.assertEqual(result, {'source': source, 'package': name, 'version': version, 'checksum': checksum, 'crate': crate, 'package_id': package['id'], 'context': context, 'status': 'success' if code == 0 else 'failure', 'out_dir': out, 'build_dir': str(build)})
                windows_host = 'x86_64-pc-windows-msvc'
                windows_args = [arg.replace(host, windows_host) for arg in args]
                windows_args[-3] = source.replace('/', '\\')
                windows_result = prepare.auxiliary_probe_shape(dict(raw, args=windows_args), target, windows_host, [package], checksums)
                self.assertIsNotNone(windows_result)
                self.assertEqual(windows_result['source'], source)
                non_windows_args = list(args)
                non_windows_args[-3] = source.replace('/', '\\')
                self.assertIsNone(prepare.auxiliary_probe_shape(dict(raw, args=non_windows_args), target, host, [package], checksums))
                for field, value in (('package_version', '9.9.9'), ('launch_error', 'failed'), ('kind', 'test'), ('exit_code', 2)):
                    changed = dict(raw, **{field: value})
                    self.assertIsNone(prepare.auxiliary_probe_shape(changed, target, host, [package], checksums))
                self.assertIsNone(prepare.auxiliary_probe_shape(raw, target, host, [package], {package['id']: '0' * 64}))
                changed_package = dict(package, targets=[{'kind': ['lib'], 'src_path': str(manifest / source)}])
                self.assertIsNone(prepare.auxiliary_probe_shape(raw, target, host, [changed_package], checksums))
                changed_package = dict(package, source=None)
                self.assertIsNone(prepare.auxiliary_probe_shape(raw, target, host, [changed_package], checksums))
                changed_args = list(args)
                changed_args[-1] = 'aarch64-unknown-linux-gnu'
                self.assertIsNone(prepare.auxiliary_probe_shape(dict(raw, args=changed_args), target, host, [package], checksums))
                changed_args = list(args)
                changed_args[-3] = 'src/probe/forged.rs'
                self.assertIsNone(prepare.auxiliary_probe_shape(dict(raw, args=changed_args), target, host, [package], checksums))
                changed_args = list(args)
                changed_args[-4] = str(target / 'debug/build/foreign/out/probe')
                self.assertIsNone(prepare.auxiliary_probe_shape(dict(raw, args=changed_args), target, host, [package], checksums))
                changed = dict(raw, cwd=str(target / 'forged'))
                self.assertIsNone(prepare.auxiliary_probe_shape(changed, target, host, [package], checksums))
                changed = dict(raw, args=args + ['--cfg=feature="forged"'])
                self.assertIsNone(prepare.auxiliary_probe_shape(changed, target, host, [package], checksums))

    def test_production_capability_proofs_reject_mutations(self):
        from test_features import _proofs, _compare
        from features import AuditError
        for route, mutation in ((route, mutation) for route in ('', 'thiserror1.0.69.', 'thiserror2.0.21.', 'anyhow1.0.104.') for mutation in ('launch', 'ordinary', 'ordinary-launch', 'checksum', 'owner', 'declared-source', 'feature', 'version', 'source', 'target', 'outdir', 'context', 'package')):
            proofs = [attach_capability(proof) for proof in _proofs()]
            _compare(proofs)
            proof = proofs[2]
            capture = proof['compiler_capture']
            if mutation in ('checksum', 'owner'):
                registry = 'registry+https://github.com/rust-lang/crates.io-index#' + {'':'proc-macro2@1.0.107','thiserror1.0.69.':'thiserror@1.0.69','thiserror2.0.21.':'thiserror@2.0.21','anyhow1.0.104.':'anyhow@1.0.104'}[route]
                proof['lock_checksums'][registry] = '0' * 64 if mutation == 'checksum' else proof['lock_checksums'][registry]
                if mutation == 'owner':
                    build = next(r for r in proof['records'] if r['kind'] == 'build')
                    messages = [json.loads(line) for line in proof['artifacts'][build['stdout']].splitlines()]
                    next(m for m in messages if m['reason'] == 'build-script-executed' and m.get('package_id') == registry)['out_dir'] = '/forged'
                    data = ''.join(json.dumps(m) + '\n' for m in messages).encode()
                    proof['artifacts'][build['stdout']] = data
                    build['stdout_sha256'] = hashlib.sha256(data).hexdigest()
                    capture['build_stdout_sha256'] = build['stdout_sha256']
            elif mutation == 'feature':
                name = route + 'capability-0.json'
                path = Path(proof['consumer_cwd']).name + '/compiler-capture/' + name
                raw = json.loads(proof['artifacts'][path])
                raw['args'].append('--cfg=feature="forged"')
                data = json.dumps(raw).encode()
                proof['artifacts'][path] = data
                capture['receipts'][name] = hashlib.sha256(data).hexdigest()
                capture['units'][{'': -3, 'thiserror1.0.69.': 2, 'thiserror2.0.21.': 4, 'anyhow1.0.104.': 6}[route]]['args'] = raw['args']
            elif mutation == 'declared-source':
                meta = next(r for r in proof['records'] if r['kind'] == 'metadata')
                doc = json.loads(proof['artifacts'][meta['stdout']])
                pkg = next(p for p in doc['packages'] if p['id'].endswith({'':'proc-macro2@1.0.107','thiserror1.0.69.':'thiserror@1.0.69','thiserror2.0.21.':'thiserror@2.0.21','anyhow1.0.104.':'anyhow@1.0.104'}[route]))
                pkg['targets'].append({'name': 'proc_macro2', 'kind': ['lib'], 'crate_types': ['lib'], 'src_path': str(Path(pkg['manifest_path']).parent / {'':'src/probe/proc_macro_span.rs','thiserror1.0.69.':'build/probe.rs','thiserror2.0.21.':'build/probe.rs','anyhow1.0.104.':'src/nightly.rs'}[route])})
                data = json.dumps(doc).encode()
                proof['artifacts'][meta['stdout']] = data
                meta['stdout_sha256'] = hashlib.sha256(data).hexdigest()
            else:
                name = 'unit.json' if mutation in ('ordinary', 'ordinary-launch') else route + 'capability-0.json'
                path = Path(proof['consumer_cwd']).name + '/compiler-capture/' + name
                raw = json.loads(proof['artifacts'][path])
                if mutation in ('launch', 'ordinary-launch'):
                    raw['launch_error'] = 'launch failed'
                elif mutation == 'ordinary':
                    raw['exit_code'] = 1
                elif mutation == 'version':
                    raw['package_version'] = '9.9.9'
                elif mutation == 'source':
                    raw['args'][-3] = 'src/lib.rs'
                elif mutation == 'target':
                    raw['args'][-1] = 'forged'
                elif mutation == 'outdir':
                    raw['args'][-4] = str(Path(proof['consumer_cwd']) / 'foreign/out/probe')
                elif mutation == 'context':
                    raw['cwd'] = '/foreign'
                elif mutation == 'package':
                    raw['package_name'] = 'other'
                data = json.dumps(raw).encode()
                proof['artifacts'][path] = data
                capture['receipts'][name] = hashlib.sha256(data).hexdigest()
                unit_index = 0 if mutation in ('ordinary', 'ordinary-launch') else {'': -3, 'thiserror1.0.69.': 2, 'thiserror2.0.21.': 4, 'anyhow1.0.104.': 6}[route]
                capture['units'][unit_index].update({key: value for key, value in raw.items() if key != 'outputs'})
            with self.assertRaises(AuditError):
                _compare(proofs)

    def test_capture_collects_overwritten_and_deleted_outputs(self):
        import copy
        import tempfile
        from features import collect_capture
        from test_features import _proofs
        proof = attach_capability(_proofs()[2])
        c = proof['compiler_capture']
        meta = json.loads(proof['artifacts'][next(r['stdout'] for r in proof['records'] if r['kind'] == 'metadata')])
        prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target, capture = root / 'target', root / 'capture'
            target.mkdir()
            capture.mkdir()
            context = copy.deepcopy(c['context'])
            context['env']['CARGO_TARGET_DIR'] = str(target)
            context['env']['SHAAR_CAPTURE_DIR'] = str(capture)
            context.update(host=c['wrapper']['target'], packages=meta['packages'], lock_checksums=proof['lock_checksums'])
            outputs = set()
            for name in sorted(name for name in c['receipts'] if name.endswith('.json')):
                raw = json.loads(proof['artifacts'][prefix + name])
                raw['env'] = {key: context['env'][key] for key in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_TARGET_DIR')}
                relocate = lambda value: value.replace(c['context']['env']['CARGO_TARGET_DIR'], str(target)).replace(c['context']['env']['SHAAR_CAPTURE_DIR'], str(capture))
                raw['args'] = [relocate(arg) for arg in raw['args']]
                raw['outputs'] = [relocate(path) for path in raw['outputs']]
                outputs.update(raw['outputs'])
                for item in raw['snapshots']:
                    item['output'], item['snapshot'] = relocate(item['output']), relocate(item['snapshot'])
                    snapshot_name = Path(item['snapshot']).relative_to(capture).as_posix()
                    snapshot = Path(item['snapshot'])
                    snapshot.parent.mkdir(parents=True, exist_ok=True)
                    snapshot.write_bytes(proof['artifacts'][prefix + snapshot_name])
                    output = Path(item['output'])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(proof['artifacts'][prefix + snapshot_name])
                (capture / name).write_text(json.dumps(raw), encoding='utf-8')
            for path in outputs:
                if Path(path).parent.name == 'probe':
                    Path(path).unlink(missing_ok=True)
            result = collect_capture(capture, target, context)
            self.assertEqual(len(result['units']), 11)
            overwritten = [output for unit in result['units'] if unit['exit_code'] == 0 for output in unit['outputs'] if 'proc_macro2.rmeta' in output['path']]
            self.assertEqual(len({output['sha256'] for output in overwritten}), 2)
            self.assertEqual(len({output['path'] for output in overwritten}), 1)


def attach_capability(proof, case=None):
    from capability_fixture import attach_capability as _attach_capability
    return _attach_capability(proof, case)


if __name__ == '__main__':
    main()
