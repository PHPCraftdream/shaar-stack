# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Build and run only the isolated Mainline regression fixture cases."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
MAINLINE = HERE.parent
ROOT = MAINLINE.parents[4]
VERIFY_PATH = ROOT / ".github/scripts/p2p/discovery/owned_dns/verify.py"
PREFIXES = ("owned::tests::", "actor::owned_tests::", "common::messages::signed_peer_length_tests::", "common::messages::ingress_tests::", "actor::socket::ingress_tests::")
SHA = re.compile(r"[0-9a-f]{40}\Z")


def load_verify():
    spec = importlib.util.spec_from_file_location("mainline_ci_verify", VERIFY_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("fixed test verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(arguments: list[str], stdout: Path, cwd: Path, env=None, stderr: Path | None = None) -> tuple[str, int]:
    stdout.parent.mkdir(parents=True, exist_ok=True)
    with stdout.open("wb") as output:
        if stderr:
            with stderr.open("wb") as errors:
                status = subprocess.run(arguments, cwd=cwd, env=env, stdout=output, stderr=errors, check=False).returncode
        else:
            status = subprocess.run(arguments, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, check=False).returncode
    return stdout.read_text(encoding="utf-8", errors="replace"), status


def git_head(root: Path) -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, text=True)
    value = result.stdout.strip()
    if result.returncode or not SHA.fullmatch(value):
        raise ValueError("cannot establish checked-out git head")
    return value


def select_cases(listing: str, ignored_listing: str, verify) -> tuple[list[str], list[str]]:
    inventory_names = verify.parse_listing(listing, "")
    ignored_names = verify.parse_listing(ignored_listing, "")
    inventory, ignored = set(inventory_names), set(ignored_names)
    if len(inventory) != len(inventory_names) or len(ignored) != len(ignored_names):
        raise ValueError("duplicate test inventory case")
    if not ignored <= inventory:
        raise ValueError("ignored inventory is not a subset of test inventory")
    runnable = inventory - ignored
    selected = []
    for prefix in PREFIXES:
        matches = sorted(name for name in runnable if name.startswith(prefix))
        if not matches:
            raise ValueError("required fixture prefix has no runnable cases: " + prefix)
        selected.extend(matches)
    return selected, sorted(name for name in ignored if any(name.startswith(prefix) for prefix in PREFIXES))


def verify_batch(batch: list[str], output: str, status: int, verify) -> list[str]:
    if not batch:
        raise ValueError("cannot verify an empty test batch")
    verify.verify({"selected": "".join(name + ": test\n" for name in batch)},
                  {"selected": (verify.cargo_execution(output), status)}, "")
    return list(batch)

def batches(names: list[str], limit: int = 12000):
    batch, length = [], 0
    for name in names:
        if len(name) + 1 > limit:
            raise ValueError("test name exceeds bounded command length")
        if batch and length + len(name) + 1 > limit:
            yield batch
            batch, length = [], 0
        batch.append(name)
        length += len(name) + 1
    if batch:
        yield batch


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--bencode-archive", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    plans = parser.add_mutually_exclusive_group(required=True)
    plans.add_argument("--plan", type=Path)
    plans.add_argument("--plan-json")
    args = parser.parse_args()
    receipt_dir = args.destination.resolve()
    receipt_dir.mkdir(parents=True, exist_ok=True)
    evidence = receipt_dir / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    receipt: dict = {"status": "failed", "commands": [], "prefixes": list(PREFIXES)}
    source = None
    lock = None
    before_lock = None
    original_lock = None
    overlay_lock_hash = None
    overlay_lock = None
    overlay_verified = False
    graph = None
    bencode_prepare = None
    bencode_root = None
    bencode_integrity = receipt_dir / "bencode-integrity" / "receipt.json"
    bencode_integrity_data = None
    integrity_data = None
    checks_receipt = receipt_dir / "integrity" / "receipt.json"

    def command(label, argv, cwd, env=None, structured=False):
        out = evidence / (label + ".stdout.log")
        err = evidence / (label + ".stderr.log") if structured else None
        text, status = run(argv, out, cwd, env, err)
        entry = {"label": label, "argv": argv, "cwd": str(cwd), "stdout_log": str(out),
                 "stdout_sha256": digest(out), "exit_code": status}
        if err:
            entry.update(stderr_log=str(err), stderr_sha256=digest(err))
        receipt["commands"].append(entry)
        return text, status

    try:
        archive = args.archive.resolve(strict=True)
        receipt["archive_sha256"] = digest(archive)
        if args.plan_json is not None:
            plan_text = args.plan_json
            plan_bytes = plan_text.encode("utf-8")
        else:
            plan_path = args.plan.resolve(strict=True)
            plan_bytes = plan_path.read_bytes()
            plan_text = plan_bytes.decode("utf-8")
        (evidence / "ci-plan.json").write_bytes(plan_bytes)
        plan = json.loads(plan_text)
        if not isinstance(plan, dict) or plan.get("scope") not in {"full", "targeted"}:
            raise ValueError("invalid CI plan scope")
        selection = plan.get("selection")
        if not isinstance(selection, dict) or selection.get("mainline") is not True:
            raise ValueError("CI plan does not select Mainline")
        head, checkout = plan.get("head"), plan.get("checkout")
        if not isinstance(head, str) or not SHA.fullmatch(head) or not isinstance(checkout, str) or not SHA.fullmatch(checkout):
            raise ValueError("invalid CI plan commit identities")
        if git_head(ROOT) != checkout:
            raise ValueError("CI plan checkout differs from checked-out HEAD")
        base = plan.get("base")
        if plan["scope"] == "targeted":
            if not isinstance(base, str) or not SHA.fullmatch(base):
                raise ValueError("targeted CI plan requires a nonempty 40-character base")
        elif base is not None and (not isinstance(base, str) or not SHA.fullmatch(base)):
            raise ValueError("invalid full-plan base")
        receipt.update(head=head, checkout=checkout, base=base, scope=plan["scope"], plan_sha256=hashlib.sha256(plan_bytes).hexdigest())

        checks = MAINLINE / "checks.py"
        _, status = command("integrity", [sys.executable, "-I", str(checks), "--archive", str(archive),
                                          "--destination", str(receipt_dir / "integrity")], MAINLINE)
        if checks_receipt.is_file() and not checks_receipt.is_symlink():
            try:
                integrity_data = json.loads(checks_receipt.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise ValueError("integrity checks receipt is unreadable") from error
        if status:
            raise ValueError("archive integrity checks failed: " + str(status))
        if not isinstance(integrity_data, dict):
            raise ValueError("archive integrity checks receipt is missing")
        prepare_spec = importlib.util.spec_from_file_location("mainline_prepare", MAINLINE / "prepare.py")
        if prepare_spec is None or prepare_spec.loader is None:
            raise ValueError("fixed preparation recipe unavailable")
        prepare = importlib.util.module_from_spec(prepare_spec)
        prepare_spec.loader.exec_module(prepare)
        recipe_sha256 = hashlib.sha256(json.dumps(prepare.recipe(), sort_keys=True).encode()).hexdigest()
        receipt["expected_checks_recipe_sha256"] = recipe_sha256
        receipt["checks_receipt_sha256"] = digest(checks_receipt) if checks_receipt.is_file() else None
        receipt["checks_recipe_sha256"] = integrity_data.get("recipe_sha256") if isinstance(integrity_data, dict) else None
        if (not isinstance(integrity_data, dict) or integrity_data.get("status") != "passed"
                or not integrity_data.get("selected")
                or integrity_data.get("executed") != integrity_data.get("selected")
                or integrity_data.get("ignored") != []
                or integrity_data.get("archive_sha256") != receipt["archive_sha256"]
                or integrity_data.get("recipe_sha256") != recipe_sha256):
            raise ValueError("archive integrity checks receipt validation failed")
        bencode_archive = args.bencode_archive.resolve(strict=True)
        receipt["bencode_archive_sha256"] = digest(bencode_archive)
        bencode_checks = MAINLINE / "ci" / "bencode" / "checks.py"
        _, bencode_status = command("bencode-integrity", [sys.executable, "-I", str(bencode_checks), "--archive", str(bencode_archive),
                                      "--destination", str(receipt_dir / "bencode-integrity")], MAINLINE)
        if bencode_integrity.is_file() and not bencode_integrity.is_symlink():
            bencode_integrity_data = json.loads(bencode_integrity.read_text(encoding="utf-8"))
        if bencode_status or not isinstance(bencode_integrity_data, dict):
            raise ValueError("serde_bencode archive integrity checks failed")
        bencode_spec = importlib.util.spec_from_file_location("mainline_bencode_prepare", MAINLINE / "ci" / "bencode" / "prepare.py")
        if bencode_spec is None or bencode_spec.loader is None:
            raise ValueError("fixed serde_bencode preparation recipe unavailable")
        bencode_prepare = importlib.util.module_from_spec(bencode_spec)
        bencode_spec.loader.exec_module(bencode_prepare)
        recipe_hash = hashlib.sha256(json.dumps(bencode_prepare.recipe(), sort_keys=True).encode("utf-8")).hexdigest()
        receipt["bencode_integrity_validation"] = bool(
            bencode_integrity_data.get("status") == "passed" and bencode_integrity_data.get("selected")
            and bencode_integrity_data.get("selected") == bencode_integrity_data.get("executed")
            and bencode_integrity_data.get("ignored") == []
            and bencode_integrity_data.get("archive_sha256") == receipt["bencode_archive_sha256"]
            and bencode_integrity_data.get("recipe_sha256") == recipe_hash)
        if not receipt["bencode_integrity_validation"]:
            raise ValueError("serde_bencode integrity receipt validation failed")
        fixture_parent = Path(tempfile.mkdtemp(prefix="shaar-mainline-", dir=os.environ["RUNNER_TEMP"])).resolve()
        if fixture_parent.is_relative_to(ROOT):
            raise ValueError("isolated fixture source directory is inside checkout")
        prepared_root = fixture_parent / "prepared"
        source = prepare.prepare(archive, prepared_root)
        provenance = prepared_root / "provenance.json"
        prepare.verify(source, archive)
        bencode_root = bencode_prepare.prepare(bencode_archive, fixture_parent / "bencode")
        bencode_prepare.verify(bencode_root, bencode_archive)
        bencode_provenance = bencode_root.parent / "provenance.json"
        (evidence / "bencode-provenance.json").write_bytes(bencode_provenance.read_bytes())
        (evidence / "provenance.json").write_bytes(provenance.read_bytes())
        bencode_recipe_files = {name: digest(MAINLINE / "ci" / "bencode" / name) for name in
                                ("prepare.py", "edits.py", "checks.py", "graph.py", "test_graph.py")}
        receipt["bencode_audit_recipe_files"] = {
            name: digest(MAINLINE / "ci" / "bencode" / name)
            for name in ("prepare.py", "edits.py", "checks.py", "graph.py", "test_graph.py")
        }
        receipt.update(source=str(source), isolated_source_root=str(fixture_parent), outside_product_workspace=True,
                       provenance_sha256=digest(provenance), recipe_files=prepare.recipe(),
                       source_sha256=digest(source / "src/lib.rs"),
                       bencode_recipe_files=bencode_recipe_files,
                       bencode_provenance_sha256=digest(bencode_provenance))
        lock = source / "Cargo.lock"
        if not lock.is_file() or lock.is_symlink():
            raise ValueError("upstream archive is missing its required Cargo.lock")
        before_lock = digest(lock)
        (evidence / "Cargo.lock").write_bytes(lock.read_bytes())
        receipt["lock_sha256_before"] = before_lock
        graph_spec = importlib.util.spec_from_file_location("mainline_bencode_graph", MAINLINE / "ci" / "bencode" / "graph.py")
        if graph_spec is None or graph_spec.loader is None:
            raise ValueError("fixed bencode graph auditor unavailable")
        graph = importlib.util.module_from_spec(graph_spec)
        graph_spec.loader.exec_module(graph)
        original_lock = lock.read_bytes()
        patch_config = '--config=patch.crates-io.serde_bencode.path=' + json.dumps(str(bencode_root))
        metadata_text, status = command("metadata-original", ["cargo", "metadata", "--locked", "--format-version", "1",
            "--manifest-path", str(source / "Cargo.toml")], source, structured=True)
        if status:
            raise ValueError("baseline Cargo metadata failed: " + str(status))
        metadata_before = json.loads(metadata_text)
        receipt["baseline_metadata_sha256"] = hashlib.sha256(metadata_text.encode("utf-8")).hexdigest()
        if digest(lock) != before_lock:
            raise ValueError("baseline Cargo metadata changed the archived lockfile")
        overlay_lock = graph.make_lock_overlay(original_lock)
        graph.validate_lock(original_lock, overlay_lock)
        lock.write_bytes(overlay_lock)
        overlay_lock_hash = digest(lock)
        evidence.joinpath("Cargo.lock.overlay").write_bytes(overlay_lock)
        receipt.update(archived_lock_sha256=before_lock, overlay_lock_sha256=overlay_lock_hash)
        metadata_args = ["cargo", patch_config, "metadata", "--locked", "--format-version", "1", "--manifest-path", str(source / "Cargo.toml")]
        metadata_text, status = command("metadata-overlay", metadata_args, source, structured=True)
        if status:
            raise ValueError("overlay Cargo metadata failed: " + str(status))
        metadata_after = json.loads(metadata_text)
        audit = graph.validate_metadata(metadata_before, metadata_after, source, bencode_root)
        receipt["graph_validation"] = audit
        evidence.joinpath("metadata-baseline.json").write_text(json.dumps(metadata_before, indent=2) + "\n", encoding="utf-8")
        evidence.joinpath("metadata-overlay.json").write_text(json.dumps(metadata_after, indent=2) + "\n", encoding="utf-8")
        _, graph_test_status = command("bencode-graph-tests", [sys.executable, "-I", "-m", "unittest", "discover", "-s",
            str(MAINLINE / "ci" / "bencode"), "-p", "test_*.py"], MAINLINE)
        if graph_test_status:
            raise ValueError("bencode graph unit tests failed")

        toolchain = {}
        for label, argv in (("cargo-version", ["cargo", "--version"]), ("rustc-version", ["rustc", "--version", "--verbose"])):
            text, status = command(label, argv, source)
            toolchain[label] = {"output": text, "exit_code": status}
            if status:
                raise ValueError(label + " failed")
        receipt["toolchain"] = toolchain
        metadata = metadata_after
        root_manifest = str((source / "Cargo.toml").resolve())
        root_packages = [p for p in metadata.get("packages", []) if p.get("name") == "n0-mainline" and p.get("version") == "0.7.0"
                         and isinstance(p.get("manifest_path"), str) and str(Path(p["manifest_path"]).resolve()) == root_manifest]
        if len(root_packages) != 1:
            raise ValueError("Cargo metadata did not resolve the prepared n0-mainline package")
        receipt["resolved_packages"] = [{"id": p["id"], "name": p["name"], "version": p["version"],
                                          "source": p.get("source"), "manifest_path": p["manifest_path"]}
                                         for p in metadata.get("packages", [])]
        locked = tomllib.loads(lock.read_text(encoding="utf-8")).get("package", [])
        receipt["lock_packages"] = [{"name": p["name"], "version": p["version"], "source": p.get("source"),
                                     "checksum": p.get("checksum")} for p in locked]

        target = receipt_dir / "build"
        env = dict(os.environ, CARGO_TARGET_DIR=str(target))
        normal_build = ["cargo", patch_config, "build", "--locked", "--manifest-path", str(source / "Cargo.toml"), "--lib", "--message-format=json"]
        _, status = command("normal-build", normal_build, source, env, structured=True)
        if status:
            raise ValueError("isolated normal library build failed: " + str(status))
        cargo = ["cargo", patch_config, "test", "--locked", "--manifest-path", str(source / "Cargo.toml"), "--lib", "--no-run", "--message-format=json"]
        build_text, status = command("build", cargo, source, env, structured=True)
        if status:
            raise ValueError("isolated library test compilation failed: " + str(status))
        executables = set()
        for line in build_text.splitlines():
            item = json.loads(line)
            target_info = item.get("target", {})
            if (item.get("reason") == "compiler-artifact" and target_info.get("name") == "n0_mainline"
                    and target_info.get("kind") == ["lib"] and isinstance(target_info.get("src_path"), str)
                    and Path(target_info["src_path"]).resolve() == (source / "src/lib.rs").resolve()
                    and item.get("profile", {}).get("test") is True and item.get("executable")):
                binary = Path(item["executable"]).resolve()
                if target.resolve() not in binary.parents:
                    raise ValueError("compiled test binary escaped isolated target directory")
                executables.add(binary)
        if len(executables) != 1:
            raise ValueError("Cargo did not report exactly one prepared library test binary")
        binary = executables.pop()
        receipt["binary_sha256"] = digest(binary)
        verify = load_verify()
        listing, status = command("inventory", [str(binary), "--list", "--format", "terse"], source)
        if status:
            raise ValueError("test inventory failed")
        ignored_listing, status = command("ignored-inventory", [str(binary), "--list", "--ignored", "--format", "terse"], source)
        if status:
            raise ValueError("ignored inventory failed")
        selected, ignored_cases = select_cases(listing, ignored_listing, verify)
        ignored_inventory = sorted(set(verify.parse_listing(ignored_listing, "")))
        receipt.update(inventory=sorted(set(verify.parse_listing(listing, ""))), ignored_inventory=ignored_inventory,
                       ignored_not_run=ignored_cases, selected=selected, executed=[])
        receipt["attempted_batches"] = []
        for index, batch in enumerate(batches(selected)):
            receipt["attempted_batches"].append(list(batch))
            text, status = command("tests-" + str(index), [str(binary), "--exact", "--color", "never", *batch], source)
            try:
                verified = verify_batch(batch, text, status, verify)
            except ValueError as error:
                raise ValueError("selected test execution invalid: " + str(error)) from error
            if status:
                raise ValueError("selected fixture tests failed: " + str(status))
            receipt["executed"].extend(verified)
        if not selected or Counter(receipt["executed"]) != Counter(selected):
            raise ValueError("selected and executed fixture inventories do not match required receipt")
        if digest(lock) != overlay_lock_hash:
            raise ValueError("Cargo.lock overlay changed during isolated build")
        receipt["lock_unchanged_during_commands"] = True
        graph.validate_lock(original_lock, lock.read_bytes())
        overlay_verified = True
        receipt["overlay_lock_validation"] = True
        receipt["lock_unchanged_during_commands"] = True
        bencode_prepare.verify(bencode_root, bencode_archive)
        receipt["overlay_lock_sha256_final"] = digest(lock)
        receipt.update(lock_sha256_after=receipt["overlay_lock_sha256_final"])
        lock.write_bytes(original_lock)
        receipt["lock_sha256_after"] = digest(lock)
        receipt["lock_unchanged"] = receipt["lock_sha256_after"] == before_lock
        prepare.verify(source, archive)
        receipt["source_and_bencode_verified_final"] = True
        receipt["status"] = "passed"
        return 0
    except Exception as error:
        receipt["error"] = str(error)
        print("Mainline isolated fixture failed: " + str(error), file=sys.stderr)
        return 1
    finally:
        if lock is not None and lock.is_file() and overlay_lock is not None:
            current_hash = digest(lock)
            if overlay_verified and current_hash == before_lock:
                receipt["lock_unchanged_during_commands"] = True
                receipt["overlay_lock_validation"] = True
            else:
                receipt["overlay_lock_sha256_final"] = current_hash
                receipt["lock_unchanged_during_commands"] = current_hash == overlay_lock_hash
                try:
                    receipt["overlay_lock_validation"] = bool(
                        graph is not None and original_lock is not None
                        and graph.validate_lock(original_lock, lock.read_bytes()))
                except Exception as error:
                    receipt["overlay_lock_validation"] = False
                    receipt["overlay_lock_validation_error"] = str(error)
                if current_hash != overlay_lock_hash:
                    receipt["status"] = "failed"
                    receipt["error"] = receipt.get("error", "Cargo.lock overlay changed during execution")
            lock.write_bytes(original_lock)
            receipt["lock_sha256_after"] = digest(lock)
            receipt["lock_unchanged"] = receipt["lock_sha256_after"] == before_lock
            if not receipt.get("overlay_lock_validation") or not receipt.get("lock_unchanged_during_commands"):
                receipt["status"] = "failed"
        if bencode_integrity.is_file() and not bencode_integrity.is_symlink():
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / "bencode-integrity-receipt.json").write_bytes(bencode_integrity.read_bytes())
        if bencode_integrity_data is not None:
            receipt["bencode_integrity_receipt_sha256"] = digest(bencode_integrity) if bencode_integrity.is_file() else None
        if source is not None and bencode_root is not None and bencode_prepare is not None and receipt.get("status") != "passed":
            try:
                prepare.verify(source, archive)
                bencode_prepare.verify(bencode_root, bencode_archive)
                receipt["source_and_bencode_verified_final"] = True
            except Exception as error:
                receipt["source_and_bencode_verified_final"] = False
                receipt["final_verification_error"] = str(error)
        if source is not None:
            if checks_receipt.is_file() and not checks_receipt.is_symlink():
                (evidence / "checks-receipt.json").write_bytes(checks_receipt.read_bytes())
        if integrity_data is not None:
            receipt["integrity_validation"] = bool(
                integrity_data.get("status") == "passed" and integrity_data.get("selected")
                and integrity_data.get("executed") == integrity_data.get("selected")
                and integrity_data.get("ignored") == []
                and integrity_data.get("archive_sha256") == receipt.get("archive_sha256")
                and integrity_data.get("recipe_sha256") == receipt.get("expected_checks_recipe_sha256")
                and receipt.get("checks_receipt_sha256")
            )
        else:
            receipt["integrity_validation"] = False
        if source is not None:
            provenance = source.parent / "provenance.json"
            if provenance.is_file() and not provenance.is_symlink():
                (evidence / "provenance.json").write_bytes(provenance.read_bytes())
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
