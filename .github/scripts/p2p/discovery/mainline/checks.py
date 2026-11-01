# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Archive-backed integrity regressions for the Mainline preparation recipe."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent


def load_prepare():
    path = HERE / "prepare.py"
    spec = importlib.util.spec_from_file_location("_mainline_checks_prepare", path)
    if spec is None or spec.loader is None:
        raise ValueError("fixed preparation recipe unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(archive: Path, destination: Path, receipt: dict | None = None) -> tuple[list[str], list[str]]:
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("destination must be new and its parent must exist")
    prepare = load_prepare()
    destination.mkdir()
    executed: list[str] = []
    pristine = destination / "pristine"
    root = prepare.prepare(archive, pristine)

    def positive():
        prepare.verify(root, archive)

    def rejected(name, mutate):
        case = destination / name
        shutil.copytree(pristine, case)
        case_root = case / prepare.PACKAGE
        mutate(case_root, case / "provenance.json")
        try:
            prepare.verify(case_root, archive)
        except (ValueError, OSError, json.JSONDecodeError):
            return
        raise AssertionError(f"verification accepted tampering: {name}")

    def source_only(root, receipt):
        path = root / prepare.SOURCE
        path.write_bytes(path.read_bytes() + b"\n")

    def receipt_only(root, receipt):
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["original_files"]["Cargo.toml"] = "0" * 64
        receipt.write_text(json.dumps(data) + "\n", encoding="utf-8")

    def recipe_drift(root, receipt):
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["recipe_files"]["numeric.py"] = "0" * 64
        receipt.write_text(json.dumps(data) + "\n", encoding="utf-8")

    def altered_generated(root, receipt):
        path = root / prepare.GENERATED
        path.write_bytes(path.read_bytes() + b"\n")

    def coordinated_manifest_mutation(root, receipt):
        manifest = root / "Cargo.toml"
        manifest.write_bytes(manifest.read_bytes() + b"\n# coordinated mutation\n")
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["original_files"]["Cargo.toml"] = digest
        data["prepared_files"]["Cargo.toml"] = digest
        receipt.write_text(json.dumps(data) + "\n", encoding="utf-8")
        if data["archive_sha256"] != prepare.ARCHIVE_SHA256:
            raise AssertionError("mutation changed the pinned archive identity")

    def wrong_archive():
        wrong = destination / "wrong-archive.crate"
        data = archive.read_bytes()
        wrong.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        try:
            prepare.verify(root, wrong)
        except ValueError:
            return
        raise AssertionError("verification accepted a different archive")

    def missing_unique_anchor():
        altered = dict(prepare.archive_files(archive))
        source = altered[prepare.SOURCE].decode("utf-8")
        altered[prepare.SOURCE] = source.replace(prepare.OLD_GUARD, "", 1).encode("utf-8")
        try:
            prepare.transform(altered)
        except ValueError:
            return
        raise AssertionError("transformation accepted a missing unique reverse anchor")

    cases = {
        "pristine-positive": positive,
        "source-only": lambda: rejected("source-only", source_only),
        "receipt-only": lambda: rejected("receipt-only", receipt_only),
        "recipe-drift": lambda: rejected("recipe-drift", recipe_drift),
        "altered-generated": lambda: rejected("altered-generated", altered_generated),
        "coordinated-manifest-mutation": lambda: rejected("coordinated-manifest-mutation", coordinated_manifest_mutation),
        "wrong-archive": wrong_archive,
        "missing-unique-anchor": missing_unique_anchor,
    }
    selected = list(cases)
    if not selected:
        raise AssertionError("integrity case inventory is empty")
    if receipt is not None:
        receipt["selected"] = selected.copy()
    for name in selected:
        cases[name]()
        executed.append(name)
        if receipt is not None:
            receipt["executed"] = executed.copy()
    if executed != selected:
        raise AssertionError("integrity selected and executed inventories differ")
    return selected, executed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    destination = args.destination
    receipt = {"status": "failed", "selected": [], "executed": [], "ignored": []}
    if destination is None:
        parser.error("--destination is required")
    destination = destination.resolve()
    receipt_path = destination / "receipt.json"
    try:
        receipt["archive_sha256"] = hashlib.sha256(args.archive.read_bytes()).hexdigest()
        prepare = load_prepare()
        receipt["recipe_sha256"] = hashlib.sha256(json.dumps(prepare.recipe(), sort_keys=True).encode()).hexdigest()
        selected, executed = run(args.archive, destination, receipt)
        receipt.update(selected=selected, executed=executed, status="passed")
        for name in executed:
            print(f"passed: {name}")
        return 0
    except Exception as error:
        receipt["error"] = str(error)
        print(f"integrity checks failed: {error}", file=sys.stderr)
        return 1
    finally:
        if destination.is_dir():
            receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
