# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Archive-backed integrity regressions for the bencode preparation recipe."""
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
    if path.is_symlink() or not path.is_file():
        raise ValueError("fixed preparation recipe unavailable or unsafe")
    spec = importlib.util.spec_from_file_location("_bencode_checks_prepare", path)
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
        verified = prepare.verify(root, archive)
        if set(verified) != set(prepare.archive_files(archive)) or set(prepare.transform(prepare.archive_files(archive))) != {prepare.SOURCE}:
            raise AssertionError("verification did not preserve the complete archive with only owned repair paths")

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

    def altered_source(root, receipt):
        path = root / prepare.SOURCE
        path.write_bytes(path.read_bytes() + b"\n")

    def recipe_drift(root, receipt):
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["recipe_files"]["edits.py"] = "0" * 64
        receipt.write_text(json.dumps(data) + "\n", encoding="utf-8")

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

    def missing_original_anchor():
        altered = dict(prepare.archive_files(archive))
        source = altered[prepare.SOURCE].decode("utf-8")
        old, _new = prepare.load_edits()[prepare.SOURCE][0]
        if not old or source.count(old) != 1:
            raise AssertionError("expected unique upstream anchor unavailable")
        altered[prepare.SOURCE] = source.replace(old, "", 1).encode("utf-8")
        try:
            prepare.transform(altered)
        except ValueError:
            return
        raise AssertionError("transformation accepted a missing original anchor")

    def duplicate_original_anchor():
        altered = dict(prepare.archive_files(archive))
        source = altered[prepare.SOURCE].decode("utf-8")
        old, _new = prepare.load_edits()[prepare.SOURCE][0]
        if not old or source.count(old) != 1:
            raise AssertionError("expected unique upstream anchor unavailable")
        altered[prepare.SOURCE] = (source + "\n" + old).encode("utf-8")
        try:
            prepare.transform(altered)
        except ValueError:
            return
        raise AssertionError("transformation accepted a duplicate original anchor")

    def reversed_repair_tamper():
        files = prepare.verify(root, archive)
        changed = dict(files)
        source = changed[prepare.SOURCE].decode("utf-8")
        _old, new = prepare.load_edits()[prepare.SOURCE][0]
        if not new or source.count(new) != 1:
            raise AssertionError("expected unique reverse anchor unavailable")
        changed[prepare.SOURCE] = source.replace(new, new[:-1] + "X", 1).encode("utf-8")
        try:
            prepare.reverse(changed, prepare.load_edits())
        except ValueError:
            return
        raise AssertionError("reverse transformation accepted repaired-source tampering")

    cases = {
        "pristine-positive": positive,
        "altered-de-rs": lambda: rejected("altered-de-rs", altered_source),
        "receipt-recipe-drift": lambda: rejected("receipt-recipe-drift", recipe_drift),
        "coordinated-manifest-and-receipt": lambda: rejected("coordinated-manifest-and-receipt", coordinated_manifest_mutation),
        "wrong-archive-checksum": wrong_archive,
        "missing-original-anchor": missing_original_anchor,
        "duplicate-original-anchor": duplicate_original_anchor,
        "reversed-repair-tamper": reversed_repair_tamper,
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
    receipt_path = destination / "receipt.json"
    try:
        receipt["archive_sha256"] = hashlib.sha256(args.archive.read_bytes()).hexdigest()
        prepare = load_prepare()
        receipt["recipe_sha256"] = hashlib.sha256(
            json.dumps(prepare.recipe(), sort_keys=True).encode("utf-8")
        ).hexdigest()
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
        if destination.is_dir() and not destination.is_symlink():
            receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
