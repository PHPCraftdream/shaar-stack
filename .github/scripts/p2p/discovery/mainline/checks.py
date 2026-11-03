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
        resource_path = root / prepare.RESOURCE_MODULE
        resource = resource_path.read_text(encoding="utf-8")
        if resource_path != root / "src/resource.rs":
            raise AssertionError("generated resource module path mismatch")
        for export in ("OwnedPutAdmission", "OwnedPutAdmissionError", "OwnedPutCleanup", "OwnedPutError", "Observer", "CleanupHold"):
            if export not in resource:
                raise AssertionError(f"generated resource exports missing {export}")
        library = (root / "src/lib.rs").read_text(encoding="utf-8")
        for export in ("OwnedPutAdmission", "OwnedPutAdmissionError", "OwnedPutCleanup", "OwnedPutError", "Observer", "CleanupHold"):
            if export not in library:
                raise AssertionError(f"crate root exports missing {export}")
        if "mod resource;" not in library:
            raise AssertionError("crate root resource module declaration missing")
        observer_path = root / prepare.PUBLICATION_OBSERVER
        observer = observer_path.read_text(encoding="utf-8")
        if not observer:
            raise AssertionError("generated publication observer is empty")
        actor = (root / "src/actor.rs").read_text(encoding="utf-8")
        if actor.count("actor.process_owned_publication_message(message, from);") != 1:
            raise AssertionError("owned actor publication dispatch mismatch")
        if "actor.process_message(message, from);" in actor or "if has_response" in actor:
            raise AssertionError("owned actor retains direct/duplicate response processing")
        wrapper = (root / prepare.OWNED_ACTOR).read_text(encoding="utf-8")
        if "self.process_message" not in wrapper or "self.owned_note_response" not in wrapper:
            raise AssertionError("owned actor wrapper behavior mismatch")
        socket_path = root / "src/actor/socket.rs"
        socket = socket_path.read_text(encoding="utf-8")
        if socket.count("is_expected_owned_publication_response(") != 2:
            raise AssertionError("socket response publication wrapper mismatch")
        if socket.count("Response") < 1 or socket.count("Error") < 1:
            raise AssertionError("socket response/error trace missing")

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

    def altered_ingress_generated(root, receipt):
        path = root / prepare.INGRESS_TESTS
        path.write_bytes(path.read_bytes() + b"\n")

    def altered_socket_generated(root, receipt):
        path = root / prepare.SOCKET_INGRESS_TESTS
        path.write_bytes(path.read_bytes() + b"\n")

    def altered_owned_actor(root, receipt):
        path = root / prepare.OWNED_ACTOR
        path.write_bytes(path.read_bytes() + b"\n")

    def altered_query_resource_tests(root, receipt):
        path = root / prepare.QUERY_RESOURCE_TESTS
        path.write_bytes(path.read_bytes() + b"\n")

    def altered_owned_completion(root, receipt):
        path = root / prepare.OWNED_COMPLETION
        path.write_bytes(path.read_bytes() + b"\n")

    def ownership_recipe_drift(root, receipt):
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["recipe_files"]["ci/ownership/queries.py"] = "0" * 64
        receipt.write_text(json.dumps(data) + "\n", encoding="utf-8")

    def coordinated_resource_source_mutation(root, receipt):
        path = root / prepare.OWNED_ACTOR
        path.write_bytes(path.read_bytes() + b"\ncoordinated mutation\n")
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["prepared_files"][prepare.OWNED_ACTOR] = hashlib.sha256(path.read_bytes()).hexdigest()
        data["changed_files"] = sorted(set(data["changed_files"]) | {prepare.OWNED_ACTOR})
        receipt.write_text(json.dumps(data) + "\n", encoding="utf-8")

    def altered_ingress_source(root, receipt):
        path = root / "src/common/messages.rs"
        path.write_bytes(path.read_bytes() + b"\n")

    def ingress_recipe_drift(root, receipt):
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["recipe_files"]["ci/ingress.py"] = "0" * 64
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

    def changed(root, path, old, new):
        file = root / path
        text = file.read_text(encoding="utf-8")
        if text.count(old) != 1:
            raise AssertionError(f"mutation anchor is not unique: {path}")
        file.write_text(text.replace(old, new, 1), encoding="utf-8")

    def missing_observer_module(root, receipt):
        changed(root, prepare.RESOURCE_MODULE, '#[path = "publication_observer.rs"]\nmod publication_observer;\n', "")

    def missing_observer_file(root, receipt):
        (root / prepare.PUBLICATION_OBSERVER).unlink()

    def missing_root_export(root, receipt):
        changed(root, "src/lib.rs", "OwnedPutAdmission,", "")

    def reverted_actor_dispatch(root, receipt):
        changed(root, "src/actor.rs", "actor.process_owned_publication_message(message, from);", "actor.process_message(message, from);")

    def reverted_response_predicate(root, receipt):
        changed(root, "src/actor/socket.rs", '                                    "Received response message"\n                                );\n\n                                self.is_expected_owned_publication_response(&message, &from)', '                                    "Received response message"\n                                );\n\n                                self.is_expected_response(&message, &from)')

    def reverted_error_predicate(root, receipt):
        changed(root, "src/actor/socket.rs", '                                    "Received error message"\n                                );\n\n                                self.is_expected_owned_publication_response(&message, &from)', '                                    "Received error message"\n                                );\n\n                                self.is_expected_response(&message, &from)')

    def coordinated_observer_tamper(root, receipt):
        path = root / prepare.PUBLICATION_OBSERVER
        path.write_bytes(path.read_bytes() + b"\ncoordinated mutation\n")
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["prepared_files"][prepare.PUBLICATION_OBSERVER] = hashlib.sha256(path.read_bytes()).hexdigest()
        data["changed_files"] = sorted(set(data["changed_files"]) | {prepare.PUBLICATION_OBSERVER})
        receipt.write_text(json.dumps(data) + "\n", encoding="utf-8")

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
        "altered-ingress-generated": lambda: rejected("altered-ingress-generated", altered_ingress_generated),
        "altered-socket-generated": lambda: rejected("altered-socket-generated", altered_socket_generated),
        "altered-owned-actor": lambda: rejected("altered-owned-actor", altered_owned_actor),
        "altered-query-resource-tests": lambda: rejected("altered-query-resource-tests", altered_query_resource_tests),
        "altered-owned-completion": lambda: rejected("altered-owned-completion", altered_owned_completion),
        "ownership-recipe-drift": lambda: rejected("ownership-recipe-drift", ownership_recipe_drift),
        "coordinated-resource-mutation": lambda: rejected("coordinated-resource-mutation", coordinated_resource_source_mutation),
        "altered-ingress-source": lambda: rejected("altered-ingress-source", altered_ingress_source),
        "ingress-recipe-drift": lambda: rejected("ingress-recipe-drift", ingress_recipe_drift),
        "coordinated-manifest-mutation": lambda: rejected("coordinated-manifest-mutation", coordinated_manifest_mutation),
        "missing-observer-module": lambda: rejected("missing-observer-module", missing_observer_module),
        "missing-observer-file": lambda: rejected("missing-observer-file", missing_observer_file),
        "missing-root-export": lambda: rejected("missing-root-export", missing_root_export),
        "reverted-actor-dispatch": lambda: rejected("reverted-actor-dispatch", reverted_actor_dispatch),
        "reverted-response-predicate": lambda: rejected("reverted-response-predicate", reverted_response_predicate),
        "reverted-error-predicate": lambda: rejected("reverted-error-predicate", reverted_error_predicate),
        "coordinated-observer-tamper": lambda: rejected("coordinated-observer-tamper", coordinated_observer_tamper),
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
