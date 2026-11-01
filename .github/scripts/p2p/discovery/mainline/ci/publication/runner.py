# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Build archive-baseline publication evidence in isolated CI."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import tomllib

import graph
import prepare


def repository_root() -> Path:
    return Path(__file__).resolve().parents[7]


def simple_dns_helper() -> Path:
    return Path(__file__).resolve().parents[3] / "simple_dns" / "prepare.py"


def validate_output_paths(destination: Path, receipt: Path) -> tuple[Path, Path]:
    repo = repository_root()
    receipt_resolved = receipt.resolve(strict=False)
    dest_resolved = destination.resolve(strict=False)
    if (receipt_resolved == repo or repo in receipt_resolved.parents or dest_resolved == repo
            or repo in dest_resolved.parents or receipt_resolved == dest_resolved
            or receipt_resolved in dest_resolved.parents or dest_resolved in receipt_resolved.parents):
        raise ValueError("staging and evidence paths must be disjoint and outside repository")
    return receipt_resolved, dest_resolved


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(root: Path) -> dict[str, str]:
    found = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in staged source")
        if path.is_file():
            found[path.relative_to(root).as_posix()] = digest(path)
    return dict(sorted(found.items()))


def command(label: str, argv: list[str], cwd: Path, logs: Path, evidence: dict,
            env: dict | None = None, combine_output: bool = False) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, text=True, timeout=600)
    out, err = logs / (label + ".stdout.log"), logs / (label + ".stderr.log")
    out.write_text(result.stdout, encoding="utf-8")
    err.write_text(result.stderr, encoding="utf-8")
    evidence["commands"].append({"label": label, "argv": argv, "exit_code": result.returncode,
        "stdout_log": str(out), "stdout_sha256": digest(out), "stderr_log": str(err),
        "stderr_sha256": digest(err)})
    if result.returncode:
        raise ValueError(label + " failed")
    return result.stdout + (result.stderr if combine_output else "")


def manifest_with_test(manifest: str) -> str:
    if "[[test]]" in manifest or "tests/publication_tests.rs" in manifest:
        raise ValueError("unexpected upstream publication test target")
    return manifest.rstrip() + '\n\n[[test]]\nname = "publication_tests"\npath = "tests/publication_tests.rs"\n'


def metadata(label: str, cargo: str, manifest: Path, cwd: Path, logs: Path, evidence: dict, env: dict) -> dict:
    output = command(label, [cargo, "metadata", "--locked", "--format-version", "1",
                             "--manifest-path", str(manifest)], cwd, logs, evidence, env)
    value = json.loads(output)
    (logs / (label + ".json")).write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "source", "original-lock", "simple-dns-archive", "destination", "evidence", "plan"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    evidence = {"status": "failed", "recipe": prepare.recipe(), "commands": []}
    receipt = args.evidence.absolute()
    owns_receipt = False
    staged_lock: Path | None = None
    try:
        repo = repository_root()
        destination, plan = args.destination.absolute(), args.plan.absolute()
        receipt_resolved, dest_resolved = validate_output_paths(destination, receipt)
        if receipt.exists() or receipt.is_symlink() or destination.exists() or destination.is_symlink():
            raise ValueError("receipt and staging destination must be unused")
        if not plan.is_file() or plan.is_symlink() or plan == repo or repo in plan.parents:
            raise ValueError("CI plan must be a regular file outside repository")
        plan_data = json.loads(plan.read_text(encoding="utf-8"))
        evidence.update(plan_sha256=digest(plan), plan=plan_data)
        selection = plan_data.get("selection", {})
        if plan_data.get("scope") not in {"targeted", "full"} or selection.get("publication") is not True:
            raise ValueError("CI plan must select publication within targeted or full scope")
        head, base = plan_data.get("head", ""), plan_data.get("base")
        checkout_id = plan_data.get("checkout", "")
        scope = plan_data.get("scope")
        if (not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head)
                or not isinstance(checkout_id, str) or not re.fullmatch(r"[0-9a-f]{40}", checkout_id)
                or (scope == "targeted" and (not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{40}", base)))
                or (scope == "full" and base is not None and
                    (not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{40}", base)))):
            raise ValueError("CI plan head/checkout and scope-appropriate base must be full commit identities")
        if receipt.parent.exists() and receipt.parent.is_symlink():
            raise ValueError("evidence parent may not be a symlink")
        if destination.parent.exists() and destination.parent.is_symlink():
            raise ValueError("destination parent may not be a symlink")
        receipt.parent.mkdir(parents=True, exist_ok=True)
        owns_receipt = True
        logs = receipt.parent / "publication-logs"
        logs.mkdir(exist_ok=False)
        checkout = command("git-head", ["git", "rev-parse", "HEAD"], repo, logs, evidence).strip()
        evidence.update(plan_sha256=digest(plan), plan=plan_data, checkout=checkout, head=head, base=base,
                        scope=plan_data["scope"], selection=selection)
        if checkout != checkout_id:
            raise ValueError("plan checkout differs from current HEAD")
        source = args.source.resolve()
        archive_resolved = args.archive.resolve(strict=False)
        lock_resolved = args.original_lock.resolve(strict=False)
        simple_archive_resolved = args.simple_dns_archive.resolve(strict=False)
        path_values = (source, archive_resolved, lock_resolved, simple_archive_resolved, plan.resolve(strict=False))
        if any(value == receipt_resolved or value in receipt_resolved.parents or receipt_resolved in value.parents
               for value in path_values):
            raise ValueError("inputs overlap evidence receipt/log directory")
        if (source == dest_resolved or source in dest_resolved.parents or dest_resolved in source.parents
                or receipt_resolved == source or source in receipt_resolved.parents or receipt_resolved in source.parents):
            raise ValueError("source, destination, and evidence paths overlap")
        if (receipt_resolved == plan.resolve(strict=False) or dest_resolved == plan.resolve(strict=False)
                or source == plan.resolve(strict=False)):
            raise ValueError("CI plan may not overlap source/staging/evidence paths")
        args.archive = archive_resolved
        args.original_lock = lock_resolved
        args.simple_dns_archive = simple_archive_resolved
        upstream = prepare.archive_files(args.archive)
        evidence.update(archive_sha256=digest(args.archive), archive_lock_sha256=prepare.sha(upstream["Cargo.lock"]))
        if tree(args.source) != {name: prepare.sha(data) for name, data in upstream.items()}:
            raise ValueError("source differs from pinned archive inventory")
        if not args.original_lock.is_file() or args.original_lock.is_symlink() or upstream.get("Cargo.lock") != args.original_lock.read_bytes():
            raise ValueError("lock is not byte-identical to pinned archive")
        helper = simple_dns_helper()
        spec = importlib.util.spec_from_file_location("publication_simple_dns_prepare", helper)
        if spec is None or spec.loader is None:
            raise ValueError("accepted simple-dns recipe unavailable")
        simple = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(simple)
        simple_files = simple.archive_files(args.simple_dns_archive)
        evidence["simple_dns_archive_sha256"] = digest(args.simple_dns_archive)
        evidence["simple_dns_recipe"] = {name: digest(simple.HERE / name) for name in ("prepare.py", "checks.py")}
        simple.validate_originals(simple_files)
        simple_changes = simple.transform(simple_files)
        if set(simple_changes) != {"src/dns/packet.rs"}:
            raise ValueError("unexpected simple-dns source delta")
        simple_prepared = dict(simple_files)
        simple_prepared.update(simple_changes)
        simple_root = receipt.parent / "simple-dns-prepared" / simple.PACKAGE
        simple_root_resolved = simple_root.resolve(strict=False)
        if (simple_root_resolved == dest_resolved or simple_root_resolved in dest_resolved.parents
                or dest_resolved in simple_root_resolved.parents or simple_root_resolved == source
                or simple_root_resolved in source.parents or source in simple_root_resolved.parents
                or simple_root_resolved == receipt_resolved or simple_root_resolved in receipt_resolved.parents
                or receipt_resolved in simple_root_resolved.parents):
            raise ValueError("simple-dns staging overlaps source, destination, or evidence")
        destination.mkdir(parents=True, exist_ok=False)
        shutil.copytree(args.source, destination, dirs_exist_ok=True)
        test_dir = destination / "tests"
        test_dir.mkdir(exist_ok=True)
        manifest_path = destination / "Cargo.toml"
        upstream_manifest = manifest_path.read_text(encoding="utf-8")
        baseline_manifest = manifest_with_test(upstream_manifest)
        test_bytes = (prepare.HERE / "tests/publication_tests.rs").read_bytes()
        (test_dir / "publication_tests.rs").write_bytes(test_bytes)
        (destination / "Cargo.lock").write_bytes(upstream["Cargo.lock"])
        manifest_path.write_text(baseline_manifest, encoding="utf-8", newline="\n")
        baseline_expected = {name: prepare.sha(data) for name, data in upstream.items()}
        baseline_expected.update({"Cargo.toml": prepare.sha(baseline_manifest.encode()),
                                 "tests/publication_tests.rs": prepare.sha(test_bytes)})
        if tree(destination) != dict(sorted(baseline_expected.items())):
            raise ValueError("baseline source inventory mismatch")
        target_dir = receipt.parent / "cargo-target"
        if target_dir.exists() or target_dir.is_symlink():
            raise ValueError("cargo target directory must be unused")
        target_dir.mkdir(parents=True, exist_ok=False)
        env = dict(os.environ)
        env["CARGO_TARGET_DIR"] = str(target_dir)
        baseline_meta = metadata("baseline-metadata", args.cargo, manifest_path, destination, logs, evidence, env)
        if (destination / "Cargo.lock").read_bytes() != upstream["Cargo.lock"]:
            raise ValueError("baseline metadata changed archive lock")
        evidence["baseline_metadata"] = baseline_meta
        changes = prepare.transform_checked(upstream, upstream)
        simple_root.parent.mkdir(parents=True, exist_ok=False)
        simple_root.mkdir(parents=True, exist_ok=False)
        for name, data in simple_prepared.items():
            target = simple_root.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        if tree(simple_root) != {name: prepare.sha(data) for name, data in sorted(simple_prepared.items())}:
            raise ValueError("prepared simple-dns tree inventory mismatch")
        candidate_lock = graph.rewrite_lock(upstream["Cargo.lock"], simple_root.as_posix())
        patched_manifest = manifest_with_test(upstream_manifest + f'\n[patch.crates-io]\nsimple-dns = {{ path = "{simple_root.as_posix()}" }}\n')
        for name, data in changes.items():
            (destination / name).write_bytes(data)
        manifest_path.write_text(patched_manifest, encoding="utf-8", newline="\n")
        (destination / "Cargo.lock").write_bytes(candidate_lock)
        staged_lock = destination / "Cargo.lock"
        expected = {name: prepare.sha(data) for name, data in upstream.items()}
        expected.update({name: prepare.sha(data) for name, data in changes.items()})
        expected.update({"Cargo.toml": prepare.sha(patched_manifest.encode()), "Cargo.lock": prepare.sha(candidate_lock),
                         "tests/publication_tests.rs": prepare.sha(test_bytes)})
        if tree(destination) != dict(sorted(expected.items())):
            raise ValueError("candidate source inventory mismatch")
        candidate_meta = metadata("candidate-metadata", args.cargo, manifest_path, destination, logs, evidence, env)
        evidence["candidate_metadata"] = candidate_meta
        graph_evidence = graph.validate_lock_rewrite(upstream["Cargo.lock"], candidate_lock, simple_root.as_posix())
        graph_evidence.update(graph.compare_metadata(baseline_meta, candidate_meta, simple_root.as_posix()))
        evidence["graph"] = graph_evidence
        versions = command("cargo-version", [args.cargo, "--version"], destination, logs, evidence, env)
        rustc = command("rustc-version", ["rustc", "--version", "--verbose"], destination, logs, evidence, env)
        evidence["toolchain"] = {"cargo": versions, "rustc": rustc}
        build = command("normal-build", [args.cargo, "build", "--locked", "--lib", "--message-format=json", "--manifest-path", str(manifest_path)], destination, logs, evidence, env)
        libraries = []
        for line in build.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            target, filenames = event.get("target", {}), event.get("filenames", [])
            if (event.get("reason") == "compiler-artifact" and target.get("name") == "iroh_dns"
                    and target.get("kind") == ["lib"] and event.get("profile", {}).get("test") is False):
                libraries.extend(Path(name).resolve() for name in filenames)
        libraries = [path for path in libraries if path.is_file()]
        if not libraries:
            raise ValueError("Cargo emitted no iroh_dns library artifacts")
        evidence["library_artifacts"] = {str(path): digest(path) for path in libraries}
        integration = command("integration-build", [args.cargo, "test", "--locked", "--test", "publication_tests", "--no-run", "--message-format=json", "--manifest-path", str(manifest_path)], destination, logs, evidence, env)
        binaries = []
        for line in integration.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            target, binary = event.get("target", {}), event.get("executable")
            if event.get("reason") == "compiler-artifact" and target.get("name") == "publication_tests" and target.get("kind") == ["test"] and isinstance(binary, str):
                binaries.append(Path(binary).resolve())
        if len(binaries) != 1 or not binaries[0].is_file():
            raise ValueError("Cargo did not report exactly one publication harness")
        harness = binaries[0]
        evidence["harness_sha256"] = digest(harness)
        listed = command("harness-list", [str(harness), "--list"], destination, logs, evidence)
        ignored = command("harness-ignored-list", [str(harness), "--ignored", "--list"], destination, logs, evidence)
        cases = sorted(line.split(": test", 1)[0] for line in listed.splitlines() if ": test" in line)
        ignored_cases = sorted(line.split(": test", 1)[0] for line in ignored.splitlines() if ": test" in line)
        evidence["ignored"] = ignored_cases
        if not cases or len(cases) != len(set(cases)) or ignored_cases:
            raise ValueError("empty/duplicate/ignored Rust test inventory")
        evidence["selected"] = cases
        evidence["ignored"] = ignored_cases
        evidence["observed"] = []
        observed = []
        for index, case in enumerate(cases):
            output = command("case-" + str(index), [str(harness), case, "--exact", "--nocapture"], destination, logs, evidence)
            lines = output.splitlines()
            completed = [line for line in lines if line.startswith("test ") and (" ... ok" in line or " ... FAILED" in line)]
            if completed != ["test " + case + " ... ok"] or not any(re.search(r"1 passed; 0 failed; 0 ignored", line) for line in lines):
                raise ValueError("case completion/count mismatch: " + case)
            observed.append(case)
            evidence["observed"] = list(observed)
        if observed != cases or (destination / "Cargo.lock").read_bytes() != candidate_lock:
            raise ValueError("observed inventory mismatch or lock changed")
        integrity_env = dict(env)
        integrity_env["IROH_DNS_ARCHIVE"] = str(args.archive)
        integrity = command("source-integrity", [sys.executable, "-I", str(prepare.HERE / "test_source.py"), "-v"],
                            destination, logs, evidence, integrity_env, combine_output=True)
        integrity_lines = integrity.splitlines()
        if (not any(re.fullmatch(r"Ran [1-9][0-9]* tests? in .+", line.strip()) for line in integrity_lines)
                or not any(line.strip() == "OK" for line in integrity_lines)
                or any("skipped" in line.lower() for line in integrity_lines)):
            raise ValueError("source integrity tests did not report non-skipped completion")
        if tree(destination) != dict(sorted(expected.items())):
            raise ValueError("final staged source inventory mismatch")
        if (tree(simple_root) != {name: prepare.sha(data) for name, data in sorted(simple_prepared.items())}
                or (destination / "Cargo.lock").read_bytes() != candidate_lock):
            raise ValueError("final staged sources or lock differ from expected inputs")
        if prepare.recipe() != evidence["recipe"]:
            raise ValueError("publication source recipe changed during run")
        if {name: digest(simple.HERE / name) for name in ("prepare.py", "checks.py")} != evidence["simple_dns_recipe"]:
            raise ValueError("simple-dns source recipe changed during run")
        evidence["recipe_final"] = prepare.recipe()
        evidence.update(status="passed", selected=cases, observed=observed, archive_sha256=digest(args.archive),
                        source_sha256=tree(destination), lock_before_sha256=prepare.sha(upstream["Cargo.lock"]),
                        lock_after_sha256=prepare.sha(candidate_lock), archive_only_baseline=True,
                        product_graph_compatibility="not established")
        return 0
    except Exception as error:
        evidence["error"] = str(error)
        return 1
    finally:
        if staged_lock is not None and staged_lock.is_file():
            evidence["lock_final_sha256"] = digest(staged_lock)
        if owns_receipt and not receipt.exists():
            receipt.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
