"""CI-only owned-loopback wire checks with fresh compile witnesses per variant."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("relay_wire_graph", HERE / "graph.py")
graph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graph)
prepare = graph.prepare
CASES = {
    "protocol": ("relay_wire_protocol_poll_revocation", "PROTOCOL_POLL_AFTER_REVOCATION"),
    "renewal": ("relay_wire_renewal_admission_revocation", "RENEWAL_REQUEST_AFTER_REVOCATION"),
    "reuse": ("relay_wire_connected_reuse_revocation", "CONNECTED_REUSE_AFTER_REVOCATION"),
}


def command(arguments, cwd, env=None, timeout=900, failure_log=None):
    result = subprocess.run(arguments, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace",
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        if failure_log is not None:
            # Full compiler evidence survives the raised exception and reaches artifacts.
            failure_log.write_text(
                "exit_code=%d\ncommand=%s\n--- stdout ---\n%s\n--- stderr ---\n%s\n"
                % (result.returncode, " ".join(map(str, arguments)), result.stdout, result.stderr),
                encoding="utf-8")
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise RuntimeError("fixture prerequisite command failed: " + " ".join(map(str, arguments)))
    return result.stdout


def metadata(repository, destination, host, locked):
    arguments = ["cargo", "metadata", "--format-version", "1", "--filter-platform", host,
                 "--manifest-path", str(repository / "Cargo.toml")]
    if locked:
        arguments.append("--locked")
    destination.write_text(command(arguments, repository), encoding="utf-8")


def compile_fixture(root, variant, unit_inventory=None):
    target = root / "compiled"
    if target.exists():
        raise ValueError("wire compile target must be fresh")
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), RELAY_WIRE_VARIANT=variant)
    test_target = "relay_operation_units" if unit_inventory is not None else "relay_operation_wire"
    test_source = "tests/units.rs" if unit_inventory is not None else "tests/wire.rs"
    output = command(["cargo", "test", "--manifest-path", str(root / "Cargo.toml"), "--locked",
                      "--test", test_target, "--no-run", "--message-format=json"], root, env,
                     failure_log=root / "compile-failure.log")
    (root / "compile.jsonl").write_text(output, encoding="utf-8")
    artifacts = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    artifacts = [item for item in artifacts if item.get("reason") == "compiler-artifact"]
    relay = [item for item in artifacts if Path(item["target"]["src_path"]).resolve() == (root / "relay/src/lib.rs").resolve()]
    tests = [item for item in artifacts if item.get("executable") and
             Path(item["target"]["src_path"]).resolve() == (root / test_source).resolve()]
    if len(relay) != 1 or len(tests) != 1 or relay[0]["fresh"] or tests[0]["fresh"]:
        raise ValueError("missing fresh selected relay and wire test compile witnesses")
    executable = Path(tests[0]["executable"]).resolve()
    if not executable.is_relative_to(target.resolve()):
        raise ValueError("wire executable came from a different target")
    listed = command([str(executable), "--list", "--format=terse"], root, timeout=30)
    names = unit_inventory if unit_inventory is not None else [name for name, _ in CASES.values()]
    expected = {name + ": test" for name in names}
    inventory = {line for line in listed.splitlines() if line.endswith(": test")}
    other = {line for line in listed.splitlines() if line and not line.endswith(": test")}
    if inventory != expected or not other <= {f"{len(names)} tests, 0 benchmarks"}:
        raise ValueError("wire fixture test inventory changed")
    return executable, {"variant": variant, "fresh_relay": True, "fresh_test": True,
                        "relay_source_sha256": prepare.digest((root / "relay/src/lib.rs").read_bytes()),
                        "executable_sha256": prepare.digest(executable.read_bytes()),
                        "test_count": len(names), "test_target": test_target,
                        "test_source_sha256": prepare.digest((root / test_source).read_bytes()),
                        "relay_package_id": relay[0]["package_id"],
                        "test_package_id": tests[0]["package_id"]}


def execute(root, executable, variant):
    args = [str(executable), "--test-threads=1", "--show-output"]
    expected_count = 3
    if variant != "baseline":
        args += [CASES[variant][0], "--exact"]
        expected_count = 1
    result = subprocess.run(args, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", timeout=180, check=False)
    output = result.stdout
    (root / "run.log").write_text(output, encoding="utf-8")
    print(output)
    if output.count("RELAY_WIRE_SOURCE_VARIANT=" + variant) != expected_count:
        raise ValueError("executed fixture did not witness the selected source variant")
    if output.count("RELAY_WIRE_POSITIVE_INITIAL_AND_AUTOMATIC_RENEWAL_SAME_CONTROL") != expected_count:
        raise ValueError("wire fixture lacked its positive control")
    if variant == "baseline":
        if result.returncode or not re.search(r"test result: ok\. 3 passed; 0 failed;", output):
            raise ValueError("owned relay wire baseline failed")
        if output.count("RELAY_WIRE_JOINED_CLEANUP") != 3:
            raise ValueError("baseline did not join cleanup")
        if "RELAY_WIRE_INDEPENDENT_RESERVATION_SURVIVED" not in output:
            raise ValueError("independent reservation positive control missing")
    else:
        test, marker = CASES[variant]
        if result.returncode == 0 or marker not in output:
            raise ValueError("counterfactual did not fail its phase-specific assertion")
        if f"test {test} ... FAILED" not in output or not re.search(r"test result: FAILED\. 0 passed; 1 failed;", output):
            raise ValueError("counterfactual failed outside the selected test")
        if variant == "protocol" and "RELAY_WIRE_BARRIER_NEGOTIATED_BEFORE_PROTOCOL_ADMISSION" not in output:
            raise ValueError("protocol counterfactual did not reach the pre-admission barrier")
    return {"expected_tests": expected_count, "exit_code": result.returncode,
            "phase_failure_expected": variant != "baseline", "output_sha256": prepare.digest(output.encode())}


def execute_units(root, executable, inventory):
    if len(inventory) != 25 or len(set(inventory)) != 25:
        raise ValueError("unit run requires exactly 25 distinct owned cases")
    result = subprocess.run([str(executable), "--test-threads=1", "--show-output"], cwd=root,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", timeout=180, check=False)
    output = result.stdout
    (root / "run.log").write_text(output, encoding="utf-8")
    print(output)
    completed = re.findall(r"^RELAY_UNIT_COMPLETED=(.+)$", output, re.MULTILINE)
    if result.returncode or not re.search(r"test result: ok\. 25 passed; 0 failed; 0 ignored;", output):
        raise ValueError("owned operation unit suite did not pass exactly 25 cases")
    if len(completed) != 25 or set(completed) != set(inventory):
        raise ValueError("unit dispatch did not execute every unchanged body exactly once")
    for name in inventory:
        if f"test {name} ... ok" not in output:
            raise ValueError("unit result missing: " + name)
    return {"expected_tests": 25, "exit_code": result.returncode, "unit_inventory": inventory,
            "output_sha256": prepare.digest(output.encode()), "unit_bodies_unchanged": True}


def run_units(source, baseline_metadata, product_lock, root, host):
    graph.create(source, baseline_metadata, product_lock, root, units=True)
    metadata(root, root / "metadata.json", host, False)
    graph.verify(baseline_metadata, product_lock, root, root / "metadata.json")
    record = json.loads((root / "fixture-provenance.json").read_text())
    inventory = record["unit_inventory"]
    lock = (root / "Cargo.lock").read_bytes()
    immutable = prepare.hashes(prepare.files(root))
    executable, witness = compile_fixture(root, "units", inventory)
    outcome = execute_units(root, executable, inventory)
    if lock != (root / "Cargo.lock").read_bytes() or immutable != prepare.hashes(prepare.files(root)):
        raise ValueError("unit execution changed fixture sources or lock")
    return {**witness, **outcome, "lock_sha256": prepare.digest(lock)}


def run(repository, source, destination):
    if os.environ.get("CI", "").lower() != "true":
        raise ValueError("wire compilation and execution are CI-only")
    repository, source, destination = repository.resolve(), source.resolve(), destination.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    product_lock = repository / "Cargo.lock"
    lock_before = product_lock.read_bytes()
    product_sources = prepare.hashes(prepare.files(source))
    host = next(line.removeprefix("host: ") for line in command(["rustc", "-vV"], repository).splitlines() if line.startswith("host: "))
    baseline_metadata = destination / "product-metadata.json"
    metadata(repository, baseline_metadata, host, True)
    units = run_units(source, baseline_metadata, product_lock, destination / "units", host)
    baseline = destination / "baseline"
    graph.create(source, baseline_metadata, product_lock, baseline)
    metadata(baseline, baseline / "metadata.json", host, False)
    graph.verify(baseline_metadata, product_lock, baseline, baseline / "metadata.json")
    results = {}
    for variant in ("baseline", *CASES):
        root = baseline if variant == "baseline" else destination / ("counterfactual-" + variant)
        if variant != "baseline":
            prepare.counterfactual(baseline, root, variant)
            metadata(root, root / "metadata.json", host, True)
            graph.verify(baseline_metadata, product_lock, root, root / "metadata.json")
        lock = (root / "Cargo.lock").read_bytes()
        immutable = prepare.hashes(prepare.files(root))
        executable, witness = compile_fixture(root, variant)
        outcome = execute(root, executable, variant)
        if lock != (root / "Cargo.lock").read_bytes() or immutable != prepare.hashes(prepare.files(root)):
            raise ValueError("wire execution changed fixture sources or lock")
        results[variant] = {**witness, **outcome, "lock_sha256": prepare.digest(lock)}
    if product_lock.read_bytes() != lock_before or prepare.hashes(prepare.files(source)) != product_sources:
        raise ValueError("wire fixtures changed production source or lock")
    receipt = {"host": host, "unit_tests": 25, "units": units,
               "baseline_wire_tests": 3, "counterfactual_runs": 3,
               "runner_sha256": prepare.digest(Path(__file__).read_bytes()),
               "runtime_verified": True, "product_lock_sha256": prepare.digest(lock_before),
               "production_files": product_sources, "results": results}
    (destination / "run-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    run(args.repository, args.source, args.destination)


if __name__ == "__main__":
    main()
