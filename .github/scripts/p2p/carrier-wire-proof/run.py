"""CI-only Carrier protocol baseline and independently compiled guard counterfactual."""
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
CASE = "carrier_protocol_fixture_revocation"
FAILURE = "CARRIER_PROTOCOL_POLL_AFTER_REVOCATION"
MARKERS = (
    "CARRIER_PROTOCOL_ENTERED_BOUND",
    "CARRIER_PROTOCOL_POSITIVE_ACCEPTED",
    "CARRIER_PROTOCOL_REVOKED_NO_INNER_POLL",
    "CARRIER_PROTOCOL_RETAINED_UNTIL_LAST_DROP",
    "CARRIER_PROTOCOL_JOINED_CLEANUP",
)


def module(name):
    spec = importlib.util.spec_from_file_location("carrier_proof_" + name, HERE / (name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def command(arguments, cwd, env=None, timeout=1200, failure_log=None):
    try:
        result = subprocess.run(arguments, cwd=cwd, env=env, text=True, encoding="utf-8",
                                errors="replace", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        if failure_log is not None:
            failure_log.write_text("prerequisite timeout\n" + str(error), encoding="utf-8")
        raise RuntimeError("proof prerequisite timed out") from error
    if result.returncode:
        if failure_log is not None:
            failure_log.write_text(
                "exit_code=%d\n--- stdout ---\n%s\n--- stderr ---\n%s\n"
                % (result.returncode, result.stdout, result.stderr), encoding="utf-8")
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise RuntimeError("proof prerequisite failed: " + " ".join(map(str, arguments)))
    return result.stdout


def metadata(root, output, host, target):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    text = command(["cargo", "metadata", "--format-version", "1", "--locked",
                    "--filter-platform", host, "--manifest-path", str(root / "Cargo.toml")], root, env)
    output.write_text(text, encoding="utf-8")
    return json.loads(text)


def compile_fixture(workspace, directory, relay, graph):
    target = directory / "compiled"
    if target.exists():
        raise ValueError("Carrier compile target must be fresh")
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    output = command(["cargo", "test", "--manifest-path", str(workspace / "Cargo.toml"),
                      "--locked", "-p", "shaar-p2p", "--lib", "--no-run", "--message-format=json"],
                     workspace, env, failure_log=directory / "compile-failure.log")
    (directory / "compile.jsonl").write_text(output, encoding="utf-8")
    artifacts = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    artifacts = [item for item in artifacts if item.get("reason") == "compiler-artifact"]
    relay_witness = [item for item in artifacts
                     if Path(item["target"]["src_path"]).resolve() == relay / "src/lib.rs"]
    unit_source = workspace / "crates/shaar-p2p/src/lib.rs"
    unit_witness = [item for item in artifacts if item.get("executable")
                    and Path(item["target"]["src_path"]).resolve() == unit_source]
    if len(relay_witness) != 1 or len(unit_witness) != 1:
        raise ValueError("missing selected relay or Carrier unit executable witness")
    if relay_witness[0]["fresh"] or unit_witness[0]["fresh"]:
        raise ValueError("Carrier protocol witnesses must be freshly compiled")
    executable = Path(unit_witness[0]["executable"]).resolve()
    if not executable.is_relative_to(target):
        raise ValueError("Carrier executable came from a different compile target")
    listing = command([str(executable), "--list", "--format=terse"], workspace, timeout=30)
    (directory / "inventory.log").write_text(listing, encoding="utf-8")
    names = [line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")]
    if len(names) != len(set(names)):
        raise ValueError("duplicate Carrier executable test names")
    selected = [name for name in names if name.endswith("::" + CASE)
                and "carrier_protocol_fixture" in name.split("::")]
    if len(selected) != 1:
        raise ValueError("Carrier protocol test must be included exactly once")
    for prefix, count in (("destination_roles_", 15), ("destination_guard_", 22),
                          ("carrier_destination_", 33)):
        if sum(name.split("::")[-1].startswith(prefix) for name in names) != count:
            raise ValueError("existing source inventory changed: " + prefix)
    return executable, selected[0], {
        "fresh_relay": True,
        "fresh_carrier_unit": True,
        "relay_package_id": relay_witness[0]["package_id"],
        "carrier_package_id": unit_witness[0]["package_id"],
        "executable_sha256": graph.digest(executable.read_bytes()),
        "relay_source_sha256": graph.digest((relay / "src/lib.rs").read_bytes()),
        "carrier_source_sha256": graph.digest(unit_source.read_bytes()),
        "unit_inventory": names,
        "selected_test": selected[0],
    }


def execute(workspace, directory, executable, test, variant, graph):
    try:
        result = subprocess.run([str(executable), "--test-threads=1", "--show-output", test, "--exact"],
                                cwd=workspace, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", timeout=90, check=False)
    except subprocess.TimeoutExpired as error:
        (directory / "run.log").write_text("scenario outer timeout\n" + str(error), encoding="utf-8")
        raise RuntimeError("scenario timeout is not a phase counterfactual") from error
    output = result.stdout
    (directory / "run.log").write_text(output, encoding="utf-8")
    print(output)
    command([sys.executable, "-I", str(workspace / ".github/scripts/scan_identity_output.py"),
             str(directory / "run.log")], workspace, timeout=30)
    if variant == "baseline":
        if result.returncode or not re.search(r"test result: ok\. 1 passed; 0 failed;", output):
            raise ValueError("Carrier protocol baseline failed")
        if any(output.count(marker) != 1 for marker in MARKERS):
            raise ValueError("Carrier baseline did not witness every asserted phase exactly once")
        if FAILURE in output:
            raise ValueError("Carrier baseline emitted its negative assertion marker")
    else:
        if result.returncode == 0 or FAILURE not in output:
            raise ValueError("Carrier counterfactual missed its protocol-poll assertion")
        if f"test {test} ... FAILED" not in output:
            raise ValueError("counterfactual did not fail the selected Carrier test")
        if not re.search(r"test result: FAILED\. 0 passed; 1 failed;", output):
            raise ValueError("counterfactual failed outside its scenario")
        for marker in ("CARRIER_PROTOCOL_POSITIVE_ACCEPTED", "CARRIER_PROTOCOL_ENTERED_BOUND"):
            if output.count(marker) != 1:
                raise ValueError("counterfactual did not reach its positive control and bound barrier")
    return {"exit_code": result.returncode, "phase_failure_expected": variant != "baseline",
            "output_sha256": graph.digest(output.encode())}


def run(repository, destination):
    if os.environ.get("CI", "").lower() != "true":
        raise ValueError("Carrier protocol compilation and execution are CI-only")
    repository, destination = repository.resolve(), destination.resolve()
    if not destination.is_relative_to(repository) or destination.exists():
        raise ValueError("Carrier destination must be fresh and inside the caller repository")
    relative = destination.relative_to(repository).as_posix()
    if subprocess.run(["git", "check-ignore", "--quiet", "--", relative], cwd=repository).returncode:
        raise ValueError("Carrier fixture destination must be ignored")
    graph = module("graph")
    instrument = module("instrument")
    scenario = HERE / "scenario.rs"
    if not scenario.is_file():
        raise ValueError("the authored Carrier scenario is missing")
    destination.mkdir(parents=True, exist_ok=False)
    host = next(line.removeprefix("host: ") for line in command(["rustc", "-vV"], repository).splitlines()
                if line.startswith("host: "))
    product = metadata(repository, destination / "product-metadata.json", host,
                       destination / "metadata-target")
    relay_packages = [package for package in product["packages"] if package["name"] == "libp2p-relay"]
    if len(relay_packages) != 1 or relay_packages[0]["source"] is not None:
        raise ValueError("product must select one prepared relay path package")
    relay_source = Path(relay_packages[0]["manifest_path"]).resolve().parent
    product_lock = (repository / "Cargo.lock").read_bytes()
    product_paths = graph.product_paths(repository, product)
    original_hashes = graph.selected_hashes(repository, product_paths)
    results = {}
    for variant in ("baseline", "counterfactual"):
        directory = destination / variant
        directory.mkdir()
        workspace = directory / "workspace"
        provenance, copied_paths = graph.create(repository, product, workspace, relay_source,
                                                instrument, variant, scenario)
        if copied_paths != product_paths:
            raise ValueError("product source inventory changed between variants")
        write_json(directory / "fixture-provenance.json", provenance)
        fixture = metadata(workspace, directory / "metadata.json", host, directory / "metadata-target")
        copied_relay = workspace / provenance["relay_relative"]
        proof = graph.verify(product, fixture, product_lock, workspace, copied_relay)
        write_json(directory / "graph-receipt.json", proof)
        immutable = graph.hashes(workspace)
        executable, test, witness = compile_fixture(workspace, directory, copied_relay, graph)
        outcome = execute(workspace, directory, executable, test, variant, graph)
        if immutable != graph.hashes(workspace):
            raise ValueError("Carrier fixture source or lock changed during compilation/execution")
        results[variant] = {**witness, **outcome, "fixture_lock_sha256": graph.digest(product_lock)}
        write_json(directory / "variant-receipt.json", results[variant])
    if results["baseline"]["unit_inventory"] != results["counterfactual"]["unit_inventory"]:
        raise ValueError("counterfactual changed the executable test inventory")
    if original_hashes != graph.selected_hashes(repository, product_paths):
        raise ValueError("Carrier proof changed original product sources or lock")
    write_json(destination / "run-receipt.json", {
        "host": host,
        "runtime_verified": True,
        "product_lock_sha256": graph.digest(product_lock),
        "production_files": original_hashes,
        "recipe_sha256": {path.name: graph.digest(path.read_bytes())
                          for path in sorted(HERE.iterdir()) if path.is_file()},
        "results": results,
    })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args()
    run(arguments.repository, arguments.destination)


if __name__ == "__main__":
    main()
