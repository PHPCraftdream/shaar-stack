"""CI-only driver fixtures; downloaded sources are handled only as data."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tomllib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import graph  # noqa: E402
sys.path.insert(0, str(HERE.parents[1] / "backend"))
import runtime  # noqa: E402
from policy import replace  # noqa: E402

MUTEX_PROBE = '''        #[cfg(test)]
        pub(crate) fn driver_test_available(&self) -> bool {
            self.inner.try_lock().is_ok()
        }

'''
PROTOCOL_SETUP = '''    #[cfg(test)]
    pub(crate) fn driver_test_terminal(&mut self, now: Instant, reason: TransportError, draining: bool) {
        self.close_common();
        self.set_close_timer(now);
        if draining {
            self.state.move_to_draining(Some(reason.into()), &mut self.endpoint_events);
        } else {
            self.state.move_to_closed(reason);
        }
    }

'''
INTERNAL_MODULE = '\n#[cfg(test)]\n#[path = "driver_failure_internals.rs"]\nmod driver_failure;\n'


def install_hooks(roots, destination):
    connection = roots["noq"] / "src/connection.rs"
    mutex = roots["noq"] / "src/mutex.rs"
    protocol = roots["noq-proto"] / "src/connection/mod.rs"
    inputs = {path: path.read_text(encoding="utf-8") for path in (connection, mutex, protocol)}
    if any("driver_test_" in text or "mod driver_failure;" in text for text in inputs.values()):
        raise ValueError("unexpected existing driver inspection hooks")
    anchor = "        pub(crate) fn new(value: T) -> Self {"
    outputs = {
        connection: inputs[connection] + INTERNAL_MODULE,
        mutex: replace(inputs[mutex], anchor, MUTEX_PROBE + anchor, count=2),
        protocol: replace(inputs[protocol], runtime.LOCAL_ABORT_API, PROTOCOL_SETUP + runtime.LOCAL_ABORT_API),
    }
    restored = {
        connection: outputs[connection][:-len(INTERNAL_MODULE)],
        mutex: replace(outputs[mutex], MUTEX_PROBE, "", count=2),
        protocol: replace(outputs[protocol], PROTOCOL_SETUP, ""),
    }
    if restored != inputs:
        raise ValueError("fixture hook reversal changed production bodies")
    receipt = {}
    for path, text in outputs.items():
        receipt[str(path.relative_to(destination))] = {
            "production_sha256": hashlib.sha256(inputs[path].encode()).hexdigest(),
            "fixture_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "reversal_matches_production": True,
        }
        path.write_text(text, encoding="utf-8", newline="\n")
    shutil.copyfile(HERE / "internals.rs", roots["noq"] / "src/driver_failure_internals.rs")
    (destination / "fixture-hooks.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


def copy_sources(backend, destination):
    destination.mkdir(parents=True, exist_ok=False)
    roots = {}
    for name in ("noq", "noq-proto"):
        source = backend / name / f"{name}-1.3.0"
        target = destination / name
        shutil.copytree(source, target, ignore=shutil.ignore_patterns("target", "__pycache__"))
        roots[name] = target
    return roots


def install_suite(target):
    target.mkdir()
    for name in ("suite.rs", "support.rs"):
        shutil.copyfile(HERE / name, target / name)


def archive_fixture(backend, destination):
    roots = copy_sources(backend, destination)
    root = roots["noq"]
    install_hooks(roots, destination)
    suite = root / "src/driver_failure"
    install_suite(suite)
    (suite / "mod.rs").write_text(
        '#![forbid(unsafe_code)]\nuse crate as noq;\npub(crate) mod suite;\n', encoding="utf-8")
    library = root / "src/lib.rs"
    library.write_text(replace(library.read_text(encoding="utf-8"), "mod tests;",
        "mod tests;\n#[cfg(test)]\nmod driver_failure;"), encoding="utf-8")
    manifest = root / "Cargo.toml"
    manifest.write_text(manifest.read_text(encoding="utf-8") +
        '\n[patch.crates-io]\nnoq-proto = { path = "../noq-proto" }\n', encoding="utf-8")
    lock_path = root / "Cargo.lock"
    original = lock_path.read_bytes()
    blocks = original.decode().split("[[package]]")
    found = 0
    for index, block in enumerate(blocks[1:], 1):
        entry = tomllib.loads("[[package]]" + block)["package"][0]
        if entry["name"] == "noq-proto":
            if entry["version"] != "1.3.0" or entry.get("checksum") != "7c1e5b6fe668491eca022f745a0a9402585626c73a7b839b3424ace15d6a9c8f":
                raise ValueError("runtime archive protocol identity changed")
            blocks[index] = "\n".join(line for line in block.split("\n")
                if not line.startswith(("source =", "checksum =")))
            found += 1
    if found != 1:
        raise ValueError("runtime archive protocol entry missing")
    lock_path.write_text("[[package]]".join(blocks), encoding="utf-8")
    protocol = roots["noq-proto"] / "src/tests/mod.rs"
    protocol.write_text(protocol.read_text(encoding="utf-8") + "\nmod driver_failure;\n", encoding="utf-8")
    shutil.copyfile(HERE / "protocol.rs", protocol.with_name("driver_failure.rs"))
    print("Runtime archive baseline lock SHA256:", hashlib.sha256(original).hexdigest())
    print("Only noq-proto source identity changes; protocol archive test lock is unchanged.")


def product_fixture(backend, product_lock, baseline_metadata, destination):
    destination.mkdir(parents=True, exist_ok=False)
    install_suite(destination / "src")
    (destination / "src/lib.rs").write_text(
        '#![forbid(unsafe_code)]\nuse noq;\n#[cfg(test)]\nmod suite;\n', encoding="utf-8")
    metadata = json.loads(baseline_metadata.read_text(encoding="utf-8"))
    manifest = '''[package]
name = "noq-driver-product-proof"
version = "0.0.0"
edition = "2024"
publish = false
[workspace]
[dependencies]
'''
    manifest += graph.manifest_dependencies(metadata)
    manifest += "\n[patch.crates-io]\n"
    for name in ("noq", "noq-proto"):
        path = (backend / name / f"{name}-1.3.0").resolve().as_posix()
        manifest += f'{name} = {{ path = {json.dumps(path)} }}\n'
    (destination / "Cargo.toml").write_text(manifest, encoding="utf-8")
    shutil.copyfile(product_lock, destination / "Cargo.lock")
    print("Product fixture mirrors resolved features across the driver dependency closure.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("archive", "counterfactual", "product", "verify-product"))
    parser.add_argument("--backend", type=Path)
    parser.add_argument("--product-lock", type=Path)
    parser.add_argument("--baseline-metadata", type=Path)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if args.action in ("archive", "counterfactual"):
        archive_fixture(args.backend, args.destination)
        if args.action == "counterfactual":
            root = args.destination / "noq"
            connection = root / "src/connection.rs"
            text = runtime.transform_abort(connection.read_text(encoding="utf-8"),
                                           runtime.RUNTIME_ABORT_SWAPS, reverse=True)
            connection.write_text(text, encoding="utf-8")
            endpoint = root / "src/endpoint.rs"
            text = replace(endpoint.read_text(encoding="utf-8"), runtime.ENDPOINT_ABORT_NEW,
                           runtime.ENDPOINT_ABORT_OLD)
            endpoint.write_text(text, encoding="utf-8")
    elif args.action == "product":
        product_fixture(args.backend, args.product_lock, args.baseline_metadata, args.destination)
    else:
        graph.verify(args.product_lock, args.destination / "Cargo.lock", args.baseline_metadata)
