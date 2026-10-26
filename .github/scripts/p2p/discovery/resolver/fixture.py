"""CI-only owned tests inside the actual prepared resolver modules."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("resolver_prepare", HERE / "prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)

# Published manifests omit test_support. Exclude only these original test modules.
EXCLUSIONS = {
    "src/cache.rs": ["mod tests {"],
    "src/caching_client.rs": ["mod tests {"],
    "src/config.rs": ["mod tests {"],
    "src/connection_provider.rs": ["mod tests {"],
    "src/hosts.rs": ["mod tests {"],
    "src/lib.rs": ["mod tests;"],
    "src/lookup.rs": ["mod tests {"],
    "src/lookup_ip.rs": ["pub(crate) mod tests {"],
    "src/name_server.rs": ["mod tests {", "mod opportunistic_enc_tests {", "mod resolver_metrics_tests {",
                           "mod reconnect_tests {", "mod mock_provider {"],
    "src/name_server_pool.rs": ["mod tests {"],
    "src/resolver.rs": ["pub(crate) mod testing {", "mod tests {"],
    "src/tls.rs": ["mod tests {"],
    "src/recursor/handle.rs": ["mod tests {"],
    "src/recursor/mod.rs": ["mod tests;"],
    "src/system_conf/mod.rs": ["    mod tests {"],
    "src/system_conf/unix.rs": ["mod tests {"],
}
MODULES = {"src/name_server.rs": "connections", "src/name_server_pool.rs": "cleanup"}


def transformed(source, counterfactual=None):
    if counterfactual not in (None, "connections", "cleanup"):
        raise ValueError("unknown resolver counterfactual mechanism")
    files = prepare.verify(source)
    production = prepare.hashes(files)
    reversed_files = []
    if counterfactual:
        name = next(parent for parent, mechanism in MODULES.items() if mechanism == counterfactual)
        text = files[name].decode()
        for old, new in reversed(prepare.patch.EDITS[name]):
            text = prepare.patch.replace(text, new, old)
        files[name] = text.encode()
        reversed_files.append(name)
    production_delta = {name: {"prepared_sha256": production[name], "counterfactual_sha256": prepare.digest(files[name])}
                        for name in reversed_files}
    for name, anchors in EXCLUSIONS.items():
        text = files[name].decode()
        for anchor in anchors:
            indent = anchor[:len(anchor) - len(anchor.lstrip())]
            text = prepare.patch.replace(text, "\n" + anchor, "\n" + indent + "#[cfg(any())]\n" + anchor)
        files[name] = text.encode()
    for parent, name in MODULES.items():
        files[parent] += f'\n#[cfg(all(test, feature = "tokio"))]\n#[path = "locking_{name}.rs"]\nmod locking_{name};\n'.encode()
        files[f"src/locking_{name}.rs"] = (HERE / f"{name}.rs").read_bytes()
    if prepare.digest(files["Cargo.lock"]) != prepare.LOCK_DIGEST:
        raise ValueError("resolver fixture archive lock changed")
    record = {
        "production_files": production, "fixture_files": prepare.hashes(files),
        "archive_lock_sha256": prepare.LOCK_DIGEST, "counterfactual": counterfactual,
        "production_source_delta": production_delta,
        "excluded_upstream_test_modules": EXCLUSIONS,
        "owned_inputs": prepare.hashes({name: (HERE / name).read_bytes() for name in
                                       ("fixture.py", "connections.rs", "cleanup.rs")}),
    }
    return files, record


def fixture(source, destination, counterfactual=None):
    files, record = transformed(source, counterfactual)
    prepare.write_tree(files, destination)
    (destination / "fixture-provenance.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--counterfactual", choices=("connections", "cleanup"))
    args = parser.parse_args()
    fixture(args.source, args.destination, args.counterfactual)


if __name__ == "__main__":
    main()
