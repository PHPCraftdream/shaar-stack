"""Collect evidence for the exact cargo-deny list, or fail on an ambiguous match."""
import importlib.util
import json
from pathlib import Path
import sys
from urllib.parse import unquote


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


list_probe = load("list_probe")
evidence = load("notice_evidence")


def select(metadata, listing):
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise evidence.EvidenceError("metadata packages missing")
    index = {}
    for package in packages:
        if not isinstance(package, dict):
            raise evidence.EvidenceError("malformed metadata package")
        name, version, source = (package.get(k) for k in ("name", "version", "source"))
        manifest, package_id = package.get("manifest_path"), package.get("id")
        if not all(isinstance(x, str) and x for x in (name, version, manifest, package_id)):
            raise evidence.EvidenceError("metadata package identity missing")
        if source is None:
            source = "path+" + Path(manifest).parent.absolute().as_uri()
        elif not isinstance(source, str):
            raise evidence.EvidenceError("unsupported metadata source")
        key = (name, version, unquote(source).replace("\\", "/"))
        index.setdefault(key, []).append(package_id)
    selected = set()
    for item in listing["package_ids"]:
        parts = item.split(" ", 2)
        if len(parts) != 3 or not parts[2].startswith(("path+file:", "registry+", "git+")):
            raise evidence.EvidenceError(f"unsupported cargo-deny package identity: {item}")
        key = (parts[0], parts[1], unquote(parts[2]).replace("\\", "/"))
        matches = index.get(key, [])
        if len(matches) != 1 or matches[0] in selected:
            raise evidence.EvidenceError(f"missing or ambiguous metadata identity: {item}")
        selected.add(matches[0])
    return selected


def collect_selected(metadata_path, list_path, output, source_map_path):
    metadata = evidence._load_json(metadata_path, evidence.MAX_METADATA_BYTES)
    with list_path.open("rb") as stream:
        listing = list_probe.summarize(stream.read(list_probe.MAX_BYTES + 1))
    selected = select(metadata, listing)
    mapping = {p["id"]: str(Path(p["manifest_path"]).parent) for p in metadata["packages"]}
    workspace = metadata.get("workspace_members")
    if not isinstance(workspace, list) or any(not isinstance(item, str) for item in workspace):
        raise evidence.EvidenceError("metadata must identify workspace_members")
    protected = selected | set(workspace)
    packages = {p["id"]: p for p in metadata["packages"]}
    if not protected.issubset(packages):
        raise evidence.EvidenceError("workspace member missing from metadata")
    roots = [evidence._source_root(Path(mapping[item]), packages[item]["manifest_path"])
             for item in protected]
    # Protect the source map as well as the final output from source-tree writes.
    if source_map_path.resolve(strict=False) == output.resolve(strict=False):
        raise evidence.EvidenceError("source map aliases output")
    evidence._write_output(source_map_path, json.dumps(mapping, sort_keys=True).encode("utf-8"), [metadata_path, list_path], roots)
    manifest, collected_roots = evidence.collect(metadata_path, source_map_path, selected)
    manifest["selection"] = {"kind": "cargo-deny-list", "package_count": len(selected)}
    evidence.write_manifest(output, manifest, [metadata_path, list_path, source_map_path], roots + list(collected_roots.values()))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("expected metadata, cargo-deny list, output, source map")
    collect_selected(*(Path(arg) for arg in sys.argv[1:]))
