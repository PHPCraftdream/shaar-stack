"""Copy the product workspace without changing manifests, identities or feature unions."""
import hashlib
import json
import re
import tomllib
from pathlib import Path, PurePosixPath
import shutil
import subprocess

ROOTS = {"shaar-p2p", "libp2p", "libp2p-relay", "tokio", "futures"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tracked(repository):
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=repository)
    paths = [name.decode("utf-8") for name in output.split(b"\0") if name]
    for name in paths:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("tracked path escapes workspace")
    return paths


def files(root):
    return sorted(path for path in root.rglob("*") if path.is_file())


def hashes(root):
    return {path.relative_to(root).as_posix(): digest(path.read_bytes()) for path in files(root)}


def product_paths(repository, metadata):
    selected = set(tracked(repository))
    for package in metadata["packages"]:
        if package.get("source") is not None:
            continue
        directory = Path(package["manifest_path"]).resolve().parent
        if not directory.is_relative_to(repository):
            raise ValueError("path dependency is outside the caller repository")
        for path in files(directory):
            relative = path.relative_to(directory)
            if any(part in (".git", "target", "compiled") for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError("fixture source symlink is not supported")
            selected.add(path.relative_to(repository).as_posix())
    return sorted(selected)


def selected_hashes(repository, paths):
    return {name: digest((repository / name).read_bytes()) for name in paths}


def rebase_manifests(repository, root):
    records = {}
    pattern = re.compile(r"\bpath\s*=\s*(\"[^\"\n]*\"|'[^'\n]*')")
    for path in root.rglob("Cargo.toml"):
        before = path.read_bytes()
        def replace(match):
            value = tomllib.loads("value = " + match.group(1))["value"]
            original = Path(value)
            if not original.is_absolute():
                return match.group(0)
            original = original.resolve()
            if not original.is_relative_to(repository):
                raise ValueError("absolute manifest path escapes product repository")
            return "path = " + json.dumps((root / original.relative_to(repository)).as_posix())
        after = pattern.sub(replace, before.decode()).encode()
        if after != before:
            path.write_bytes(after)
            records[path.relative_to(root).as_posix()] = {
                "original_sha256": digest(before), "rebased_sha256": digest(after)}
    return records


def deadline_counterfactual(root, instrument):
    path = root / "crates/shaar-p2p/src/carrier/relay/gate_factory.rs"
    original = path.read_bytes()
    guard = "if !matches!(record.state, RecordState::Established) && Instant::now() >= record.deadline {"
    changed = "if Instant::now() >= record.deadline {"
    text = instrument.replace_once(original.decode(), guard, changed)
    if instrument.replace_once(text, changed, guard).encode() != original:
        raise ValueError("deadline counterfactual changed more than its established exemption")
    path.write_bytes(text.encode())
    return {"original_sha256": digest(original), "counterfactual_sha256": digest(path.read_bytes()),
            "defect": "established admission deadline exemption removed only"}


def create(repository, metadata, root, relay_source, instrument, variant, scenario):
    if variant not in ("baseline", "counterfactual", "counterfactual-deadline"):
        raise ValueError("unknown Carrier fixture variant")
    paths = product_paths(repository, metadata)
    originals = selected_hashes(repository, paths)
    root.mkdir(parents=True, exist_ok=False)
    relay_relative = relay_source.relative_to(repository)
    for name in paths:
        relative = Path(name)
        if relative.is_relative_to(relay_relative):
            continue
        source = repository / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    relay_variant = "counterfactual" if variant == "counterfactual" else "baseline"
    relay_record = instrument.instrument(relay_source, root / relay_relative, relay_variant)
    owner_deadline = deadline_counterfactual(root, instrument) if variant == "counterfactual-deadline" else None
    manifest_rebases = rebase_manifests(repository, root)
    scenario_relative = scenario.relative_to(repository)
    scenario_target = root / scenario_relative
    if not scenario_target.is_file() or scenario_target.read_bytes() != scenario.read_bytes():
        raise ValueError("scenario must be a tracked, byte-preserved product fixture source")
    driver = root / "crates/shaar-p2p/src/carrier/driver/mod.rs"
    original_driver = driver.read_bytes()
    marker = b"mod carrier_protocol_fixture;"
    if marker in original_driver:
        raise ValueError("carrier protocol fixture was already injected")
    newline = "\r\n" if b"\r\n" in original_driver else "\n"
    suffix = (newline + "#[cfg(test)]" + newline + "#[path = "
              + json.dumps(scenario_target.as_posix()) + "]" + newline
              + "mod carrier_protocol_fixture;" + newline).encode()
    driver.write_bytes(original_driver + suffix)
    if driver.read_bytes()[:-len(suffix)] != original_driver:
        raise ValueError("driver injection changed existing source bytes")
    if originals != selected_hashes(repository, paths):
        raise ValueError("product source changed while copying the fixture")
    record = {
        "variant": variant,
        "product_source_sha256": originals,
        "fixture_source_sha256": hashes(root),
        "driver_original_sha256": digest(original_driver),
        "driver_injection_sha256": digest(suffix),
        "scenario_sha256": digest(scenario.read_bytes()),
        "relay_relative": relay_relative.as_posix(),
        "manifest_path_rebases": manifest_rebases,
        "owner_deadline_counterfactual": owner_deadline,
        "relay": relay_record,
    }
    return record, paths


def closure(metadata):
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [identity for identity, package in packages.items() if package["name"] in ROOTS]
    if len(roots) != len(ROOTS):
        raise ValueError("product proof roots are missing or ambiguous")
    found = set()
    pending = list(roots)
    while pending:
        identity = pending.pop()
        if identity in found:
            continue
        found.add(identity)
        pending.extend(dependency["pkg"] for dependency in nodes[identity]["deps"]
                       if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]))
    def key(identity):
        package = packages[identity]
        return package["name"], package["version"], package.get("source")
    result = {}
    for identity in found:
        node = nodes[identity]
        result[key(identity)] = (
            set(node["features"]),
            {(dependency["name"], key(dependency["pkg"]), kind["kind"], kind["target"])
             for dependency in node["deps"] for kind in dependency["dep_kinds"]
             if kind["kind"] != "dev"},
        )
    if len(result) != len(found):
        raise ValueError("ambiguous normalized product identities")
    return result


def verify(product, fixture, product_lock, root, relay_source):
    expected = closure(product)
    actual = closure(fixture)
    if expected != actual:
        raise ValueError("carrier fixture identities, features or non-dev edges differ")
    if (root / "Cargo.lock").read_bytes() != product_lock:
        raise ValueError("carrier fixture changed the product lock bytes")
    selected = [package for package in fixture["packages"] if package["name"] == "libp2p-relay"]
    if len(selected) != 1 or Path(selected[0]["manifest_path"]).resolve() != relay_source / "Cargo.toml":
        raise ValueError("fixture did not select its copied instrumented relay")
    return {"packages": len(expected), "exact_features_and_edges": True,
            "product_lock_sha256": digest(product_lock), "fixture_lock_sha256": digest(product_lock)}
