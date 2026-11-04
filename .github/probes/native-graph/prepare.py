# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Prepare pinned native graph source trees from local archives."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tomllib
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "native-graph-proof"))
REPO = HERE.parents[2]
REVISION = "0f5f547cc65514e4537d4e66f776319ea8e30a2e"
ADAPTER_SHA = "035d35f41362c79d43f44dc1d5cdaf9c8c718fa3781fd09cf458b7b47cb014ba"
ADAPTER_TOP = f"iroh-address-lookups-{REVISION}"
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_ENTRIES = 512
MAX_MEMBER = 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024
FUTURE_SHA = "e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe"
FUTURE_TOP = "n0-future-0.3.2"
FUTURE_TARGET = 'cfg(not(all(target_family = "wasm", target_os = "unknown")))'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def future_transform(files: dict[str, bytes]) -> dict[str, bytes]:
    """Move Tokio's native runtime test feature into a dev dependency."""
    name = "Cargo.toml"
    original = files.get(name)
    if original is None:
        raise ValueError("future manifest missing")
    old_block = (b"[target.'" + FUTURE_TARGET.encode() + b"'.dependencies.tokio]\n"
                 b'version = "1.28"\nfeatures = [\n    "rt",\n    "time",\n    "macros",\n    "test-util",\n]\n')
    if original.count(old_block) != 1:
        raise ValueError("future native Tokio dependency block mismatch")
    dev_header = (b"[target.'" + FUTURE_TARGET.encode()
                  + b"'.dev-dependencies.tokio]")
    if dev_header in original:
        raise ValueError("future native Tokio dev dependency header already exists")
    new_block = (b"[target.'" + FUTURE_TARGET.encode() + b"'.dependencies.tokio]\n"
                 b'version = "1.28"\nfeatures = [\n    "rt",\n    "time",\n    "macros",\n]\n')
    dev_block = (b"\n" + dev_header + b"\n"
                 b'version = "1.28"\nfeatures = ["test-util"]\n')
    return {name: original.replace(old_block, new_block + dev_block, 1)}


def future_reverse(original: dict[str, bytes], changed: dict[str, bytes]) -> dict[str, bytes]:
    """Validate and reverse only the exact future manifest transformation."""
    if set(changed) != {"Cargo.toml"}:
        raise ValueError("future changed paths are not Cargo.toml only")
    expected = future_transform(original)["Cargo.toml"]
    if changed["Cargo.toml"] != expected:
        raise ValueError("future manifest differs beyond exact transformation")
    old_block = (b"[target.'" + FUTURE_TARGET.encode() + b"'.dependencies.tokio]\n"
                 b'version = "1.28"\nfeatures = [\n    "rt",\n    "time",\n    "macros",\n    "test-util",\n]\n')
    new_block = (b"[target.'" + FUTURE_TARGET.encode() + b"'.dependencies.tokio]\n"
                 b'version = "1.28"\nfeatures = [\n    "rt",\n    "time",\n    "macros",\n]\n')
    dev_header = (b"[target.'" + FUTURE_TARGET.encode()
                  + b"'.dev-dependencies.tokio]")
    combined = (new_block + b"\n" + dev_header + b"\n"
                b'version = "1.28"\nfeatures = ["test-util"]\n')
    recovered = dict(original)
    if changed["Cargo.toml"].count(combined) != 1:
        raise ValueError("future transformed block mismatch")
    recovered["Cargo.toml"] = changed["Cargo.toml"].replace(combined, old_block, 1)
    if recovered != original:
        raise ValueError("future reversal did not recover original files")
    return recovered


def hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: sha(data) for name, data in sorted(files.items())}


def fixed_module(name: str, path: Path):
    if path.resolve() != path or not path.is_file() or path.is_symlink():
        raise ValueError(f"fixed recipe unavailable: {name}")
    spec = importlib.util.spec_from_file_location("_native_graph_" + name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import fixed recipe: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _archive_files(archive: Path, expected_sha: str, top: str, label: str) -> dict[str, bytes]:
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError(f"{label} archive identity/size mismatch")
    if sha(archive.read_bytes()) != expected_sha:
        raise ValueError(f"{label} archive SHA-256 mismatch")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    file_keys: set[str] = set()
    dir_keys: set[str] = set()
    total = 0
    with tarfile.open(archive, "r:gz") as source:
        for index, member in enumerate(source, 1):
            path = PurePosixPath(member.name)
            if (index > MAX_ENTRIES or path.is_absolute() or ".." in path.parts or "." in path.parts
                    or "\\" in member.name or re.match(r"^[A-Za-z]:", member.name)
                    or any(":" in part for part in path.parts) or not path.parts
                    or path.parts[0] != top or len(path.parts) > 16
                    or not (member.isfile() or member.isdir())):
                raise ValueError(f"unsafe {label} archive member")
            name = path.relative_to(top).as_posix()
            if name == ".":
                continue
            key = name.casefold()
            if key in seen:
                raise ValueError(f"duplicate {label} archive path")
            parents = {p.as_posix().casefold() for p in PurePosixPath(name).parents if str(p) != "."}
            if member.isdir():
                if key in file_keys or parents & file_keys:
                    raise ValueError(f"{label} file/directory collision")
                dir_keys.add(key)
                seen.add(key)
                continue
            if parents & file_keys or any(item.startswith(key + "/") for item in file_keys) or key in dir_keys:
                raise ValueError(f"{label} file/directory prefix collision")
            if member.size < 0 or member.size > MAX_MEMBER:
                raise ValueError(f"{label} member size bound exceeded")
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError(f"{label} expansion bound exceeded")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError(f"{label} archive member unreadable")
            data = stream.read(MAX_MEMBER + 1)
            if len(data) != member.size:
                raise ValueError(f"{label} archive member length mismatch")
            seen.add(key)
            file_keys.add(key)
            files[name] = data
    return files


def adapter_archive(archive: Path) -> dict[str, bytes]:
    files = _archive_files(archive, ADAPTER_SHA, ADAPTER_TOP, "adapter")
    try:
        manifest = tomllib.loads(files["iroh-mainline-address-lookup/Cargo.toml"].decode("utf-8"))
        package = manifest["package"]
    except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("adapter package manifest invalid") from exc
    if (package.get("name"), package.get("version")) != ("iroh-mainline-address-lookup", "0.6.1"):
        raise ValueError("adapter package identity mismatch")
    return files


def future_archive(archive: Path) -> dict[str, bytes]:
    files = _archive_files(archive, FUTURE_SHA, FUTURE_TOP, "future")
    try:
        manifest = tomllib.loads(files["Cargo.toml"].decode("utf-8"))
        package = manifest["package"]
    except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("future package manifest invalid") from exc
    if (package.get("name"), package.get("version")) != ("n0-future", "0.3.2"):
        raise ValueError("future package identity mismatch")
    return files


def verify_future_provenance(archive: Path, root: Path) -> dict:
    original = future_archive(archive)
    changed = future_transform(original)
    prepared = {**original, **changed}
    if future_reverse(original, changed) != original:
        raise ValueError("future reverse check failed")
    source = root / "target/native-graph/n0-future-0.3.2"
    if any(path.is_symlink() for path in (root, root/'target', root/'target/native-graph', source)):
        raise ValueError('linked future provenance path')
    if inventory(source) != hashes(prepared):
        raise ValueError("prepared source inventory mismatch: future")
    recipe = {".github/probes/native-graph/prepare.py": sha((HERE / "prepare.py").read_bytes())}
    expected = {"package": "n0-future", "version": "0.3.2",
                "source": {"kind": "registry-archive", "archive_sha256": FUTURE_SHA},
                "archive_sha256": FUTURE_SHA, "recipe_files": recipe,
                "original_files": hashes(original), "prepared_files": hashes(prepared),
                "changed_files": sorted(name for name in prepared if original.get(name) != prepared[name])}
    receipt_path = source.parent / (source.name + ".provenance.json")
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("prepared receipt missing or linked: future")
    raw = receipt_path.read_bytes()
    try:
        receipt = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("prepared receipt invalid: future") from exc
    if receipt != expected:
        raise ValueError("prepared receipt mismatch: future")
    return {"prepared_manifest_path": str(source / "Cargo.toml"),
            "prepared_manifest_sha256": sha(prepared["Cargo.toml"]),
            "prepared_receipt_path": str(receipt_path),
            "prepared_receipt_sha256": sha(raw), "archive_sha256": FUTURE_SHA,
            "recipe_files": expected["recipe_files"]}


def adapter_transform(files: dict[str, bytes]) -> dict[str, bytes]:
    """Add the isolated package's workspace link without changing upstream bytes."""
    root_name = "Cargo.toml"
    root_bytes = files.get(root_name)
    if root_bytes is None:
        raise ValueError("adapter workspace manifest missing")
    try:
        root = tomllib.loads(root_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("invalid adapter workspace manifest") from exc
    workspace = root.get("workspace")
    selected = "iroh-mainline-address-lookup/Cargo.toml"
    if (not isinstance(workspace, dict) or selected.rsplit("/", 1)[0] not in workspace.get("members", [])
            or not isinstance(workspace.get("lints"), dict) or not workspace["lints"]):
        raise ValueError("adapter workspace member/lints declaration missing")
    original = files.get(selected)
    if original is None:
        raise ValueError("selected adapter manifest missing")
    try:
        parsed = tomllib.loads(original.decode('utf-8'))
        package = parsed.get('package')
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("invalid selected adapter manifest") from exc
    if not isinstance(package, dict) or parsed.get('lints', {}).get('workspace') is not True or "workspace" in package:
        raise ValueError("selected adapter package workspace/lints mismatch")
    if original.count(b'[package]\n') != 1:
        raise ValueError("selected adapter manifest must have one package header")
    position = original.index(b'[package]\n') + len(b'[package]\n')
    prepared = original[:position] + b'workspace = ".."\n' + original[position:]
    try:
        parsed = tomllib.loads(prepared.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("prepared selected adapter manifest is invalid") from exc
    if parsed.get("package", {}).get("workspace") != "..":
        raise ValueError("prepared package workspace is not scalar path")
    return {selected: prepared}


def adapter_reverse(original: dict[str, bytes], changed: dict[str, bytes]) -> dict[str, bytes]:
    """Validate the exact insertion and recover the byte-identical source map."""
    selected = "iroh-mainline-address-lookup/Cargo.toml"
    if set(changed) != {selected}:
        raise ValueError("adapter changed paths are not the selected manifest only")
    expected = adapter_transform(original)[selected]
    if changed[selected] != expected:
        raise ValueError("adapter selected manifest differs beyond exact insertion")
    recovered = dict(original)
    recovered[selected] = changed[selected].replace(b'workspace = ".."\n', b"", 1)
    if recovered != original:
        raise ValueError("adapter reversal did not recover original files")
    return recovered


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    root.mkdir(parents=True)
    for name, data in files.items():
        path = root.joinpath(*PurePosixPath(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def inventory(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in generated source tree")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sha(path.read_bytes())
    return result


def recipe_map(module, extras: tuple[Path, ...] = ()) -> dict[str, str]:
    result = dict(module.recipe())
    for path in extras:
        result[str(path.relative_to(REPO)).replace("\\", "/")] = sha(path.read_bytes())
    result[".github/probes/native-graph/prepare.py"] = sha((HERE / "prepare.py").read_bytes())
    return dict(sorted(result.items()))


def build_expected(archives: dict[str, Path], modules: dict[str, object]):
    adapter = adapter_archive(archives["adapter"])
    adapter_changed = adapter_transform(adapter)
    if adapter_reverse(adapter, adapter_changed) != adapter:
        raise ValueError("adapter reverse check failed")
    adapter_prepared = dict(adapter)
    adapter_prepared.update(adapter_changed)
    future = future_archive(archives["future"])
    future_changed = future_transform(future)
    if future_reverse(future, future_changed) != future:
        raise ValueError("future reverse check failed")
    future_prepared = dict(future)
    future_prepared.update(future_changed)
    mainline = modules["mainline"].archive_files(archives["mainline"])
    mainline_prepared = dict(mainline)
    mainline_prepared.update(modules["mainline"].transform(mainline))
    bencode = modules["bencode"].archive_files(archives["bencode"])
    bencode_prepared = dict(bencode)
    bencode_prepared.update(modules["bencode"].transform(bencode))
    dns = modules["dns"].archive_files(archives["dns"])
    dns_changed = modules["dns"].transform(dns)
    modules["dns"].reverse(dns, dns_changed)
    dns_prepared = dict(dns)
    dns_prepared.update(dns_changed)
    return {"adapter": ("adapter", adapter, adapter_prepared, ADAPTER_SHA),
            "future": ("n0-future-0.3.2", future, future_prepared, FUTURE_SHA),
            "mainline": ("n0-mainline-0.7.0", mainline, mainline_prepared, modules["mainline"].ARCHIVE_SHA256),
            "bencode": ("serde_bencode-0.2.4", bencode, bencode_prepared, modules["bencode"].ARCHIVE_SHA256),
            "dns": ("iroh-dns-1.3.0", dns, dns_prepared, modules["dns"].ARCHIVE_SHA256)}


def verify_all(archives: dict[str, Path], destination: Path) -> dict[str, Path]:
    mainline_path = REPO / ".github/scripts/p2p/discovery/mainline/prepare.py"
    bencode_path = REPO / ".github/scripts/p2p/discovery/mainline/ci/bencode/prepare.py"
    dns_path = REPO / ".github/scripts/p2p/discovery/mainline/ci/publication/prepare.py"
    modules = {"mainline": fixed_module("mainline", mainline_path),
               "bencode": fixed_module("bencode", bencode_path),
               "dns": fixed_module("dns", dns_path)}
    expected = build_expected(archives, modules)
    roots: dict[str, Path] = {}
    for name, (relative, original, prepared, archive_sha) in expected.items():
        root = destination / relative
        if inventory(root) != hashes(prepared):
            raise ValueError(f"prepared source inventory mismatch: {name}")
        receipt_path = root.parent / (root.name + ".provenance.json")
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise ValueError(f"prepared receipt missing or linked: {name}")
        if name == "adapter":
            recipe = {".github/probes/native-graph/prepare.py": sha((HERE / "prepare.py").read_bytes())}
            source = {"kind": "git-archive", "repository": "https://github.com/n0-computer/iroh-address-lookups", "revision": REVISION}
            package = "iroh-mainline-address-lookup"; version = "0.6.1"
        elif name == "future":
            recipe = {".github/probes/native-graph/prepare.py": sha((HERE / "prepare.py").read_bytes())}
            source = {"kind": "registry-archive", "archive_sha256": archive_sha}
            package = "n0-future"; version = "0.3.2"
        elif name == "mainline":
            recipe = recipe_map(modules[name]); source = {"kind": "registry-archive", "archive_sha256": archive_sha}
            package = "n0-mainline"; version = "0.7.0"
        elif name == "bencode":
            recipe = recipe_map(modules[name]); source = {"kind": "registry-archive", "archive_sha256": archive_sha}
            package = "serde_bencode"; version = "0.2.4"
        else:
            recipe = recipe_map(modules[name]); source = {"kind": "registry-archive", "archive_sha256": archive_sha}
            package = "iroh-dns"; version = "1.3.0"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        changed = sorted(name for name in prepared if original.get(name) != prepared[name])
        expected_receipt = {"package": package, "version": version, "source": source,
                            "archive_sha256": archive_sha, "recipe_files": recipe,
                            "original_files": hashes(original), "prepared_files": hashes(prepared),
                            "changed_files": changed}
        if receipt != expected_receipt:
            raise ValueError(f"prepared receipt mismatch: {name}")
        roots[name] = root / "iroh-mainline-address-lookup" if name == "adapter" else root
    return roots


def prepare_all(archives: dict[str, Path], destination: Path) -> dict[str, Path]:
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("output root must be new and parent must exist")
    paths = {"mainline": REPO / ".github/scripts/p2p/discovery/mainline/prepare.py",
             "bencode": REPO / ".github/scripts/p2p/discovery/mainline/ci/bencode/prepare.py",
             "dns": REPO / ".github/scripts/p2p/discovery/mainline/ci/publication/prepare.py"}
    modules = {name: fixed_module(name, path) for name, path in paths.items()}
    expected = build_expected(archives, modules)
    destination.mkdir()
    try:
        for name, (relative, original, prepared, archive_sha) in expected.items():
            root = destination / relative
            write_tree(root, prepared)
            if name == "adapter":
                recipe = {".github/probes/native-graph/prepare.py": sha((HERE / "prepare.py").read_bytes())}
                source = {"kind": "git-archive", "repository": "https://github.com/n0-computer/iroh-address-lookups", "revision": REVISION}
                package = "iroh-mainline-address-lookup"
                version = "0.6.1"
            elif name == "future":
                recipe = {".github/probes/native-graph/prepare.py": sha((HERE / "prepare.py").read_bytes())}
                source = {"kind": "registry-archive", "archive_sha256": archive_sha}
                package = "n0-future"
                version = "0.3.2"
            else:
                recipe = recipe_map(modules[name]); source = {"kind": "registry-archive", "archive_sha256": archive_sha}
                package, version = {"mainline": ("n0-mainline", "0.7.0"), "bencode": ("serde_bencode", "0.2.4"), "dns": ("iroh-dns", "1.3.0")}[name]
            receipt = {"package": package, "version": version, "source": source,
                       "archive_sha256": archive_sha, "recipe_files": recipe,
                       "original_files": hashes(original), "prepared_files": hashes(prepared),
                       "changed_files": sorted(item for item in prepared if original.get(item) != prepared[item])}
            (root.parent / (root.name + ".provenance.json")).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return verify_all(archives, destination)
    except BaseException:
        import shutil
        shutil.rmtree(destination)
        raise


class AuxiliaryProbeShapeTests(unittest.TestCase):
    def test_known_nested_probe_and_declared_target_rejection(self):
        manifest = Path('/registry/proc-macro2').resolve()
        target = Path('/tmp/aux').resolve()
        raw = {
            'package_name': 'proc-macro2',
            'package_version': '1.0.107',
            'kind': 'compile',
            'exit_code': 1,
            'launch_error': None,
            'manifest_dir': str(manifest),
            'cwd': str(manifest),
            'args': [
                '--cfg=procmacro2_build_probe',
                '--edition=2021',
                '--crate-name=proc_macro2',
                '--crate-type=lib',
                '--cap-lints=allow',
                '--emit=dep-info,metadata',
                '--out-dir', str(target / 'debug/build/proc-macro2-abc/out/probe'),
                'src/probe/proc_macro_span.rs',
                '--target', 'x86_64-unknown-linux-gnu',
            ],
            'outputs': [],
            'snapshots': [],
        }
        actualsha = '985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9'
        package = {
            'id': 'proc',
            'name': 'proc-macro2',
            'version': '1.0.107',
            'source': 'registry+https://github.com/rust-lang/crates.io-index',
            'manifest_path': str(manifest / 'Cargo.toml'),
            'targets': [
                {'kind': ['custom-build'], 'src_path': str(manifest / 'build.rs')},
            ],
        }
        checksums = {'proc': actualsha}
        result = auxiliary_probe_shape(
            raw, target, 'x86_64-unknown-linux-gnu', [package], checksums)
        self.assertIsNotNone(result)
        self.assertEqual(result['source'], 'src/probe/proc_macro_span.rs')
        package['targets'].append({'kind': ['lib'], 'src_path': str(manifest / 'src/probe/proc_macro_span.rs')})
        self.assertIsNone(auxiliary_probe_shape(
            raw, target, 'x86_64-unknown-linux-gnu', [package], checksums))



def auxiliary_probe_shape(raw, target_dir, host, packages=None, checksums=None):
    """Prove an exact, known auxiliary build-script compiler invocation."""
    known = {
        ("proc-macro2", "1.0.107"): "985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9",
        ("thiserror", "1.0.69"): "b6aaf5339b578ea85b50e080feb250a3e8ae8cfcdff9a461c9ec2904bc923f52",
        ("thiserror", "2.0.21"): "09e52cb86a36cede5cb101bf8908837b3e4c6e5e59fe7fd85c23fb56200d189e",
        ("anyhow", "1.0.104"): "330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470",
    }
    try:
        name, version = raw["package_name"], raw["package_version"]
        checksum = known[(name, version)]
    except (KeyError, TypeError):
        return None
    if packages is not None:
        matches = [p for p in packages if p.get("name") == name and p.get("version") == version and Path(p.get('manifest_path', '')).parent == Path(raw.get('manifest_dir', ''))]
        if len(matches) != 1:
            return None
        package = matches[0]
        if package.get("source") != "registry+https://github.com/rust-lang/crates.io-index" or (checksums or {}).get(package.get("id")) != checksum:
            return None
        if not any(t.get("kind") == ["custom-build"] for t in package.get("targets", [])):
            return None
        sources = [t.get("src_path") for t in package.get("targets", [])]
    else:
        return None
    if (raw.get("kind") != "compile" or raw.get("launch_error") is not None
            or raw.get("exit_code") not in (0, 1)):
        return None
    manifest = Path(raw.get("manifest_dir", ""))
    cwd = Path(raw.get("cwd", ""))
    if not manifest.is_absolute() or ".." in manifest.parts or cwd != manifest:
        return None
    args = raw.get("args")
    if not isinstance(args, list):
        return None
    if name == "proc-macro2":
        cfg, edition, crate = "--cfg=procmacro2_build_probe", "2021", "proc_macro2"
        source_set = {"src/probe/proc_macro_span.rs", "src/probe/proc_macro_span_location.rs", "src/probe/proc_macro_span_file.rs"}
    elif name == "anyhow":
        cfg, edition, crate, source_set = "--cfg=anyhow_build_probe", "2018", "anyhow", {"src/nightly.rs"}
    else:
        cfg, edition, crate, source_set = None, "2018", "thiserror", {"build/probe.rs"}
    prefix = ([cfg] if cfg else []) + [f"--edition={edition}", f"--crate-name={crate}", "--crate-type=lib", "--cap-lints=allow", "--emit=dep-info,metadata", "--out-dir"]
    if len(args) != len(prefix) + 4 or args[:len(prefix)] != prefix:
        return None
    out, source, target_flag, target = args[len(prefix):]
    if isinstance(host, str) and 'windows' in host:
        source = source.replace('\\', '/')
    if (source not in source_set or target_flag != "--target" or target != host
            or any(Path(src) == manifest / source for src in sources if isinstance(src, str))):
        return None
    target_dir = Path(target_dir)
    if not target_dir.is_absolute() or ".." in target_dir.parts:
        return None
    parent = target_dir / host / 'debug/build' if name == 'thiserror' else target_dir / 'debug/build'
    out_path = Path(out)
    if not out_path.is_absolute() or '..' in out_path.parts or out_path.name != 'probe' or out_path.parent.name != 'out':
        return None
    candidate = out_path.parent.parent
    if candidate.parent != parent or not re.fullmatch(re.escape(name) + r'-[0-9a-f]+', candidate.name):
        return None
    return {"source": source, "package": name, "version": version, "checksum": checksum,
            "crate": crate, "package_id": package["id"],
            "context": "target" if name == "thiserror" else "host",
            "status": "success" if raw["exit_code"] == 0 else "failure",
            "out_dir": out, "build_dir": str(candidate)}


def audit_compiler_units(proof, packages, buildbytes, recipebytes):
    """Preserve the prepare API while delegating compiler-unit auditing to the fixture."""
    from features import audit_compiler_units as audit

    return audit(proof, packages, buildbytes, recipebytes)


def audit_auxiliary(probes, proof, packages, cargo, messages, normalized, unit_by_output, stable_identity):
    """Validate raw auxiliary probes against package and Cargo build evidence."""
    from features import _need, _canonical

    result = []
    seen = set()
    env = proof['compiler_capture']['context']['env']
    wrapper = proof['compiler_capture']['wrapper']
    for raw, original_shape in probes:
        shape = auxiliary_probe_shape(
            raw, env['CARGO_TARGET_DIR'], wrapper['target'], packages,
            proof.get('lock_checksums', {}))
        _need(shape is not None and shape == original_shape, "auxiliary probe shape changed")
        pkg = next(p for p in packages if p.get('id') == shape['package_id'])
        pid = pkg['id']
        artifacts = [a for a in cargo if a.get('package_id') == pid and
                     a.get('target', {}).get('kind') == ['custom-build'] and
                     a.get('executable') is None]
        _need(len(artifacts) == 1, "auxiliary build artifact is missing or duplicated")
        owned = unit_by_output.get(id(artifacts[0]))
        _need(owned and owned[1].get('id') == pid and owned[2].get('kind') == ['custom-build'] and
              owned[0].get('context') == 'host', "auxiliary build script ownership mismatch")
        executed = [m for m in messages if m.get('package_id') == pid and
                    m.get('out_dir') == str(Path(shape['build_dir']) / 'out') and
                    m.get('reason') == 'build-script-executed']
        _need(len(executed) == 1, "auxiliary build-script execution mismatch")
        expected = [] if raw['exit_code'] else [
            str(Path(shape['out_dir']) / f"lib{shape['crate']}.rmeta"),
            str(Path(shape['out_dir']) / f"{shape['crate']}.d")]
        _need(raw['outputs'] == expected, "auxiliary output list mismatch")
        semantic = (stable_identity(pkg), shape['source'], shape['context'])
        _need(semantic not in seen, "duplicate auxiliary probe")
        seen.add(semantic)
        result.append({"package": stable_identity(pkg), "kind": ["auxiliary-build-probe"],
                       "source": shape['source'], "context": shape['context'],
                       "triple": wrapper['target'], "status": raw['exit_code'],
                       "features": [], "owner": owned[0]['sha256'],
                       "outputs": sorted(Path(path).name for path in expected)})
    return sorted(result, key=lambda item: _canonical(item))


def cargo_output_aliases(unit, artifact, package, target_dir, host, root_manifest):
    from cargo_aliases import cargo_output_aliases as aliases
    return aliases(unit, artifact, package, target_dir, host, root_manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("adapter", "mainline", "bencode", "dns", "future"):
        parser.add_argument("--" + name + "-archive", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    names = ("adapter", "mainline", "bencode", "dns", "future")
    roots = prepare_all({name: getattr(args, name + "_archive") for name in names}, args.destination)
    for name, root in roots.items():
        print(f"{name}={root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
