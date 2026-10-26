"""Prepare the reviewed resolver archive as data, without executing its code."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tomllib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("resolver_patch", HERE / "patch.py")
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)
VERSION = "0.26.3"
PACKAGE = f"hickory-resolver-{VERSION}"
DIGEST = "3f3da5255c95d5a716857d54b5b8f4e8d67c3484d3beaaaae2ce25063b3ba981"
LOCK_DIGEST = "f66318e14be75c418cd2e86705564bd4e6d6cfc6d7ef4ee9456fe91f0105791a"
TREE_DIGEST = "071dc3d22724e8b23dd61e15d05b17ca90fa3f8503dfa5eb6aeba59e56823f64"
VCS = "bd37cafbdd86112a6da32878f8c9bab22e14377e"
MAX_ARCHIVE = 2 * 1024 * 1024
PINS = {
    "Cargo.toml": "77f8bbd4fee5d6b9e5ae9930fe4df68c775858413d9743b112ce31f218e11e99",
    "Cargo.lock": LOCK_DIGEST,
    "LICENSE-APACHE": "6b9522191b8cb7126b2d214edd7f782d2ccd83c467e9c03b8af9e0bf903b49b4",
    "LICENSE-MIT": "dc470946f0a127507a9e577a20da1eb19eae0abc383b2be1f786f6427944f06c",
    "src/lib.rs": "c1568bed06f5807ade30705f15aa86b8eaac7f4aafc55d433dd4f691d008c4a1",
    "src/name_server.rs": "ddb6335e5859c92bf14e83a0f945f14d6b487a1932734101f988fdece0c3d7ea",
    "src/name_server_pool.rs": "cf41556017f8a1b5abd1315070b2d60b619e247eef3bb4136192c71f1f334b8e",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hashes(files):
    return {name: digest(data) for name, data in sorted(files.items())}


def recipe():
    return hashes({name: (HERE / name).read_bytes() for name in ("prepare.py", "patch.py")})


def archive_files(archive):
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("resolver archive exceeds reviewed size bound")
    if digest(archive.read_bytes()) != DIGEST:
        raise ValueError("resolver archive checksum mismatch")
    files = {}
    total = 0
    with tarfile.open(archive) as source:
        members = source.getmembers()
        if len(members) > 128:
            raise ValueError("resolver archive entry bound exceeded")
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or ":" in member.name or not path.parts or path.parts[0] != PACKAGE
                    or path.as_posix() != member.name.rstrip("/") or len(path.parts) > 8
                    or not (member.isfile() or member.isdir())):
                raise ValueError("unexpected resolver archive entry")
            if member.isdir():
                continue
            name = path.relative_to(PACKAGE).as_posix()
            total += member.size
            if total > 4 * MAX_ARCHIVE or name in files:
                raise ValueError("resolver archive expansion or duplicate entry")
            files[name] = source.extractfile(member).read()
    return files


def originals(files):
    manifest = tomllib.loads(files["Cargo.toml"].decode())
    if (manifest["package"]["name"], manifest["package"]["version"], manifest["package"]["license"]) != (
            "hickory-resolver", VERSION, "MIT OR Apache-2.0"):
        raise ValueError("resolver package identity or license changed")
    if json.loads(files[".cargo_vcs_info.json"]) != {"git": {"sha1": VCS}, "path_in_vcs": "crates/resolver"}:
        raise ValueError("resolver source provenance changed")
    for name, expected in PINS.items():
        if digest(files[name]) != expected:
            raise ValueError(f"resolver original source bytes changed: {name}")
    if digest(json.dumps(hashes(files), sort_keys=True, separators=(",", ":")).encode()) != TREE_DIGEST:
        raise ValueError("resolver original source tree changed")


def transform(files):
    changed = patch.transform(files)
    originals(files)
    if patch.reverse(dict(files, **changed)) != files:
        raise ValueError("resolver original-byte reverse mismatch")
    changed["Cargo.toml"] = files["Cargo.toml"] + b"\n[workspace]\n"
    changed["src/lib.rs"] = b"#![forbid(unsafe_code)]\n" + files["src/lib.rs"]
    return changed


def receipt(original, prepared):
    return {
        "package": "hickory-resolver", "version": VERSION, "archive_sha256": DIGEST,
        "archive_lock_sha256": LOCK_DIGEST, "vcs_revision": VCS, "license": "MIT OR Apache-2.0",
        "recipe_files": recipe(), "original_files": hashes(original), "prepared_files": hashes(prepared),
        "changed_files": sorted(name for name in prepared if prepared[name] != original.get(name)),
        "fixture_instrumentation": False, "resolver_lifecycle_acceptance": False,
    }


def write_tree(files, destination):
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def prepare(archive, destination):
    original = archive_files(archive)
    prepared = dict(original, **transform(original))
    record = receipt(original, prepared)
    destination.mkdir(parents=True, exist_ok=False)
    root = destination / PACKAGE
    write_tree(prepared, root)
    (destination / "provenance.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return root


def verify(root):
    record = json.loads((root.parent / "provenance.json").read_text(encoding="utf-8"))
    paths = list(root.rglob("*"))
    if root.is_symlink() or any(path.is_symlink() for path in paths):
        raise ValueError("resolver prepared source link")
    files = {p.relative_to(root).as_posix(): p.read_bytes() for p in paths if p.is_file()}
    if hashes(files) != record["prepared_files"]:
        raise ValueError("resolver prepared source drift")
    restored = patch.reverse(files)
    if not restored["Cargo.toml"].endswith(b"\n[workspace]\n") or not restored["src/lib.rs"].startswith(b"#![forbid(unsafe_code)]\n"):
        raise ValueError("resolver preparation boundary changed")
    restored["Cargo.toml"] = restored["Cargo.toml"].removesuffix(b"\n[workspace]\n")
    restored["src/lib.rs"] = restored["src/lib.rs"].removeprefix(b"#![forbid(unsafe_code)]\n")
    originals(restored)
    expected = dict(restored, **transform(restored))
    if files != expected or record != receipt(restored, expected):
        raise ValueError("resolver prepared provenance mismatch")
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    print(prepare(args.archive, args.destination))


if __name__ == "__main__":
    main()
