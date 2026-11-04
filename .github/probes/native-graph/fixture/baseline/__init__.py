# SPDX-License-Identifier: MIT OR Apache-2.0
"""CI-only extraction of the pinned baseline source archive."""

import hashlib
import io
import json
import os
import tarfile
import tomllib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import graph as graph_module

BASE = "67e10f3d836b48b954e9f82cc9ffb1d12bb1d71f"
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_ENTRIES = 20_000
INPUTS = ("Cargo.toml", "crates/shaar/Cargo.toml", "Cargo.lock")


def capture_inventory(directory):
    directory = Path(directory)
    records = []
    try:
        if directory.is_symlink():
            raise OSError(f"symlink directory: {directory}")
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise OSError(f"symlink entry: {path}")
            if path.is_file():
                data = path.read_bytes()
                records.append({"name": path.relative_to(directory).as_posix(),
                                "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    except OSError as error:
        return [{"error": str(error)}]
    return records


def materialize(repo, destination, run):
    """Extract BASE via git archive; run(argv) returns stdout bytes."""
    commit = run(["git", "rev-parse", BASE]).decode("ascii").strip()
    if commit != BASE:
        raise ValueError("baseline commit does not match pin")
    archive = run(["git", "archive", "--format=tar", BASE])
    if not isinstance(archive, bytes) or len(archive) > MAX_ARCHIVE:
        raise ValueError("baseline archive is invalid or too large")

    root = os.path.abspath(os.fspath(destination))
    if os.path.exists(root):
        raise ValueError("destination must be fresh")
    os.makedirs(root)

    seen = set()
    records = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        members = tar.getmembers()
        if len(members) > MAX_ENTRIES:
            raise ValueError("too many archive entries")
        for member in members:
            name = member.name.rstrip("/") if member.isdir() else member.name
            parts = name.split("/")
            if (not name or name.startswith("/") or "\\" in name
                    or any(p in ("", ".", "..") or ":" in p for p in parts)):
                raise ValueError("unsafe archive path")
            key = "/".join(parts).casefold()
            if key in seen:
                raise ValueError("case-folding archive path collision")
            seen.add(key)
            if not (member.isdir() or member.isreg()):
                raise ValueError("archive contains unsupported entry type")
            records.append((member, parts))

        for member, parts in records:
            path = os.path.join(root, *parts)
            if member.isdir():
                os.makedirs(path, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise ValueError("missing archive file data")
            with source, open(path, "xb") as output:
                output.write(source.read())

    input_hashes = {}
    for name in INPUTS:
        path = os.path.join(root, *name.split("/"))
        with open(path, "rb") as source:
            input_hashes[name] = hashlib.sha256(source.read()).hexdigest()
    return {
        "commit": commit,
        "source_root": root,
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "input_hashes": input_hashes,
    }


def prepare_sources(repo, root, run):
    """Prepare six fixed source archives using the supplied command runner."""
    repo = Path(repo)
    root = Path(root)
    (root / "target").mkdir(parents=True, exist_ok=True)
    (root / "target" / "p2p").mkdir(parents=True, exist_ok=True)
    scripts = root / ".github" / "scripts"
    commands = (
        [
            sys.executable,
            "-I",
            str(scripts / "backend" / "prepare.py"),
            "--noq-archive",
            str(repo / "target/backend-archives/noq/noq-proto.crate"),
            "--iroh-archive",
            str(repo / "target/backend-archives/iroh/iroh.crate"),
            "--runtime-archive",
            str(repo / "target/backend-archives/runtime/noq.crate"),
            "--lock",
            str(root / ".github/probes/iroh-paths/Cargo.lock"),
            "--destination",
            str(root / "target/backend"),
        ],
        [
            sys.executable,
            "-I",
            str(scripts / "p2p" / "prepare.py"),
            "--archive",
            str(repo / "target/p2p/relay-archive/relay.crate"),
            "--destination",
            str(root / "target/p2p/relay"),
            "--swarm-archive",
            str(repo / "target/p2p/swarm-archive/swarm.crate"),
            "--swarm-destination",
            str(root / "target/p2p/swarm"),
        ],
        [
            sys.executable,
            "-I",
            str(scripts / "p2p/discovery/simple_dns/prepare.py"),
            "prepare",
            "--archive",
            str(repo / "target/p2p/simple-dns-archive/simple-dns.crate"),
            "--destination",
            str(root / "target/p2p/simple-dns"),
        ],
        [
            sys.executable,
            "-I",
            str(scripts / "p2p/discovery/dns/prepare.py"),
            "prepare",
            "--archive",
            str(repo / "target/p2p/dns-archive/dns.crate"),
            "--destination",
            str(root / "target/p2p/dns"),
        ],
        [
            sys.executable,
            "-I",
            str(scripts / "p2p/discovery/resolver/prepare.py"),
            "--archive",
            str(repo / "target/p2p/resolver-archive/resolver.crate"),
            "--destination",
            str(root / "target/p2p/resolver"),
        ],
        [
            sys.executable,
            "-I",
            str(scripts / "p2p/discovery/kad/kad.py"),
            "prepare",
            "--archive",
            str(repo / "target/p2p/kad-archive/kad.crate"),
            "--destination",
            str(root / "target/p2p/kad"),
        ],
    )
    for command in commands:
        run(command)


def apply_route(root):
    """Apply the isolated adapter route and return manifest hashes."""
    root = Path(root)
    manifests = (root / "Cargo.toml", root / "crates" / "shaar" / "Cargo.toml")
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in manifests}
    cargo = manifests[0]
    text = cargo.read_text(encoding="utf-8")
    parsed = tomllib.loads(text)
    workspace = parsed.get("workspace", {})
    if "exclude" in workspace:
        raise ValueError("baseline workspace already has exclusions")
    if text.count("[workspace]\n") != 1:
        raise ValueError("expected unique workspace section")
    text = text.replace(
        "[workspace]\n",
        '[workspace]\nexclude = ["target/native-graph/adapter/iroh-mainline-address-lookup"]\n',
        1,
    )
    if tomllib.loads(text).get("workspace", {}).get("exclude") != [
        "target/native-graph/adapter/iroh-mainline-address-lookup"
    ]:
        raise ValueError("failed to set exact workspace exclusion")
    patches = (
        'n0-future = { path = "target/native-graph/n0-future-0.3.2", version = "=0.3.2" }',
        'n0-mainline = { path = "target/native-graph/n0-mainline-0.7.0", version = "=0.7.0" }',
        'serde_bencode = { path = "target/native-graph/serde_bencode-0.2.4", version = "=0.2.4" }',
        'iroh-dns = { path = "target/native-graph/iroh-dns-1.3.0", version = "=1.3.0" }',
    )
    if any(line in text for line in patches):
        raise ValueError("native graph patch already present")
    if "[patch.crates-io]" not in text:
        raise ValueError("root crates.io patch section missing")
    cargo.write_text(text.rstrip() + "\n" + "\n".join(patches) + "\n", encoding="utf-8")
    sdk = manifests[1]
    sdk_text = sdk.read_text(encoding="utf-8")
    original = 'iroh-dns = "=1.3.0"'
    replacement = original + '\niroh-mainline-address-lookup = { path = "../../target/native-graph/adapter/iroh-mainline-address-lookup", version = "=0.6.1" }\nn0-mainline = { version = "=0.7.0" }'
    if sdk_text.count(original) != 1:
        raise ValueError("expected unique SDK iroh-dns pin")
    sdk.write_text(sdk_text.replace(original, replacement, 1), encoding="utf-8")
    after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in manifests}
    return {"before": before, "after": after}



def validate_wrapper_records(proof, wrapper):
    """Validate the five fixed compiler-wrapper probe receipts and artifacts."""
    records = wrapper.get("records") if isinstance(wrapper, dict) else None
    if not isinstance(records, list) or len(records) != 5:
        raise ValueError("wrapper must contain exactly five records")
    if not isinstance(proof, dict) or not isinstance(records[0].get("cwd"), str):
        raise ValueError("wrapper command cwd missing")
    root = Path(records[0]["cwd"])
    if not root.is_absolute():
        raise ValueError("wrapper cwd not absolute")
    evidence = root / "target" / "native-graph-evidence" / "compiler-wrapper"
    compiler = wrapper.get("compiler")
    version = wrapper.get("version")
    compile_argv = wrapper.get("test_argv")
    if not isinstance(compile_argv, list) or not compile_argv:
        raise ValueError("wrapper test compile argv missing")
    test_exe = compile_argv[-1]
    source = evidence / "wrapper.rs"
    expected_test = [compiler, "--edition=2024", "--test", str(source), "-o", test_exe]
    if compile_argv != expected_test:
        raise ValueError("wrapper test compile argv mismatch")
    if Path(test_exe).parent != evidence or Path(test_exe).name not in ("capture-tests", "capture-tests.exe"):
        raise ValueError("wrapper test executable path mismatch")
    expected = [
        ["rustup", "which", "rustc"],
        [compiler, "-vV"],
        wrapper.get("recipe"),
        compile_argv,
        [test_exe, "--test-threads=1"],
    ]
    artifacts = proof.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("proof artifacts missing")
    expected_cwd = str(root)
    for index, (record, argv) in enumerate(zip(records, expected)):
        if not isinstance(record, dict) or record.get("argv") != argv or record.get("exit_code") != 0:
            raise ValueError("wrapper command record mismatch")
        if record.get("cwd") != expected_cwd:
            raise ValueError("wrapper record cwd mismatch")
        graph_module._wrapper_record_streams(record, artifacts, index, version, compiler)
    source_path = Path(wrapper.get("source_path", ""))
    if not source_path.is_absolute() or source_path != evidence / "wrapper.rs":
        raise ValueError("wrapper source path mismatch")
    return None


def native_wrapper_source():
    """Return the pinned, dependency-free Rust compiler capture wrapper."""
    import wrapper_source
    return wrapper_source.native_wrapper_source()


def collect_output_aliases(collected, build_stdout, packages, context, manifest, capture_dir):
    from cargo_aliases import collect_output_aliases as collect
    return collect(collected, build_stdout, packages, context, manifest, capture_dir)


def validate_externs(pending, unit_by_output, packages, nodes):
    """Bind rustc --extern edges to Cargo metadata and captured output owners."""
    package_index = {p.get('id'): p for p in packages}
    node_index = nodes
    units = {}
    edges = {}
    for raw, package, row, normalized in pending:
        unit_id = id(normalized)
        units[unit_id] = normalized
        aliases = set()
        args = raw.get("args")
        if not isinstance(args, list):
            raise ValueError("invalid raw compiler arguments")
        externs = []
        intrinsics = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--extern":
                i += 1
                if i >= len(args):
                    raise ValueError("missing --extern value")
                value = args[i]
            elif arg.startswith("--extern="):
                value = arg[len("--extern="):]
            else:
                i += 1
                continue
            if "=" not in value:
                if (value != "proc_macro" or value in aliases or
                        row.get("kind") != ["proc-macro"] or
                        row.get("crate_types") != ["proc-macro"] or
                        normalized.get("context") != "host"):
                    raise ValueError("invalid --extern intrinsic or compilation context")
                declared = any(
                    (d.get("rename") or d.get("name", "")).replace("-", "_") == value
                    for d in package.get("dependencies", []))
                resolved = any(
                    d.get("name", "").replace("-", "_") == value
                    for d in node_index.get(package.get("id"), {}).get("deps", []))
                if declared or resolved:
                    raise ValueError("--extern intrinsic shadows a Cargo dependency")
                aliases.add(value)
                intrinsics.append(value)
                i += 1
                continue
            alias, path = value.split("=", 1)
            owner = unit_by_output.get(path)
            if not alias or alias in aliases or owner is None:
                raise ValueError("--extern alias is duplicate or path has no captured owner")
            aliases.add(alias)
            owner_unit, target, owner_row = owner
            deps = [d for d in node_index.get(package.get("id"), {}).get("deps", [])
                    if d.get("pkg") == target.get("id") and
                    d.get("name", "").replace("-", "_") == alias]
            if len(deps) != 1:
                raise ValueError("--extern owner has ambiguous or missing Cargo dependency for this alias")
            dep = deps[0]
            expected_kind = "build" if "custom-build" in row.get("kind", []) else "normal"
            matching_kinds = [k for k in dep.get("dep_kinds", [])
                              if (k.get("kind") or "normal") == expected_kind]
            if not matching_kinds:
                raise ValueError("--extern dependency kind conflicts with compiler target")
            if dep.get("name", "").replace("-", "_") != alias:
                raise ValueError("--extern alias conflicts with dependency package name")
            expected_context = "host" if "proc-macro" in owner_row.get("kind", []) else normalized.get("context")
            if owner_unit.get("context") != expected_context:
                raise ValueError("--extern owner has conflicting compilation context")
            declarations = [d for d in package.get("dependencies", [])
                            if d.get("name") == target.get("name") and
                            (d.get("rename") or d.get("name", "")).replace("-", "_") == alias and
                            (d.get("kind") or "normal") == expected_kind and
                            any(d.get("target") == k.get("target") for k in matching_kinds)]
            if not declarations:
                raise ValueError("--extern alias absent from Cargo metadata")
            kinds = sorted({k.get("kind") or "normal" for k in dep.get("dep_kinds", [])})
            externs.append({"alias": alias,
                            "unit": {key: owner[0][key] for key in
                                     ("package", "target", "kind", "crate_types", "context", "triple", "features")},
                            "kind": kinds})
            edges.setdefault(unit_id, []).append((alias, kinds, id(owner_unit), externs[-1]))
            i += 1
        normalized["intrinsics"] = sorted(intrinsics)
        normalized["dependencies"] = sorted(externs, key=lambda x: json.dumps(x, sort_keys=True))

    state = {}
    stack = []
    for root in sorted(units):
        if state.get(root) == 2:
            continue
        stack.append((root, False))
        while stack:
            current, exiting = stack.pop()
            if exiting:
                ordered_edges = sorted(edges.get(current, []), key=lambda e: (e[0], json.dumps(e[1], sort_keys=True)))
                for alias, kinds, owner_id, dep in ordered_edges:
                    dep["unit"]["sha256"] = units[owner_id]["sha256"]
                base = {key: value for key, value in units[current].items() if key not in ("dependencies", "sha256")}
                canonical = {"unit": base, "dependencies": [
                    {"alias": alias, "kind": kinds, "unit": units[owner_id]["sha256"]}
                    for alias, kinds, owner_id, _ in ordered_edges]}
                payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                units[current]["sha256"] = hashlib.sha256(payload).hexdigest()
                state[current] = 2
                continue
            if state.get(current) == 2:
                continue
            if state.get(current) == 1:
                raise ValueError("cycle in captured unit dependencies")
            state[current] = 1
            stack.append((current, True))
            for _, _, owner_id, _ in reversed(sorted(edges.get(current, []), key=lambda e: (e[0], json.dumps(e[1], sort_keys=True)))):
                if state.get(owner_id) == 1:
                    raise ValueError("cycle in captured unit dependencies")
                if state.get(owner_id) != 2:
                    stack.append((owner_id, False))
