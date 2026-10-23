"""Prepare reviewed bounded relay source as data; never execute archive code."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import tomllib

VERSION = "0.22.0"
DIGEST = "e5227b053db429996242c00f6c756fd9b5382b942a03eec34b465431df29697a"
MAX_ARCHIVE = 2 * 1024 * 1024
SWARM_DIGEST = "57ccbe1baeaef036ffde4b265871e11c64d29464036bba635378f356bcdca854"


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError("reviewed relay source anchor changed")
    return text.replace(old, new)


def prepare(archive, destination):
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("relay archive exceeds reviewed size bound")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != DIGEST:
        raise ValueError("relay archive checksum mismatch")
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")
    root = destination / f"libp2p-relay-{VERSION}"
    manifest_path = root / "Cargo.toml"
    original_manifest = manifest_path.read_text(encoding="utf-8")
    manifest = tomllib.loads(original_manifest)
    if manifest["package"]["name"] != "libp2p-relay" or manifest["package"]["version"] != VERSION:
        raise ValueError("unexpected relay package identity")
    notice = (root / "src/protocol/outbound_hop.rs").read_text(encoding="utf-8").split("use std", 1)[0]
    if manifest["package"].get("license") != "MIT" or not all(
        marker in notice for marker in ("Copyright 2021 Protocol Labs", "Permission is hereby granted", 'THE SOFTWARE IS PROVIDED "AS IS"')
    ):
        raise ValueError("relay license identity or embedded notice changed")
    library_path = root / "src/lib.rs"
    library = replace(library_path.read_text(encoding="utf-8"), "mod protocol;", "mod bounded_lease;\nmod protocol;")
    protocol_path = root / "src/protocol/outbound_hop.rs"
    protocol = replace(protocol_path.read_text(encoding="utf-8"), """    let renewal_timeout = reservation
        .expire
        .checked_sub(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        // Renew the reservation after 3/4 of the reservation expiration timestamp.
        .and_then(|duration| duration.checked_sub(duration / 4))
        .map(Duration::from_secs)
        .map(Delay::new)""", """    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs());
    let renewal_timeout = crate::bounded_lease::renewal_delay(reservation.expire, now)
        .map(Delay::new)""")
    protocol = replace(protocol, "use std::{io, time::Duration};", "use std::io;")
    owned = Path(__file__).with_name("lease.rs").read_bytes()
    module = root / "src/bounded_lease.rs"
    if module.exists():
        raise ValueError("unexpected existing bounded lease module")
    # Check every anchor and input before changing extracted source files.
    library_path.write_text(library, encoding="utf-8", newline="\n")
    protocol_path.write_text(protocol, encoding="utf-8", newline="\n")
    module.write_bytes(owned)
    manifest_path.write_text(original_manifest + "\n[workspace]\n", encoding="utf-8", newline="\n")
    receipt = {
        "package": "libp2p-relay", "version": VERSION, "archive_sha256": DIGEST,
        "lease_source_sha256": hashlib.sha256(owned).hexdigest(),
        "patch_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "max_lease_seconds": 86400, "fixture_instrumentation": False,
    }
    (destination / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return root


def prepare_swarm(archive, destination):
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("swarm archive exceeds reviewed size bound")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SWARM_DIGEST:
        raise ValueError("swarm archive checksum mismatch")
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")
    root = destination / "libp2p-swarm-0.48.0"
    path = root / "Cargo.toml"
    original = path.read_text(encoding="utf-8")
    manifest = tomllib.loads(original)
    if manifest["package"]["name"] != "libp2p-swarm" or manifest["package"]["version"] != "0.48.0":
        raise ValueError("unexpected swarm package identity")
    notice = (root / "src/lib.rs").read_text(encoding="utf-8")[:1800]
    if manifest["package"].get("license") != "MIT" or "Copyright 2019 Parity Technologies" not in notice:
        raise ValueError("swarm license identity or embedded notice changed")
    updated = replace(original, '''[target.'cfg(target_family="wasm")'.dependencies.wasm-bindgen-futures]
version = "=0.4.58"''', '''[target.'cfg(target_family="wasm")'.dependencies.wasm-bindgen-futures]
version = "=0.4.79"''')
    path.write_text(updated + "\n[workspace]\n", encoding="utf-8", newline="\n")
    receipt = {"package": "libp2p-swarm", "version": "0.48.0", "archive_sha256": SWARM_DIGEST,
               "wasm_bindgen_futures_requirement": "=0.4.79", "previous_requirement": "=0.4.58",
               "native_source_changed": False,
               "patch_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (destination / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return root


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--swarm-archive", type=Path, required=True)
    parser.add_argument("--swarm-destination", type=Path, required=True)
    args = parser.parse_args()
    print(prepare(args.archive, args.destination))
    print(prepare_swarm(args.swarm_archive, args.swarm_destination))


if __name__ == "__main__":
    main()
