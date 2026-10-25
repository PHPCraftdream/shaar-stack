"""Prepare the locked Kademlia archive as data; never execute archive code."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib

VERSION = "0.49.0"
PACKAGE = f"libp2p-kad-{VERSION}"
DIGEST = "973caa45045e53f3cf1cf3d596888b82602b30640fd75485836c81aa66e7c38a"
LOCK_DIGEST = "1fef5141047eb6e9d4d514bf99a6af4e0bc05bafc6281174931ccc993038bfa2"
VCS = "7171dce2f90c05ba7892d4ba926abb1881db27c7"
MAX_ARCHIVE = 2 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError("reviewed Kademlia source anchor changed")
    return text.replace(old, new)


DISCOVERED_OLD = '''            for peer in others_iter.clone() {
                tracing::trace!(
                    ?peer,
                    %source,
                    query=?query_id,
                    "Peer reported by source in query"
                );
                let addrs = peer.multiaddrs.iter().cloned().collect();
                query.peers.addresses.insert(peer.node_id, addrs);
            }
            query.on_success(source, others_iter.map(|kp| kp.node_id))'''
DISCOVERED_NEW = '''            if query.is_finished() {
                return;
            }
            // First admitted peers and addresses win; failed peers keep their charge.
            let mut accepted = smallvec::SmallVec::<[PeerId; 32]>::new();
            for peer in others_iter {
                if !query.peers.addresses.contains_key(&peer.node_id)
                    && query.peers.addresses.len() >= 32
                {
                    continue;
                }
                let mut bounded = smallvec::SmallVec::<[&Multiaddr; 4]>::new();
                let previous = query.peers.addresses.get(&peer.node_id);
                for address in &peer.multiaddrs {
                    if previous.map_or(0, |addresses| addresses.len()) + bounded.len() >= 4 {
                        break;
                    }
                    if address.as_ref().len() <= 256
                        && !previous.is_some_and(|addresses| addresses.contains(address))
                        && !bounded.contains(&address)
                    {
                        bounded.push(address);
                    }
                }
                if previous.is_none() && bounded.is_empty() {
                    continue;
                }
                let addresses = query.peers.addresses.entry(peer.node_id).or_default();
                addresses.extend(bounded.into_iter().cloned());
                if !accepted.contains(&peer.node_id) {
                    accepted.push(peer.node_id);
                }
            }
            query.on_success(source, accepted)'''
ADDRESS_OLD = '''                for addr in addrs.iter_mut() {
                    if addr == old {
                        *addr = new.clone();
                    }
                }'''
ADDRESS_NEW = '''                if old != new {
                    if let Some(index) = addrs.iter().position(|address| address == old) {
                        // Preserve dial priority while enforcing the query-cache budget.
                        if new.as_ref().len() > 256 || addrs.contains(new) {
                            addrs.remove(index);
                        } else {
                            addrs[index] = new.clone();
                        }
                    }
                }'''


def transform(files):
    """Return only reviewed production deltas; all other archive bytes stay intact."""
    manifest = tomllib.loads(files["Cargo.toml"].decode())
    if (manifest["package"]["name"], manifest["package"]["version"]) != ("libp2p-kad", VERSION):
        raise ValueError("unexpected Kademlia package identity")
    notice = files["src/lib.rs"].decode().split("//!", 1)[0]
    if manifest["package"].get("license") != "MIT" or not all(marker in notice for marker in (
        "Copyright 2018 Parity Technologies", "Permission is hereby granted", 'THE SOFTWARE IS PROVIDED "AS IS"',
    )):
        raise ValueError("Kademlia license or embedded notice changed")
    vcs = json.loads(files[".cargo_vcs_info.json"])
    if vcs != {"git": {"sha1": VCS}, "path_in_vcs": "protocols/kad"}:
        raise ValueError("Kademlia source provenance changed")
    if digest(files["Cargo.lock"]) != LOCK_DIGEST:
        raise ValueError("Kademlia archive test lock changed")
    behaviour = replace(files["src/behaviour.rs"].decode(), DISCOVERED_OLD, DISCOVERED_NEW)
    behaviour = replace(behaviour, ADDRESS_OLD, ADDRESS_NEW)
    behaviour = replace(behaviour, "    #[cfg(test)]\n    pub(crate) fn set_automatic_bootstrap_throttle(",
                        "    pub fn set_automatic_bootstrap_throttle(")
    closest = replace(files["src/query/peers/closest.rs"].decode(),
                      "        for peer in closer_peers {\n            let key = peer.into();",
                      """        for peer in closer_peers {
            // No eviction: failed and timed-out states still consume the lifetime budget.
            if self.closest_peers.len() >= 32 {
                break;
            }
            let key = peer.into();""")
    if closest.count(".take(K_VALUE.into())") != 1 or "NonZeroUsize::new(20)" not in files["src/lib.rs"].decode():
        raise ValueError("Kademlia initial closest-peer bound changed")
    return {
        "Cargo.toml": files["Cargo.toml"] + b"\n[workspace]\n",
        "src/behaviour.rs": behaviour.encode(),
        "src/query/peers/closest.rs": closest.encode(),
    }


def archive_files(archive):
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("Kademlia archive exceeds reviewed size bound")
    if digest(archive.read_bytes()) != DIGEST:
        raise ValueError("Kademlia archive checksum mismatch")
    files = {}
    total = 0
    with tarfile.open(archive) as source:
        members = source.getmembers()
        if len(members) > 128:
            raise ValueError("Kademlia archive entry bound exceeded")
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or not path.parts or path.parts[0] != PACKAGE or len(path.parts) > 8
                    or not (member.isfile() or member.isdir())):
                raise ValueError("unexpected Kademlia archive entry")
            if member.isdir():
                continue
            name = path.relative_to(PACKAGE).as_posix()
            total += member.size
            if total > 4 * MAX_ARCHIVE or name in files:
                raise ValueError("Kademlia archive expansion or duplicate entry")
            files[name] = source.extractfile(member).read()
    return files


def hashes(files):
    return {name: digest(data) for name, data in sorted(files.items())}


def prepare(archive, destination):
    files = archive_files(archive)
    changes = transform(files)
    receipt = {
        "package": "libp2p-kad", "version": VERSION, "archive_sha256": DIGEST,
        "archive_lock_sha256": LOCK_DIGEST, "vcs_revision": VCS, "license": "MIT",
        "preparer_sha256": digest(Path(__file__).read_bytes()),
        "original_files": hashes(files), "changed_files": sorted(changes),
        "query_referral_peers": 32, "addresses_per_peer": 4, "encoded_address_bytes": 256,
        "states_per_closest_iterator": 32, "global_operation_contact_bound": False,
        "fixture_instrumentation": False,
    }
    files.update(changes)
    receipt["prepared_files"] = hashes(files)
    # Validate every input and anchor before creating a fresh, never-overwritten tree.
    destination.mkdir(parents=True, exist_ok=False)
    root = destination / PACKAGE
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (destination / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return root


def verify(root):
    receipt = json.loads((root.parent / "provenance.json").read_text(encoding="utf-8"))
    if (receipt["archive_sha256"] != DIGEST or receipt["preparer_sha256"] != digest(Path(__file__).read_bytes())
            or receipt["fixture_instrumentation"]):
        raise ValueError("Kademlia prepared provenance mismatch")
    files = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    if hashes(files) != receipt["prepared_files"]:
        raise ValueError("Kademlia prepared source drift")
    return files


# Published archive omits quickcheck. The standalone fixture excludes upstream test
# modules only; production bodies and the archive lock remain byte-for-byte intact.
UPSTREAM_TESTS = {
    "src/behaviour.rs": "mod test;",
    **{f"src/{name}.rs": "#[cfg(test)]\nmod tests {" for name in (
        "addresses", "bootstrap", "handler", "jobs", "kbucket", "kbucket/bucket",
        "kbucket/key", "protocol", "record", "record/store/memory", "query/peers/closest",
        "query/peers/closest/disjoint",
    )},
    "src/query/peers/fixed.rs": "#[cfg(test)]\nmod test {",
}


def fixture(source, destination):
    files = verify(source)
    original = dict(files)
    for name, anchor in UPSTREAM_TESTS.items():
        replacement = "#[cfg(any())]\nmod test;" if anchor == "mod test;" else anchor.replace("cfg(test)", "cfg(any())")
        files[name] = replace(files[name].decode(), anchor, replacement).encode()
    tests = Path(__file__).with_name("kad_tests.rs").read_text(encoding="utf-8")
    sections = tests.split("// CLOSEST ITERATOR CONTRACT\n")
    if len(sections) != 2:
        raise ValueError("Kademlia fixture section anchor changed")
    for name, section in zip(("src/behaviour.rs", "src/query/peers/closest.rs"), sections):
        files[name] += ("\n" + section.removeprefix("#![forbid(unsafe_code)]\n")).encode()
    if files["Cargo.lock"] != original["Cargo.lock"] or digest(files["Cargo.lock"]) != LOCK_DIGEST:
        raise ValueError("Kademlia fixture lock changed")
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    receipt = {"archive_sha256": DIGEST, "archive_lock_sha256": LOCK_DIGEST,
               "production_files": hashes(original), "fixture_files": hashes(files),
               "owned_tests_sha256": digest(tests.encode()), "excluded_upstream_test_modules": sorted(UPSTREAM_TESTS)}
    (destination / "fixture-provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="mode", required=True)
    build = modes.add_parser("prepare")
    build.add_argument("--archive", type=Path, required=True)
    build.add_argument("--destination", type=Path, required=True)
    tests = modes.add_parser("fixture")
    tests.add_argument("--source", type=Path, required=True)
    tests.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "prepare":
        print(prepare(args.archive, args.destination))
    else:
        fixture(args.source, args.destination)


if __name__ == "__main__":
    main()
