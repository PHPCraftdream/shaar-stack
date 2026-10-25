"""Prepare the pinned iroh wrapper bridge and detached calibration as data."""
import argparse
import hashlib
from pathlib import Path
import shutil
import tarfile
import tomllib
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "support"))
from packet_identity import apply as add_packet_identity  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts/backend"))
from policy import connection_limit_bridge, forwarder, joined_actor_shutdown, listener_limits, replace  # noqa: E402

DIGEST = "885787b892b5e2507c701f132ecbd45d2bad4bbb75157a19427087c16dadb833"


LEGACY_PATH_DISPATCH = "Path(evt @ PathEvent::RemoteStatus { .. }) => {"
CID_PATH_DISPATCH = "Path(evt @ (PathEvent::RemoteStatus { .. } | PathEvent::RemoteCidsAvailable { .. })) => {"


def pair_runtime_events(runtime: Path, proto: Path):
    connection = runtime / "src/connection.rs"
    text = connection.read_text(encoding="utf-8")
    protocol = (proto / "src/connection/paths.rs").read_text(encoding="utf-8")
    if text.count(CID_PATH_DISPATCH) + text.count(LEGACY_PATH_DISPATCH) != 1:
        raise ValueError("native CID runtime dispatch anchor changed")
    if "RemoteCidsAvailable" not in protocol and CID_PATH_DISPATCH in text:
        # Only the isolated copy loses an informational event absent from its paired protocol.
        text = replace(text, CID_PATH_DISPATCH, LEGACY_PATH_DISPATCH)
        connection.write_text(text, encoding="utf-8", newline="\n")
    elif "RemoteCidsAvailable" in protocol and CID_PATH_DISPATCH not in text:
        raise ValueError("native CID protocol/runtime event mismatch")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--noq-source", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    lock_text = (args.probe / "Cargo.lock").read_text(encoding="utf-8")
    lock = tomllib.loads(lock_text)
    entry = next(p for p in lock["package"] if p["name"] == "iroh" and p["version"] == "1.3.0")
    if args.archive.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("reviewed iroh archive exceeds 2 MiB")
    if entry["checksum"] != DIGEST or hashlib.sha256(args.archive.read_bytes()).hexdigest() != DIGEST:
        raise ValueError("iroh archive does not match reviewed lock checksum")
    if not (args.noq_source / "Cargo.toml").is_file():
        raise ValueError("prepared Noq source is missing")
    owned_budget = Path(__file__).resolve().parents[4] / "scripts/backend/ingress_budget.rs"
    if (args.runtime_source / "src/ingress_budget.rs").read_bytes() != owned_budget.read_bytes():
        raise ValueError("prepared Noq runtime budget mismatch")
    args.destination.mkdir(parents=True, exist_ok=False)
    source = args.destination / "source"
    source.mkdir()
    with tarfile.open(args.archive) as archive:
        archive.extractall(source, filter="data")
    iroh = source / "iroh-1.3.0"
    listener_limits(iroh)
    connection_limit_bridge(iroh)
    joined_actor_shutdown(iroh)
    config = iroh / "src/endpoint/quic.rs"
    text = forwarder(config.read_text(encoding="utf-8"))
    anchor = "    pub fn application_data_filter(mut self, filter: fn(noq_proto::FourTuple) -> bool) -> Self {\n        self.0.application_data_filter(filter);\n        self\n    }"
    addition = """

    /// Fixture-only: withhold automatic address exchange until explicit route admission.
    pub fn spike_disable_nat_traversal(mut self) -> Self {
        self.0.max_remote_nat_traversal_addresses(0);
        self
    }"""
    config.write_text(replace(text, anchor, anchor + addition), encoding="utf-8")
    connection = iroh / "src/endpoint/connection.rs"
    connection_text = connection.read_text(encoding="utf-8")
    connection_anchor = "        self.inner.send_datagram(data)\n    }"
    if connection_text.count(connection_anchor) != 1:
        raise ValueError("iroh connection fixture anchor changed")
    connection_addition = """

    /// Fixture-only native Backup path on this connection; no NAT discovery or reconnect.
    /// cancel-safe: NO — the fixture terminates rather than retrying path admission.
    pub async fn spike_open_ip_path(&self, remote: SocketAddr) -> bool {
        self.inner.open_path_ensure(noq::FourTuple::new(remote, None), noq::PathStatus::Backup)
            .await.is_ok()
    }"""
    connection.write_text(connection_text.replace(connection_anchor, connection_anchor + connection_addition), encoding="utf-8")
    transports = iroh / "src/socket/transports.rs"
    transports_text = transports.read_text(encoding="utf-8")
    transmit_anchor = "impl<'a> Transmit<'a> {"
    if transports_text.count(transmit_anchor) != 1:
        raise ValueError("iroh transmit fixture anchor changed")
    transmit_addition = """
    /// Fixture-only constructor; ECN remains private and unset in these tests.
    pub fn spike_new(contents: &'a [u8], segment_size: Option<usize>) -> Self {
        Self { ecn: None, contents, segment_size }
    }
"""
    transports.write_text(transports_text.replace(transmit_anchor, transmit_anchor + transmit_addition), encoding="utf-8")
    iroh_manifest = iroh / "Cargo.toml"
    iroh_manifest.write_text(iroh_manifest.read_text(encoding="utf-8") + "\n[workspace]\n", encoding="utf-8")
    project = args.destination / "probe"
    project.mkdir()
    shutil.copytree(args.probe / "src", project / "src")
    (project / "tests").mkdir()
    for name in ("calibration.rs", "mixed_path.rs", "wire.rs"):
        shutil.copyfile(Path(__file__).with_name(name), project / "tests" / name)
    support = project / "tests/support"
    support.mkdir()
    for script in Path(__file__).with_name("support").glob("*.rs"):
        shutil.copyfile(script, support / script.name)
    shutil.copytree(Path(__file__).with_name("support") / "nat", support / "nat",
                    ignore=shutil.ignore_patterns("*.py", "__pycache__"))
    (project / "tests/nat_control.rs").write_text(
        '#![forbid(unsafe_code)]\n#[path = "support/nat/tests.rs"]\nmod suite;\n', encoding="utf-8")
    noq = args.destination / "noq-source"
    shutil.copytree(args.noq_source, noq)
    add_packet_identity(noq)
    runtime = args.destination / "runtime-source"
    shutil.copytree(args.runtime_source, runtime)
    pair_runtime_events(runtime, noq)
    manifest = (args.probe / "Cargo.toml").read_text(encoding="utf-8")
    if manifest.count('    "net",\n') != 1:
        raise ValueError("pinned Tokio feature anchor changed")
    manifest = manifest.replace('    "net",\n', '    "net",\n    "fs",\n')
    manifest += '\n[patch.crates-io]\niroh = { path = "../source/iroh-1.3.0" }\n'
    manifest += 'noq-proto = { path = "../noq-source" }\n'
    manifest += 'noq = { path = "../runtime-source" }\n'
    manifest += '\n[[bin]]\nname = "nat-peer"\npath = "tests/support/nat/main.rs"\n'
    (project / "Cargo.toml").write_text(manifest, encoding="utf-8")
    # Only source identity changes for these exact same-version path replacements.
    blocks = lock_text.split("[[package]]")
    replaced = set()
    for index, block in enumerate(blocks[1:], 1):
        package = tomllib.loads("[[package]]" + block)["package"][0]
        if package["name"] not in ("iroh", "noq-proto", "noq"):
            continue
        if package["version"] != "1.3.0" or package["name"] in replaced:
            raise ValueError("unexpected patched package identity")
        blocks[index] = "\n".join(line for line in block.split("\n")
                                    if not line.startswith(("source = ", "checksum = ")))
        replaced.add(package["name"])
    if replaced != {"iroh", "noq-proto", "noq"}:
        raise ValueError("missing patched lock entries")
    (project / "Cargo.lock").write_text("[[package]]".join(blocks), encoding="utf-8")
    print(f"Prepared wrapper bridge at {project}; downloaded code not executed")


if __name__ == "__main__":
    main()
