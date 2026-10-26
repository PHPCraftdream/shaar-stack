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
        .map(Delay::new)
        .ok_or(ReserveError::Protocol(
            ProtocolViolation::InvalidReservationExpiration,
        ))?;""", """    let received_at = web_time::Instant::now();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok();
    let lease = crate::bounded_lease::lease(reservation.expire, now)
        .ok_or(ReserveError::Protocol(ProtocolViolation::InvalidReservationExpiration))?;
    let expires_at = received_at.checked_add(lease.expires_after)
        .ok_or(ReserveError::Protocol(ProtocolViolation::InvalidReservationExpiration))?;
    let renewal_timeout = Delay::new(lease.renew_after);""")
    protocol = replace(protocol, "use std::{io, time::Duration};", "use std::io;")
    protocol = replace(protocol, "    pub(crate) renewal_timeout: Delay,", "    pub(crate) renewal_timeout: Delay,\n    pub(crate) expires_at: web_time::Instant,")
    protocol = replace(protocol, "    Ok(Reservation {\n        renewal_timeout,", "    Ok(Reservation {\n        renewal_timeout,\n        expires_at,")
    handler_path = root / "src/priv_client/handler.rs"
    client_path = root / "src/priv_client.rs"
    handler = replace(handler_path.read_text(encoding="utf-8"), "        renewal: bool,\n        limit: Option<protocol::Limit>,", "        renewal: bool,\n        limit: Option<protocol::Limit>,\n        expires_at: web_time::Instant,")
    handler = replace(handler, "                        renewal_timeout,\n                        addrs,", "                        renewal_timeout,\n                        expires_at,\n                        addrs,")
    handler = replace(handler, "                            renewal_timeout,\n                            addrs,", "                            renewal_timeout,\n                            expires_at,\n                            addrs,")
    handler = replace(handler, "        renewal_timeout: Delay,\n        addrs: Vec<Multiaddr>,", "        renewal_timeout: Delay,\n        expires_at: web_time::Instant,\n        addrs: Vec<Multiaddr>,")
    handler = replace(handler, "Event::ReservationReqAccepted { renewal, limit }", "Event::ReservationReqAccepted { renewal, limit, expires_at }")
    client = replace(client_path.read_text(encoding="utf-8"), "        renewal: bool,\n        limit: Option<protocol::Limit>,", "        renewal: bool,\n        limit: Option<protocol::Limit>,\n        /// Validated monotonic reservation expiry, captured when the response was parsed.\n        expires_at: web_time::Instant,")
    client = replace(client, "handler::Event::ReservationReqAccepted { renewal, limit }", "handler::Event::ReservationReqAccepted { renewal, limit, expires_at }")
    client = replace(client, "                    relay_peer_id: event_source,\n                    renewal,\n                    limit,", "                    relay_peer_id: event_source,\n                    renewal,\n                    limit,\n                    expires_at,")
    client = replace(client, "        relay_peer_id: PeerId,\n        /// Indicates whether the request replaces an existing reservation.",
                     "        relay_peer_id: PeerId,\n        /// Authenticated relay control connection, not a peer-claimed address.\n        connection_id: ConnectionId,\n        /// Indicates whether the request replaces an existing reservation.")
    client = replace(client, "    OutboundCircuitEstablished {\n        relay_peer_id: PeerId,\n        limit: Option<protocol::Limit>,\n    },",
                     "    OutboundCircuitEstablished {\n        relay_peer_id: PeerId,\n        connection_id: ConnectionId,\n        limit: Option<protocol::Limit>,\n    },")
    client = replace(client, "    InboundCircuitEstablished {\n        src_peer_id: PeerId,\n        limit: Option<protocol::Limit>,\n    },",
                     "    InboundCircuitEstablished {\n        relay_peer_id: PeerId,\n        connection_id: ConnectionId,\n        /// Relay-announced source; end-to-end Noise authentication is still required.\n        src_peer_id: PeerId,\n        limit: Option<protocol::Limit>,\n    },")
    client = replace(client, "                    relay_peer_id: event_source,\n                    renewal,",
                     "                    relay_peer_id: event_source,\n                    connection_id: connection,\n                    renewal,")
    client = replace(client, "                    relay_peer_id: event_source,\n                    limit,",
                     "                    relay_peer_id: event_source,\n                    connection_id: connection,\n                    limit,")
    client = replace(client, "                Event::InboundCircuitEstablished { src_peer_id, limit }",
                     "                Event::InboundCircuitEstablished { relay_peer_id: event_source, connection_id: connection, src_peer_id, limit }")
    client = replace(client, "        let action = match ready!(self.from_transport.poll_next_unpin(cx)) {", """        let action = match ready!(self.from_transport.poll_next_unpin(cx)) {
            Some(transport::TransportToBehaviourMsg::ListenReq { to_listener, .. })
                if to_listener.is_closed() => {
                    // One cancelled message was consumed; yield before draining the next.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            Some(transport::TransportToBehaviourMsg::DialReq { send_back, .. })
                if send_back.is_canceled() => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }""")
    handler = replace(handler, "In::Reserve { to_listener } => {\n                self.make_new_reservation(to_listener);\n            }",
                      "In::Reserve { to_listener } => {\n                if !to_listener.is_closed() { self.make_new_reservation(to_listener); }\n            }")
    handler = replace(handler, "                self.establish_new_circuit(to_dial, dst_peer_id);",
                      "                if !to_dial.is_canceled() { self.establish_new_circuit(to_dial, dst_peer_id); }")
    transport_path = root / "src/priv_client/transport.rs"
    transport = replace(transport_path.read_text(encoding="utf-8"),
                        "    fn close(&mut self, reason: Result<(), Error>) {\n        self.queued_events",
                        "    fn close(&mut self, reason: Result<(), Error>) {\n        self.from_behaviour.close();\n        self.queued_events")
    import sys
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from relay.patch import patch as operation_patch
    library, client, handler, transport, reservation = operation_patch(library, client, handler, transport)
    operation_sources = {
        "operation_gate.rs": "gate.rs",
        "operation_tests.rs": "tests.rs",
        "priv_client/operation_handler_tests.rs": "fixtures/handler_tests.rs",
        "operation_client_tests.rs": "fixtures/client_tests.rs",
    }
    operation_bytes = {name: (Path(__file__).parent / "relay" / source).read_bytes()
                       for name, source in operation_sources.items()}
    operation_bytes["priv_client/handler/reservation.rs"] = reservation.encode("utf-8")
    owned = Path(__file__).with_name("lease.rs").read_bytes()
    module = root / "src/bounded_lease.rs"
    if module.exists():
        raise ValueError("unexpected existing bounded lease module")
    # Check every anchor and input before changing extracted source files.
    library_path.write_text(library, encoding="utf-8", newline="\n")
    protocol_path.write_text(protocol, encoding="utf-8", newline="\n")
    handler_path.write_text(handler, encoding="utf-8", newline="\n")
    client_path.write_text(client, encoding="utf-8", newline="\n")
    transport_path.write_text(transport, encoding="utf-8", newline="\n")
    module.write_bytes(owned)
    for name, content in operation_bytes.items():
        path = root / "src" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    manifest_path.write_text(original_manifest + "\n[workspace]\n", encoding="utf-8", newline="\n")
    receipt = {
        "package": "libp2p-relay", "version": VERSION, "archive_sha256": DIGEST,
        "lease_source_sha256": hashlib.sha256(owned).hexdigest(),
        "patch_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "max_lease_seconds": 86400, "fixture_instrumentation": False,
        "relay_operation_gate": "owner-captured-generation-v1",
        "operation_source_sha256": {name: hashlib.sha256(content).hexdigest()
                                    for name, content in operation_bytes.items()},
        "operation_patch_sha256": {name: hashlib.sha256((Path(__file__).parent / "relay" / name).read_bytes()).hexdigest()
                                   for name in ("patch.py", "handler_patch.py")},
        "operation_gate_unit_tests": 13,
        "operation_handler_unit_tests": 7,
        "operation_client_unit_tests": 5,
        "operation_runtime_fixture_verified": False,
        "reservation_expiry_api": "validated-monotonic-instant",
        "authenticated_relay_connection_context": True,
        "cancelled_transport_requests_rejected_before_admission": True,
        "prepared_source_sha256": {name: hashlib.sha256(text.encode("utf-8")).hexdigest()
                                   for name, text in (("lib.rs", library), ("protocol/outbound_hop.rs", protocol),
                                                      ("priv_client/handler.rs", handler),
                                                      ("priv_client.rs", client),
                                                      ("priv_client/transport.rs", transport))},
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
