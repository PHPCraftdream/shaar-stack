"""Source-only owned relay wire fixture and reversible one-defect variants."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
VARIANTS = {
    "protocol": ("src/operation_gate.rs", "if !self.poll_live(cx, true) {", "if false {"),
    "renewal": ("src/priv_client/handler.rs",
                "if !operation.live() || self.pending_streams.len() >= MAX_CONCURRENT_STREAMS_PER_CONNECTION {",
                "if self.pending_streams.len() >= MAX_CONCURRENT_STREAMS_PER_CONNECTION {"),
    "reuse": ("src/priv_client.rs",
              "Some(connection_id) if { crate::wire_probe::before_reuse(); operation.bind(*connection_id) } =>",
              "Some(connection_id) if { crate::wire_probe::before_reuse(); true } =>"),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def files(root):
    service = {"fixture-provenance.json", "graph-receipt.json", "metadata.json", "compile.jsonl",
               "compile-failure.log", "run.log", "run-receipt.json", "wire-provenance.json"}
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
            if p.is_file() and p.relative_to(root).as_posix() not in service
            and not any(part in ("target", "compiled", ".git") for part in p.relative_to(root).parts)}


def hashes(tree):
    return {name: digest(data) for name, data in sorted(tree.items())}


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError("wire fixture source anchor changed: " + old[:80])
    return text.replace(old, new)


def observations():
    return {
        "src/lib.rs": [("mod operation_gate;", "mod operation_gate;\n#[doc(hidden)]\npub mod wire_probe;")],
        "src/operation_gate.rs": [
            ("futures::future::poll_fn(|cx| {", "futures::future::poll_fn(|cx| {\n            if crate::wire_probe::before_protocol_poll(cx).is_pending() { return Poll::Pending; }"),
            ("                return Poll::Ready(Err(denied().into()));", "                crate::wire_probe::after_protocol_poll();\n                return Poll::Ready(Err(denied().into()));"),
            ("            future.as_mut().poll(cx)", "            let result = future.as_mut().poll(cx);\n            crate::wire_probe::after_protocol_poll();\n            result"),
        ],
        "src/priv_client/handler.rs": [
            ("        self.pending_streams.push_back((serial, operation.clone(), sender));", "        self.pending_streams.push_back((serial, operation.clone(), sender));\n        crate::wire_probe::request_admitted();"),
            ("            let (_, operation, sender) = self.pending_streams.remove(position).expect(\"position exists\");", "            let (_, operation, sender) = self.pending_streams.remove(position).expect(\"position exists\");\n            crate::wire_probe::negotiated(result.is_ok());"),
            ("                    self.make_new_reservation(to_listener, operation);", "                    crate::wire_probe::before_renewal();\n                    self.make_new_reservation(to_listener, operation);"),
        ],
        "src/priv_client.rs": [
            ("Some(connection_id) if operation.bind(*connection_id) => ToSwarm::NotifyHandler {",
             "Some(connection_id) if { crate::wire_probe::before_reuse(); operation.bind(*connection_id) } => {\n                        crate::wire_probe::reuse_admitted();\n                        ToSwarm::NotifyHandler {"),
            ("                            dst_peer_id,\n                        }),\n                    },\n                    None => {", "                            dst_peer_id,\n                        }),\n                    }\n                    },\n                    None => {"),
        ],
        "src/protocol/outbound_hop.rs": [
            ("pub(crate) async fn make_reservation(stream: Stream) -> Result<Reservation, ReserveError> {", "pub(crate) async fn make_reservation(stream: Stream) -> Result<Reservation, ReserveError> {\n    crate::wire_probe::reserve_started();"),
            ("    substream.send(msg).await?;\n\n    substream.close().await?;", "    substream.send(msg).await?;\n    crate::wire_probe::reserve_serialized();\n\n    substream.close().await?;"),
            ("    let msg = proto::HopMessage {\n        r#type: proto::HopMessageType::Connect as i32,", "    crate::wire_probe::connect_started();\n    let msg = proto::HopMessage {\n        r#type: proto::HopMessageType::Connect as i32,"),
        ],
    }


def verified_product(source):
    tree = files(source)
    receipt = json.loads((source.parent / "provenance.json").read_text(encoding="utf-8"))
    if receipt["archive_sha256"] != "e5227b053db429996242c00f6c756fd9b5382b942a03eec34b465431df29697a":
        raise ValueError("wire fixture requires the pinned relay archive")
    for group in ("prepared_source_sha256", "operation_source_sha256"):
        for name, expected in receipt[group].items():
            if digest(tree["src/" + name]) != expected:
                raise ValueError("prepared relay source drift")
    if receipt["fixture_instrumentation"]:
        raise ValueError("wire fixture cannot use an instrumented baseline")
    return tree


def transform(source):
    original = verified_product(source)
    tree = dict(original)
    for name, edits in observations().items():
        text = tree[name].decode("utf-8")
        for old, new in edits:
            text = replace(text, old, new)
        tree[name] = text.encode()
    tree["src/wire_probe.rs"] = (HERE / "probe.rs").read_bytes()
    # Mechanically reverse every observation before accepting the fixture.
    for name, edits in observations().items():
        text = tree[name].decode()
        for old, new in reversed(edits):
            text = replace(text, new, old)
        if text.encode() != original[name]:
            raise ValueError("wire instrumentation is not reversible")
    for name in original.keys() - observations().keys():
        if tree[name] != original[name]:
            raise ValueError("wire fixture changed an unrelated production file")
    return tree, {"production_files": hashes(original), "instrumented_files": hashes(tree),
                  "recipe_sha256": digest(Path(__file__).read_bytes()), "fixture_only": True,
                  "wire_tests_authored": 3, "runtime_verified": False}


UNIT_GROUPS = (
    ("gate", "src/operation_gate.rs", "src/operation_tests.rs", "tests", "operation_tests.rs", "operation_gate", 13),
    ("handler", "src/priv_client/handler.rs", "src/priv_client/operation_handler_tests.rs", "operation_handler_tests", "operation_handler_tests.rs", "priv_client::handler", 7),
    ("client", "src/priv_client.rs", "src/operation_client_tests.rs", "operation_client_tests", "operation_client_tests.rs", "priv_client", 5),
    ("transport", "src/priv_client/transport.rs", "src/priv_client/operation_transport_tests.rs", "operation_transport_tests", "operation_transport_tests.rs", "priv_client::transport", 5),
)


def unit_transform(source):
    # Compile the unchanged unit bodies inside their original production modules.
    # Only test attributes/visibility and fixture-only dispatch bridges are adapted.
    import re
    original = verified_product(source)
    tree = dict(original)
    edits, inventory = {}, []
    bridge = ['#![forbid(unsafe_code)]', 'pub const SOURCE_TAG: &str = "owned-operation-unit-bodies-v1";',
              'pub fn run(case: usize) {', '    match case {']
    harness = ['#![forbid(unsafe_code)]']
    for group, parent, tests, module, filename, rust_path, count in UNIT_GROUPS:
        text = tree[tests].decode("utf-8")
        names = re.findall(r'^#\[test\]\nfn ([A-Za-z_][A-Za-z_0-9]*)\(', text, re.MULTILINE)
        if len(names) != count or len(set(names)) != count:
            raise ValueError("owned operation unit inventory changed: " + group)
        edits[tests] = [(f"#[test]\nfn {name}(", f"pub(super) fn {name}(") for name in names]
        for old, new in edits[tests]:
            text = replace(text, old, new)
        tree[tests] = text.encode()
        old = f'#[cfg(test)]\n#[path = "{filename}"]\nmod {module};'
        new = f'#[path = "{filename}"]\nmod {module};'
        dispatch = ['\npub(crate) fn operation_unit_fixture(case: usize) {', '    match case {']
        harness.append(f'mod {group} {{')
        for local, name in enumerate(names):
            case = len(inventory)
            qualified = group + "::" + name
            inventory.append(qualified)
            dispatch.append(f'        {local} => {module}::{name}(),')
            bridge.append(f'        {case} => crate::{rust_path}::operation_unit_fixture({local}),')
            harness.extend(['    #[test]', f'    fn {name}() {{',
                            '        assert_eq!(libp2p_relay::unit_bridge::SOURCE_TAG, "owned-operation-unit-bodies-v1");',
                            f'        libp2p_relay::unit_bridge::run({case});',
                            f'        println!("RELAY_UNIT_COMPLETED={qualified}");', '    }'])
        dispatch.extend(['        _ => panic!("unknown operation unit case"),', '    }', '}'])
        harness.append('}')
        new += '\n' + '\n'.join(dispatch) + '\n'
        edits[parent] = [(old, new)]
        tree[parent] = replace(tree[parent].decode(), old, new).encode()
    bridge.extend(['        _ => panic!("unknown operation unit case"),', '    }', '}'])
    old, new = 'mod operation_gate;', 'mod operation_gate;\n#[doc(hidden)]\npub mod unit_bridge;'
    edits['src/lib.rs'] = [(old, new)]
    tree['src/lib.rs'] = replace(tree['src/lib.rs'].decode(), old, new).encode()
    tree['src/unit_bridge.rs'] = ('\n'.join(bridge) + '\n').encode()
    for name, changes in edits.items():
        restored = tree[name].decode()
        for old, new in reversed(changes):
            restored = replace(restored, new, old)
        if restored.encode() != original[name]:
            raise ValueError("unit bridge changed a unit body or production implementation")
    for name in original.keys() - edits.keys():
        if tree[name] != original[name]:
            raise ValueError("unit bridge changed an unrelated production file")
    if len(inventory) != 30:
        raise ValueError("exactly 30 owned unit cases are required")
    record = {"production_files": hashes(original), "instrumented_files": hashes(tree),
              "recipe_sha256": digest(Path(__file__).read_bytes()), "fixture_only": True,
              "unit_inventory": inventory, "unit_tests_authored": 30, "runtime_verified": False,
              "unit_bridge_reversible_edits": edits, "unit_bodies_unchanged": True}
    return tree, record, ('\n'.join(harness) + '\n').encode()


def write(tree, destination):
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in tree.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def instrument(source, destination):
    tree, receipt = transform(source)
    write(tree, destination)
    (destination / "wire-provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


def counterfactual(source, destination, variant):
    record = json.loads((source / "fixture-provenance.json").read_text())
    baseline = files(source)
    lock = baseline["Cargo.lock"]
    relative, old, new = VARIANTS[variant]
    target = "relay/" + relative
    modified = dict(baseline)
    modified[target] = replace(modified[target].decode(), old, new).encode()
    if replace(modified[target].decode(), new, old).encode() != baseline[target]:
        raise ValueError("counterfactual is not reversible")
    probe = "relay/src/wire_probe.rs"
    modified[probe] = replace(modified[probe].decode(), 'BUILD_VARIANT: &str = "baseline"',
                              f'BUILD_VARIANT: &str = "{variant}"').encode()
    write(modified, destination)
    if (destination / "Cargo.lock").read_bytes() != lock:
        raise ValueError("counterfactual changed the fixture lock")
    record.update({"variant": variant, "one_defect_file": target, "baseline_files": hashes(baseline),
                   "fixture_files": hashes({k: v for k, v in modified.items() if k != "fixture-provenance.json"}),
                   "counterfactual_lock_sha256": digest(lock)})
    (destination / "fixture-provenance.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("instrument", "counterfactual"))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--variant", choices=VARIANTS)
    args = parser.parse_args()
    if args.mode == "instrument":
        instrument(args.source, args.destination)
    else:
        counterfactual(args.source, args.destination, args.variant)


if __name__ == "__main__":
    main()
