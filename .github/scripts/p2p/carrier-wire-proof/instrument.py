"""Reversible, CI-only observations in an isolated copy of the prepared relay."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
GATE = "src/operation_gate.rs"
LIBRARY = "src/lib.rs"
MARKER = """        futures::future::poll_fn(|cx| {
            if !self.poll_live(cx, true) {
                return Poll::Ready(Err(denied().into()));
            }
            future.as_mut().poll(cx)
        })"""
OBSERVED = """        futures::future::poll_fn(|cx| {
            let descriptor = self.0.authority.as_ref().map(|authority| (
                authority.descriptor.peer(), authority.descriptor.kind(),
                authority.descriptor.generation().get(),
            ));
            let control = self.0.control.lock().ok().and_then(|control| *control);
            if crate::wire_probe::before_protocol_poll(cx, self, descriptor, control).is_pending() {
                return Poll::Pending;
            }
            if !self.poll_live(cx, true) {
                crate::wire_probe::protocol_denied(descriptor, control);
                return Poll::Ready(Err(denied().into()));
            }
            crate::wire_probe::inner_poll_started(descriptor, control);
            future.as_mut().poll(cx)
        })"""
GUARD = "if !self.poll_live(cx, true) {"
MODULE = "mod operation_gate;"
EXPORTED = "mod operation_gate;\n#[doc(hidden)]\npub mod wire_probe;"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("relay source anchor drift: " + old[:90])
    return text.replace(old, new)


def verified(prepared):
    path = HERE.parent / "relay/fixtures/wire/prepare.py"
    spec = importlib.util.spec_from_file_location("carrier_accepted_relay_prepare", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verified_product(prepared)


def instrument(prepared, destination, variant):
    if os.environ.get("CI", "").lower() != "true":
        raise ValueError("carrier relay instrumentation is CI-only")
    if variant not in ("baseline", "counterfactual"):
        raise ValueError("unknown carrier protocol variant")
    original = verified(prepared)
    tree = dict(original)
    original_gate = original[GATE].decode()
    newline = "\r\n" if "\r\n" in original_gate else "\n"
    marker = MARKER.replace("\n", newline)
    observed = OBSERVED.replace("\n", newline)
    gate = replace_once(original_gate, marker, observed)
    if replace_once(gate, observed, marker).encode() != original[GATE]:
        raise ValueError("protocol observation is not byte reversible")
    baseline_gate = gate.encode()
    if variant == "counterfactual":
        gate = replace_once(gate, GUARD, "if false {")
        if replace_once(gate, "if false {", GUARD).encode() != baseline_gate:
            raise ValueError("counterfactual changes more than its protocol guard")
    tree[GATE] = gate.encode()
    tree[LIBRARY] = replace_once(original[LIBRARY].decode(), MODULE, EXPORTED).encode()
    if replace_once(tree[LIBRARY].decode(), EXPORTED, MODULE).encode() != original[LIBRARY]:
        raise ValueError("probe export is not byte reversible")
    probe = (HERE / "probe.rs").read_text(encoding="utf-8")
    tree["src/wire_probe.rs"] = replace_once(
        probe, 'BUILD_VARIANT: &str = "baseline"',
        'BUILD_VARIANT: &str = "' + variant + '"').encode()
    for name, data in original.items():
        if name not in (GATE, LIBRARY) and tree[name] != data:
            raise ValueError("unrelated relay source changed: " + name)
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in tree.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    record = {
        "variant": variant,
        "fixture_only": True,
        "runtime_verified": False,
        "original_source_sha256": {name: digest(data) for name, data in sorted(original.items())},
        "instrumented_source_sha256": {name: digest(data) for name, data in sorted(tree.items())},
        "baseline_gate_sha256": digest(baseline_gate),
        "guard_only_counterfactual": variant == "counterfactual",
        "probe_sha256": digest(tree["src/wire_probe.rs"]),
    }
    (destination / "carrier-wire-proof.json").write_text(json.dumps(record, indent=2) + "\n")
    return record
