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
HANDLER = "src/priv_client/handler.rs"
LISTENER = "src/priv_client/transport.rs"
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
CAPABILITY = "impl OperationCapability {"
IDENTITY = """impl OperationCapability {
    pub(crate) fn proof_identity(&self) -> Option<(PeerId, OperationKind, u64, Option<ConnectionId>)> {
        let authority = self.0.authority.as_ref()?;
        let control = self.0.control.lock().ok().and_then(|control| *control);
        Some((authority.descriptor.peer(), authority.descriptor.kind(),
              authority.descriptor.generation().get(), control))
    }
"""
ERROR_SEND = """                    if let Err(e) =
                        to_listener.try_send(transport::ToListenerMsg::Reservation(Err(error)))
                    {
                        tracing::debug!("Unable to send error to listener: {}", e.into_send_error())
                    }"""
ERROR_OBSERVED = ERROR_SEND + """ else {
                        crate::wire_probe::typed_error_queued(&operation);
                    }"""
LISTENER_POLL = """    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {"""
LISTENER_HELD = """    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if crate::wire_probe::before_listener_poll(cx, &self.operation).is_pending() {
            return Poll::Pending;
        }
        loop {"""
LISTENER_BROKEN = LISTENER_HELD + """
            if !self.is_closed && !self.operation.live() {
                self.close(Ok(()));
                continue;
            }"""


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


def transformed(original, edits):
    text = original.decode()
    newline = "\r\n" if "\r\n" in text else "\n"
    applied = []
    for old, new in edits:
        old, new = old.replace("\n", newline), new.replace("\n", newline)
        text = replace_once(text, old, new)
        applied.append((old, new))
    restored = text
    for old, new in reversed(applied):
        restored = replace_once(restored, new, old)
    if restored.encode() != original:
        raise ValueError("fixture instrumentation is not byte reversible")
    return text.encode()


def instrument(prepared, destination, variant):
    if os.environ.get("CI", "").lower() != "true":
        raise ValueError("carrier relay instrumentation is CI-only")
    if variant not in ("baseline", "counterfactual", "counterfactual-listener"):
        raise ValueError("unknown carrier protocol variant")
    original = verified(prepared)
    tree = dict(original)
    gate_edits = [(MARKER, OBSERVED), (CAPABILITY, IDENTITY)]
    baseline_gate = transformed(original[GATE], gate_edits)
    if variant == "counterfactual":
        gate_edits.append((GUARD, "if false {"))
    tree[GATE] = transformed(original[GATE], gate_edits)
    tree[LIBRARY] = transformed(original[LIBRARY], [(MODULE, EXPORTED)])
    tree[HANDLER] = transformed(original[HANDLER], [(ERROR_SEND, ERROR_OBSERVED)])
    listener_edits = [(LISTENER_POLL, LISTENER_HELD)]
    baseline_listener = transformed(original[LISTENER], listener_edits)
    if variant == "counterfactual-listener":
        listener_edits.append((LISTENER_HELD, LISTENER_BROKEN))
    tree[LISTENER] = transformed(original[LISTENER], listener_edits)
    probe = (HERE / "probe.rs").read_text(encoding="utf-8")
    tree["src/wire_probe.rs"] = replace_once(
        probe, 'BUILD_VARIANT: &str = "baseline"',
        'BUILD_VARIANT: &str = "' + variant + '"').encode()
    for name, data in original.items():
        if name not in (GATE, LIBRARY, HANDLER, LISTENER) and tree[name] != data:
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
        "baseline_listener_sha256": digest(baseline_listener),
        "guard_only_counterfactual": variant == "counterfactual",
        "listener_only_counterfactual": variant == "counterfactual-listener",
        "probe_sha256": digest(tree["src/wire_probe.rs"]),
    }
    (destination / "carrier-wire-proof.json").write_text(json.dumps(record, indent=2) + "\n")
    return record
