"""CI-only observation hooks in fresh disposable copies, never product preparation."""

import ast
import hashlib
import importlib.util
from pathlib import Path
import tomllib

PACKET_HELPER = ".github/probes/iroh-paths/gate/bridge/support/packet_identity.py"
PACKET_HELPER_SHA = "c4e299523dd1b5c118855952992cce9ac9f65d7a018f9b9cfd42bce14d92d50a"
ORACLE = ".github/probes/iroh-paths/gate/bridge/support/wire_oracle.rs"
ORACLE_SHA = "40a3945e9e6cd3ec4a45cab61fe167f7f9be27292b602acf11c1f651f1abe080"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def package(root, name):
    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    if manifest["package"]["name"] != name or manifest["package"]["version"] != "1.3.0":
        raise ValueError("prepared fixture dependency identity changed: " + name)


def owned(path, repo):
    path = path.resolve()
    path.relative_to((repo / "target").resolve())
    return path


def edit(root, relative, before, after, records):
    path = root / relative
    original = path.read_bytes()
    text = original.decode("utf-8")
    if text.count(before) != 1 or after in text:
        raise ValueError("fixture observation anchor changed: " + relative)
    result = text.replace(before, after, 1)
    if result.count(after) != 1 or result.replace(after, before, 1).encode() != original:
        raise ValueError("fixture edit cannot restore original bytes: " + relative)
    path.write_bytes(result.encode())
    records.append({"path": relative, "before": digest(original), "after": digest(result.encode()),
                    "reverse_verified": True})


def packet_identity(repo, source):
    source = owned(source, repo)
    package(source, "noq-proto")
    helper = repo / PACKET_HELPER
    code = helper.read_bytes()
    if digest(code) != PACKET_HELPER_SHA:
        raise ValueError("reviewed ciphertext helper changed")
    tree = ast.parse(code)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "apply")
    constants = {node.targets[0].id: ast.literal_eval(node.value)
                 for node in function.body if isinstance(node, ast.Assign)
                 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {"call", "before", "after"}}
    replacement = next(ast.literal_eval(node.args[1]) for node in ast.walk(function)
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                       and node.func.attr == "replace" and isinstance(node.func.value, ast.Name)
                       and node.func.value.id == "packet_text")
    paths = ["src/connection/packet_builder.rs", "src/connection/qlog.rs"]
    original = {name: (source / name).read_bytes() for name in paths}
    for name, anchor in zip(paths, (constants["call"], constants["before"])):
        if original[name].decode().count(anchor) != 1:
            raise ValueError("finalized packet observation boundary changed: " + name)
    spec = importlib.util.spec_from_file_location("reviewed_carrier_packet_identity", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.apply(source)
    records = []
    for name, before, after in zip(paths, (constants["call"], constants["before"]),
                                   (replacement, constants["after"])):
        transformed = (source / name).read_bytes()
        expected = original[name].decode().replace(before, after, 1).encode()
        if transformed != expected or transformed.decode().replace(after, before, 1).encode() != original[name]:
            raise ValueError("ciphertext helper changed unrelated bytes: " + name)
        records.append({"path": name, "before": digest(original[name]), "after": digest(transformed),
                        "reverse_verified": True})
    return {"helper_sha256": PACKET_HELPER_SHA, "files": records}


def native_helpers(repo, source):
    source = owned(source, repo)
    package(source, "iroh")
    records = []
    anchor = """    pub fn application_data_filter(mut self, filter: fn(noq_proto::FourTuple) -> bool) -> Self {
        self.0.application_data_filter(filter);
        self
    }"""
    edit(source, "src/endpoint/quic.rs", anchor, anchor + """

    /// Fixture-only: explicit path phases, no automatic candidate exchange.
    pub fn spike_disable_nat_traversal(mut self) -> Self {
        self.0.max_remote_nat_traversal_addresses(0);
        self
    }""", records)
    anchor = "        self.inner.send_datagram(data)\n    }"
    edit(source, "src/endpoint/connection.rs", anchor, anchor + """

    /// Fixture-only native Backup path on the original authenticated connection.
    /// cancel-safe: NO — cancelled admission is not retried by the fixture.
    pub async fn spike_open_ip_path(&self, remote: std::net::SocketAddr) -> bool {
        self.inner.open_path_ensure(noq::FourTuple::new(remote, None), noq::PathStatus::Backup)
            .await.is_ok()
    }""", records)
    return {"files": records}


def observer(repo, root):
    root = owned(root, repo)
    probe = Path(__file__).with_name("probe.rs")
    support = root / "target/carrier-frame-support"
    support.mkdir(parents=True, exist_ok=False)
    sources = {"probe.rs": probe}
    copied = []
    for name, source in sources.items():
        data = source.read_bytes()
        (support / name).write_bytes(data)
        copied.append({"name": name, "sha256": digest(data)})
    records = []
    root_lib = "crates/shaar-p2p/src/lib.rs"
    text = (root / root_lib).read_text(encoding="utf-8")
    if "carrier_frame_probe" in text or not text.startswith("#![forbid(unsafe_code)]"):
        raise ValueError("fixture carrier crate root changed")
    original = (root / root_lib).read_bytes()
    extra = '\n#[path = "../../../target/carrier-frame-support/probe.rs"]\npub mod carrier_frame_probe;\n'
    (root / root_lib).write_bytes(original + extra.encode())
    records.append({"path": root_lib, "before": digest(original), "after": digest(original + extra.encode()),
                    "reverse_verified": (original + extra.encode())[:-len(extra.encode())] == original})
    receive = "                permit.send(Inbound { received, source });"
    driver = (root / "crates/shaar-p2p/src/bridge/driver.rs").read_text(encoding="utf-8")
    guards = ("if !handle.is_current(&received) { continue; }",
              "if !shared.matches(&source, link) { continue; }", receive)
    if any(driver.count(guard) != 1 for guard in guards) or [driver.index(guard) for guard in guards] != sorted(driver.index(guard) for guard in guards):
        raise ValueError("authenticated/current carrier receive boundary changed")
    edit(root, "crates/shaar-p2p/src/bridge/driver.rs", receive,
         "                crate::carrier_frame_probe::received(handle.peer_id(), &received, &source);\n" + receive,
         records)
    return {"files": records, "support": copied}


def workspace(repo, root, scenario, allow_all):
    if not isinstance(allow_all, bool):
        raise ValueError("fixture policy variant must be an explicit boolean")
    root = owned(root, repo)
    scenario = scenario.resolve()
    scenario.relative_to(repo.resolve())
    oracle = repo / ORACLE
    if digest(oracle.read_bytes()) != ORACLE_SHA:
        raise ValueError("reviewed decoded-frame oracle changed")
    capture = observer(repo, root)
    records, copied = capture["files"], capture["support"]
    for name, source in (("scenario.rs", scenario), ("wire_oracle.rs", oracle)):
        data = source.read_bytes()
        (root / "target/carrier-frame-support" / name).write_bytes(data)
        copied.append({"name": name, "sha256": digest(data)})
    admission = "crates/shaar/src/network/admission/mod.rs"
    edit(root, admission, "impl Endpoint {", """fn carrier_frame_prefix(identity: &Identity) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(64);
    for byte in identity.public_key_bytes() {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

impl Endpoint {
    #[cfg(test)]
    pub(in crate::network) fn carrier_frame_raw(&self) -> &iroh::Endpoint {
        &self.inner
    }
""", records)
    if allow_all:
        edit(root, admission, ".application_data_filter(|path| policy::native_ip(path.remote().ip()))",
             ".application_data_filter(|_| true)", records)
    edit(root, admission, ".datagram_receive_buffer_size(None)",
         ".datagram_receive_buffer_size(Some(32 * 1024))", records)
    edit(root, admission, ".datagram_send_buffer_size(0)", """.datagram_send_buffer_size(32 * 1024)
            .spike_disable_nat_traversal()
            .send_observed_address_reports(false)
            .receive_observed_address_reports(false)
            .keep_alive_interval(std::time::Duration::from_secs(1))
            .qlog_from_path(
                &std::path::PathBuf::from(std::env::var_os("SHAAR_CARRIER_FRAME_TRACE").expect("fixture trace directory")),
                &carrier_frame_prefix(identity),
            )""", records)
    tests = "crates/shaar/src/network/signaling/owned_tests.rs"
    original = (root / tests).read_bytes()
    if b"carrier_frame_fixture" in original:
        raise ValueError("SDK carrier fixture is already installed")
    extra = '\n#[path = "../../../../../target/carrier-frame-support/scenario.rs"]\nmod carrier_frame_fixture;\n'
    (root / tests).write_bytes(original + extra.encode())
    records.append({"path": tests, "before": digest(original), "after": digest(original + extra.encode()),
                    "reverse_verified": (original + extra.encode())[:-len(extra.encode())] == original})
    return {"allow_all": bool(allow_all), "fixture_datagram_bytes": 32 * 1024,
            "oracle_sha256": ORACLE_SHA, "files": records, "support": copied}
