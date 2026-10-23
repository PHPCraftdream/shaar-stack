"""CI-only preparation controls and clean-source calibration package generation."""
import argparse
import json
import tarfile
from pathlib import Path
import shutil
import sys
import tempfile
import tomllib
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy  # noqa: E402
import prepare  # noqa: E402


def make_probe(destination, probe):
    target = destination / "probe"
    target.mkdir()
    shutil.copytree(probe / "src", target / "src")
    (target / "tests").mkdir()
    for source in (probe / "tests/baseline_custom_only.rs", probe / "gate/bridge/calibration.rs"):
        shutil.copyfile(source, target / "tests" / source.name)
    manifest = (probe / "Cargo.toml").read_text(encoding="utf-8")
    manifest += "\n[patch.crates-io]\n" + "".join(
        f'{name} = {{ path = "../{name}/{name}-{prepare.VERSION}" }}\n' for name in prepare.PACKAGES)
    (target / "Cargo.toml").write_text(manifest, encoding="utf-8")
    lock = (probe / "Cargo.lock").read_text(encoding="utf-8")
    blocks = lock.split("[[package]]")
    matched = set()
    for index, block in enumerate(blocks[1:], 1):
        package = tomllib.loads("[[package]]" + block)["package"][0]
        if package["name"] in prepare.PACKAGES and package["version"] == prepare.VERSION:
            if package.get("checksum") != prepare.PACKAGES[package["name"]]:
                raise ValueError("clean calibration lock checksum mismatch")
            blocks[index] = "\n".join(line for line in block.split("\n")
                                      if not line.startswith(("source =", "checksum =")))
            matched.add(package["name"])
    if matched != set(prepare.PACKAGES):
        raise ValueError("clean calibration lock entries missing")
    (target / "Cargo.lock").write_text("[[package]]".join(blocks), encoding="utf-8")


class PreparationChecks(unittest.TestCase):
    def test_shared_policy_is_exactly_the_runtime_policy_used_by_gate(self):
        for relative in ("src/config/transport.rs", "src/connection/spaces.rs", "src/connection/mod.rs",
                         "src/connection/datagrams.rs", "src/config/mod.rs", "src/endpoint.rs"):
            production = (ROOTS["noq-proto"] / relative).read_text(encoding="utf-8")
            gate = (ARGS.gate_noq / relative).read_text(encoding="utf-8")
            suffix = '\n#[cfg(test)]\n#[path = "payload_policy_bounds.rs"]\nmod payload_policy_bounds;\n'
            if relative.endswith("datagrams.rs"):
                self.assertTrue(gate.endswith(suffix))
                gate = gate[:-len(suffix)]
            self.assertEqual(production, gate)

    def test_production_has_no_spike_or_ciphertext_instrumentation(self):
        for root in ROOTS.values():
            self.assertEqual(tomllib.loads((root / "Cargo.toml").read_text())["package"]["license"], "MIT OR Apache-2.0")
            self.assertTrue(list(root.glob("LICENSE*")))
        for package, relative in [("iroh", "src/endpoint/connection.rs"), ("iroh", "src/socket/transports.rs"),
                                  ("iroh", "src/endpoint/quic.rs"), ("noq-proto", "src/connection/packet_builder.rs")]:
            text = (ROOTS[package] / relative).read_text(encoding="utf-8")
            for forbidden in ("spike_open_ip_path", "spike_disable_nat_traversal", "spike_new", "raw.data ="):
                self.assertNotIn(forbidden, text)
        self.assertFalse((ROOTS["noq-proto"] / "src/tests/payload_policy.rs").exists())
        self.assertFalse((ROOTS["noq-proto"] / "src/connection/payload_policy_bounds.rs").exists())
        wrapper = (ROOTS["iroh"] / "src/endpoint/quic.rs").read_text(encoding="utf-8")
        self.assertEqual(wrapper.count("pub fn application_data_filter("), 1)
        provenance = ARGS.destination / "provenance.json"
        self.assertEqual(json.loads(provenance.read_text())["fixture_instrumentation"], False)
        for package, relative in [("iroh", "src/endpoint/connection.rs"), ("iroh", "src/socket/transports.rs"),
                                  ("noq-proto", "src/connection/packet_builder.rs"), ("noq-proto", "src/connection/qlog.rs")]:
            with tarfile.open(ARCHIVES[package]) as archive:
                with archive.extractfile(f"{package}-{prepare.VERSION}/{relative}") as original:
                    self.assertEqual((ROOTS[package] / relative).read_bytes(), original.read())

    def test_checksum_failure_never_creates_output(self):
        with tempfile.TemporaryDirectory(dir=ARGS.destination) as temporary:
            directory = Path(temporary)
            invalid = directory / "invalid.crate"
            invalid.write_bytes(b"not the reviewed source")
            for package in prepare.PACKAGES:
                archives = dict(ARCHIVES, **{package: invalid})
                with self.subTest(package=package), self.assertRaisesRegex(ValueError, "checksum"):
                    prepare.prepare(archives, ARGS.probe / "Cargo.lock", directory / "output")
                self.assertFalse((directory / "output").exists())

    def test_size_lock_and_existing_destination_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=ARGS.destination) as temporary:
            directory = Path(temporary)
            invalid = directory / "large.crate"
            with invalid.open("wb") as stream:
                stream.truncate(prepare.MAX_ARCHIVE + 1)
            lock = tomllib.loads((ARGS.probe / "Cargo.lock").read_text())
            with self.assertRaisesRegex(ValueError, "size bound"):
                prepare.validate_archive(invalid, "iroh", lock)
            for package in lock["package"]:
                if package["name"] == "iroh":
                    package["checksum"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "checksum"):
                prepare.validate_archive(ARCHIVES["iroh"], "iroh", lock)
            with self.assertRaises(FileExistsError):
                prepare.prepare(ARCHIVES, ARGS.probe / "Cargo.lock", directory)

    def test_listener_bridge_rejects_repeat_preparation_without_overwriting(self):
        root = ROOTS["iroh"]
        paths = [root / "src/endpoint.rs", root / "src/socket.rs"]
        before = [path.read_bytes() for path in paths]
        with self.assertRaisesRegex(ValueError, "listener limits source already modified"):
            policy.listener_limits(root)
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_connection_limits_reject_repeat_preparation_without_overwriting(self):
        for root, apply, files in [
            (ROOTS["noq-proto"], policy.endpoint_capacity, ("src/config/mod.rs", "src/endpoint.rs")),
            (ROOTS["iroh"], policy.connection_limit_bridge, ("src/endpoint.rs", "src/socket.rs")),
        ]:
            paths = [root / name for name in files]
            before = [path.read_bytes() for path in paths]
            with self.assertRaisesRegex(ValueError, "already modified"):
                apply(root)
            self.assertEqual([path.read_bytes() for path in paths], before)

    def test_actor_shutdown_module_is_owned_and_repeat_does_not_overwrite(self):
        root = ROOTS["iroh"]
        paths = [root / name for name in ("src/lib.rs", "src/socket.rs", "src/actor_shutdown.rs")]
        before = [path.read_bytes() for path in paths]
        self.assertEqual(before[2], Path(policy.__file__).with_name("actor_shutdown.rs").read_bytes())
        with self.assertRaisesRegex(ValueError, "actor shutdown module already exists"):
            policy.joined_actor_shutdown(root)
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_runtime_ingress_transform_rejects_repeat_without_overwriting(self):
        root = ROOTS["noq"]
        paths = [root / name for name in ("src/lib.rs", "src/endpoint.rs", "src/connection.rs")]
        before = [path.read_bytes() for path in paths]
        with self.assertRaisesRegex(ValueError, "existing ingress budget module"):
            prepare.runtime.apply(root)
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_source_anchor_drift_and_repeat_patch_are_rejected(self):
        for source in ("", "unexpected source", "aa"):
            with self.assertRaises(ValueError):
                policy.replace(source, "a", "replacement")
        wrapper = (ROOTS["iroh"] / "src/endpoint/quic.rs").read_text(encoding="utf-8")
        with self.assertRaises(ValueError):
            policy.forwarder("missing API anchor")
        # Noq's exact anchors reject applying the production patch twice.
        text = (ROOTS["noq-proto"] / "src/connection/spaces.rs").read_text(encoding="utf-8")
        with self.assertRaises(ValueError):
            policy.spaces(text)
        self.assertIn("application_data_filter", wrapper)


class ProductWorkspaceChecks(unittest.TestCase):
    def test_product_manifest_uses_prepared_backend_without_qlog(self):
        repo = ARGS.probe.resolve().parents[2]
        root = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
        for name in prepare.PACKAGES:
            expected = f"target/backend/{name}/{name}-{prepare.VERSION}"
            self.assertEqual(root["patch"]["crates-io"][name], {"path": expected})
        sdk = tomllib.loads((repo / "crates/shaar/Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(sdk["dependencies"]["iroh"]["version"], "=1.3.0")
        self.assertFalse(sdk["dependencies"]["iroh"]["default-features"])
        self.assertNotIn("qlog", sdk["dependencies"]["iroh"]["features"])
        self.assertTrue((repo / "crates/shaar/tests/backend_gate.rs").is_file())

    def test_product_lock_pins_the_reviewed_backend_family(self):
        repo = ARGS.probe.resolve().parents[2]
        actual = tomllib.loads((repo / "Cargo.lock").read_text(encoding="utf-8"))["package"]
        baseline = tomllib.loads((ARGS.probe / "Cargo.lock").read_text(encoding="utf-8"))["package"]
        for name in ("iroh", "iroh-base", "noq", "noq-proto", "noq-udp"):
            matches = [package for package in actual if package["name"] == name]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["version"], prepare.VERSION)
            if name in prepare.PACKAGES:
                self.assertNotIn("source", matches[0])
            else:
                reviewed = next(package for package in baseline if package["name"] == name)
                self.assertEqual(matches[0]["checksum"], reviewed["checksum"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--noq-archive", type=Path, required=True)
    parser.add_argument("--iroh-archive", type=Path, required=True)
    parser.add_argument("--runtime-archive", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--gate-noq", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    ARGS, remaining = parser.parse_known_args()
    ARCHIVES = {"noq-proto": ARGS.noq_archive, "iroh": ARGS.iroh_archive, "noq": ARGS.runtime_archive}
    ROOTS = prepare.prepare(ARCHIVES, ARGS.probe / "Cargo.lock", ARGS.destination)
    make_probe(ARGS.destination, ARGS.probe)
    unittest.main(argv=[sys.argv[0], *remaining])
