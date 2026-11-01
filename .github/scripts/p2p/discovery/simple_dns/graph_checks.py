# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import graph  # noqa: E402
from simple_dns import prepare  # noqa: E402


class SimpleDnsGraphChecks(unittest.TestCase):
    def setUp(self):
        self.roots = {name: Path(name).resolve() for name in (
            "libp2p-relay", "libp2p-swarm", "libp2p-kad", "libp2p-dns", "hickory-resolver")}
        self.roots["simple-dns"] = (Path(__file__).resolve().parents[5] /
            "target/p2p/simple-dns/simple-dns-0.12.0")
        self.old = {"package": [{"name": "simple-dns", "version": "0.12.0",
                                  "source": "registry+https://github.com/rust-lang/crates.io-index",
                                  "checksum": prepare.ARCHIVE_SHA256}]}
        self.new = {"package": [{"name": name, "version": version,
                                  "source": None if name in self.roots else "registry",
                                  "checksum": None if name in self.roots else "registry-checksum"}
                                 for name, version in graph.FAMILY.items()]}
        self.metadata = {"packages": [], "resolve": {"nodes": []}}
        for package in self.new["package"]:
            name, version = package["name"], package["version"]
            self.metadata["packages"].append({"name": name, "version": version,
                "source": package["source"], "id": f"{name}@{version}",
                "manifest_path": str(self.roots[name] / "Cargo.toml") if name in self.roots else "registry/Cargo.toml"})
            self.metadata["resolve"]["nodes"].append({"id": f"{name}@{version}"})
        self.simple_dns = self.roots["simple-dns"]

    def validate(self, old=None, new=None, metadata=None):
        return graph.validate(old or self.old, new or self.new, metadata or self.metadata,
            *(self.roots[name] for name in ("libp2p-relay", "libp2p-swarm", "libp2p-kad",
                                             "libp2p-dns", "hickory-resolver", "simple-dns")))

    def test_original_verify_cli_arguments_remain_compatible(self):
        legacy = graph.build_parser().parse_args([
            "verify", "--workspace", "workspace", "--metadata", "metadata.json",
            "--relay-source", "relay", "--swarm-source", "swarm", "--kad-source", "kad",
            "--dns-source", "dns", "--resolver-source", "resolver",
        ])
        self.assertIsNone(legacy.simple_dns_source)
        receipt = graph.validate(
            self.old, self.new, self.metadata,
            *(self.roots[name] for name in ("libp2p-relay", "libp2p-swarm", "libp2p-kad",
                                             "libp2p-dns", "hickory-resolver")))
        self.assertTrue(receipt["reviewed_simple_dns_identity_replacement"])
        explicit = graph.build_parser().parse_args([
            "verify", "--workspace", "workspace", "--metadata", "metadata.json",
            "--relay-source", "relay", "--swarm-source", "swarm", "--kad-source", "kad",
            "--dns-source", "dns", "--resolver-source", "resolver",
            "--simple-dns-source", "simple-dns",
        ])
        self.assertEqual(explicit.simple_dns_source, Path("simple-dns"))

    def test_exact_resolved_simple_dns_identity_and_path_are_required(self):
        self.validate()
        self.assertIsNone(self.metadata["packages"][next(
            i for i, package in enumerate(self.metadata["packages"])
            if package["name"] == "simple-dns")]["source"])
        self.assertEqual(Path(next(p for p in self.metadata["packages"]
            if p["name"] == "simple-dns")["manifest_path"]).resolve(),
            (self.simple_dns / "Cargo.toml").resolve())
        metadata = copy.deepcopy(self.metadata)
        next(p for p in metadata["packages"] if p["name"] == "simple-dns")["source"] = "registry"
        with self.assertRaisesRegex(ValueError, "prepared source: simple-dns"):
            self.validate(metadata=metadata)
        metadata = copy.deepcopy(self.metadata)
        next(p for p in metadata["packages"] if p["name"] == "simple-dns")["id"] = "other"
        with self.assertRaisesRegex(ValueError, "reviewed source APIs"):
            self.validate(metadata=metadata)
        metadata = copy.deepcopy(self.metadata)
        next(p for p in metadata["packages"] if p["name"] == "simple-dns")["manifest_path"] = "wrong/Cargo.toml"
        with self.assertRaisesRegex(ValueError, "prepared source: simple-dns"):
            self.validate(metadata=metadata)

    def test_identity_substitution_does_not_allow_mutating_edges_or_fallback(self):
        new = copy.deepcopy(self.new)
        new["package"].append(copy.deepcopy(self.old["package"][0]))
        with self.assertRaisesRegex(ValueError, "reviewed path identity"):
            self.validate(new=new)
        old = copy.deepcopy(self.old)
        old["package"][0]["dependencies"] = ["changed"]
        with self.assertRaisesRegex(ValueError, "dependency edge"):
            self.validate(old=old)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
