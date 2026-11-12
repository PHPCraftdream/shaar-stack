"""CI-only raw-source receipt and binding contracts, loaded by test_notice_evidence."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


class RegistryRawSourceTests(unittest.TestCase):
    def inputs(self):
        root = Path(__file__).resolve().parents[3]
        registry = root / "docs/legal/notices-material/registry"
        rows = json.loads((registry / "inventory.json").read_bytes())["identities"]
        spec = importlib.util.spec_from_file_location("raw_registry_replay", registry / "replay.py")
        replay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(replay)
        selected = [r for r in rows if (r["name"], r["version"]) in replay.raw_sources.RAW_PACKAGES]
        self.assertEqual({(r["name"], r["version"]) for r in selected}, set(replay.raw_sources.RAW_PACKAGES))
        return registry, replay, selected

    def members(self, row):
        # CI checks retained bindings; full archive replay compares these bytes to the .crate.
        return {m["archive_member"]: bytes.fromhex(m["bytes_hex"])
                for m in row["raw_source_binding"]["archive_metadata"].values()}

    def test_exact_raw_bindings_preserve_both_jni_alternatives_and_all_bytes(self):
        registry, replay, rows = self.inputs()
        receipt = replay.raw_sources.raw_receipt(registry)
        count = size = 0
        for row in rows:
            with self.subTest(package=row["name"]):
                n, length = replay.raw_sources.validate_raw_sources(row, registry, self.members(row), receipt)
                count += n
                size += length
                replay.validate_terms_evidence(row)
                self.assertEqual(row["classification"], "package-complete")
                alternatives = [a for g in row["terms_evidence"]["groups"] for a in g["alternatives"]]
                self.assertTrue(all(a["availability"] == "available" for a in alternatives))
                self.assertEqual({a["expression"] for a in alternatives},
                                 {"MIT", "Apache-2.0"} if row["name"].startswith("jni") else {"MIT"})
                for material in row["raw_materials"]:
                    self.assertNotIn("archive_member", material)
        self.assertEqual((count, size), (8, 38580))

    def test_raw_binding_rejects_wrong_identity_revision_metadata_scope_and_receipt(self):
        registry, replay, rows = self.inputs()
        receipt = replay.raw_sources.raw_receipt(registry)
        for original in rows:
            for mutation in ("version", "checksum", "revision", "path", "metadata", "role", "hash", "url", "missing"):
                row = copy.deepcopy(original)
                if mutation == "version":
                    row["version"] = "0.0.0"
                elif mutation == "checksum":
                    row["checksum"] = "0" * 64
                elif mutation == "revision":
                    row["raw_source_binding"]["revision"] = "0" * 40
                elif mutation == "path":
                    row["raw_source_binding"]["package_path_in_vcs"] = "other"
                elif mutation == "metadata":
                    row["raw_source_binding"]["archive_metadata"][".cargo_vcs_info.json"]["sha256"] = "0" * 64
                elif mutation == "role":
                    row["raw_materials"][0]["role"] = "reference_context"
                elif mutation == "hash":
                    row["raw_materials"][0]["material_sha256"] = "0" * 64
                elif mutation == "url":
                    row["raw_materials"][0]["url"] += "-other"
                else:
                    row["raw_materials"].pop()
                with self.subTest(package=original["name"], mutation=mutation), self.assertRaises(ValueError):
                    replay.raw_sources.validate_raw_sources(row, registry, self.members(original), receipt)
            bad_receipt = copy.deepcopy(receipt)
            record = next(r for r in bad_receipt["records"] if r["url"] == original["raw_materials"][0]["url"])
            record["identities"] = ["jni@0.21.1"]
            with self.assertRaises(ValueError):
                replay.raw_sources.validate_raw_sources(original, registry, self.members(original), bad_receipt)

    def test_changed_archived_vcs_or_retained_raw_bytes_are_rejected(self):
        registry, replay, rows = self.inputs()
        receipt = replay.raw_sources.raw_receipt(registry)
        original = rows[0]
        row = copy.deepcopy(original)
        item = row["raw_source_binding"]["archive_metadata"][".cargo_vcs_info.json"]
        vcs = json.loads(bytes.fromhex(item["bytes_hex"]))
        vcs["git"]["sha1"] = "0" * 40
        content = json.dumps(vcs).encode()
        item["bytes_hex"] = content.hex()
        item["sha256"] = hashlib.sha256(content).hexdigest()
        with self.assertRaises(ValueError):
            replay.raw_sources.validate_raw_sources(row, registry, self.members(row), receipt)
        read = replay.raw_sources.data_io.bounded_regular
        with mock.patch.object(replay.raw_sources.data_io, "bounded_regular", side_effect=lambda path, cap: read(path, cap) + b"changed"):
            with self.assertRaises(ValueError):
                replay.raw_sources.validate_raw_sources(original, registry, self.members(original), receipt)

    def test_macro_receipt_rejects_failed_requests_wrong_scope_and_budget_changes(self):
        registry, replay, _ = self.inputs()
        document = json.loads((registry / "raw-sources/receipts/jni-macro-receipt.json").read_bytes())
        self.assertEqual(len(replay.raw_sources.macro_records(document)), 4)
        for mutation in ("proposal", "status", "elapsed", "http", "curl", "identity", "revision",
                         "duplicate", "request", "object", "total", "unavailable"):
            changed = copy.deepcopy(document)
            attempt = changed["attempts"][0]
            if mutation == "proposal":
                changed["proposal_sha256"] = "0" * 64
            elif mutation == "status":
                changed["status"] = "stopped"
            elif mutation == "elapsed":
                changed["elapsed_seconds"] = 301
            elif mutation == "http":
                attempt["http_status_output"] = "302"
            elif mutation == "curl":
                attempt["curl_exit_code"] = 1
            elif mutation == "identity":
                attempt["candidate"]["package"]["checksum"] = "0" * 64
            elif mutation == "revision":
                attempt["candidate"]["revision"] = "0" * 40
            elif mutation == "duplicate":
                changed["attempts"][1] = copy.deepcopy(attempt)
            elif mutation == "request":
                attempt["request_seconds"] = 31
            elif mutation == "object":
                attempt["bytes"] = 65537
            elif mutation == "total":
                changed["body_bytes_total"] += 1
            else:
                attempt["text_available"] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                replay.raw_sources.macro_records(changed)
        read = replay.raw_sources.data_io.bounded_regular
        with mock.patch.object(replay.raw_sources.data_io, "bounded_regular", side_effect=lambda path, cap:
                               read(path, cap) + (b"changed" if path.name == "jni-macro-receipt.json" else b"")):
            with self.assertRaises(ValueError):
                replay.raw_sources.raw_receipt(registry)

    def test_raw_terms_cannot_use_reference_material_or_a_missing_binding(self):
        _, replay, rows = self.inputs()
        for original in rows:
            for mutation in ("reference", "missing", "forged"):
                row = copy.deepcopy(original)
                if mutation == "reference":
                    for material in row["raw_materials"]:
                        material["role"] = "reference_context"
                elif mutation == "missing":
                    row["raw_materials"] = []
                else:
                    row["terms_evidence"]["groups"][0]["alternatives"][0]["evidence"][0]["sha256"] = "0" * 64
                with self.subTest(package=row["name"], mutation=mutation), self.assertRaises(ValueError):
                    replay.validate_terms_evidence(row)


class RegistryGapBindingTests(unittest.TestCase):
    """Pinned repository-root license bindings for the gap pass; archive bytes are replayed separately."""

    def inputs(self):
        root = Path(__file__).resolve().parents[3]
        material = root / "docs/legal/notices-material"
        registry = material / "registry"
        spec = importlib.util.spec_from_file_location("gap_registry_replay", registry / "replay.py")
        replay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(replay)
        inventory = json.loads((registry / "inventory.json").read_bytes())
        prepared = json.loads((material / "prepared/inventory.json").read_bytes())
        gap = replay.raw_sources.GAP_PACKAGES
        rows = [r for r in inventory["identities"] if (r["name"], r["version"]) in gap]
        rows += [r for r in prepared["identities"]
                 if (r["cargo_identity"]["name"], r["cargo_identity"]["version"]) in gap]
        self.assertEqual(len(rows), len(gap))
        return registry, replay, rows, inventory, prepared

    def members(self, row):
        return {m["archive_member"]: bytes.fromhex(m["bytes_hex"])
                for m in row["raw_source_binding"]["archive_metadata"].values()}

    def test_every_gap_binding_validates_with_exact_totals_and_both_alternatives(self):
        registry, replay, rows, _, _ = self.inputs()
        sources = replay.raw_sources
        receipt = sources.raw_receipt(registry)
        files = size = 0
        for row in rows:
            name, version, _, declared = sources.gap_view(row)
            with self.subTest(package=f"{name}@{version}"):
                n, length = sources.validate_gap_binding(row, registry, self.members(row), receipt)
                files += n
                size += length
                view = sources.terms_view(row)
                replay.validate_terms_evidence(view)
                self.assertEqual(view["classification"], "package-complete")
                alternatives = [a for g in view["terms_evidence"]["groups"] for a in g["alternatives"]]
                self.assertTrue(all(a["availability"] == "available" for a in alternatives))
                self.assertEqual(sorted(a["expression"] for a in alternatives), sources.declared_identifiers(declared))
                for material in row["raw_materials"]:
                    self.assertNotIn("archive_member", material)
        self.assertEqual((files, size, len(rows)), sources.GAP_TOTALS)

    def test_gap_receipt_rejects_failed_requests_scope_and_budget_changes(self):
        registry, replay, _, _, _ = self.inputs()
        sources = replay.raw_sources
        document = json.loads((registry / "raw-sources/receipts/n1-gap-receipt.json").read_bytes())
        self.assertEqual(len(sources.gap_records(document)), 27)
        for mutation in ("schema", "status", "elapsed", "http", "curl", "blob", "identity", "url", "duplicate",
                         "request", "object", "total", "missing", "execution", "listing"):
            changed = copy.deepcopy(document)
            entry = changed["records"][0]
            if mutation == "schema":
                changed["schema"] = "other"
            elif mutation == "status":
                changed["status"] = "stopped"
            elif mutation == "elapsed":
                changed["elapsed_seconds"] = 1801
            elif mutation == "http":
                entry["http_status"] = 302
            elif mutation == "curl":
                entry["curl_exit_code"] = 1
            elif mutation == "blob":
                entry["git_blob_matches_listing"] = False
            elif mutation == "identity":
                entry["identities"] = ["jni@0.22.4"]
            elif mutation == "url":
                entry["url"] += "-other"
            elif mutation == "duplicate":
                changed["records"][1] = copy.deepcopy(entry)
            elif mutation == "request":
                entry["request_seconds"] = 31
            elif mutation == "object":
                entry["bytes"] = 65537
            elif mutation == "total":
                changed["body_bytes_total"] += 1
            elif mutation == "missing":
                changed["records"].pop()
            elif mutation == "execution":
                changed["execution_or_import"] = True
            else:
                entry["git_blob_sha1"] = "0" * 40
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                sources.gap_records(changed)
        read = sources.data_io.bounded_regular
        with mock.patch.object(sources.data_io, "bounded_regular", side_effect=lambda path, cap:
                               read(path, cap) + (b"x" if path.name == "n1-gap-receipt.json" else b"")):
            with self.assertRaises(ValueError):
                sources.raw_receipt(registry)

    def test_gap_binding_rejects_wrong_identity_revision_metadata_text_and_receipt(self):
        registry, replay, rows, _, _ = self.inputs()
        sources = replay.raw_sources
        receipt = sources.raw_receipt(registry)
        vcs = ".cargo_vcs_info.json"
        for original in rows:
            is_path = "cargo_identity" in original
            name, _, _, declared = sources.gap_view(original)
            for mutation in ("version", "checksum", "revision", "path", "repository", "metadata", "dirty",
                             "role", "hash", "url", "identifier", "missing", "extra"):
                row = copy.deepcopy(original)
                binding = row["raw_source_binding"]
                if mutation == "version":
                    (row["cargo_identity"] if is_path else row)["version"] = "0.0.0"
                elif mutation == "checksum":
                    if is_path:
                        row["upstream_archive"]["sha256"] = "0" * 64
                    else:
                        row["checksum"] = "0" * 64
                elif mutation == "revision":
                    binding["revision"] = "0" * 40
                elif mutation == "path":
                    binding["package_path_in_vcs"] += "/other"
                elif mutation == "repository":
                    binding["repository"] += "-other"
                elif mutation == "metadata":
                    binding["archive_metadata"][vcs]["sha256"] = "0" * 64
                elif mutation == "dirty":
                    info = json.loads(bytes.fromhex(binding["archive_metadata"][vcs]["bytes_hex"]))
                    info["git"]["dirty"] = True
                    content = json.dumps(info).encode()
                    binding["archive_metadata"][vcs].update(
                        bytes_hex=content.hex(), sha256=hashlib.sha256(content).hexdigest(), bytes=len(content))
                elif mutation == "role":
                    row["raw_materials"][0]["role"] = "reference_context"
                elif mutation == "hash":
                    row["raw_materials"][0]["material_sha256"] = "0" * 64
                elif mutation == "url":
                    row["raw_materials"][0]["url"] += "-other"
                elif mutation == "identifier":
                    row["raw_materials"][0]["identifiers"] = ["ISC"]
                elif mutation == "missing":
                    row["raw_materials"].pop()
                else:
                    row["raw_materials"].append(copy.deepcopy(row["raw_materials"][0]))
                archived = self.members(row if mutation == "dirty" else original)
                with self.subTest(package=name, mutation=mutation), self.assertRaises(ValueError):
                    sources.validate_gap_binding(row, registry, archived, receipt)
            row = copy.deepcopy(original)
            (row["package_manifest"] if is_path else row)["declared_license"] = "ISC"
            with self.subTest(package=name, mutation="declared"), self.assertRaises(ValueError):
                sources.validate_gap_binding(row, registry, self.members(original), receipt)
            bad = copy.deepcopy(receipt)
            record = next(r for r in bad["records"] if r["url"] == original["raw_materials"][0]["url"])
            record["identities"] = ["jni@0.22.4"]
            with self.subTest(package=name, mutation="receipt"), self.assertRaises(ValueError):
                sources.validate_gap_binding(original, registry, self.members(original), bad)
            read = sources.data_io.bounded_regular
            with mock.patch.object(sources.data_io, "bounded_regular", side_effect=lambda path, cap:
                                   read(path, cap) + (b"x" if "raw-sources/" in path.as_posix()
                                                      and "receipts" not in path.as_posix() else b"")):
                with self.subTest(package=name, mutation="bytes"), self.assertRaises(ValueError):
                    sources.validate_gap_binding(original, registry, self.members(original), receipt)

    def test_swapped_license_text_is_rejected_even_with_matching_hashes(self):
        registry, replay, rows, _, _ = self.inputs()
        sources = replay.raw_sources
        receipt = sources.raw_receipt(registry)
        row = next(r for r in rows if sources.gap_view(r)[0] == "yamux")
        apache = next(m for m in row["raw_materials"] if m["source_file"] == "LICENSE-APACHE")
        mit = next(m for m in row["raw_materials"] if m["source_file"] == "LICENSE-MIT")
        read = sources.data_io.bounded_regular
        mit_bytes = read(registry / mit["material_path"], 65536)
        for record in receipt["records"]:
            if record["url"] == apache["url"]:
                record.update(bytes=len(mit_bytes), sha256=hashlib.sha256(mit_bytes).hexdigest(),
                              git_blob_sha1=hashlib.sha1(b"blob %d\0" % len(mit_bytes) + mit_bytes).hexdigest())
        apache.update(material_bytes=len(mit_bytes), material_sha256=hashlib.sha256(mit_bytes).hexdigest())
        with mock.patch.object(sources.data_io, "bounded_regular", side_effect=lambda path, cap:
                               mit_bytes if path.name == "LICENSE-APACHE" else read(path, cap)):
            with self.assertRaises(ValueError):
                sources.validate_gap_binding(row, registry, self.members(row), receipt)

    def test_corpus_counts_remaining_gaps_and_raw_tree_layout_are_exact(self):
        registry, _, _, inventory, prepared = self.inputs()
        complete = {"package-complete", "preserved_complete_text"}
        registry_rows = inventory["identities"]
        path_rows = prepared["identities"]
        available = sum(r["classification"] in complete for r in registry_rows)
        self.assertEqual((available, len(registry_rows)), (517, 533))
        self.assertEqual(inventory["counts"]["registry_text_available_identities"], 517)
        self.assertEqual(len(path_rows), 17)
        self.assertTrue(all(r.get("classification", "package-complete") == "package-complete" for r in path_rows))
        remaining = sorted(r["name"] + "@" + r["version"] for r in registry_rows if r["classification"] not in complete)
        self.assertEqual(remaining, sorted([
            "base45@3.2.0", "block2@0.6.2", "dispatch2@0.3.1", "enum-assoc@1.4.1",
            "if-watch@3.2.2", "objc2@0.6.5", "objc2-core-foundation@0.3.2", "objc2-core-wlan@0.3.2",
            "objc2-encode@4.1.0", "objc2-foundation@0.3.2", "objc2-security@0.3.2",
            "objc2-security-foundation@0.3.2", "objc2-system-configuration@0.3.2", "pharos@0.5.3",
            "winapi-i686-pc-windows-gnu@0.4.0", "winapi-x86_64-pc-windows-gnu@0.4.0"]))
        prefix = "docs/legal/notices-material/registry/"
        referenced = {m["material_path"] for r in registry_rows for m in r.get("raw_materials", [])}
        referenced |= {m["material_path"].removeprefix(prefix) for r in path_rows for m in r.get("raw_materials", [])}
        raw_root = registry / "raw-sources"
        on_disk = {p.relative_to(registry).as_posix() for p in raw_root.rglob("*")
                   if p.is_file() and p.parent.name != "receipts"}
        self.assertEqual(on_disk, referenced)
        for directory in [raw_root, *[p for p in raw_root.rglob("*") if p.is_dir()]]:
            self.assertLessEqual(len(list(directory.iterdir())), 7, directory)


class RegistryBlockerBindingTests(unittest.TestCase):
    """Predecessor-repository text and package license index, with the provenance class visible downstream."""

    def inputs(self):
        root = Path(__file__).resolve().parents[3]
        registry = root / "docs/legal/notices-material/registry"
        spec = importlib.util.spec_from_file_location("blocker_registry_replay", registry / "replay.py")
        replay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(replay)
        rows = json.loads((registry / "inventory.json").read_bytes())["identities"]
        by_key = {(r["name"], r["version"]): r for r in rows}
        return root, registry, replay.blocker_sources, by_key

    def members(self, row):
        return {m["archive_member"]: bytes.fromhex(m["bytes_hex"])
                for m in row["raw_source_binding"]["archive_metadata"].values()}

    def test_predecessor_binding_validates_and_is_labelled(self):
        _, registry, sources, rows = self.inputs()
        receipt = sources.blocker_receipt(registry)
        row = rows[("futures-bounded", "0.3.0")]
        self.assertEqual(sources.validate_predecessor(row, registry, self.members(row), receipt), (1, 1074))
        self.assertEqual((1, 1074, 1), sources.TOTALS)
        self.assertEqual(row["provenance_class"], "predecessor-repository")
        self.assertEqual(row["classification"], "package-complete")
        old = row["raw_source_binding"]["predecessor"]
        self.assertEqual((old["version"], old["package_path_in_vcs"]), ("0.2.3", "misc/futures-bounded"))
        self.assertEqual(row["raw_source_binding"]["text_repository"], "https://github.com/libp2p/rust-libp2p")

    def test_predecessor_binding_rejects_scope_class_metadata_text_and_receipt_changes(self):
        _, registry, sources, rows = self.inputs()
        receipt = sources.blocker_receipt(registry)
        original = rows[("futures-bounded", "0.3.0")]
        vcs = ".cargo_vcs_info.json"
        for mutation in ("version", "checksum", "class", "binding_class", "revision", "path", "repository",
                         "text_revision", "text_repository", "metadata", "dirty", "changelog", "old_sha",
                         "old_version", "old_path", "old_meta", "role", "hash", "url", "identifier", "missing",
                         "extra", "declared"):
            row = copy.deepcopy(original)
            binding, old = row["raw_source_binding"], row["raw_source_binding"]["predecessor"]
            members = self.members(original)
            if mutation == "version":
                row["version"] = "0.0.0"
            elif mutation == "checksum":
                row["checksum"] = "0" * 64
            elif mutation == "class":
                del row["provenance_class"]
            elif mutation == "binding_class":
                binding["provenance_class"] = "other"
            elif mutation == "revision":
                binding["revision"] = "0" * 40
            elif mutation == "path":
                binding["package_path_in_vcs"] = "x"
            elif mutation == "repository":
                binding["repository"] += "-other"
            elif mutation == "text_revision":
                binding["text_revision"] = "0" * 40
            elif mutation == "text_repository":
                binding["text_repository"] += "-other"
            elif mutation == "metadata":
                binding["archive_metadata"][vcs]["sha256"] = "0" * 64
            elif mutation == "dirty":
                info = json.loads(members[f"futures-bounded-0.3.0/{vcs}"])
                info["git"]["dirty"] = True
                content = json.dumps(info).encode()
                binding["archive_metadata"][vcs].update(
                    bytes_hex=content.hex(), sha256=hashlib.sha256(content).hexdigest(), bytes=len(content))
                members = self.members(row)
            elif mutation == "changelog":
                content = members["futures-bounded-0.3.0/CHANGELOG.md"].replace(b"libp2p/rust-libp2p", b"other/repo")
                binding["archive_metadata"]["CHANGELOG.md"].update(
                    bytes_hex=content.hex(), sha256=hashlib.sha256(content).hexdigest(), bytes=len(content))
                members = self.members(row)
            elif mutation == "old_sha":
                old["sha256"] = "0" * 64
            elif mutation == "old_version":
                old["version"] = "0.2.4"
            elif mutation == "old_path":
                old["package_path_in_vcs"] = ""
            elif mutation == "old_meta":
                content = bytes.fromhex(old["archive_metadata"][vcs]["bytes_hex"]).replace(b"edca09b5", b"0000000a")
                old["archive_metadata"][vcs].update(
                    bytes_hex=content.hex(), sha256=hashlib.sha256(content).hexdigest(), bytes=len(content))
            elif mutation == "role":
                row["raw_materials"][0]["role"] = "reference_context"
            elif mutation == "hash":
                row["raw_materials"][0]["material_sha256"] = "0" * 64
            elif mutation == "url":
                row["raw_materials"][0]["url"] += "-other"
            elif mutation == "identifier":
                row["raw_materials"][0]["identifiers"] = ["ISC"]
            elif mutation == "missing":
                row["raw_materials"].pop()
            elif mutation == "extra":
                row["raw_materials"].append(copy.deepcopy(row["raw_materials"][0]))
            else:
                row["declared_license"] = "ISC"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                sources.validate_predecessor(row, registry, members, receipt)
        bad = copy.deepcopy(receipt)
        bad["records"][0]["identities"] = ["jni@0.22.4"]
        with self.assertRaises(ValueError):
            sources.validate_predecessor(original, registry, self.members(original), bad)
        read = sources.data_io.bounded_regular
        with mock.patch.object(sources.data_io, "bounded_regular", side_effect=lambda path, cap:
                               read(path, cap) + (b"x" if path.name == "LICENSE" else b"")):
            with self.assertRaises(ValueError):
                sources.validate_predecessor(original, registry, self.members(original), receipt)

    def test_blocker_receipt_rejects_failed_request_scope_and_budget_changes(self):
        _, registry, sources, _ = self.inputs()
        document = json.loads((registry / sources.RECEIPT_REL).read_bytes())
        self.assertEqual(len(sources.receipt_records(document)), 1)
        for mutation in ("schema", "status", "elapsed", "http", "curl", "blob", "identity", "url", "request",
                         "object", "total", "missing", "execution", "listing", "requests"):
            changed = copy.deepcopy(document)
            entry = changed["records"][0]
            if mutation == "schema":
                changed["schema"] = "other"
            elif mutation == "status":
                changed["status"] = "stopped"
            elif mutation == "elapsed":
                changed["elapsed_seconds"] = 301
            elif mutation == "http":
                entry["http_status"] = 302
            elif mutation == "curl":
                entry["curl_exit_code"] = 1
            elif mutation == "blob":
                entry["git_blob_matches_listing"] = False
            elif mutation == "identity":
                entry["identities"] = ["jni@0.22.4"]
            elif mutation == "url":
                entry["url"] += "-other"
            elif mutation == "request":
                entry["request_seconds"] = 31
            elif mutation == "object":
                entry["bytes"] = 65537
            elif mutation == "total":
                changed["body_bytes_total"] += 1
            elif mutation == "missing":
                changed["records"].pop()
            elif mutation == "execution":
                changed["execution_or_import"] = True
            elif mutation == "requests":
                changed["bounds"]["requests_max"] = 2
            else:
                entry["git_blob_sha1"] = "0" * 40
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                sources.receipt_records(changed)
        read = sources.data_io.bounded_regular
        with mock.patch.object(sources.data_io, "bounded_regular", side_effect=lambda path, cap:
                               read(path, cap) + (b"x" if path.name == "blocker-receipt.json" else b"")):
            with self.assertRaises(ValueError):
                sources.blocker_receipt(registry)

    def test_license_index_validates_and_rejects_unmapped_or_swapped_texts(self):
        _, registry, sources, rows = self.inputs()
        original = rows[("ring", "0.17.14")]
        index = original["license_index"]
        member = index["archive_member"]
        terms = next(m for m in original["materials"] if m["archive_member"] == member)
        members = {member: (registry / terms["material_path"]).read_bytes()}
        self.assertEqual(sources.validate_index(original, registry, members), 2)
        self.assertEqual(original["provenance_class"], "package-license-index")
        self.assertEqual(original["classification"], "package-complete")
        for mutation in ("class", "declared", "checksum", "member", "maps", "expression", "role", "material",
                         "hash", "evidence", "classification", "named"):
            row = copy.deepcopy(original)
            changed = dict(members)
            if mutation == "class":
                row["provenance_class"] = "other"
            elif mutation == "declared":
                row["declared_license"] = "ISC"
            elif mutation == "checksum":
                row["checksum"] = "0" * 64
            elif mutation == "member":
                row["license_index"]["archive_member"] += "x"
            elif mutation == "maps":
                del row["license_index"]["maps"]["LICENSE-BoringSSL"]
            elif mutation == "expression":
                row["license_index"]["maps"]["LICENSE-other-bits"]["expression"] = "Apache-2.0"
            elif mutation == "role":
                next(m for m in row["materials"] if m["archive_member"].endswith("LICENSE-BoringSSL"))["role"] = "component_terms"
            elif mutation == "material":
                row["materials"] = [m for m in row["materials"] if not m["archive_member"].endswith("LICENSE-other-bits")]
            elif mutation == "hash":
                row["license_index"]["maps"]["LICENSE-other-bits"]["sha256"] = "0" * 64
            elif mutation == "evidence":
                row["terms_evidence"]["groups"][1]["alternatives"][0]["evidence"][0]["material_path"] += "x"
            elif mutation == "classification":
                row["classification"] = "component-only"
            else:
                changed = {member: members[member].replace(b"LICENSE-BoringSSL", b"LICENSE-Other")}
                row["license_index"]["sha256"] = hashlib.sha256(changed[member]).hexdigest()
                row["license_index"]["bytes"] = len(changed[member])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                sources.validate_index(row, registry, changed)
        read = sources.data_io.bounded_regular
        with mock.patch.object(sources.data_io, "bounded_regular", side_effect=lambda path, cap: (
                read(path, cap).replace(b"Permission to use, copy", b"Permission to use, kopy")
                if path.name == "LICENSE-other-bits" else read(path, cap))):
            with self.assertRaises(ValueError):
                sources.validate_index(original, registry, members)

    def test_provenance_class_reaches_corpus_manifests_and_notices(self):
        root, _, _, _ = self.inputs()
        notices = root / ".github/actions/dependency-license/notices"
        loaded = {}
        with mock.patch.dict(sys.modules):
            for name in ("notice_corpus", "notice_render"):
                spec = importlib.util.spec_from_file_location(name, notices / (name + ".py"))
                loaded[name] = importlib.util.module_from_spec(spec)
                sys.modules[name] = loaded[name]
                spec.loader.exec_module(loaded[name])
        entries, _ = loaded["notice_corpus"].load(root)
        expected = {("futures-bounded", "0.3.0"): "predecessor-repository", ("ring", "0.17.14"): "package-license-index"}
        classes = {(e.name, e.version): e.provenance for e in entries.values() if e.provenance}
        self.assertEqual(classes, expected)
        found = [e for e in entries.values() if (e.name, e.version) in expected]
        self.assertTrue(all(e.complete for e in found))
        manifest = json.loads((root / "docs/legal/notices-material/release/manifest-x86_64-unknown-linux-gnu.json").read_bytes())
        self.assertEqual({(i["name"], i["version"]): i["provenance"] for i in manifest["identities"] if "provenance" in i},
                         expected)
        text, _ = loaded["notice_render"].render_notices(root, "t", ["p"], found, {"registry": "0", "prepared": "0"}, [])
        for (name, version), cls in expected.items():
            self.assertIn(f"{name} {version} | ".encode(), text)
            self.assertIn(f"registry provenance={cls} |".encode(), text)
