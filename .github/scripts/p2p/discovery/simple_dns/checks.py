# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from simple_dns import prepare  # noqa: E402


class SimpleDnsRecipeChecks(unittest.TestCase):
    def test_archive_identity_size_and_non_execution(self):
        archive = Path(sys.argv[1])
        data = archive.read_bytes()
        self.assertLessEqual(len(data), prepare.MAX_ARCHIVE)
        self.assertEqual(hashlib.sha256(data).hexdigest(), prepare.ARCHIVE_SHA256)
        files = prepare.archive_files(archive)
        self.assertIn("src/dns/packet.rs", files)

    def test_recipe_patch_roundtrip_from_exact_archive_bytes(self):
        files = prepare.archive_files(Path(sys.argv[1]))
        original = files["src/dns/packet.rs"]
        patched = prepare.transform(files)["src/dns/packet.rs"]
        self.assertEqual(prepare.reverse(patched.decode()).encode(), original)
        self.assertIn(b"if exact && data.has_remaining()", patched)
        self.assertNotEqual(patched, original)

    def test_prepared_source_drift_and_provenance_are_rejected(self):
        files = prepare.archive_files(Path(sys.argv[1]))
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "prepared"
            prepare.prepare(Path(sys.argv[1]), destination)
            root = destination / prepare.PACKAGE
            prepared_files = dict(files)
            prepared_files.update(prepare.transform(files))
            self.assertEqual(prepare.verify(root), prepared_files)
            target = root / "src/dns/packet.rs"
            target.write_bytes(target.read_bytes() + b"drift")
            with self.assertRaisesRegex(ValueError, "prepared simple-dns file digest"):
                prepare.verify(root)

    def test_wrong_archive_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            wrong = Path(temporary) / "wrong.crate"
            wrong.write_bytes(b"not a reviewed archive")
            with self.assertRaisesRegex(ValueError, "checksum"):
                prepare.archive_files(wrong)

    def test_transform_rejects_changed_original_patch_anchor(self):
        files = prepare.archive_files(Path(sys.argv[1]))
        original = files["src/dns/packet.rs"]
        files["src/dns/packet.rs"] = original.replace(b"let mut header = Header::parse(&mut data)?;", b"let header = Header::parse(&mut data)?;", 1)
        with self.assertRaisesRegex(ValueError, "parser bytes differ from verified upstream"):
            prepare.transform(files)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
