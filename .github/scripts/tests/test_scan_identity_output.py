"""Unit tests for scan_identity_output.py.

Oracle literals are independent of scanner helpers.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

import scan_identity_output as scanner  # noqa: E402

# Independent oracle literals (RFC 8032 section 7.1).
SEED1_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SEED2_HEX = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
SEED3_HEX = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
PUB1_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
PUB2_HEX = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
PUB3_HEX = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"

RFC_SEEDS_HEX = [SEED1_HEX, SEED2_HEX, SEED3_HEX]
PUBS_HEX = [PUB1_HEX, PUB2_HEX, PUB3_HEX]

# Deterministic repeated-byte fixtures exercised by identity storage and
# security tests (storage.rs zeros/0xcd junk; security.rs 0x11/0x22/0x33).
# The 0xcd entry is the 32-byte run embedded in storage.rs's 33-byte
# junk fixture (vec![0xcd; 33]).
REPEATED_SEEDS = [
    bytes([0x00]) * 32,
    bytes([0x02]) * 32,
    bytes([0x06]) * 32,
    bytes([0x07]) * 32,
    bytes([0x08]) * 32,
    bytes([0x11]) * 32,
    bytes([0x22]) * 32,
    bytes([0x33]) * 32,
    bytes([0xCD]) * 32,
    bytes([9]) * 32,
    bytes([11]) * 32,
    bytes([3, 10, 17, 24, 31, 38, 45, 52, 59, 66, 73, 80, 87, 94, 101, 108, 115, 122, 129, 136, 143, 150, 157, 164, 171, 178, 185, 192, 199, 206, 213, 220]),
]

# All fixtures: three RFC hex seeds plus deterministic repeated-byte seeds.
ALL_SEEDS = [bytes.fromhex(h) for h in RFC_SEEDS_HEX] + REPEATED_SEEDS

# A realistic-looking clean cargo test log.
CLEAN_LOG = (
    b"   Compiling shaar v0.1.0 (crates/shaar)\n"
    b"    Finished `test` profile [unoptimized + debuginfo] target(s)\n"
    b"     Running unittests src/lib.rs\n"
    b"\n"
    b"running 12 tests\n"
    b"test identity::store::tests::basic ... ok\n"
    b"test store::tests::roundtrip ... ok\n"
    b"\n"
    b"test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured\n"
)


def debug_array(raw: bytes, sep: str = ", ") -> str:
    """Rust Debug decimal array for independently given bytes."""
    return "[" + sep.join(str(b) for b in raw) + "]"


def run_main(path: str) -> tuple[int, str]:
    """Run scanner.main with captured stdout; return (code, output)."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = scanner.main(["scan_identity_output.py", path])
    return code, buffer.getvalue()


def write_log(tmp: str, data: bytes) -> str:
    path = os.path.join(tmp, "log.txt")
    with open(path, "wb") as handle:
        handle.write(data)
    return path


class DetectionTest(unittest.TestCase):
    """Every fixture must be found in each supported representation."""

    def _assert_detected(self, data: bytes) -> None:
        self.assertTrue(scanner.scan_bytes(data))

    def test_raw_bytes_embedded(self) -> None:
        for seed in ALL_SEEDS:
            self._assert_detected(
                b"some log line\nnoise " + seed + b" more noise\n"
            )

    def test_raw_hex_collision_is_detected(self) -> None:
        self.assertTrue(scanner.scan_bytes(b"3" * 40))
        self.assertTrue(scanner.scan_bytes(b"33" * 31 + b"34"))

    def test_hex_lowercase(self) -> None:
        for seed in ALL_SEEDS:
            self._assert_detected(b"seed=" + seed.hex().encode() + b";done")

    def test_hex_uppercase(self) -> None:
        for seed in ALL_SEEDS:
            self._assert_detected(b"seed=" + seed.hex().upper().encode())

    def test_hex_mixed_case(self) -> None:
        for seed in ALL_SEEDS:
            hex_str = seed.hex()
            mixed = "".join(
                c.upper() if i % 2 else c.lower()
                for i, c in enumerate(hex_str)
            )
            self._assert_detected(b"seed=" + mixed.encode())

    def test_decimal_tokens_are_bounded_and_arrays_are_nested(self) -> None:
        seed = bytes.fromhex(SEED1_HEX)
        nested = b"outer [" + debug_array(seed).encode() + b"]"
        self.assertTrue(scanner.scan_bytes(nested))
        self.assertFalse(scanner.scan_bytes(b"[" + b"9" * 5000 + b"]"))
        self.assertFalse(scanner.scan_bytes(b"[999, " + debug_array(seed)[1:].encode()))

    def test_debug_array_exact(self) -> None:
        for seed in ALL_SEEDS:
            self._assert_detected(debug_array(seed).encode())

    def test_debug_array_extra_whitespace(self) -> None:
        for seed in ALL_SEEDS:
            self._assert_detected(debug_array(seed, sep=" ,  ").encode())
            self._assert_detected(debug_array(seed, sep=",\n ").encode())

    def test_debug_array_embedded_in_log(self) -> None:
        self._assert_detected(
            (
                "INFO identity::key Debug: "
                + debug_array(bytes.fromhex(SEED2_HEX))
                + " end"
            ).encode()
        )
        self._assert_detected(
            (
                "assertion failed, left: " + debug_array(bytes([0x33]) * 32)
            ).encode()
        )

    def test_brackets_whitespace(self) -> None:
        spaced = "[ " + debug_array(bytes.fromhex(SEED3_HEX))[1:-1] + " ]"
        self._assert_detected(spaced.encode())

    def test_33_byte_cd_junk_fixture_contains_run(self) -> None:
        """storage.rs vec![0xcd; 33] contains the 32-byte run."""
        junk = bytes([0xCD]) * 33
        self.assertTrue(scanner.scan_bytes(junk))


class ExactMatchTest(unittest.TestCase):
    """Prefixes and over-long arrays must not match."""

    def test_31_value_prefix_array_not_matched(self) -> None:
        for seed in ALL_SEEDS:
            values = debug_array(seed)[1:-1].split(", ")[:31]
            self.assertFalse(
                scanner.scan_bytes(("[" + ", ".join(values)).encode())
            )
            self.assertFalse(
                scanner.scan_bytes(("[" + ", ".join(values) + "]").encode())
            )

    def test_hex_prefix_not_matched(self) -> None:
        for seed in ALL_SEEDS:
            if seed == bytes([0x33]) * 32:
                continue
            prefix = seed.hex()[:40].encode()
            self.assertFalse(scanner.scan_bytes(prefix))
            self.assertFalse(scanner.scan_bytes(b"seed=" + prefix + b"..."))

    def test_33_byte_array_with_seed_prefix_not_matched(self) -> None:
        for seed in ALL_SEEDS:
            values = debug_array(seed)[1:-1].split(", ")
            longer = "[" + ", ".join(values + ["0"]) + "]"
            self.assertFalse(scanner.scan_bytes(longer.encode()))


class NearMissTest(unittest.TestCase):
    """Single-byte changes and public keys must not match."""

    def test_single_byte_change_first_middle_last(self) -> None:
        for seed in ALL_SEEDS:
            for position in (0, 15, 31):
                changed = bytearray(seed)
                changed[position] ^= 0x01
                changed = bytes(changed)
                self.assertFalse(scanner.scan_bytes(changed))
                self.assertFalse(scanner.scan_bytes(debug_array(changed).encode()))
                if seed != bytes([0x33]) * 32:
                    self.assertFalse(scanner.scan_bytes(changed.hex().encode()))

    def test_repeated_byte_seed_trailing_change(self) -> None:
        """[0x33]*31 + [0x34] must not match the [0x33]*32 fixture."""
        changed = bytes([0x33]) * 31 + bytes([0x34])
        target = bytes([0x33]) * 32
        self.assertFalse(scanner.scan_bytes(changed))
        self.assertFalse(scanner.scan_bytes(debug_array(changed).encode()))
        self.assertTrue(scanner.scan_bytes(changed.hex().encode()))

    def test_public_keys_do_not_match(self) -> None:
        for pub_hex in PUBS_HEX:
            raw = bytes.fromhex(pub_hex)
            self.assertFalse(scanner.scan_bytes(raw))
            self.assertFalse(scanner.scan_bytes(pub_hex.encode()))
            self.assertFalse(scanner.scan_bytes(pub_hex.upper().encode()))
            self.assertFalse(scanner.scan_bytes(debug_array(raw).encode()))


class CleanInputTest(unittest.TestCase):
    """A realistic clean log must exit 0."""

    def test_clean_log_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log(tmp, CLEAN_LOG)
            code, out = run_main(path)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "identity output scan: clean")

    def test_exact_read_limit_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log(tmp, b"x" * scanner.READ_LIMIT)
            code, out = run_main(path)
        self.assertEqual(code, 0)
        self.assertEqual(out, "identity output scan: clean\n")

    def test_chunk_boundary_crossing_seed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log(tmp, b"x" * (scanner.CHUNK_SIZE - 10) + ALL_SEEDS[0])
            code, out = run_main(path)
        self.assertEqual(code, 1)
        self.assertEqual(out, "identity output scan: known seed material detected\n")

    def test_empty_file_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log(tmp, b"")
            code, out = run_main(path)
        self.assertEqual(code, 0)
        self.assertIn("clean", out)


class FailClosedTest(unittest.TestCase):
    """IO problems must fail closed with exit 1 and static messages."""

    def test_missing_file(self) -> None:
        code, out = run_main(os.path.join("no", "such", "file.log"))
        self.assertEqual(code, 1)
        self.assertEqual(out, "identity output scan: cannot read input\n")

    def test_unreadable_file_mocked(self) -> None:
        buffer = io.StringIO()
        with mock.patch(
            "builtins.open", side_effect=PermissionError("denied")
        ), contextlib.redirect_stdout(buffer):
            code = scanner.main(["scan_identity_output.py", "x.log"])
        self.assertEqual(code, 1)
        self.assertEqual(buffer.getvalue(), "identity output scan: cannot read input\n")

    def test_invalid_path_value_error_is_static(self) -> None:
        buffer = io.StringIO()
        with mock.patch("builtins.open", side_effect=ValueError("secret path detail")), contextlib.redirect_stdout(buffer):
            code = scanner.main(["scan_identity_output.py", "SENSITIVE"])
        self.assertEqual(code, 1)
        self.assertEqual(buffer.getvalue(), "identity output scan: cannot read input\n")

    def test_os_error_text_is_redacted(self) -> None:
        buffer = io.StringIO()
        with mock.patch("builtins.open", side_effect=OSError("SECRET-DIAGNOSTIC")), contextlib.redirect_stdout(buffer):
            code = scanner.main(["scan_identity_output.py", "SENSITIVE"])
        self.assertEqual(code, 1)
        self.assertEqual(buffer.getvalue(), "identity output scan: cannot read input\n")

    def test_oversize_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "big.log")
            with open(path, "wb") as handle:
                handle.seek(scanner.READ_LIMIT + 1)
                handle.write(b"\0")
            code, out = run_main(path)
        self.assertEqual(code, 1)
        self.assertEqual(out, "identity output scan: cannot read input\n")

    def test_read_bounded_raises_on_oversize(self) -> None:
        chunk = b"x" * scanner.CHUNK_SIZE
        fake = io.BytesIO(chunk * 70)  # ~4.3 MiB, above the 4 MiB limit
        with mock.patch(
            "builtins.open", mock.mock_open(read_data=b"")
        ) as mocked:
            mocked.return_value.read = lambda size: fake.read(size)
            with self.assertRaises(scanner.ScanInputError):
                scanner.read_bounded("fake.log")

    def test_partial_trailing_seed_beyond_limit_is_failure(self) -> None:
        """Truncated input is not reported clean: oversize fails closed."""
        payload = b"a" * scanner.READ_LIMIT + bytes.fromhex(SEED1_HEX)[:16]
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log(tmp, payload)
            code, out = run_main(path)
        self.assertEqual(code, 1)
        self.assertEqual(out, "identity output scan: cannot read input\n")


class RedactionTest(unittest.TestCase):
    """No fixture material or log content may ever be printed."""

    def _forbidden_fragments(self) -> list[bytes]:
        fragments: list[bytes] = []
        for hex_str in RFC_SEEDS_HEX + PUBS_HEX:
            raw = bytes.fromhex(hex_str)
            fragments.append(raw)
            fragments.append(hex_str.encode())
            fragments.append(hex_str.upper().encode())
            fragments.append(debug_array(raw).encode())
        for seed in REPEATED_SEEDS:
            fragments.append(seed)
            fragments.append(debug_array(seed).encode())
        return fragments

    def test_detection_output_is_redacted(self) -> None:
        leak = (
            b"seed=" + SEED1_HEX.encode() + b" raw="
            + bytes.fromhex(SEED1_HEX) + b" dbg="
            + debug_array(bytes.fromhex(SEED1_HEX)).encode() + b"\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log(tmp, leak)
            code, out = run_main(path)
        self.assertEqual(code, 1)
        encoded_out = out.encode("utf-8", "replace")
        for fragment in self._forbidden_fragments():
            self.assertNotIn(fragment, encoded_out)

    def test_repeated_byte_leak_output_is_redacted(self) -> None:
        leaked = bytes([0x33]) * 32
        leak = (
            b"left: " + leaked.hex().encode() + b", right: "
            + debug_array(leaked).encode() + b"\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log(tmp, leak)
            code, out = run_main(path)
        self.assertEqual(code, 1)
        encoded_out = out.encode("utf-8", "replace")
        for fragment in (
            leaked,
            leaked.hex().encode(),
            leaked.hex().upper().encode(),
            debug_array(leaked).encode(),
        ):
            self.assertNotIn(fragment, encoded_out)

    def test_io_failure_output_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log(tmp, bytes.fromhex(SEED2_HEX))
            code, out = run_main(os.path.join(tmp, "missing.log"))
            self.assertEqual(code, 1)
            encoded_out = out.encode("utf-8", "replace")
            for fragment in self._forbidden_fragments():
                self.assertNotIn(fragment, encoded_out)


class CliTest(unittest.TestCase):
    """Argument handling."""

    def test_no_arguments(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = scanner.main(["scan_identity_output.py"])
        self.assertEqual(code, 2)
        self.assertEqual(buffer.getvalue(), "usage: scan_identity_output.py <path-to-log>\n")

    def test_too_many_arguments(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = scanner.main(["s", "a.log", "b.log"])
        self.assertEqual(code, 2)
        self.assertEqual(buffer.getvalue(), "usage: scan_identity_output.py <path-to-log>\n")

    def test_single_path_works(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log(tmp, CLEAN_LOG)
            code, _ = run_main(path)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
