#!/usr/bin/env python3
"""CI output oracle for known identity fixture bytes.

Scans a bounded cargo-test log for known raw, hexadecimal, and Rust Debug
representations. This is a regression check for listed fixtures, not for
unknown or runtime-generated seeds. The all-space fixture is checked only
as hexadecimal/Debug data; raw spaces cannot be distinguished from indentation.
"""

from __future__ import annotations

import sys
from typing import List, Sequence, Tuple

READ_LIMIT = 4 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


class ScanInputError(Exception):
    """The input could not be scanned safely."""


def seeds() -> Tuple[bytes, ...]:
    """Return RFC and deterministic identity-test seed fixtures."""
    return (
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
        bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
        bytes([0x00]) * 32,
        bytes([0x06]) * 32,
        bytes([0x07]) * 32,
        bytes([0x08]) * 32,
        bytes([0x02]) * 32,
        bytes([0x11]) * 32,
        bytes([0x22]) * 32,
        bytes([0x33]) * 32,
        bytes([0xCD]) * 32,
        bytes([9]) * 32,
        bytes([11]) * 32,
        *(bytes([value]) * 32 for value in (31, 32, 67, 68, 69, 71, 72, 81, 82, 83, 84)),
        bytes([3, 10, 17, 24, 31, 38, 45, 52, 59, 66, 73, 80, 87, 94, 101, 108, 115, 122, 129, 136, 143, 150, 157, 164, 171, 178, 185, 192, 199, 206, 213, 220]),
    )


def debug_form(seed: bytes) -> bytes:
    return ("[" + ", ".join(str(value) for value in seed) + "]").encode("ascii")


def contains_debug_array(data: bytes, seed: bytes) -> bool:
    expected = list(seed)
    start = 0
    while True:
        index = data.find(b"[", start)
        if index < 0:
            return False
        parsed, end = _parse_values_at(data, index)
        if parsed == expected:
            return True
        start = max(index + 1, end)


def _parse_values_at(data: bytes, start: int) -> Tuple[List[int], int]:
    index = start + 1
    values: List[int] = []
    length = len(data)
    while index < length:
        while index < length and data[index] in b" \t\r\n\v\f":
            index += 1
        if index < length and data[index] == ord("]"):
            return values, index + 1
        first = index
        while index < length and 48 <= data[index] <= 57:
            index += 1
        digits = index - first
        if digits == 0 or digits > 3:
            return [], index
        value = int(data[first:index])
        if value > 255:
            return [], index
        if len(values) < 33:
            values.append(value)
        while index < length and data[index] in b" \t\r\n\v\f":
            index += 1
        if index < length and data[index] == ord(","):
            index += 1
            continue
        if index < length and data[index] == ord("]"):
            return values, index + 1
        return [], index
    return [], index


def scan_bytes(data: bytes) -> bool:
    lowered = data.lower()
    for seed in seeds():
        hex_seed = seed.hex().encode("ascii")
        # Raw all-space bytes are indistinguishable from ordinary log indentation.
        raw_match = seed != b" " * 32 and seed in data
        if raw_match or hex_seed in lowered or contains_debug_array(data, seed):
            return True
    return False


def read_bounded(path: str, limit: int = READ_LIMIT) -> bytes:
    """Read incrementally; 4 MiB is a conservative CI test-log budget.

    Files larger than the budget fail closed rather than being partially
    scanned.
    """
    chunks = []
    total = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ScanInputError("input unavailable")
                chunks.append(chunk)
    except (OSError, ValueError) as exc:
        raise ScanInputError("input unavailable") from exc
    return b"".join(chunks)


def main(argv: Sequence[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: scan_identity_output.py <path-to-log>\n")
        return EXIT_USAGE
    try:
        data = read_bounded(argv[1])
    except ScanInputError:
        print("identity output scan: cannot read input")
        return EXIT_FAIL
    if scan_bytes(data):
        print("identity output scan: known seed material detected")
        return EXIT_FAIL
    print("identity output scan: clean")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv))
