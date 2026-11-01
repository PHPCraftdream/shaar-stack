# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Source-owned API edits for pinned iroh-dns 1.3.0."""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib

ARCHIVE_SHA256 = "80276761b56e904e26ea71d0863beef0bb8d5ab6b639cbd1338e4b615209e3a1"
PACKAGE = "iroh-dns-1.3.0"
HERE = Path(__file__).resolve().parent
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_ENTRIES = 2048
MAX_MEMBER = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recipe() -> dict[str, str]:
    names = ("prepare.py", "runner.py", "test_source.py", "graph.py", "execution/ci.py", "execution/verify.sh", "tests/publication_tests.rs")
    return {name: sha((HERE / name).read_bytes()) for name in names}


def archive_files(archive: Path) -> dict[str, bytes]:
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("pinned iroh-dns archive missing, linked, or oversized")
    if sha(archive.read_bytes()) != ARCHIVE_SHA256:
        raise ValueError("iroh-dns archive checksum mismatch")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    file_names: set[str] = set()
    directories: set[str] = set()
    total = 0
    with tarfile.open(archive, "r:gz") as source:
        for index, member in enumerate(source, 1):
            path = PurePosixPath(member.name)
            if (index > MAX_ENTRIES or path.is_absolute() or ".." in path.parts or "." in path.parts
                    or "\\" in member.name or re.match(r"^[A-Za-z]:", member.name)
                    or any(":" in part for part in path.parts) or not path.parts
                    or path.parts[0] != PACKAGE or len(path.parts) > 24
                    or not (member.isfile() or member.isdir())):
                raise ValueError("unsafe or excessive archive entry")
            name = path.relative_to(PACKAGE).as_posix()
            if name == ".":
                continue
            key = name.casefold()
            if key in seen:
                raise ValueError("duplicate case-insensitive archive path")
            parents = {p.as_posix().casefold() for p in PurePosixPath(name).parents if str(p) != "."}
            if member.isdir():
                if key in file_names or parents & file_names:
                    raise ValueError("archive file/directory collision")
                directories.add(key)
                seen.add(key)
                continue
            if parents & file_names or any(n.startswith(key + "/") for n in file_names) or key in directories:
                raise ValueError("archive file/directory prefix collision")
            if member.size < 0 or member.size > MAX_MEMBER:
                raise ValueError("archive member bound exceeded")
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError("archive expansion bound exceeded")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("archive member unreadable")
            data = stream.read(MAX_MEMBER + 1)
            if len(data) != member.size or len(data) > MAX_MEMBER:
                raise ValueError("archive member length mismatch")
            files[name] = data
            file_names.add(key)
            seen.add(key)
    return files


def verify_original(files: dict[str, bytes], expected: dict[str, bytes]) -> None:
    if files != expected:
        raise ValueError("source inventory or bytes differ from pinned archive")


def verify_prepared(files: dict[str, bytes], changed: dict[str, bytes], archive: Path, receipt: dict) -> None:
    original = archive_files(archive)
    verify_original(files, original)
    expected = transform(original)
    reverse(original, expected)
    if changed != expected:
        raise ValueError("prepared changes differ from archive-bound recipe")
    expected_receipt = {
        "archive_sha256": ARCHIVE_SHA256,
        "recipe": recipe(),
        "source_sha256": {name: sha(data) for name, data in sorted(original.items())},
        "prepared_sha256": {name: sha(data) for name, data in sorted({**original, **expected}.items())},
    }
    if receipt != expected_receipt:
        raise ValueError("prepared receipt differs from recomputed archive and recipe evidence")

def validate(files: dict[str, bytes]) -> None:
    package = tomllib.loads(files["Cargo.toml"].decode("utf-8"))["package"]
    if (package.get("name"), package.get("version"), package.get("license")) != (
            "iroh-dns", "1.3.0", "MIT OR Apache-2.0"):
        raise ValueError("unexpected upstream package identity/license")


def edits() -> dict[str, list[tuple[str, str]]]:
    old_constructor = '''    pub fn from_txt_strings(
        secret_key: &SecretKey,
        name: &str,
        values: impl IntoIterator<Item = impl AsRef<str>>,
        ttl: u32,
    ) -> Result<SignedPacket, SignedPacketBuildError> {
        let public_key = secret_key.public();'''
    new_constructor = '''    pub fn from_txt_strings(
        secret_key: &SecretKey,
        name: &str,
        values: impl IntoIterator<Item = impl AsRef<str>>,
        ttl: u32,
    ) -> Result<SignedPacket, SignedPacketBuildError> {
        Self::from_txt_strings_inner(secret_key, name, values, ttl, None)
    }

    /// Creates a packet at a supplied Unix-microsecond timestamp.
    pub(crate) fn from_txt_strings_at(
        secret_key: &SecretKey,
        name: &str,
        values: impl IntoIterator<Item = impl AsRef<str>>,
        ttl: u32,
        timestamp_micros: u64,
    ) -> Result<SignedPacket, SignedPacketBuildError> {
        Self::from_txt_strings_inner(secret_key, name, values, ttl, Some(timestamp_micros))
    }

    fn from_txt_strings_inner(
        secret_key: &SecretKey,
        name: &str,
        values: impl IntoIterator<Item = impl AsRef<str>>,
        ttl: u32,
        timestamp_micros: Option<u64>,
    ) -> Result<SignedPacket, SignedPacketBuildError> {
        let public_key = secret_key.public();'''
    old_now = "        let timestamp = Timestamp::now();\n        let signature = secret_key.sign(&signable(timestamp.as_micros(), &encoded_packet));"
    new_now = "        let timestamp = timestamp_micros.map(Timestamp::from_micros).unwrap_or_else(Timestamp::now);\n        let signature = secret_key.sign(&signable(timestamp.as_micros(), &encoded_packet));"
    old_encoding = '''    FailedBuildingPacket {
        #[error(std_err)]
        source: pkarr::SignedPacketBuildError,
    },'''
    new_encoding = '''    FailedBuildingPacket {
        #[error(std_err)]
        source: pkarr::SignedPacketBuildError,
    },
    #[error("Publication timestamp exceeds the signed i64 range")]
    InvalidTimestamp,
    #[error("Publication signing key does not match endpoint id")]
    WrongSigningKey,'''
    old_api = '''    pub fn to_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket, EncodingError> {
        self.to_attrs().to_pkarr_signed_packet(secret_key, ttl)
    }'''
    new_api = old_api + '''

    /// Creates a signed packet at a caller-supplied Unix-microsecond timestamp.
    pub fn to_pkarr_signed_packet_at(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
        timestamp_micros: u64,
    ) -> Result<pkarr::SignedPacket, EncodingError> {
        if self.endpoint_id.as_bytes() != secret_key.public().as_bytes() {
            return Err(n0_error::e!(EncodingError::WrongSigningKey));
        }
        let _ = i64::try_from(timestamp_micros)
            .map_err(|_| n0_error::e!(EncodingError::InvalidTimestamp))?;
        let attrs = self.to_attrs();
        pkarr::SignedPacket::from_txt_strings_at(
            secret_key, crate::IROH_TXT_NAME, attrs.to_txt_strings(), ttl, timestamp_micros,
        )
        .map_err(|err| n0_error::e!(EncodingError::FailedBuildingPacket, err))
    }'''
    root_attr = "#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]"
    return {
        "src/pkarr.rs": [(old_constructor, new_constructor), (old_now, new_now)],
        "src/attrs.rs": [(old_encoding, new_encoding)],
        "src/endpoint_info.rs": [(old_api, new_api)],
        "src/lib.rs": [(root_attr, "#![forbid(unsafe_code)]\n" + root_attr)],
    }


def apply(files: dict[str, bytes], pairs: dict[str, list[tuple[str, str]]]) -> dict[str, bytes]:
    if not set(pairs) <= set(files):
        raise ValueError("required upstream source missing")
    output = dict(files)
    for path, source_pairs in pairs.items():
        text = files[path].decode("utf-8")
        for old, new in source_pairs:
            if not old or old == new or text.count(old) != 1:
                raise ValueError("unique edit anchor mismatch: " + path)
            text = text.replace(old, new, 1)
        output[path] = text.encode("utf-8")
    return output


def transform(files: dict[str, bytes]) -> dict[str, bytes]:
    validate(files)
    output = apply(files, edits())
    return {name: data for name, data in output.items() if data != files[name]}


def reverse(files: dict[str, bytes], changed: dict[str, bytes]) -> None:
    pairs = edits()
    if set(changed) != set(pairs):
        raise ValueError("changed-file set differs from recipe")
    restored = dict(changed)
    for path, source_pairs in reversed(tuple(pairs.items())):
        text = restored[path].decode("utf-8")
        for old, new in reversed(source_pairs):
            if not new or text.count(new) != 1:
                raise ValueError("reverse anchor mismatch: " + path)
            text = text.replace(new, old, 1)
        restored[path] = text.encode("utf-8")
    for path in pairs:
        if restored[path] != files[path]:
            raise ValueError("reverse byte identity failed: " + path)


def transform_checked(files: dict[str, bytes], original: dict[str, bytes]) -> dict[str, bytes]:
    verify_original(files, original)
    changed = transform(files)
    reverse(files, changed)
    return changed
