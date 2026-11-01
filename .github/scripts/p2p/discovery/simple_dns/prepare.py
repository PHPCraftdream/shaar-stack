# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Prepare and verify the pinned, bounded simple-dns patch source."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib

ARCHIVE_SHA256 = "2b6f884fa9a8d48101774bfbd3aeb81e968dd22cffd19a372da69f183db22c1a"
PACKAGE = "simple-dns-0.12.0"
VERSION = "0.12.0"
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_ENTRIES = 128
MAX_MEMBER = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
HERE = Path(__file__).resolve().parent
START = "    /// Parses a packet from a slice of bytes\n    pub fn parse(data: &'a [u8]) -> crate::Result<Self> {\n"
END = "\n    fn parse_section<T: WireFormat<'a>>(\n"
ORIGINAL_BODY = '''        let mut data = BytesBuffer::new(data);
        let mut header = Header::parse(&mut data)?;

        let questions = Self::parse_section(&mut data, header.questions)?;
        let answers = Self::parse_section(&mut data, header.answers)?;
        let name_servers = Self::parse_section(&mut data, header.name_servers)?;
        let mut additional_records: Vec<ResourceRecord> =
            Self::parse_section(&mut data, header.additional_records)?;

        header.extract_info_from_opt_rr(
            additional_records
                .iter()
                .position(|rr| rr.rdata.type_code() == crate::TYPE::OPT)
                .map(|i| additional_records.remove(i)),
        );

        Ok(Self {
            header,
            questions,
            answers,
            name_servers,
            additional_records,
        })
    }
'''
REPLACEMENT = '''    /// Parses a packet from a slice of bytes
    pub fn parse(data: &'a [u8]) -> crate::Result<Self> {
        Self::parse_inner(data, false)
    }

    /// Parses a packet and rejects bytes after its declared sections.
    pub fn parse_exact(data: &'a [u8]) -> crate::Result<Self> {
        Self::parse_inner(data, true)
    }

    fn parse_inner(data: &'a [u8], exact: bool) -> crate::Result<Self> {
        let mut data = BytesBuffer::new(data);
        let mut header = Header::parse(&mut data)?;

        let questions = Self::parse_section(&mut data, header.questions)?;
        let answers = Self::parse_section(&mut data, header.answers)?;
        let name_servers = Self::parse_section(&mut data, header.name_servers)?;
        let mut additional_records: Vec<ResourceRecord> =
            Self::parse_section(&mut data, header.additional_records)?;

        if exact && data.has_remaining() {
            return Err(crate::SimpleDnsError::InvalidDnsPacket);
        }

        header.extract_info_from_opt_rr(
            additional_records
                .iter()
                .position(|rr| rr.rdata.type_code() == crate::TYPE::OPT)
                .map(|i| additional_records.remove(i)),
        );

        Ok(Self {
            header,
            questions,
            answers,
            name_servers,
            additional_records,
        })
    }
'''


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: digest(data) for name, data in sorted(files.items())}


def recipe() -> dict[str, str]:
    return {name: digest((HERE / name).read_bytes()) for name in ("prepare.py", "checks.py")}


def archive_files(archive: Path) -> dict[str, bytes]:
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("simple-dns archive exceeds size bound")
    if digest(archive.read_bytes()) != ARCHIVE_SHA256:
        raise ValueError("simple-dns archive checksum mismatch")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    file_paths: set[str] = set()
    directory_paths: set[str] = set()
    total = 0
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if len(members) > MAX_ENTRIES:
            raise ValueError("simple-dns archive entry bound exceeded")
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "." in path.parts
                    or "\\" in member.name or re.match(r"^[A-Za-z]:", member.name)
                    or any(":" in part for part in path.parts)
                    or not path.parts or path.parts[0] != PACKAGE or len(path.parts) > 16
                    or not (member.isfile() or member.isdir())):
                raise ValueError("unexpected simple-dns archive member")
            name = path.relative_to(PACKAGE).as_posix()
            if name == ".":
                if not member.isdir() or "" in seen:
                    raise ValueError("simple-dns package root must be a unique directory")
                seen.add("")
                continue
            normalized = name.casefold()
            if normalized in seen:
                raise ValueError("duplicate simple-dns archive path")
            if member.isdir():
                if (normalized in file_paths or any(
                        parent.as_posix().casefold() in file_paths
                        for parent in PurePosixPath(name).parents if str(parent) != ".")):
                    raise ValueError("simple-dns archive file/directory collision")
                directory_paths.add(normalized)
                seen.add(normalized)
                continue
            if any(parent.as_posix().casefold() in file_paths
                   for parent in PurePosixPath(name).parents if str(parent) != "."):
                raise ValueError("simple-dns archive file/directory prefix collision")
            if member.size < 0 or member.size > MAX_MEMBER:
                raise ValueError("simple-dns member size bound exceeded")
            if any(existing.startswith(normalized + "/") for existing in file_paths):
                raise ValueError("simple-dns archive file/directory prefix collision")
            if normalized in directory_paths:
                raise ValueError("simple-dns archive file/directory collision")
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError("simple-dns archive expansion bound exceeded")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("simple-dns archive member unreadable")
            data = stream.read(MAX_MEMBER + 1)
            if len(data) != member.size or len(data) > MAX_MEMBER:
                raise ValueError("simple-dns member length mismatch")
            seen.add(normalized)
            file_paths.add(normalized)
            files[name] = data
    return files


def validate_originals(files: dict[str, bytes]) -> None:
    manifest = tomllib.loads(files["Cargo.toml"].decode("utf-8"))
    package = manifest["package"]
    if (package["name"], package["version"]) != ("simple-dns", VERSION):
        raise ValueError("unexpected simple-dns package identity")
    license_text = files.get("LICENSE", b"").decode("utf-8")
    if package.get("license") != "MIT" or "MIT License" not in license_text:
        raise ValueError("upstream MIT license or manifest license changed")


def transform(files: dict[str, bytes]) -> dict[str, bytes]:
    validate_originals(files)
    name = "src/dns/packet.rs"
    original = files[name].decode("utf-8")
    if original.count(START) != 1 or original.count(END) != 1:
        raise ValueError("simple-dns parser anchors are not unique")
    before, remainder = original.split(START, 1)
    body, after = remainder.split(END, 1)
    original_body = body.rstrip("\n")
    expected_body = ORIGINAL_BODY.rstrip("\n")
    if original_body != expected_body or original.count("pub fn parse_exact("):
        raise ValueError("simple-dns parser bytes differ from verified upstream")
    patched = before + REPLACEMENT + END + after
    if reverse(patched).encode("utf-8") != files[name]:
        raise ValueError("simple-dns parser reverse transformation failed")
    return {name: patched.encode("utf-8")}


def reverse(patched: str) -> str:
    if patched.count(REPLACEMENT) != 1:
        raise ValueError("simple-dns patched parser shape changed")
    return patched.replace(REPLACEMENT, START + ORIGINAL_BODY, 1)


def prepare(archive: Path, destination: Path) -> Path:
    if destination.exists() or destination.is_symlink():
        raise ValueError("simple-dns destination already exists")
    original = archive_files(archive)
    changes = transform(original)
    prepared = dict(original)
    prepared.update(changes)
    if not destination.parent.is_dir():
        raise ValueError("simple-dns destination parent must exist")
    root = destination / PACKAGE
    root.mkdir(parents=True, exist_ok=False)
    for name, data in prepared.items():
        output = root.joinpath(*PurePosixPath(name).parts)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
    receipt = {
        "package": "simple-dns", "version": VERSION, "archive_sha256": ARCHIVE_SHA256,
        "license": "MIT (upstream; not relicensed)", "recipe_files": recipe(),
        "original_files": hashes(original), "prepared_files": hashes(prepared),
        "changed_files": sorted(changes),
    }
    (destination / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return root


def verify(root: Path) -> dict[str, bytes]:
    if (root.name != PACKAGE or root.is_symlink() or root.parent.is_symlink()
            or root.parent.parent.is_symlink()):
        raise ValueError("unexpected simple-dns prepared root")
    provenance = json.loads((root.parent / "provenance.json").read_text(encoding="utf-8"))
    if (provenance.get("archive_sha256") != ARCHIVE_SHA256
            or provenance.get("recipe_files") != recipe()
            or provenance.get("package") != "simple-dns"
            or provenance.get("version") != VERSION
            or provenance.get("license") != "MIT (upstream; not relicensed)"
            or provenance.get("changed_files") != ["src/dns/packet.rs"]):
        raise ValueError("simple-dns provenance or preparation recipe mismatch")
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("link in prepared simple-dns source")
        relative = path.relative_to(root).as_posix().casefold()
        if path.is_dir():
            directories.add(relative)
        elif path.is_file():
            if relative in files or relative in directories:
                raise ValueError("duplicate prepared simple-dns path")
            files[path.relative_to(root).as_posix()] = path.read_bytes()
    if any(name.casefold() in directories for name in files):
        raise ValueError("prepared simple-dns file/directory collision")
    if hashes(files) != provenance.get("prepared_files"):
        raise ValueError("prepared simple-dns file digest mismatch")
    if sorted(files) != sorted(provenance.get("original_files", {})):
        raise ValueError("prepared simple-dns file set differs from original")
    restored = dict(files)
    restored["src/dns/packet.rs"] = reverse(restored["src/dns/packet.rs"].decode("utf-8")).encode("utf-8")
    validate_originals(restored)
    if hashes(restored) != provenance.get("original_files"):
        raise ValueError("simple-dns original-file reverse verification failed")
    return files


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="mode", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--archive", type=Path, required=True)
    prepare_parser.add_argument("--destination", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.archive, args.destination)
    else:
        verify(args.source)


if __name__ == "__main__":
    main()
