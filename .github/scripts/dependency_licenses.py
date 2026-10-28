#!/usr/bin/env python3
"""CI dependency-license installation, check, and report operations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

VERSION = "0.20.2"
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
SUBPROCESS_TIMEOUT = 180
RELEASES = {
    "Windows": ("x86_64-pc-windows-msvc", "975a22143262fd27476d19ee00c7af67978426e40e1dee94eed6bbade1cf87dc"),
    "Linux": ("x86_64-unknown-linux-musl", "9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f"),
}
RECEIPTS = (
    "target/backend/provenance.json", "target/p2p/relay/provenance.json",
    "target/p2p/swarm/provenance.json", "target/p2p/dns/provenance.json",
    "target/p2p/resolver/provenance.json", "target/p2p/kad/provenance.json",
)


def install():
    platform = os.environ["RUNNER_OS"]
    triple, expected = RELEASES[platform]
    archive = f"cargo-deny-{VERSION}-{triple}.tar.gz"
    url = f"https://github.com/EmbarkStudios/cargo-deny/releases/download/{VERSION}/{archive}"
    with tempfile.TemporaryDirectory(prefix="cargo-deny-") as isolated:
        root = Path(isolated)
        downloaded = root / archive
        subprocess.run(["curl", "--fail", "--location", "--max-time", "120", "--max-filesize", str(MAX_ARCHIVE_BYTES), url, "--output", str(downloaded)], check=True, timeout=SUBPROCESS_TIMEOUT)
        if downloaded.stat().st_size > MAX_ARCHIVE_BYTES:
            raise RuntimeError("cargo-deny archive exceeds size limit")
        if hashlib.sha256(downloaded.read_bytes()).hexdigest() != expected:
            raise RuntimeError("cargo-deny archive checksum mismatch")
        extracted = root / "extract"
        extracted.mkdir()
        with tarfile.open(downloaded, "r:gz") as bundle:
            bundle.extractall(extracted, filter="data")
        suffix = ".exe" if platform == "Windows" else ""
        binaries = list(extracted.rglob("cargo-deny" + suffix))
        if len(binaries) != 1 or not binaries[0].is_file():
            raise RuntimeError("expected exactly one cargo-deny executable in verified archive")
        destination = Path(os.environ["RUNNER_TEMP"]) / ("cargo-deny-bin" + suffix)
        shutil.copy2(binaries[0], destination)
        destination.chmod(0o755)


def check():
    executable = Path(os.environ["RUNNER_TEMP"]) / ("cargo-deny-bin.exe" if os.environ["RUNNER_OS"] == "Windows" else "cargo-deny-bin")
    result = subprocess.run([str(executable), "--locked", "--config", ".github/deny.toml", "check", "licenses"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT)
    output = result.stdout.decode("utf-8", errors="replace")
    (Path(os.environ["RUNNER_TEMP"]) / "dependency-licenses.log").write_text(output, encoding="utf-8")
    printable = output.encode(sys.stdout.encoding or "utf-8", errors="backslashreplace").decode(sys.stdout.encoding or "utf-8")
    print(printable, end="", flush=True)
    return result.returncode


def report():
    out = Path("target/dependency-license-report")
    out.mkdir(parents=True, exist_ok=True)
    required = [Path(os.environ["RUNNER_TEMP"]) / "dependency-licenses.log", Path("Cargo.lock"), Path("Cargo.toml"), Path("target/p2p/metadata.json"), Path("target/p2p/graph-receipt.json"), *(Path(p) for p in RECEIPTS)]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError("missing required license evidence: " + ", ".join(missing))
    for path in required:
        if path.name in ("metadata.json", "graph-receipt.json") or path.name in ("Cargo.lock", "Cargo.toml"):
            shutil.copy2(path, out / path.name)
    shutil.copy2(required[0], out / required[0].name)
    for path in required[5:]:
        shutil.copy2(path, out / (path.parent.parent.name + "-" + path.parent.name + "-provenance.json"))
    receipts = {str(path): json.loads(path.read_text(encoding="utf-8")) for path in required[5:]}
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in required[1:5]}
    (out / "provenance.json").write_text(json.dumps({"evidence_sha256": hashes, "prepared_source_receipts": receipts, "note": "Receipt provenance does not establish graph coverage or legal compliance."}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("install", "check", "report"))
    operation = parser.parse_args().operation
    if operation == "install":
        install()
    elif operation == "check":
        raise SystemExit(check())
    else:
        report()
