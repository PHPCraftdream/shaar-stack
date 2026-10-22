"""Verify and prepare isolated Noq source as data; compilation belongs to CI."""
import argparse
import hashlib
from pathlib import Path
import tarfile
import tomllib
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from transform import apply  # noqa: E402


DIGEST = "7c1e5b6fe668491eca022f745a0a9402585626c73a7b839b3424ace15d6a9c8f"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    lock = tomllib.loads(args.lock.read_text(encoding="utf-8"))
    entry = next(p for p in lock["package"]
                 if p["name"] == "noq-proto" and p["version"] == "1.3.0")
    if args.archive.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("reviewed Noq archive must not exceed 2 MiB")
    digest = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if digest != DIGEST or entry["checksum"] != DIGEST:
        raise ValueError("Noq archive does not match the reviewed lock checksum")
    args.destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(args.archive) as archive:
        archive.extractall(args.destination, filter="data")
    root = args.destination / "noq-proto-1.3.0"
    apply(root, Path(__file__).with_name("payload_policy.rs"))
    manifest = root / "Cargo.toml"
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n[workspace]\n", encoding="utf-8")
    print(f"Prepared checksum-verified Noq spike at {root}; no downloaded code executed")


if __name__ == "__main__":
    main()
