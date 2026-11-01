# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Stage the archive-only timestamp fixture outside the product workspace."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import prepare


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--simple-dns-archive", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    if evidence.exists() or evidence.is_symlink():
        raise ValueError("CI evidence destination must be new")
    # Keep compiled dependency sources out of the product workspace.
    root = Path(tempfile.mkdtemp(prefix="shaar-publication-", dir=os.environ["RUNNER_TEMP"]))
    receipt = root / "evidence" / "receipt.json"
    plan = root / "ci-plan.json"
    receipt.parent.mkdir()
    try:
        original = root / "original"
        original.mkdir()
        files = prepare.archive_files(args.archive.resolve())
        prepare.validate(files)
        for name, data in files.items():
            path = original.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        plan.write_text(json.dumps(json.loads(os.environ["CI_PLAN_JSON"]), sort_keys=True), encoding="utf-8")
        result = subprocess.run([
            sys.executable, "-I", str(HERE / "runner.py"),
            "--archive", str(args.archive.resolve()), "--source", str(original),
            "--original-lock", str(original / "Cargo.lock"),
            "--simple-dns-archive", str(args.simple_dns_archive.resolve()),
            "--destination", str(root / "prepared"), "--evidence", str(receipt),
            "--plan", str(plan),
        ], check=False)
        if not receipt.is_file():
            raise ValueError("runner produced no receipt")
        return result.returncode
    except Exception as error:
        if not receipt.exists():
            receipt.write_text(json.dumps({"status": "failed", "error": str(error)}), encoding="utf-8")
        print(str(error), file=sys.stderr)
        return 1
    finally:
        shutil.copytree(receipt.parent, evidence,
                        ignore=shutil.ignore_patterns("cargo-target", "simple-dns-prepared"))
        if plan.is_file():
            shutil.copy2(plan, evidence / "ci-plan.json")


if __name__ == "__main__":
    sys.exit(main())
