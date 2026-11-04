# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Produce one fixed external reference inside the existing publication CI step."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE.parents[1]))
import runner

REVISION = "f6ae1eb8c41e53a583341cb790db71ab266b9383"
SOURCE = "git+https://github.com/pubky/pkarr?rev=" + REVISION + "#" + REVISION
LICENSE_SHA256 = "089e801fd0cd8e0258a1e1fe226a1046bb2d702a5349a0ef5a0e232b39a29594"
REVIEWED = {
    "Cargo.toml": "e6953daab4142a665244e501963d50f527154636e5bf8b252a9f0c309fb9b9cc",
    "src/types/signed_packet.rs": "bc936c3253d1ebaf595ee9676f5f88ea6078602a57f16c188ef96fa42333030d",
    "src/types/keys.rs": "90d6686affee58a6dacd02790fc005f3080dad2151f22ac6baf7e2cbb85f69c4",
}


def main() -> int:
    root = runner.repository_root()
    evidence = root / "target/publication-evidence/reference"
    evidence.mkdir(parents=True, exist_ok=False)
    workspace = evidence / "workspace"
    workspace.mkdir()
    logs = evidence / "logs"
    logs.mkdir()
    for name in ("Cargo.toml", "main.rs"):
        shutil.copyfile(HERE / name, workspace / name)
    receipt = {"status": "failed", "revision": REVISION, "commands": [],
               "plan": json.loads(os.environ["CI_PLAN_JSON"])}
    env = dict(os.environ, CARGO_TARGET_DIR=str(root / "target/publication-reference-build"))
    manifest = str(workspace / "Cargo.toml")
    try:
        if receipt["plan"]["selection"].get("publication") is not True:
            raise ValueError("independent reference requires existing publication selection")
        runner.command("lock", ["cargo", "generate-lockfile", "--manifest-path", manifest],
                       workspace, logs, receipt, env)
        raw = runner.command("metadata", ["cargo", "metadata", "--locked", "--format-version", "1",
                             "--manifest-path", manifest], workspace, logs, receipt, env)
        metadata = json.loads(raw)
        packages = [p for p in metadata["packages"] if p["name"] == "pkarr"]
        if len(packages) != 1 or packages[0]["version"] != "8.1.0" or packages[0]["source"] != SOURCE:
            raise ValueError("reference resolved to unreviewed source")
        package = packages[0]
        nodes = [n for n in metadata["resolve"]["nodes"] if n["id"] == package["id"]]
        if len(nodes) != 1 or set(nodes[0]["features"]) != {"signed_packet"}:
            raise ValueError("reference client/network features must be disabled")
        source = Path(package["manifest_path"]).parent
        retained = evidence / "reviewed-source"
        retained.mkdir()
        for index, (relative, expected) in enumerate(REVIEWED.items()):
            path = source / relative
            if runner.digest(path) != expected:
                raise ValueError("consumed reference differs from reviewed source: " + relative)
            shutil.copyfile(path, retained / (str(index) + ".source"))
        license_path = source.parent / "LICENSE"
        if runner.digest(license_path) != LICENSE_SHA256:
            raise ValueError("reference license differs from authentic reviewed bytes")
        shutil.copyfile(license_path, retained / "LICENSE")
        receipt.update(source=SOURCE, reviewed_sha256=REVIEWED,
                       lock_sha256=runner.digest(workspace / "Cargo.lock"))
        runner.command("tests", ["cargo", "test", "--locked", "--manifest-path", manifest],
                       workspace, logs, receipt, env)
        outputs = [evidence / name for name in ("native-record.bin", "native-record-repeat.bin")]
        for index, output in enumerate(outputs):
            runner.command("generate-" + str(index),
                           ["cargo", "run", "--locked", "--manifest-path", manifest, "--", str(output)],
                           workspace, logs, receipt, env)
        data = outputs[0].read_bytes()
        if not 105 <= len(data) <= 1104 or outputs[1].read_bytes() != data:
            raise ValueError("independent reference is oversized or nondeterministic")
        if runner.digest(workspace / "Cargo.lock") != receipt["lock_sha256"]:
            raise ValueError("locked reference execution changed the lock")
        receipt.update(status="passed", record_sha256=hashlib.sha256(data).hexdigest(),
                       record_size=len(data), timestamp_us=1700000000000000,
                       dns_sha256=hashlib.sha256(data[104:]).hexdigest(),
                       generator_sha256=runner.digest(workspace / "main.rs"))
        return 0
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        receipt["error"] = str(error)
        print(error, file=sys.stderr)
        return 1
    finally:
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
