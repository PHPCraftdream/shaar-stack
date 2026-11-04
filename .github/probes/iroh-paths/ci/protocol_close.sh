#!/usr/bin/env bash
# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
python -I - <<'PY'
import ast
import hashlib
import json
from pathlib import Path
import shutil
policy = ast.parse(Path(".github/scripts/backend/policy.py").read_text(encoding="utf-8"))
names = {"PROTOCOL_CLOSE_OLD", "PROTOCOL_CLOSE_NEW"}
blocks = {node.targets[0].id: ast.literal_eval(node.value) for node in policy.body
          if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
          and node.targets[0].id in names}
source = Path("target/backend/iroh/iroh-1.3.0")
destination = Path("target/protocol-close-counterfactual/iroh-1.3.0")
original = (source / "src/socket.rs").read_bytes()
old, new = (blocks[name].encode("utf-8") for name in ("PROTOCOL_CLOSE_OLD", "PROTOCOL_CLOSE_NEW"))
if original.count(new) != 1 or old in original:
    raise ValueError("bounded protocol close source anchor mismatch")
reverted = original.replace(new, old)
if reverted.count(old) != 1 or reverted.replace(old, new) != original:
    raise ValueError("protocol close byte reversal mismatch")
shutil.copytree(source, destination)
(destination / "src/socket.rs").write_bytes(reverted)
originals = {path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file()}
copied = {path.relative_to(destination): path.read_bytes() for path in destination.rglob("*") if path.is_file()}
expected = dict(originals)
expected[Path("src/socket.rs")] = reverted
if copied != expected:
    raise ValueError("counterfactual changed bytes outside the protocol close observer")
digest = lambda data: hashlib.sha256(data).hexdigest()
receipt = {
    "production_files": {path.as_posix(): digest(data) for path, data in originals.items()},
    "counterfactual_socket_sha256": digest(reverted),
    "restored_socket_sha256": digest(reverted.replace(old, new)),
    "product_lock_sha256": digest(Path("Cargo.lock").read_bytes()),
}
(destination.parent / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
print("Exact protocol-close reversal SHA256:", receipt["restored_socket_sha256"])
PY
test_name=network::signaling::endpoint::tests::high_pto_close_joins_native_socket_with_connecting_and_endpoint_aliases_retained
log="$RUNNER_TEMP/shaar-protocol-close-counterfactual.log"
if cargo --config 'patch.crates-io.iroh.path="target/protocol-close-counterfactual/iroh-1.3.0"' test -p shaar --lib --locked "$test_name" -- --exact --color never >"$log" 2>&1; then
  status=0
else
  status=$?
fi
python -I -X utf8 .github/scripts/scan_identity_output.py "$log"
cat "$log"
if [[ "$status" -eq 0 ]]; then printf 'Unbounded protocol close unexpectedly passed\n'; exit 1; fi
grep -Fx "test $test_name ... FAILED" "$log"
grep -Fx 'HIGH_PTO_INITIAL_WITNESS_OK' "$log"
grep -Fx 'HIGH_PTO_JOINED_CLOSE_DEADLINE' "$log"
grep -E '^test result: FAILED\. 0 passed; 1 failed;' "$log"
if grep -E 'Elapsed\(\(\)\)|HIGH_PTO_INITIAL_WITNESS_DEADLINE|HIGH_PTO_FIXTURE_DEADLINE|error\[E[0-9]+\]|error: could not compile' "$log"; then exit 1; fi
python -I - <<'PY'
import hashlib
import json
from pathlib import Path
source = Path("target/backend/iroh/iroh-1.3.0")
receipt = json.loads(Path("target/protocol-close-counterfactual/receipt.json").read_text(encoding="utf-8"))
actual = {path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
          for path in source.rglob("*") if path.is_file()}
if actual != receipt["production_files"]:
    raise ValueError("counterfactual mutated production sources")
if hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest() != receipt["product_lock_sha256"]:
    raise ValueError("counterfactual changed the product lock")
PY
