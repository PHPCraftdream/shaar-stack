"""Shared production Noq policy plus isolated backend regression fixtures."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts/backend"))
from policy import connection, datagrams as production_datagrams, replace, spaces, transport  # noqa: E402


def datagrams(text):
    return production_datagrams(text) + '\n#[cfg(test)]\n#[path = "payload_policy_bounds.rs"]\nmod payload_policy_bounds;\n'


def apply(root: Path, test_source: Path):
    edits = {
        "src/config/transport.rs": transport,
        "src/connection/spaces.rs": spaces,
        "src/connection/mod.rs": connection,
        "src/connection/datagrams.rs": datagrams,
    }
    # Build every edited text before writing any file.
    outputs = {name: edit((root / name).read_text(encoding="utf-8")) for name, edit in edits.items()}
    tests = root / "src/tests/mod.rs"
    outputs["src/tests/mod.rs"] = replace(tests.read_text(encoding="utf-8"), "mod token;", "mod token;\nmod payload_policy;\nmod payload_policy_resources;")
    payload_tests = root / "src/tests/payload_policy.rs"
    budget_tests = root / "src/connection/payload_policy_bounds.rs"
    resource_tests = root / "src/tests/payload_policy_resources.rs"
    if any(p.exists() for p in (payload_tests, budget_tests, resource_tests)):
        raise ValueError("unexpected preexisting policy tests")
    test_bytes = test_source.read_bytes()
    budget_bytes = test_source.with_name("payload_policy_bounds.rs").read_bytes()
    resource_bytes = test_source.with_name("payload_policy_resources.rs").read_bytes()
    for name, text in outputs.items():
        (root / name).write_text(text, encoding="utf-8", newline="\n")
    payload_tests.write_bytes(test_bytes)
    budget_tests.write_bytes(budget_bytes)
    resource_tests.write_bytes(resource_bytes)
