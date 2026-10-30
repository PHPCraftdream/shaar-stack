"""CI-only selected-target runner with an actual binary inventory and exact case batches."""

from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY = load("runner_policy", Path(__file__).with_name("policy.py"))
VERIFY = load("runner_verify", ROOT / ".github/scripts/p2p/discovery/owned_dns/verify.py")
SCANNER = load("runner_scanner", ROOT / ".github/scripts/scan_identity_output.py")


def safe_text(path):
    data = SCANNER.read_bounded(str(path))
    if SCANNER.scan_bytes(data):
        path.write_text("Output rejected by the identity scanner\n", encoding="utf-8")
        raise ValueError("identity material detected; unsafe log redacted")
    return data.decode("utf-8")


def capture(arguments, log, *, stderr=None):
    # The workflow timeout owns the Cargo process tree; do not kill only its parent.
    environment = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target"))
    with log.open("wb") as output:
        if stderr:
            with stderr.open("wb") as errors:
                status = subprocess.run(arguments, cwd=ROOT, env=environment, stdout=output, stderr=errors, check=False).returncode
        else:
            status = subprocess.run(arguments, cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT, check=False).returncode
    text = safe_text(log)
    if stderr:
        print(safe_text(stderr), end="")
    print(text, end="")
    return text, status


def validate(targets):
    if not isinstance(targets, list) or not 1 <= len(targets) <= 32:
        raise ValueError("selected Rust targets must be a nonempty bounded list")
    seen = set()
    allowed = {value for _, values in POLICY.SUITES.values() for value in values} | {""}
    for target in targets:
        if set(target) != {"package", "kind", "name", "filters"} or target["package"] not in POLICY.PACKAGES:
            raise ValueError("unknown selected target")
        kind, name = target["kind"], target["name"]
        if kind not in {"lib", "bin", "test"} or not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,100}", name):
            raise ValueError("invalid Cargo target")
        key = (target["package"], kind, name)
        if key in seen:
            raise ValueError("duplicate Cargo target")
        seen.add(key)
        filters = target["filters"]
        if not isinstance(filters, list) or not filters or any(value not in allowed for value in filters):
            raise ValueError("unknown selected test filter")


def cargo_target(spec):
    return ["--lib"] if spec["kind"] == "lib" else ["--" + spec["kind"] + "=" + spec["name"]]


def executable(messages, spec):
    found = set()
    source_root = (ROOT / "crates" / spec["package"]).resolve()
    for line in messages.splitlines():
        item = json.loads(line)
        if item.get("reason") != "compiler-artifact" or item.get("profile", {}).get("test") is not True:
            continue
        target = item.get("target", {})
        if target.get("kind") != [spec["kind"]] or target.get("name") != spec["name"]:
            continue
        source = Path(target["src_path"]).resolve()
        if not source.is_relative_to(source_root):
            continue
        binary = Path(item["executable"]).resolve()
        if not binary.is_relative_to((ROOT / "target").resolve()):
            raise ValueError("test executable escaped the selected target directory")
        found.add(binary)
    if len(found) != 1:
        raise ValueError("Cargo must report exactly one selected executable")
    return found.pop()


def selected_cases(listing, ignored_listing, filters):
    inventory = set(VERIFY.parse_listing(listing, ""))
    ignored = set(VERIFY.parse_listing(ignored_listing, ""))
    if not ignored <= inventory:
        raise ValueError("ignored inventory is not a subset of the binary inventory")
    runnable = inventory - ignored
    for selector in filters:
        if not any(selector in name for name in runnable):
            raise ValueError("test selector matched no runnable cases: " + repr(selector))
    chosen = sorted(name for name in runnable if any(selector in name for selector in filters))
    return chosen, sorted(name for name in ignored if any(selector in name for selector in filters))


def batches(names, limit=12000):
    batch, length = [], 0
    for name in names:
        if len(name) + 1 > limit:
            raise ValueError("test name exceeds the bounded command length")
        if batch and length + len(name) + 1 > limit:
            yield batch
            batch, length = [], 0
        batch.append(name)
        length += len(name) + 1
    if batch:
        yield batch


def tests(targets):
    directory = ROOT / "target/ci-selected"
    directory.mkdir(parents=True, exist_ok=True)
    receipt = []
    for index, spec in enumerate(targets):
        prefix = directory / str(index)
        arguments = ["cargo", "test", "--locked", "-p", spec["package"], *cargo_target(spec)]
        messages, status = capture(arguments + ["--no-run", "--message-format=json"],
                                   prefix.with_suffix(".build.jsonl"), stderr=prefix.with_suffix(".build.stderr"))
        if status:
            raise ValueError("selected target compilation failed: " + str(status))
        binary = executable(messages, spec)
        listing, status = capture([str(binary), "--list", "--format=terse"], prefix.with_suffix(".list.log"))
        if status:
            raise ValueError("test binary listing failed")
        ignored, status = capture([str(binary), "--list", "--ignored", "--format=terse"], prefix.with_suffix(".ignored.log"))
        if status:
            raise ValueError("ignored test listing failed")
        cases, skipped = selected_cases(listing, ignored, spec["filters"])
        executed = []
        for batch_index, batch in enumerate(batches(cases)):
            output, status = capture(arguments + ["--", "--exact", "--color", "never", *batch],
                                     directory / f"{index}-run-{batch_index}.log")
            expected = "".join(name + ": test\n" for name in batch)
            VERIFY.verify({"selected": expected}, {"selected": (VERIFY.cargo_execution(output), status)}, "")
            executed.extend(batch)
        if Counter(executed) != Counter(cases):
            raise ValueError("selected and executed test inventories differ")
        receipt.append({**spec, "executed": executed, "ignored_not_executed": skipped})
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print("Verified selected cases:", sum(len(item["executed"]) for item in receipt))


def self_test():
    global ROOT
    original = ROOT
    directory = original / "target/ci-selected/self-test"
    fixture = directory / "workspace"
    source = fixture / "crates/shaar-p2p/src/lib.rs"
    source.parent.mkdir(parents=True, exist_ok=True)
    (fixture / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/shaar-p2p"]\n', encoding="utf-8")
    (source.parents[1] / "Cargo.toml").write_text(
        '[package]\nname = "shaar-p2p"\nversion = "0.0.0"\nedition = "2024"\nlicense = "MIT OR Apache-2.0"\n', encoding="utf-8")
    source.write_text('''#![forbid(unsafe_code)]
pub mod carrier {
    pub mod driver {
        pub mod protocols {
            #[cfg(test)]
            mod tests {
                #[test]
                fn chosen_alpha() {}
                #[test]
                fn chosen_beta() {}
                #[test]
                #[ignore]
                fn ignored_failure() { panic!("IGNORED_CASE_RAN"); }
            }
        }
    }
}
#[test]
fn unselected_failure() { panic!("UNSELECTED_CASE_RAN"); }
''', encoding="utf-8")
    try:
        ROOT = fixture
        _, status = capture(["cargo", "generate-lockfile", "--offline"], directory / "lock.log")
        if status:
            raise ValueError("stdlib-only runner fixture lock failed")
        tests([POLICY.target("shaar-p2p", ("carrier::driver::protocols::",))])
        receipt = json.loads((fixture / "target/ci-selected/receipt.json").read_text(encoding="utf-8"))
        expected = ["carrier::driver::protocols::tests::chosen_alpha", "carrier::driver::protocols::tests::chosen_beta"]
        if receipt[0]["executed"] != expected or receipt[0]["ignored_not_executed"] != ["carrier::driver::protocols::tests::ignored_failure"]:
            raise ValueError("runner fixture selected or executed the wrong cases")
    finally:
        ROOT = original


def main():
    mode = sys.argv[1]
    if mode == "self-test":
        self_test()
        return
    targets = json.loads(os.environ["CI_TARGETS"])
    validate(targets)
    if mode == "lint":
        for spec in targets:
            arguments = ["cargo", "clippy", "--locked", "-p", spec["package"], *cargo_target(spec)]
            subprocess.run([*arguments, "--", "-D", "warnings"], cwd=ROOT, check=True)
    elif mode == "test":
        tests(targets)
    else:
        raise ValueError("unknown selected-target runner mode")


if __name__ == "__main__":
    main()
