"""CI verifier for selected owned-DNS test artifacts and runs."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys

NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_:]*$")
RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in .+$", re.MULTILINE)
EVENT = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)$", re.MULTILINE)


def _scanner(path: Path):
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location("scan_identity_output", path)
    if spec is None or spec.loader is None:
        raise ValueError("identity scanner unavailable")
    scanner = module_from_spec(spec)
    spec.loader.exec_module(scanner)
    return scanner


def artifacts(text: str, target_dir: Path) -> tuple[Path, ...]:
    seen_selected = set()
    selected = set()
    for line in text.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("malformed cargo JSON message") from exc
        if not isinstance(message, dict) or not isinstance(message.get("reason"), str):
            raise ValueError("malformed cargo JSON message")
        if message["reason"] != "compiler-artifact":
            continue
        package_id = message.get("package_id")
        target = message.get("target", {})
        if not isinstance(target, dict):
            raise ValueError("malformed cargo artifact target")
        if not isinstance(package_id, str):
            continue
        if target.get("name") != "shaar_p2p" or target.get("kind") != ["lib"] or target.get("crate_types") != ["lib"]:
            continue
        src_path = target.get("src_path")
        profile = message.get("profile")
        if not isinstance(src_path, str) or not isinstance(profile, dict) or profile.get("test") is not True:
            continue
        if Path(src_path).resolve() != (Path(__file__).resolve().parents[5] / "crates" / "shaar-p2p" / "src" / "lib.rs").resolve():
            continue
        seen_selected.add(package_id)
        executable = message.get("executable")
        if not isinstance(executable, str) or not executable:
            raise ValueError("selected library test artifact has no executable")
        path = Path(executable).resolve()
        root = target_dir.resolve()
        if path == root or root not in path.parents:
            raise ValueError("selected test artifact is outside target directory")
        selected.add(path)
    if not seen_selected:
        raise ValueError("cargo did not report the shaar-p2p library test target")
    if not selected:
        raise ValueError("cargo omitted the executable for the selected shaar-p2p library test target")
    return tuple(sorted(selected))


def parse_listing(text: str) -> tuple[str, ...]:
    names = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"(.+): test", line.strip())
        if not match or not NAME.fullmatch(match.group(1)):
            raise ValueError("malformed filtered test listing")
        name = match.group(1)
        if "owned_dns_" not in name:
            raise ValueError("unfiltered test in selected binary inventory")
        names.append(name)
    if len(set(names)) != len(names):
        raise ValueError("duplicate test in selected binary inventory")
    return tuple(names)


def verify(inventories: dict[str, str], executions: dict[str, tuple[str, int]]) -> int:
    if not inventories or set(inventories) != set(executions):
        raise ValueError("selected binary and execution sets differ")
    total = 0
    for binary, listing in inventories.items():
        expected = Counter(parse_listing(listing))
        output, status = executions[binary]
        output = "\n".join(output.splitlines())
        events = EVENT.findall(output)
        observed = Counter(name for name, _ in events)
        if observed != expected:
            raise ValueError(f"execution differs from binary inventory: {binary}")
        if output and any(line.strip() and not (EVENT.fullmatch(line) or RESULT.fullmatch(line) or re.fullmatch(r"running [0-9]+ tests?", line)) for line in output.splitlines()):
            raise ValueError(f"malformed test output line: {binary}")
        if len(re.findall(r"^running [0-9]+ tests?$", output, re.MULTILINE)) > 1:
            raise ValueError(f"duplicate harness header: {binary}")
        for line in output.splitlines():
            if not line.strip():
                continue
            if line.startswith("running "):
                if not re.fullmatch(r"running [0-9]+ tests?", line):
                    raise ValueError(f"malformed harness header: {binary}")
                if int(line.split()[1]) != len(expected):
                    raise ValueError(f"unexpected harness test count: {binary}")
                continue
            if not (EVENT.fullmatch(line) or RESULT.fullmatch(line)):
                raise ValueError(f"malformed test output line: {binary}")
        if any(state != "ok" for _, state in events):
            raise ValueError(f"failed or ignored test in {binary}")
        if status != 0:
            raise ValueError(f"test binary returned nonzero status: {binary} ({status})")
        results = RESULT.findall(output)
        if len(results) != 1:
            raise ValueError(f"malformed/ambiguous result: {binary}")
        state, passed, failed, ignored, measured, filtered = results[0]
        if state != "ok" or (int(passed), int(failed), int(ignored), int(measured)) != (len(expected), 0, 0, 0):
            raise ValueError(f"unexpected test result counts: {binary}")
        if int(filtered) < 0:
            raise ValueError(f"unexpected filtered execution status: {binary}")
        if not expected:
            continue
        total += len(expected)
    if not total:
        raise ValueError("no owned-DNS tests selected across binaries")
    return total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--status", type=int, required=True)
    parser.add_argument("--scanner", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.status != 0:
            raise ValueError("cargo test --no-run failed")
        selected = artifacts(args.artifacts.read_text(encoding="utf-8"), args.target_dir)
        scanner = _scanner(args.scanner)
        inventories, executions = {}, {}
        for index, binary in enumerate(selected):
            list_path, run_path, status_path = (args.directory / f"list-{index}.log", args.directory / f"run-{index}.log", args.directory / f"status-{index}.txt")
            list_command = [str(binary), "owned_dns_", "--list", "--format", "terse"]
            with list_path.open("wb") as output:
                list_status = subprocess.run(list_command, stdout=output, stderr=subprocess.STDOUT, check=False).returncode
            if list_status != 0:
                data = scanner.read_bounded(str(list_path))
                if scanner.scan_bytes(data):
                    raise ValueError("known seed material detected in owned-DNS listing")
                listing_diagnostic = data.decode("utf-8")
                print(f"failed owned-DNS listing for {binary} ({list_status}):", file=sys.stderr)
                print(listing_diagnostic, end="" if listing_diagnostic.endswith("\n") else "\n", file=sys.stderr)
                raise ValueError(f"test binary listing failed: {binary} ({list_status})")
            listing = scanner.read_bounded(str(list_path)).decode("utf-8")
            if scanner.scan_bytes(listing.encode("utf-8")):
                raise ValueError("known seed material detected in owned-DNS listing")
            try:
                parse_listing(listing)
            except ValueError:
                print(f"unverified owned-DNS listing for {binary}:", file=sys.stderr)
                print(listing, end="" if listing.endswith("\n") else "\n", file=sys.stderr)
                raise
            with run_path.open("wb") as output:
                run_status = subprocess.run([str(binary), "owned_dns_"], stdout=output, stderr=subprocess.STDOUT, check=False).returncode
            status_path.write_text(str(run_status), encoding="ascii")
            execution = scanner.read_bounded(str(run_path)).decode("utf-8")
            if scanner.scan_bytes(execution.encode("utf-8")):
                raise ValueError("known seed material detected in owned-DNS test output")
            key = str(binary)
            inventories[key] = listing
            executions[key] = (execution, run_status)
        try:
            verified = verify(inventories, executions)
        except ValueError:
            for binary, (execution, _) in executions.items():
                print(f"unverified owned-DNS execution for {binary}:", file=sys.stderr)
                print(execution, end="" if execution.endswith("\n") else "\n", file=sys.stderr)
            raise
        print(f"verified {verified} owned-DNS tests across {len(selected)} binaries")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, IndexError) as exc:
        print(f"owned DNS test verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
