"""Unprivileged runner tool availability; never NAT/product acceptance or installation."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import subprocess
import time

TOOLS = {"ip": ("-Version",), "nft": ("--version",), "setpriv": ("--version",),
         "tcpdump": ("--version",), "conntrack": ("--version",),
         "iptables": ("--version",), "ip6tables": ("--version",)}
REQUIRED = {"ip", "nft", "setpriv", "tcpdump"}
SCOPE = "unprivileged-tool-preflight-not-product-acceptance"
MAX_OUTPUT = 16384


def trusted_tool(name):
    found = shutil.which(name)
    if not found:
        return None
    try:
        candidate = Path(found).absolute()
        path = candidate.resolve(strict=True)
        roots = tuple(Path(root) for root in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"))
        if (path.is_file() and any(path.is_relative_to(root) for root in roots)
                and any(candidate.is_relative_to(root) for root in roots)):
            return candidate  # Preserve argv[0] for trusted system multi-call binaries.
    except OSError:
        pass
    return None


def bounded_command(arguments, deadline):
    """Event-driven bounded stdout/stderr, finite lifetime and owned-PID reaping."""
    limit = min(deadline, time.monotonic() + 5)
    if limit <= time.monotonic():
        return {"exit_code": None, "output": "command budget exhausted before admission"}
    output = bytearray()
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"})
    except OSError:
        return {"exit_code": None, "output": "cannot launch trusted tool"}
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = limit - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("tool command deadline exceeded")
                chunk = os.read(process.stdout.fileno(), min(4096, MAX_OUTPUT + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    raise ValueError("tool command output limit exceeded")
        status = process.wait(timeout=max(0, limit - time.monotonic()))
        return {"exit_code": status, "output": output.decode("utf-8", errors="replace")[:1024]}
    except (TimeoutError, ValueError, subprocess.TimeoutExpired):
        process.kill()
        process.wait(timeout=5)
        return {"exit_code": None, "output": "bounded command refused: timeout or output limit"}
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def inspect(source):
    started = time.monotonic()
    deadline = started + 60
    uid = getattr(os, "geteuid", lambda: None)()
    report = {"schema": 1, "scope": SCOPE, "source_revision": source,
              "platform": platform.system(), "euid": uid,
              "python": platform.python_version(), "image_version": os.environ.get("ImageVersion", "unknown")[:200],
              "product_cases_executed": 0, "privileged_commands_executed": 0,
              "kernel_namespace_quota_verified": False, "tools": {}, "errors": [], "status": "blocked"}
    if report["platform"] != "Linux" or type(uid) is not int or uid <= 0:
        report["errors"].append("requires an unprivileged Linux runner")
        return report
    git = trusted_tool("git")
    check = bounded_command([str(git), "rev-parse", "HEAD"], deadline) if git else None
    if not check or check["exit_code"] != 0 or check["output"].strip() != source:
        report["errors"].append("checked-out source revision mismatch or trusted git unavailable")
        return report
    for name, arguments in TOOLS.items():
        path = trusted_tool(name)
        result = bounded_command([str(path), *arguments], deadline) if path else {"exit_code": None, "output": "not found in trusted preinstalled system paths"}
        available = path is not None and result["exit_code"] == 0
        report["tools"][name] = {"required": name in REQUIRED, "available": available,
                                "path": str(path) if path else None, **result}
        if name in REQUIRED and not available:
            report["errors"].append("required tool unavailable: " + name)
    report["conntrack_mode"] = "cli" if report["tools"]["conntrack"]["available"] else "kernel-preflight-required"
    report["host_proc_conntrack_present"] = Path("/proc/net/nf_conntrack").exists()
    report["elapsed_seconds"] = time.monotonic() - started
    report["status"] = "ready" if not report["errors"] else "blocked"
    return report


def validate_report(report):
    if (type(report.get("schema")) is not int or report["schema"] != 1 or report.get("scope") != SCOPE
            or type(report.get("source_revision")) is not str
            or not re.fullmatch(r"[0-9a-f]{40}", report["source_revision"])
            or type(report.get("product_cases_executed")) is not int or report["product_cases_executed"] != 0
            or type(report.get("privileged_commands_executed")) is not int or report["privileged_commands_executed"] != 0
            or report.get("kernel_namespace_quota_verified") is not False
            or report.get("status") not in ("ready", "blocked")):
        raise ValueError("tool preflight scope/source/outcome mismatch")
    if report["status"] == "ready":
        if (report.get("platform") != "Linux" or type(report.get("euid")) is not int
                or report["euid"] <= 0 or report.get("errors") or set(report.get("tools", {})) != set(TOOLS)):
            raise ValueError("tool readiness requires non-root Linux and a complete tool inventory")
        for name in REQUIRED:
            tool = report["tools"][name]
            if tool.get("available") is not True or tool.get("exit_code") != 0 or tool.get("required") is not True:
                raise ValueError("required tool cannot be missing in a ready report")
    elif not report.get("errors"):
        raise ValueError("blocked tool report requires a concrete reason")


def main():
    parser = argparse.ArgumentParser(description=SCOPE)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", default="target/controlled-network-tools/report.json")
    arguments = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", arguments.source):
        parser.error("source must be the exact reviewed commit SHA")
    output = Path(arguments.output).resolve()
    allowed = Path.cwd().resolve() / "target/controlled-network-tools"
    if not output.is_relative_to(allowed) or output == allowed or output.exists():
        parser.error("output must be a fresh file inside target/controlled-network-tools")
    report = inspect(arguments.source)
    validate_report(report)
    encoded = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    if len(encoded) > 65536:
        raise ValueError("tool report artifact limit exceeded")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(encoded)
    print(json.dumps(report))
    return 0 if report["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
