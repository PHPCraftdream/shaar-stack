"""Owned namespace commands and child supervision shared by the QUIC CI case."""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time


def atomic(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream)
    os.replace(temporary, path)


def namespace(cfg, key):
    name = cfg["ns"][key]
    if not re.fullmatch(r"sn[0-9a-f]{6}", cfg["prefix"]) or not name.startswith(cfg["prefix"] + "-"):
        raise ValueError("namespace is not owned by this case")
    return name


def command(cfg, key, *args):
    return ["ip", "netns", "exec", namespace(cfg, key), *map(str, args)]


def run(cfg, key, args, output):
    result = subprocess.run(command(cfg, key, *args), capture_output=True, text=True, timeout=15)
    Path(output).write_text(result.stdout + "\n" + result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"owned namespace command failed: {key} {args[0]} rc={result.returncode}")
    return result.stdout


def configure(cfg, root, kind):
    for value in cfg["ip"].values():
        ipaddress.IPv4Address(value)
    ports = cfg["translated_ports"]
    if len(ports) != 2 or not all(isinstance(port, int) and 1024 <= port <= 65535 for port in ports):
        raise ValueError("invalid translated port pair")
    # Disable aggregation only on owned veth devices, never host interfaces.
    for key in ("host_a", "host_b", "rtr_a", "rtr_b", "wan"):
        links = json.loads(run(cfg, key, ["ip", "-j", "-d", "link", "show"], root / f"links-{key}.json"))
        for link in links:
            name = link["ifname"]
            if name == "lo" or link.get("linkinfo", {}).get("info_kind") == "bridge":
                continue
            if not name.startswith(cfg["prefix"]) or link.get("linkinfo", {}).get("info_kind") != "veth":
                raise ValueError("refusing to alter a non-owned/non-veth interface")
            run(cfg, key, ["ethtool", "-K", name, "gro", "off", "gso", "off", "tso", "off"], root / f"offload-{name}.txt")
    for side, key in enumerate(("rtr_a", "rtr_b")):
        host = cfg["ip"][("host_a", "host_b")[side]]
        source_port = cfg["port"][("src_a", "src_b")[side]]
        if source_port == ports[side]:
            raise ValueError("native private and translated source ports must differ")
        run(cfg, key, ["iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", host,
                      "-p", "udp", "--sport", source_port, "-j", "MASQUERADE", "--to-ports", ports[side]],
            root / f"native-masquerade-{key}.txt")
        if kind == "blocked":
            run(cfg, key, ["iptables", "-I", "FORWARD", "1", "-s", host, "-p", "udp", "--sport", source_port,
                          "-m", "comment", "--comment", "p03-native-block", "-j", "DROP"], root / f"native-block-{key}.txt")
        rules = run(cfg, key, ["iptables-save", "-c"], root / f"rules-before-{key}.txt")
        if "DNAT" in rules:
            raise ValueError("DNAT is not permitted in this fixture")


def spawn(cfg, root, binary, ns, name, config, children, child_type):
    config_path = root / f"{name}-config.json"
    atomic(config_path, config)
    stderr = (root / "records" / f"{name}.stderr").open("xb")
    try:
        process = subprocess.Popen(command(cfg, ns, "setpriv", "--reuid", cfg["helper_uid"],
                                           "--regid", cfg["helper_gid"], "--clear-groups", binary, config_path),
                                   stdout=subprocess.DEVNULL, stderr=stderr)
    except BaseException:
        stderr.close()
        raise
    child = child_type(name, process, stderr, str(root / "STOP"), str(root / f"{name}-report.json"))
    children.append(child)
    return child


def unprivileged(pid, uid):
    fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
              for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines() if ":" in line}
    ids = [int(value) for value in fields["Uid"].split()]
    if uid <= 0 or ids != [uid] * 4 or int(fields["CapEff"], 16) != 0:
        raise ValueError("Rust helper did not drop root/capabilities")
    return {"uid": uid, "effective_capabilities": 0}


def wait_files(paths, children, seconds=35):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if any(child.proc.poll() is not None for child in children):
            raise RuntimeError("owned QUIC/capture child exited before completing its phase")
        if all(path.is_file() for path in paths):
            return [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        time.sleep(0.05)
    raise TimeoutError("QUIC fixture phase deadline")


def finish(child):
    if child.proc.wait(timeout=15) != 0:
        raise RuntimeError(f"{child.name} failed; inspect its stderr")


def helper(cfg, binary, root, role, relay):
    path = root / f"{role}-config.json"
    atomic(path, {"role": role, "nonce": cfg["nonce"], "case_dir": str(root), "relay": relay})
    with (root / "records" / f"{role}.stderr").open("xb") as stderr:
        result = subprocess.run([str(binary), str(path)], stdout=subprocess.PIPE, stderr=stderr,
                                text=True, timeout=20)
    if result.returncode != 0:
        raise RuntimeError(f"{role} helper failed rc={result.returncode}")
    return result.stdout


def conntrack_snapshot(cfg, root):
    return {key: run(cfg, key, ["conntrack", "-L", "-p", "udp"], root / f"conntrack-{key}.txt").splitlines()
            for key in ("rtr_a", "rtr_b")}


def snapshot(cfg, root, kind, ctparse, rows, conntrack):
    evidence = []
    for side, key in enumerate(("rtr_a", "rtr_b")):
        lines = conntrack[key]
        other = ("rtr_b_wan", "rtr_a_wan")[side]
        own = ("rtr_a_wan", "rtr_b_wan")[side]
        target = cfg["translated_ports"][1 - side]
        if kind == "positive":
            entry = ctparse.find_translation(lines, cfg["ip"][("host_a", "host_b")[side]],
                cfg["port"][("src_a", "src_b")[side]], cfg["ip"][other], target,
                cfg["ip"][other], target, cfg["ip"][own], cfg["translated_ports"][side])
            if entry is None or not any(row["side"] == side for row in rows):
                raise ValueError("missing replied conntrack/WAN translation correlation")
            evidence.append(entry)
        if kind == "blocked":
            rules = run(cfg, key, ["iptables-save", "-c"], root / f"rules-after-{key}.txt")
            dropped = sum(int(re.match(r"\[(\d+):\d+\]", line).group(1))
                          for line in rules.splitlines() if "p03-native-block" in line and re.match(r"\[(\d+):\d+\]", line))
            if dropped <= 0:
                raise ValueError("blocked native case never attempted an outgoing UDP probe")
            evidence.append({"router": key, "native_dropped": dropped})
    if kind == "wrong-tuple" and not any(row["side"] == 0 and row["dst"][1] == cfg["translated_ports"][1] + 1 for row in rows):
        raise ValueError("wrong-tuple case never attempted the deliberately wrong public port")
    if kind == "blocked" and rows:
        raise ValueError("blocked native packets escaped to WAN")
    return evidence
