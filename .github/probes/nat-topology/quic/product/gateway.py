"""Controller-owned PCP gateway of the mapped-port cases (leaf DIRECT-T).

Runs as root inside the Server's router namespace, started and reaped by the case controller like its nft commands (it is
the one privileged child of a product case and is never listed among the unprivileged identities). It answers the PCP MAP
requests of the one Server host on the router's LAN address and keeps one DNAT rule per granted port in a table of its own,
so the router's product table stays immutable. PCP only: no NAT-PMP, no UPnP and no lease expiry (a case lasts minutes).
Self-contained on purpose: it runs under `python -I`, so nothing here imports a sibling module.
"""

import argparse
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time

PCP_PORT = 5351
VERSION, OPCODE_MAP, RESPONSE, UDP = 2, 1, 0x80, 17
MAP_LEN = 60
OK, NOT_AUTHORIZED, NO_RESOURCES = 0, 2, 8
MAX_LIFETIME = 7200
MIN_PORT = 1024
MAX_MAPPINGS = 4
MAX_EVENTS = 64
NFT_SECONDS = 10
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


class Stop(Exception):
    """Raised by the signal handler: the controller asked the gateway to end."""


def mapped(address):
    """The IPv4 address as the 16-byte IPv4-mapped IPv6 form PCP carries."""
    return b"\0" * 10 + b"\xff\xff" + ipaddress.IPv4Address(address).packed


def parse(data, client):
    """The UDP MAP request of `client` in `data` as (nonce, internal port, lifetime), or None for anything else."""
    if len(data) != MAP_LEN or data[0] != VERSION or data[1] != OPCODE_MAP or data[8:24] != mapped(client) or data[36] != UDP:
        return None
    internal = int.from_bytes(data[40:42], "big")
    if internal < MIN_PORT:
        return None
    return data[24:36], internal, int.from_bytes(data[4:8], "big")


def answer(nonce, internal, external, code, lifetime, wan, epoch):
    """The MAP response: the granted external endpoint, or the result code of a refusal."""
    out = bytearray(MAP_LEN)
    out[0], out[1], out[3] = VERSION, RESPONSE | OPCODE_MAP, code
    out[4:8] = lifetime.to_bytes(4, "big")
    out[8:12] = epoch.to_bytes(4, "big")
    out[24:36] = nonce
    out[36] = UDP
    out[40:42] = internal.to_bytes(2, "big")
    out[42:44] = external.to_bytes(2, "big")
    out[44:60] = mapped(wan)
    return bytes(out)


def setup_rules(table):
    return (f"add table inet {table}\nadd counter inet {table} hits\n"
            f"add chain inet {table} dnat {{ type nat hook prerouting priority -100; policy accept; }}\n")


def dnat_rules(table, wan, client, ports):
    """The whole DNAT chain for the granted ports, replaced in one transaction (the named counter survives the flush)."""
    lines = [f"flush chain inet {table} dnat"]
    lines += [f"add rule inet {table} dnat ip daddr {wan} udp dport {port} counter name hits dnat ip to {client}:{port}"
              for port in sorted(ports)]
    return "\n".join(lines) + "\n"


def run_nft(binary, args, text=None):
    done = subprocess.run([binary, *args], input=text, capture_output=True, text=True, timeout=NFT_SECONDS, env=ENV, check=False)
    if done.returncode != 0:
        raise RuntimeError("nft failed: " + done.stderr[:200])
    return done.stdout


def read_hits(binary, table):
    """Packets and bytes that the DNAT rules matched: the proof that traffic crossed the mapping."""
    document = json.loads(run_nft(binary, ["--json", "list", "counter", "inet", table, "hits"]))
    for entry in document.get("nftables", []):
        raw = entry.get("counter")
        if raw is not None:
            return {"packets": raw["packets"], "bytes": raw["bytes"]}
    raise RuntimeError("the hits counter is missing")


class Gateway:
    """Answers MAP requests; `apply(ports)` installs the DNAT rules for the granted ports."""

    def __init__(self, mode, wan, client, apply):
        self.mode, self.wan, self.client, self.apply = mode, wan, client, apply
        self.ports, self.events, self.dropped, self.ignored = set(), [], 0, 0
        self.started = time.monotonic()

    def note(self, op, port, lifetime=0):
        if len(self.events) < MAX_EVENTS:
            self.events.append({"op": op, "port": port, "lifetime": lifetime})
        else:
            self.dropped += 1

    def handle(self, data, source):
        """The reply datagram for one received datagram, or None when it is ignored (another sender, not a MAP request)."""
        request = parse(data, self.client) if source == self.client else None
        if request is None:
            self.ignored += 1
            return None
        nonce, port, lifetime = request
        epoch = int(time.monotonic() - self.started)
        if self.mode == "refuse":
            self.note("refused", port, lifetime)
            return answer(nonce, port, 0, NOT_AUTHORIZED, 0, self.wan, epoch)
        if lifetime == 0:
            if port in self.ports:
                self.ports.discard(port)
                self.apply(self.ports)
            self.note("delete", port)
            return answer(nonce, port, port, OK, 0, self.wan, epoch)
        if port not in self.ports and len(self.ports) >= MAX_MAPPINGS:
            self.note("refused", port, lifetime)
            return answer(nonce, port, 0, NO_RESOURCES, 0, self.wan, epoch)
        renewal = port in self.ports
        if not renewal:
            self.ports.add(port)
            self.apply(self.ports)
        granted = min(lifetime, MAX_LIFETIME)
        self.note("renew" if renewal else "map", port, granted)
        return answer(nonce, port, port, OK, granted, self.wan, epoch)


def emit(label, event):
    sys.stdout.write("SHAAR_NAT_" + label + " " + json.dumps(event, sort_keys=True) + "\n")
    sys.stdout.flush()


def check_args(args):
    if re.fullmatch("[0-9a-f]{32}", args.nonce) is None or re.fullmatch("sn[0-9a-f]{6}", args.prefix) is None:
        raise ValueError("invalid nonce or namespace prefix")
    if not args.nft.startswith("/") or "\0" in args.nft:
        raise ValueError("the nft tool needs an absolute path")
    for value in (args.listen, args.wan, args.client):
        ipaddress.IPv4Address(value)


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="gateway.py")
    for name in ("nonce", "prefix", "nft", "listen", "wan", "client"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--mode", required=True, choices=("grant", "refuse"))
    args = parser.parse_args(argv)
    check_args(args)
    return args


def serve(args):
    table = args.prefix + "_mapgw"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen, PCP_PORT))
    run_nft(args.nft, ["--file", "-"], setup_rules(table))
    gateway = Gateway(args.mode, args.wan, args.client,
                      lambda ports: run_nft(args.nft, ["--file", "-"], dnat_rules(table, args.wan, args.client, ports)))

    def stop(_signum, _frame):
        raise Stop()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    emit("READY", {"role": "gateway", "nonce": args.nonce, "pid": os.getpid(), "mode": args.mode})
    try:
        while True:
            data, (host, port) = sock.recvfrom(2048)
            reply = gateway.handle(data, host)
            if reply is not None:
                sock.sendto(reply, (host, port))
    except Stop:
        pass
    finally:
        hits = read_hits(args.nft, table)
        run_nft(args.nft, ["delete", "table", "inet", table])
    emit("RESULT", {"role": "gateway", "nonce": args.nonce, "pid": os.getpid(), "mode": args.mode, "events": gateway.events,
                    "dropped": gateway.dropped, "ignored": gateway.ignored, "active": sorted(gateway.ports), "hits": hits})
    return 0


if __name__ == "__main__":
    sys.exit(serve(parse_args(sys.argv[1:])))
