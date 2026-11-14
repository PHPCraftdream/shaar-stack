#!/usr/bin/env python3
"""Public-network smoke harness: `validate`, `server`, `client` (CI-only, stdlib only).

Runs the normal shaar-server / shaar-client binaries once each over the public
Mainline DHT, a pinned libp2p relay and public Yggdrasil peers, with every cap of
contract.json enforced by the metering thread. No retries, no load, no secrets:
the identities are disposable and derived from public run metadata.
"""

import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("smoke_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTRACT, KEYS, BUDGET = load("contract"), load("keys"), load("budget")


class Abort(Exception):
    """Fail closed before or during the run; the message is evidence, never a secret."""


def verify_binary(path, manifest, name, revision):
    """The binary must be the CI-built, gate-off product recorded in the manifest."""
    if manifest.get("source_revision") != revision or manifest.get("normal_native_gate_enabled") is not False:
        raise Abort("product manifest is not for this revision with the native gate OFF")
    expected = manifest.get("products", {}).get(name, {}).get("sha256")
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if not isinstance(expected, str) or digest != expected:
        raise Abort(f"{name} does not match the manifest digest")
    return digest


def resolve_targets(contract, getaddrinfo=socket.getaddrinfo):
    """Resolve the exact hosts once. Every address must be globally routable."""
    targets = contract["targets"]
    bootstrap = []
    for entry in targets["mainline_bootstrap"]:
        rows = getaddrinfo(entry["host"], entry["port"], socket.AF_INET, socket.SOCK_DGRAM)
        ips = sorted({row[4][0] for row in rows})
        if not ips or not all(CONTRACT.public_ipv4(ip) for ip in ips):
            raise Abort(f"bootstrap {entry['host']} did not resolve to public IPv4 addresses")
        bootstrap.append({"host": entry["host"], "port": entry["port"], "all": ips, "used": f"{ips[0]}:{entry['port']}"})
    ygg, allowed = [], set()
    for entry in targets["ygg_peers"]:
        host, port = CONTRACT.split_peer(entry["uri"])
        rows = getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        ips = sorted({row[4][0] for row in rows})
        parsed = [ipaddress.ip_address(ip) for ip in ips]
        if not ips or not all(ip.is_global for ip in parsed):
            raise Abort(f"ygg peer {host} did not resolve to global addresses")
        allowed.update(parsed)
        ygg.append({"uri": entry["uri"], "all": ips})
    relay = targets["libp2p_relay"]
    relay_ip = ipaddress.ip_address(relay["address"].rsplit(":", 1)[0])
    return {"bootstrap": bootstrap, "ygg": ygg, "ygg_allowed": allowed, "relay_allowed": {relay_ip}}


def interface_addresses(text):
    """Addresses from `ip -o addr show` output."""
    found = []
    for line in text.splitlines():
        match = re.search(r"\binet6?\s+([0-9a-fA-F:.]+)(?:/\d+)?", line)
        if match:
            found.append(match[1])
    return found


def require_native_unreachable(addresses):
    """Native QUIC must be unreachable by construction: no globally routable local address."""
    for text in addresses:
        ip = ipaddress.ip_address(text)
        if ip.is_global and not ip.is_multicast:
            raise Abort("runner has a globally routable address; Native would not be blocked by construction")
    return sorted(addresses)


def local_addresses(run=subprocess.run):
    result = run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=5, check=False)
    if result.returncode != 0:
        raise Abort("cannot enumerate interface addresses")
    return require_native_unreachable(interface_addresses(result.stdout))


def listening(port, read=BUDGET.read_text):
    """True when a loopback TCP LISTEN socket exists, without connecting to it."""
    needle = f"0100007F:{port:04X}"
    for path in ("/proc/net/tcp",):
        for line in read(path).splitlines()[1:]:
            fields = line.split()
            if len(fields) > 3 and fields[1] == needle and fields[3] == "0A":
                return True
    return False


def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class Target(threading.Thread):
    """Fixed target fixture: exactly one accepted connection, one request line, one reply line."""

    def __init__(self, nonce, request_max, reply_max):
        super().__init__(daemon=True)
        self.expect, self.reply = CONTRACT.app_request(nonce), CONTRACT.app_reply(nonce)
        if len(self.expect) > request_max or len(self.reply) > reply_max:
            raise Abort("APP exchange exceeds its byte budget")
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.listener.settimeout(0.25)
        self.address = self.listener.getsockname()
        self.stop = threading.Event()
        self.accepts, self.request_ok, self.bytes_in, self.bytes_out = 0, False, 0, 0
        self.done = threading.Event()
        self.errors = []

    def run(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepts += 1
            if self.accepts > 1:
                self.errors.append("extra target connection")
                connection.close()
                continue
            with connection:
                self._serve(connection)
            self.done.set()

    def _serve(self, connection):
        connection.settimeout(10)
        data = b""
        try:
            while b"\n" not in data and len(data) <= len(self.expect):
                chunk = connection.recv(256)
                if not chunk:
                    break
                data += chunk
            self.bytes_in = len(data)
            if data == self.expect:
                self.request_ok = True
                connection.sendall(self.reply)
                self.bytes_out = len(self.reply)
            else:
                self.errors.append("unexpected request bytes")
        except OSError as error:
            self.errors.append("target I/O: " + type(error).__name__)

    def close(self):
        self.stop.set()
        self.listener.close()
        self.join(timeout=2)


def exchange(port, nonce, deadline_s, reply_max):
    """One local connection: send the request line, read the reply line. No retry."""
    request, expected = CONTRACT.app_request(nonce), CONTRACT.app_reply(nonce)
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.settimeout(deadline_s)
        connection.sendall(request)
        data, first = b"", None
        while b"\n" not in data and len(data) <= reply_max:
            chunk = connection.recv(256)
            if not chunk:
                break
            first = first or time.monotonic() - started
            data += chunk
    return {"request_bytes": len(request), "reply_bytes": len(data), "match": data == expected,
            "first_byte_s": None if first is None else round(first, 2), "total_s": round(time.monotonic() - started, 2)}


class Product:
    """One owned child process plus its metering thread."""

    def __init__(self, exe, config, workdir, meter, interval):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        self.out = open(workdir / "product.stdout.log", "wb")
        self.err = open(workdir / "product.stderr.log", "wb")
        self.proc = subprocess.Popen([exe, "--config", str(config)], cwd=workdir, stdin=subprocess.DEVNULL,
                                     stdout=self.out, stderr=self.err)
        self.meter, self.interval, self.lock = meter, interval, threading.Lock()
        self.started = time.monotonic()
        self.stop_event, self.violated = threading.Event(), threading.Event()
        self.failure = None
        self.thread = threading.Thread(target=self._meter_loop, daemon=True)
        self.thread.start()

    def _meter_loop(self):
        while not self.stop_event.is_set():
            try:
                with self.lock:
                    fresh = BUDGET.sample(self.proc.pid, self.meter, time.monotonic() - self.started)
            except Exception as error:  # fail closed: an unmetered run is not allowed to continue
                self.failure = "meter failure: " + type(error).__name__
                fresh = ["meter_failure"]
                self.meter.violations.append("meter_failure")
            if fresh:
                self.violated.set()
                self.proc.kill()
                return
            self.stop_event.wait(self.interval)

    def totals(self):
        with self.lock:
            return self.meter.totals()

    def alive(self):
        return self.proc.poll() is None

    def stop(self, grace):
        """SIGINT, then kill the owned PID only; returns the exit code."""
        self.stop_event.set()
        if self.alive():
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.thread.join(timeout=5)
        self.out.close()
        self.err.close()
        return self.proc.returncode


def wait_until(deadline_epoch, product, clock=time.time, sleep=time.sleep, extra=None):
    """Sleep in short slices until the epoch, a dead/violated product, or `extra()` is true."""
    while clock() < deadline_epoch:
        if not product.alive() or product.violated.is_set() or (extra and extra()):
            return
        sleep(0.25)


def sanitized_tail(path, secrets, limit=4096):
    data = Path(path).read_bytes()[-limit:]
    text = data.decode("utf-8", "replace")
    if any(secret.hex() in text or secret in data for secret in secrets):
        return "[redacted: key material pattern]"
    return text


def write_evidence(directory, evidence, secrets):
    body = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if any(secret.hex() in body for secret in secrets):
        raise Abort("evidence would contain key material")
    Path(directory).mkdir(parents=True, exist_ok=True)
    Path(directory, "evidence.json").write_text(body, encoding="utf-8")
    return body


def common_setup(args, role, env=os.environ):
    contract, digest = CONTRACT.load_contract()
    dispatch = CONTRACT.validate_dispatch(env, digest)
    CONTRACT.require_runnable(contract)
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    name = "shaar-" + role
    exe = args.bin
    binary_digest = verify_binary(exe, manifest, name, dispatch["revision"])
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=False)
    run_id, attempt = dispatch["run_id"], dispatch["attempt"]
    seeds = {r: KEYS.derive_seed(run_id, attempt, r) for r in ("server", "client")}
    pubs = {r: KEYS.public_key(seed).hex() for r, seed in seeds.items()}
    return {"contract": contract, "digest": digest, "dispatch": dispatch, "exe": exe, "binary_digest": binary_digest,
            "workdir": workdir, "seeds": seeds, "pubs": pubs, "nonce": KEYS.derive_nonce(run_id, attempt),
            "addresses": local_addresses(), "resolved": resolve_targets(contract), "t0": int(args.t0)}


def network_text(setup, relay_address):
    relay = setup["contract"]["targets"]["libp2p_relay"]
    return CONTRACT.render_network([row["used"] for row in setup["resolved"]["bootstrap"]], relay["peer_id"],
                                   relay_address, [row["uri"] for row in setup["resolved"]["ygg"]])


def new_meter(setup):
    BUDGET.preflight()
    rx, tx = BUDGET.parse_net_dev(BUDGET.read_text("/proc/net/dev"))
    allowed = {"ygg": setup["resolved"]["ygg_allowed"], "relay": setup["resolved"]["relay_allowed"]}
    return BUDGET.Meter(setup["contract"]["budgets"]["per_job"], allowed, rx + tx)


def base_evidence(role, setup):
    budgets = setup["contract"]["budgets"]
    return {"schema": 1, "role": role, "source_revision": setup["dispatch"]["revision"],
            "run_id": setup["dispatch"]["run_id"], "run_attempt": 1, "contract_sha256": setup["digest"],
            "product_sha256": setup["binary_digest"], "native_gate": "off (checked in manifest)",
            "public_keys": setup["pubs"], "budgets": budgets["per_job"],
            "resolved": {"mainline_bootstrap": setup["resolved"]["bootstrap"], "ygg_peers": setup["resolved"]["ygg"],
                         "relay": setup["contract"]["targets"]["libp2p_relay"]["address"]},
            "runner_addresses": setup["addresses"], "failures": [], "status": "fail"}


def finish(role, setup, evidence, product, meter, code, secrets):
    totals = meter.totals()
    evidence.update(meter_totals=totals, ygg_and_relay_connections=meter.peers(), violations=meter.violations,
                    product_exit_code=code, product_stderr_tail=sanitized_tail(setup["workdir"] / "product.stderr.log", secrets))
    if code != 0 and not meter.violations:
        evidence["failures"].append(f"product exit code {code}")
    evidence["failures"].extend("budget violation: " + name for name in meter.violations)
    evidence["status"] = "pass" if not evidence["failures"] else "fail"
    out = Path(setup["workdir"]).parent / f"{role}-evidence"
    write_evidence(out, evidence, secrets)
    print(f"public smoke {role}: {evidence['status']}; failures={evidence['failures']}; evidence in {out}")
    return 0 if evidence["status"] == "pass" else 1


def run_server(args, clock=time.time):
    setup = common_setup(args, "server")
    line = CONTRACT.timeline(setup["contract"], setup["t0"])
    if clock() > line["server_launch_by"]:
        raise Abort("server window missed before any network contact")
    workdir, budgets = setup["workdir"], setup["contract"]["budgets"]
    secrets = list(setup["seeds"].values())
    KEYS.write_key_file(workdir / "server.key", setup["seeds"]["server"])
    (workdir / "allowlist.txt").write_text(setup["pubs"]["client"] + "\n", encoding="utf-8")
    target = Target(setup["nonce"], budgets["app"]["request_bytes_max"], budgets["app"]["reply_bytes_max"])
    target.start()
    relay = setup["contract"]["targets"]["libp2p_relay"]["address"]
    host, port = target.address
    config = workdir / "server.ktav"
    config.write_text(CONTRACT.render_server(f"{host}:{port}", network_text(setup, relay)), encoding="utf-8")
    while clock() < setup["t0"]:  # shared window origin: never launch before it
        time.sleep(0.5)
    if clock() > line["server_launch_by"]:
        raise Abort("server window missed before any network contact")
    meter = new_meter(setup)
    evidence = base_evidence("server", setup)
    product = Product(setup["exe"], config, workdir, meter, budgets["sample_interval_ms"] / 1000)
    try:
        wait_until(line["server_end_at"], product, clock, extra=lambda: target.done.is_set())
        if target.done.is_set():
            time.sleep(3)  # let the stream close cleanly before SIGINT
    finally:
        alive = product.alive()
        code = product.stop(budgets["timeline"]["shutdown_grace_s"])
        target.close()
    totals = product.totals()
    evidence["target"] = {"accepts": target.accepts, "request_ok": target.request_ok,
                          "bytes_in": target.bytes_in, "bytes_out": target.bytes_out, "errors": target.errors}
    evidence["observed"] = {"ygg_connections": totals["ygg_connections"], "relay_connections": totals["relay_connections"],
                            "server_alive_until_stop": alive}
    if not alive:
        evidence["failures"].append("server exited before the end of its window")
    if target.accepts != 1 or not target.request_ok or target.errors:
        evidence["failures"].append("the target did not see exactly one valid authorized exchange")
    if totals["ygg_connections"] < 1:
        evidence["failures"].append("no Yggdrasil peer connection observed")
    if totals["relay_connections"] < 1:
        evidence["failures"].append("no relay connection observed")
    return finish("server", setup, evidence, product, meter, code, secrets)


def run_client(args, clock=time.time, sleep=time.sleep):
    setup = common_setup(args, "client")
    line = CONTRACT.timeline(setup["contract"], setup["t0"])
    budgets = setup["contract"]["budgets"]
    timing = budgets["timeline"]
    if clock() > line["client_start_at"] + 5:
        raise Abort("client window missed before any network contact")
    while clock() < line["client_start_at"]:
        sleep(0.5)
    workdir, secrets = setup["workdir"], list(setup["seeds"].values())
    KEYS.write_key_file(workdir / "client.key", setup["seeds"]["client"])
    silent = socket.socket()  # owned silent relay: the Client negotiates nothing, so Native stays blocked
    silent.bind(("127.0.0.1", 0))
    silent.listen(8)
    front = free_port()
    config = workdir / "client.ktav"
    config.write_text(CONTRACT.render_client(setup["pubs"]["server"], f"127.0.0.1:{front}",
                                             network_text(setup, "%s:%d" % silent.getsockname())), encoding="utf-8")
    meter = new_meter(setup)
    evidence = base_evidence("client", setup)
    evidence["native_block"] = "by construction: no globally routable local address; relay is an owned silent loopback listener"
    product = Product(setup["exe"], config, workdir, meter, budgets["sample_interval_ms"] / 1000)
    result = None
    try:
        ready_by = clock() + timing["client_ready_wait_s"]
        wait_until(ready_by, product, clock, extra=lambda: listening(front) and product.totals()["ygg_connections"] >= 1)
        ready = product.alive() and listening(front) and product.totals()["ygg_connections"] >= 1
        evidence["ready"] = {"listener": listening(front), "ygg_connections": product.totals()["ygg_connections"]}
        if not ready:
            evidence["failures"].append("client not ready: listener or Yggdrasil peer connection missing")
        else:
            result = exchange(front, setup["nonce"], timing["client_exchange_s"], budgets["app"]["reply_bytes_max"])
    except (OSError, socket.timeout) as error:
        evidence["failures"].append("APP exchange failed: " + type(error).__name__)
    finally:
        code = product.stop(timing["shutdown_grace_s"])
        silent.close()
    evidence["app"] = result
    if result is not None and not result["match"]:
        evidence["failures"].append("APP reply did not match")
    if result is None and not evidence["failures"]:
        evidence["failures"].append("no APP reply")
    evidence["claims"] = {
        "dht_record_resolved": "not observable: the products log nothing about resolution; inferred only from the exchange succeeding by key alone",
        "route": "Yggdrasil standby inferred by exclusion (no Native path by construction, no relay negotiation); not directly observed",
        "app_payload_bytes": 0 if result is None else result["request_bytes"] + result["reply_bytes"]}
    return finish("client", setup, evidence, product, meter, code, secrets)


def run_validate(env=os.environ):
    contract, digest = CONTRACT.load_contract()
    dispatch = CONTRACT.validate_dispatch(env, digest)
    CONTRACT.require_runnable(contract)
    BUDGET.preflight()
    print("public smoke contract valid:", json.dumps({**dispatch, "approval": contract["approval"]["date"]}, sort_keys=True))


def main(argv):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("validate", "server", "client"))
    parser.add_argument("--manifest")
    parser.add_argument("--bin")
    parser.add_argument("--workdir")
    parser.add_argument("--t0")
    args = parser.parse_args(argv)
    try:
        if args.mode == "validate":
            run_validate()
            return 0
        if not (args.manifest and args.bin and args.workdir and args.t0 and args.t0.isdigit()):
            raise Abort("--manifest, --bin, --workdir and a decimal --t0 are required")
        return (run_server if args.mode == "server" else run_client)(args)
    except (CONTRACT.ContractError, Abort) as error:
        print("public smoke refused:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
