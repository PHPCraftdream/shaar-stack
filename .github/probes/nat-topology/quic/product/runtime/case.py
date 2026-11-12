"""One controlled product case: helpers, normal products, exact APP bytes and kernel observations."""

import hashlib
import json
import os
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import configs  # noqa: E402
import contract  # noqa: E402
import kernel  # noqa: E402
import network  # noqa: E402
import processes  # noqa: E402
import worker  # noqa: E402

WORKER = HERE / "worker.py"
FIXTURE_ARGS = ["--ignored", "--exact", "process_smoke::composed::nat::fixture_child", "--nocapture", "--test-threads=2"]
STARTUP = b"composed startup:"
ACTIVE_SECONDS = contract.ACTIVE_SECONDS


def atomic(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream)
    os.replace(temporary, path)


def app_expectation(spec, result):
    """Exact APP outcome for the case; a denied/failed stream never counts as a pass."""
    request, reply = worker.payloads(result["nonce"])
    if spec["target_accepts"] == 1:
        contract.require(result.get("denied") is False and result.get("reply_bytes") == len(reply)
                         and result.get("request_bytes") == len(request), "APP did not receive the exact fixed-target reply")
    else:
        contract.require(result.get("denied") is True and result.get("reply_bytes") == 0
                         and result.get("terminal") in ("eof", "reset"), "APP stream did not fail closed without reply bytes")


def target_expectation(spec, nonce, result):
    request, reply = worker.payloads(nonce)
    want = {"accepts": spec["target_accepts"], "request_bytes": len(request) if spec["target_accepts"] else 0,
            "reply_bytes": len(reply) if spec["target_accepts"] else 0}
    contract.require({key: result.get(key) for key in want} == want, "fixed-target accept/byte receipt differs from the case")


class Run:
    def __init__(self, cfg, root, case, products, tools, supervisor, purpose, started):
        self.cfg, self.root, self.case, self.spec = cfg, root, case, contract.CASES[case]
        self.products, self.tools, self.sup, self.purpose = products, tools, supervisor, purpose
        self.nonce, self.uid, self.gid = cfg["nonce"], cfg["helper_uid"], cfg["helper_gid"]
        self.work, self.started = root / "work", started
        self.hard = supervisor.deadline
        self.live = {}
        self.ev = {"case": case, "purpose": purpose, "identities": {}, "observations": {}, "markers": {}}

    def limit(self, seconds):
        return min(time.monotonic() + seconds, self.hard)

    def launch(self, name, ns, exe, args, env=None, markers=()):
        argv = processes.namespace_command(self.cfg, ns, exe, args, self.tools["ip"], self.tools["setpriv"])
        return self.sup.spawn(name, argv, env or {}, markers)

    def identity(self, child):
        """Exact /proc privilege receipt for long-lived children read after their readiness signal."""
        self.ev["identities"][child.name] = self.sup.verify_identity(child, self.uid, self.gid)

    def await_event(self, child, kind, deadline, watch=()):
        while True:
            for guard in watch:
                if guard.exited:
                    raise RuntimeError(f"owned product exited unexpectedly: {guard.name} rc={guard.returncode}")
            if child.events or (child.exited and child.open_streams == 0):
                return self.sup.event(child, kind, deadline)
            self.sup.step(deadline)

    def helper(self, name, ns, role, verify=True, **extra):
        env = {"SHAAR_NAT_ROLE": role, "SHAAR_NAT_NONCE": self.nonce, **extra}
        child = self.launch(name, ns, self.products["identity-helper"]["executable"], FIXTURE_ARGS, env)
        ready = self.await_event(child, "SHAAR_NAT_READY", self.limit(40))
        contract.validate_ready(ready, role, self.nonce, child.process.pid)
        if verify:
            self.identity(child)
        return child, ready

    def python_worker(self, name, ns, role, *extra):
        argv = ["-I", str(WORKER), role, self.nonce, *extra]
        return self.launch(name, ns, self.tools["python"], argv)

    def owned_file(self, name, text):
        path = self.work / name
        with path.open("x", encoding="utf-8") as stream:
            stream.write(text)
        os.chown(path, self.uid, self.gid)
        os.chmod(path, 0o600)
        self.ev["observations"].setdefault("config_sha256", {})[name] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return str(path)

    def product(self, name, ns, config):
        child = self.launch(name, ns, self.products["shaar-" + name]["executable"], ["--config", config], markers=(STARTUP,))
        self.ev["markers"][name] = self.sup.mark(child, STARTUP, self.limit(30))
        self.identity(child)
        return child

    def calibrate_and_install(self, ports):
        deadline = self.limit(30)
        self.ev["quota_calibration"] = [kernel.calibrate_quota(self.cfg, self.tools, router, host, deadline)
                                        for router, host in (("rtr_a", "host_a"), ("rtr_b", "host_b"))]
        self.ev["rules"] = [kernel.install_rules(self.cfg, self.tools, router, self.case, ports, self.purpose, deadline)
                            for router in ("rtr_a", "rtr_b")]
        return {router: kernel.snapshot(self.cfg, self.tools, router, deadline) for router in ("rtr_a", "rtr_b")}

    def verify_kernel(self, before):
        blocked = self.spec["udp_blocked"]
        deadline = self.limit(20)
        report = {}
        for router in ("rtr_a", "rtr_b"):
            after = kernel.snapshot(self.cfg, self.tools, router, deadline)
            client_side = router == "rtr_a"
            report[router] = network.verify(before[router], after, self.cfg["prefix"], self.purpose, blocked=blocked,
                                            require_nat=client_side and not blocked, require_drop=client_side and blocked)
        self.ev["kernel"] = report
        self.ev["forwarded_bytes"] = sum(item["quota_used"] for item in report.values())

    def observe_nat(self, native_ports):
        """Taken while NAT mappings are fresh: replied Native UDP tuple with fixed-range SNAT."""
        if self.spec["udp_blocked"]:
            return
        lines = kernel.conntrack_lines(self.cfg, self.tools, "rtr_a", self.limit(20))
        (self.root / "conntrack-rtr-a.txt").write_text("\n".join(lines[:512]) + "\n", encoding="utf-8")
        found = kernel.nat_observation(lines, self.cfg["ip"]["host_a"], self.cfg["ip"]["rtr_a_wan"], native_ports)
        contract.require(found is not None, "no replied Native UDP conntrack entry with fixed-range SNAT to the published address")
        self.ev["observations"]["native_nat_tuple"] = found

    def stop_all(self, wan_ready, server, client, target):
        sup = self.sup
        if self.spec["client_exit"] == 0:
            sup.interrupt(client)
        client_code = sup.wait(client, self.limit(45))
        contract.require(client_code == self.spec["client_exit"], f"Client exit status {client_code} differs from the case")
        sup.interrupt(server)
        contract.require(sup.wait(server, self.limit(30)) == 0, "Server did not shut down normally")
        sup.send_stdin(target, ("STOP " + self.nonce + "\n").encode("ascii"))
        receipt = self.await_event(target, "SHAAR_NAT_RESULT", self.limit(20))
        target_expectation(self.spec, self.nonce, receipt)
        self.ev["observations"]["target"] = receipt
        contract.require(sup.wait(target, self.limit(20)) == 0, "fixed-target worker failed")
        stopper = self.python_worker("stop-wan", "wan", "stop", "--port", str(wan_ready["control_port"]))
        self.await_event(stopper, "SHAAR_NAT_RESULT", self.limit(20))
        contract.require(sup.wait(stopper, self.limit(20)) == 0, "WAN control worker failed")
        return client_code

    def run(self, after_live):
        spec, ev = self.spec, self.ev
        keys, ready = self.helper("keys", "wan", "keys", verify=False, SHAAR_NAT_DIRECTORY=str(self.work / "keys"))
        contract.require(self.sup.wait(keys, self.limit(20)) == 0, "identity provisioning helper failed")
        for name in ("server.key", "client.key"):
            status = (self.work / "keys" / name).stat()
            contract.require(status.st_uid == self.uid and status.st_mode & 0o777 == 0o600, "provisioned key ownership/mode differs")
        ev["observations"]["key_files"] = "owned by the unprivileged helper identity, mode 0600"
        server_key, client_key = ready["server_key"], ready["client_key"]
        wan, wan_ready = self.helper("wan", "wan", "wan", SHAAR_NAT_SERVICE_KEY=server_key)
        wan_started = time.monotonic()
        ports = {"dht": wan_ready["dht_port"], "relay": wan_ready["relay_port"], "transit": wan_ready["transit_port"]}
        ev["wan"] = {**ports, "control_port": wan_ready["control_port"], "relay_peer": wan_ready["relay_peer"]}
        before = self.calibrate_and_install(ports)
        denied = [] if spec["target_accepts"] else ["--deny"]
        target = self.python_worker("target", spec["server_ns"], "target", *denied)
        contract.require(self.await_event(target, "SHAAR_NAT_READY", self.limit(20))["port"] == contract.TARGET_PORT,
                         "fixed target port differs")
        self.identity(target)
        relay = wan_ready["relay_peer"]
        allow = self.owned_file("allowlist.txt", configs.allowlist_text(client_key))
        server_cfg = self.owned_file("server.ktav", configs.server_text(
            self.case, str(self.work / "keys/server.key"), allow, ports, relay))
        client_cfg = self.owned_file("client.ktav", configs.client_text(
            self.case, server_key, str(self.work / "keys/client.key"), ports, relay))
        active_start = time.monotonic()
        active_end = min(active_start + ACTIVE_SECONDS, wan_started + 95)
        server = self.product("server", spec["server_ns"], server_cfg)
        publication = self.await_event(wan, "SHAAR_NAT_PUBLICATION", self.limit(45), watch=(server,))
        contract.validate_publication(publication, self.nonce, server_key)
        server_ip = contract.IPS[spec["server_ns"]]
        contract.require(any(item.rpartition(":")[0] == server_ip for item in publication["native_addresses"]),
                         "signed Server record lacks its namespace Native address")
        ev["publication"] = publication
        client = self.product("client", "host_a", client_cfg)
        contract.require("server_address=none" in ev["markers"]["client"], "Client must be configured with the Server key only")
        live = {"wan": wan, "target": target, "server": server, "client": client}
        atomic(self.root / "records/children_started", {"nonce": self.nonce, "pids": {k: v.process.pid for k, v in live.items()}})
        after_live()
        budget = int(min(worker.MAX_DEADLINE, active_end - time.monotonic()))
        contract.require(budget >= 10, "active budget exhausted before the APP campaign")
        guards = (server,) if spec["client_exit"] == 1 else (server, client)
        app = self.python_worker("app", "host_a", "app", "--deadline", str(budget), *denied)
        ev["observations"]["app_ready"] = self.await_event(app, "SHAAR_NAT_READY", self.limit(budget), watch=guards)
        result = self.await_event(app, "SHAAR_NAT_RESULT", self.limit(budget + 5), watch=guards)
        app_expectation(spec, result)
        ev["observations"]["app"] = result
        contract.require(self.sup.wait(app, self.limit(10)) == 0, "APP worker failed")
        ev["active_seconds"] = time.monotonic() - active_start
        self.observe_nat(kernel.native_candidates(publication["native_addresses"], ports["dht"]))
        ev["client_exit"] = self.stop_all(wan_ready, server, client, target)
        contract.require(self.sup.wait(wan, self.limit(20)) == 0, "WAN helper did not stop gracefully")
        self.verify_kernel(before)
        return ev
