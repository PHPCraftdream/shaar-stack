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
sys.path.insert(0, str(HERE.parent / "flows"))
import configs  # noqa: E402
import contract  # noqa: E402
import scenarios  # noqa: E402
import kernel  # noqa: E402
import natprobe  # noqa: E402
import network  # noqa: E402
import observe  # noqa: E402
import processes  # noqa: E402
import worker  # noqa: E402

WORKER = HERE / "worker.py"
FIXTURE_ARGS = ["--ignored", "--exact", "process_smoke::composed::nat::fixture_child", "--nocapture", "--test-threads=2"]
STARTUP = b"composed startup:"
RESERVE_FAIL = contract.RESERVE_FAIL
# Fixed delay for filler Servers to take their relay reservations; the reservation has no observable signal.
RELAY_SETTLE_SECONDS = 8
ACTIVE_SECONDS = contract.ACTIVE_SECONDS


def atomic(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream)
    os.replace(temporary, path)


def app_expectation(spec, result, ok=None):
    """Exact APP outcome (ok: success expected; default from the case); a denied/failed stream never counts as a pass."""
    request, reply = worker.payloads(result["nonce"])
    if spec["target_accepts"] > 0 if ok is None else ok:
        contract.require(result.get("denied") is False and result.get("reply_bytes") == len(reply)
                         and result.get("request_bytes") == len(request), "APP did not receive the exact fixed-target reply")
    else:
        contract.require(result.get("denied") is True and result.get("reply_bytes") == 0
                         and result.get("terminal") in ("eof", "reset"), "APP stream did not fail closed without reply bytes")


def target_expectation(spec, nonce, result):
    request, reply = worker.payloads(nonce)
    count = spec["target_accepts"]
    want = {"accepts": count, "request_bytes": count * len(request), "reply_bytes": count * len(reply)}
    contract.require({key: result.get(key) for key in want} == want, "fixed-target accept/byte receipt differs from the case")



class Run:
    def __init__(self, cfg, root, case, products, tools, supervisor, purpose, started):
        self.cfg, self.root, self.case, self.spec = cfg, root, case, contract.CASES[case]
        self.products, self.tools, self.sup, self.purpose = products, tools, supervisor, purpose
        self.nonce, self.uid, self.gid = cfg["nonce"], cfg["helper_uid"], cfg["helper_gid"]
        self.work, self.started = root / "work", started
        self.hard = supervisor.deadline
        self.client_ns = contract.client_ns(self.spec)
        self.live = {}
        self.client, self.fillers = None, []
        self.ev = {"case": case, "purpose": purpose, "identities": {}, "observations": {}, "markers": {}}

    def limit(self, seconds):
        return min(time.monotonic() + seconds, self.hard)

    def launch(self, name, ns, exe, args, env=None, markers=()):
        argv = processes.namespace_command(self.cfg, ns, exe, args, self.tools["ip"], self.tools["setpriv"],
                                           lan=self.spec["net"] in contract.SEGMENT_NETS)
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

    def other_key(self):
        """A valid identity seed that no allowlist contains: the unauthorized Client's private key file."""
        return self.seed_key("other", 0xD3)

    def seed_key(self, name, byte):
        """Private key file of a distinct fixture identity, owned by the unprivileged helper identity."""
        path = self.work / "keys" / (name + ".key")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(bytes([byte]) * 32)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(path, self.uid, self.gid)
        os.chmod(path, 0o600)
        return str(path)

    def product(self, name, ns, config, binary=None, extra=()):
        exe = self.products["shaar-" + (binary or name)]["executable"]
        child = self.launch(name, ns, exe, ["--config", config], markers=(STARTUP, *extra))
        self.ev["markers"][name] = self.sup.mark(child, STARTUP, self.limit(30))
        self.identity(child)
        return child

    def calibrate_and_install(self, ports):
        deadline = self.limit(45)
        pairs = (("rtr_a", "host_a"), ("rtr_b", "host_b"))
        self.ev["quota_calibration"] = [kernel.calibrate_quota(self.cfg, self.tools, router, host, deadline)
                                        for router, host in pairs]
        self.ev["observe_calibration"] = [observe.calibrate(self.cfg, self.tools, router, host, deadline)
                                          for router, host in pairs]
        flavor = network.PROFILES[self.case].get("nat")
        if flavor in natprobe.STATEMENTS:
            self.ev["nat_calibration"] = [natprobe.calibrate(self.cfg, self.tools, router, host, flavor, deadline)
                                          for router, host in pairs]
        if flavor == "cone":
            self.ev["punch_control"] = natprobe.punch(self.cfg, self.tools, deadline)
        self.ev["rules"] = [kernel.install_rules(self.cfg, self.tools, router, self.case, ports, self.purpose, deadline)
                            for router in ("rtr_a", "rtr_b")]
        return {router: kernel.snapshot(self.cfg, self.tools, router, deadline) for router in ("rtr_a", "rtr_b")}

    def counters(self, router):
        """Validated packet counters of the case's product table right now."""
        document = kernel.snapshot(self.cfg, self.tools, router, self.limit(10))
        found = network.snapshot(document, self.cfg["prefix"], self.purpose)["counters"]
        return {name: value["packets"] for name, value in found.items()}

    def expect_app(self, result, ok):
        app_expectation(self.spec, result, ok)

    def app_once(self, name, deadline, guards, denied, attempts=None, pause=None):
        """One bounded APP campaign; returns (ready, result, monotonic completion time)."""
        extra = ["--deadline", str(int(deadline))]
        if denied:
            extra.append("--deny")
        if attempts is not None:
            extra += ["--attempts", str(attempts)]
        if pause is not None:
            extra += ["--pause", str(pause)]
        app = self.python_worker(name, self.client_ns, "app", *extra)
        ready = self.await_event(app, "SHAAR_NAT_READY", self.limit(deadline), watch=guards)
        result = self.await_event(app, "SHAAR_NAT_RESULT", self.limit(deadline + 5), watch=guards)
        done = time.monotonic()
        self.expect_app(result, not denied)
        contract.require(self.sup.wait(app, self.limit(10)) == 0, "APP worker failed")
        return ready, result, done

    def verify_kernel(self, before):
        net = self.spec["net"]
        deadline = self.limit(20)
        report, watched = {}, {}
        for router in ("rtr_a", "rtr_b"):
            after = kernel.snapshot(self.cfg, self.tools, router, deadline)
            watched[router] = observe.read(self.cfg, self.tools, router, deadline)
            self.ev["observe"] = watched  # recorded before any verdict so a violation keeps its evidence
            client_side = router == "rtr_a"
            report[router] = network.verify(before[router], after, self.cfg["prefix"], self.purpose, blocked=net == "blocked",
                                            require_nat=client_side and net in ("nat", "failover", "recover"),
                                            require_drop=client_side and net == "blocked")
            observe.verify_zero(watched[router], router)
        self.ev["kernel"] = report
        self.ev["forwarded_bytes"] = sum(item["quota_used"] for item in report.values())

    def observe_nat(self):
        """Conntrack tuple while mappings are fresh; counters in verify_kernel are the required NAT oracle."""
        if self.spec["net"] != "nat":
            return
        native_ports = kernel.native_candidates(self.publication["native_addresses"], self.ports["dht"])
        seen = self.ev["observations"]
        try:
            lines = kernel.conntrack_lines(self.cfg, self.tools, "rtr_a", self.limit(20))
        except ValueError as error:
            seen["native_nat_tuple_unavailable"] = str(error)[:200]
            return
        (self.root / "conntrack-rtr-a.txt").write_text("\n".join(lines[:512]) + "\n", encoding="utf-8")
        found = kernel.nat_observation(lines, self.cfg["ip"]["host_a"], self.cfg["ip"]["rtr_a_wan"], native_ports)
        if found is None:
            seen["native_nat_tuple_unavailable"] = f"no matching replied entry among {len(lines)} conntrack entries"
        else:
            seen["native_nat_tuple"] = found

    def stop_all(self):
        sup, spec = self.sup, self.spec
        expected, client_code = contract.final_client_exit(spec), None
        if self.client is not None:
            if expected == 0:
                sup.interrupt(self.client)
            client_code = sup.wait(self.client, self.limit(45))
            contract.require(client_code == expected, f"Client exit status {client_code} differs from the case")
        server_expected = spec.get("server_exit", 0)
        if server_expected == 0:
            sup.interrupt(self.server)
        contract.require(sup.wait(self.server, self.limit(30)) == server_expected, "Server exit status differs from the case")
        for filler in self.fillers:
            sup.interrupt(filler)
            contract.require(sup.wait(filler, self.limit(30)) == 0, "filler Server did not shut down normally")
        sup.send_stdin(self.target, ("STOP " + self.nonce + "\n").encode("ascii"))
        receipt = self.await_event(self.target, "SHAAR_NAT_RESULT", self.limit(20))
        target_expectation(spec, self.nonce, receipt)
        self.ev["observations"]["target"] = receipt
        contract.require(sup.wait(self.target, self.limit(20)) == 0, "fixed-target worker failed")
        stopper = self.python_worker("stop-wan", "wan", "stop", "--port", str(self.wan_ready["control_port"]))
        self.await_event(stopper, "SHAAR_NAT_RESULT", self.limit(20))
        contract.require(sup.wait(stopper, self.limit(20)) == 0, "WAN control worker failed")
        return client_code

    def fill_relay(self, index, allow):
        """An extra composed Server with its own identity: it holds one of the owned relay's two reservations."""
        name = f"filler{index}"
        key = self.seed_key(name, 0xE0 + index)
        config = self.owned_file(name + ".ktav", configs.server_text(self.case, key, allow, self.ports, self.relay, ns="wan"))
        return self.product(name, "wan", config, binary="server")

    def settle(self, seconds):
        """Bounded fixed delay for an effect with no observable signal; owned children stay supervised meanwhile."""
        end = self.limit(seconds)
        while time.monotonic() < end:
            for child in self.fillers:
                if child.exited:
                    raise RuntimeError(f"owned filler exited during the settle delay: {child.name} rc={child.returncode}")
            try:
                self.sup.step(end)
            except TimeoutError:
                break

    def bring_up(self, after_live):
        spec, ev = self.spec, self.ev
        keys, ready = self.helper("keys", "wan", "keys", verify=False, SHAAR_NAT_DIRECTORY=str(self.work / "keys"))
        contract.require(self.sup.wait(keys, self.limit(20)) == 0, "identity provisioning helper failed")
        for name in ("server.key", "client.key"):
            status = (self.work / "keys" / name).stat()
            contract.require(status.st_uid == self.uid and status.st_mode & 0o777 == 0o600, "provisioned key ownership/mode differs")
        ev["observations"]["key_files"] = "owned by the unprivileged helper identity, mode 0600"
        self.server_key, client_key = ready["server_key"], ready["client_key"]
        self.wan, self.wan_ready = self.helper("wan", "wan", "wan", SHAAR_NAT_SERVICE_KEY=self.server_key)
        wan_started = time.monotonic()
        ready = self.wan_ready
        self.ports = {"dht": ready["dht_port"], "relay": ready["relay_port"], "transit": ready["transit_port"]}
        ev["wan"] = {**self.ports, "control_port": ready["control_port"], "relay_peer": ready["relay_peer"]}
        self.before = self.calibrate_and_install(self.ports)
        if spec["net"] in contract.SEGMENT_NETS:
            kernel.isolate_segment(self.cfg, self.tools, self.limit(10))
        if spec["net"] == "ipv6":
            kernel.add_segment_v6(self.cfg, self.tools, self.limit(10))
        count = spec["target_accepts"]
        target_args = ["--deny"] if count == 0 else ["--accepts", str(count)] if count > 1 else []
        self.target = self.python_worker("target", spec["server_ns"], "target", *target_args)
        contract.require(self.await_event(self.target, "SHAAR_NAT_READY", self.limit(20))["port"] == contract.TARGET_PORT,
                         "fixed target port differs")
        self.identity(self.target)
        self.relay = ready["relay_peer"]
        allow = self.owned_file("allowlist.txt", configs.allowlist_text(client_key))
        server_cfg = self.owned_file("server.ktav", configs.server_text(
            self.case, str(self.work / "keys/server.key"), allow, self.ports, self.relay))
        client_cfg = self.owned_file("client.ktav", configs.client_text(
            self.case, self.server_key, str(self.work / "keys/client.key"), self.ports, self.relay))
        for index in range(1, spec.get("fillers", 0) + 1):
            self.fillers.append(self.fill_relay(index, allow))
        if self.fillers:
            self.settle(RELAY_SETTLE_SECONDS)
        self.active_start = time.monotonic()
        self.active_end = min(self.active_start + ACTIVE_SECONDS, wan_started + 95)
        failing = contract.server_fails(spec)
        self.server = self.product("server", spec["server_ns"], server_cfg, extra=(RESERVE_FAIL,) if failing else ())
        if failing:
            return  # the flow observes the Server's own typed startup failure; no record, Client or live-phase hook
        self.publication = self.await_event(self.wan, "SHAAR_NAT_PUBLICATION", self.limit(45), watch=(self.server,))
        contract.validate_publication(self.publication, self.nonce, self.server_key)
        server_ip = contract.ip_for(spec["server_ns"])
        contract.require(any(item.rpartition(":")[0] == server_ip for item in self.publication["native_addresses"]),
                         "signed Server record lacks its namespace Native address")
        ev["publication"] = self.publication
        self.client = self.product("client", self.client_ns, client_cfg)
        contract.require("server_address=none" in ev["markers"]["client"], "Client must be configured with the Server key only")
        live = {"wan": self.wan, "target": self.target, "server": self.server, "client": self.client}
        atomic(self.root / "records/children_started", {"nonce": self.nonce, "pids": {k: v.process.pid for k, v in live.items()}})
        after_live()

    def run(self, after_live):
        spec, ev = self.spec, self.ev
        self.bring_up(after_live)
        scenarios.FLOWS[spec.get("flow", "single")](self)
        ev["active_seconds"] = time.monotonic() - self.active_start
        self.observe_nat()
        ev["client_exit"] = self.stop_all()
        contract.require(self.sup.wait(self.wan, self.limit(20)) == 0, "WAN helper did not stop gracefully")
        self.verify_kernel(self.before)
        contract.require(set(ev["identities"]) == set(contract.identity_roles(spec)), "verified identity set differs from the contract")
        return ev
