"""Mid-case network changes: NAT state loss, Client address switch, IPv4 loss on a dual-stack segment, total outage, full relay."""

from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "runtime"))
import contract  # noqa: E402
import dynamic  # noqa: E402
import kernel  # noqa: E402
import worker  # noqa: E402

FIRST_APP_SECONDS, FIRST_APP_ATTEMPTS = 15, 2
RECOVERY_SECONDS = int(contract.RECOVERY_SECONDS)
RECOVERY_ATTEMPTS = 10
OUTAGE_APP_SECONDS = 60
RELAY_FULL_SECONDS = 70
GROWTH = ("native_new", "native_snat", "udp_nat", "hole_in", "lan6_native", "lan6_sent")


def alive(run):
    return (run.server, run.client)


def first_app(run):
    """APP 1 over Native before the change; returns the Client-side router counters right after it."""
    _, first, _ = run.app_once("app", FIRST_APP_SECONDS, alive(run), denied=False, attempts=FIRST_APP_ATTEMPTS, pause=1.0)
    run.ev["observations"]["app"] = first
    return run.counters("rtr_a")


def recovery_app(run, changed_at, before, obs):
    """APP 2 after the change must succeed within the recovery bound; records the recovery time and counter growth."""
    _, second, done = run.app_once("app2", RECOVERY_SECONDS, alive(run), denied=False, attempts=RECOVERY_ATTEMPTS, pause=3.0)
    obs["app2"] = second
    obs["recovery_seconds"] = round(done - changed_at, 3)
    after = run.counters("rtr_a")
    obs["growth"] = {name: after[name] - before[name] for name in GROWTH}
    contract.require(obs["recovery_seconds"] <= contract.RECOVERY_SECONDS,
                     f"recovery took {obs['recovery_seconds']} s, above the {contract.RECOVERY_SECONDS} s bound")


def hole(run):
    """D4: the Client-side router loses its NAT state (the Native hole closes); Native must recover without a Client restart."""
    obs = run.ev["observations"].setdefault("perturb", {"kind": "nat-state-flush"})
    before = first_app(run)
    contract.require(before["native_snat"] > 0 and before["native_new"] > 0, "no translated Native UDP before the NAT state flush")
    flushed_at = kernel.flap_wan(run.cfg, run.tools, "rtr_a", run.limit(10))
    recovery_app(run, flushed_at, before, obs)
    contract.require(obs["growth"]["native_new"] > 0, "no new Native NAT mapping after the flush: the old mapping was not lost")


def switch(run):
    """D2: the Client host changes its IPv4 address mid-session; Native must recover from the new address."""
    obs = run.ev["observations"].setdefault("perturb", {"kind": "client-address-switch"})
    before = first_app(run)
    contract.require(before["native_snat"] > 0 and before["native_new"] > 0, "no translated Native UDP before the address switch")
    switched_at = kernel.switch_client_address(run.cfg, run.tools, run.limit(10))
    recovery_app(run, switched_at, before, obs)
    contract.require(obs["growth"]["native_new"] > 0, "the switched Client created no new Native NAT mapping")


def ipv6(run):
    """A2b: IPv4 Native UDP between the hosts is dropped for the whole case and the Client dials the Server's IPv6 candidate."""
    budget = int(min(worker.MAX_DEADLINE, run.active_end - time.monotonic()))
    contract.require(budget >= 10, "active budget exhausted before the APP campaign")
    ready, result, _ = run.app_once("app", budget, alive(run), denied=False)
    run.ev["observations"]["app_ready"], run.ev["observations"]["app"] = ready, result
    drops, _ = dynamic.remove(run.cfg, run.tools, "v4", run.limit(10))
    run.ev["observations"]["ipv6"]["v4_block_drops"] = drops


def outage_recovery(run):
    """C7: total outage (Native UDP and Ygg both blocked): typed failure and Client end; after the blocks lift a fresh Client works."""
    obs = run.ev["observations"].setdefault("outage", {})
    dynamic.install(run.cfg, run.tools, "native", run.ports, run.limit(10))
    dynamic.install(run.cfg, run.tools, "ygg", run.ports, run.limit(10))
    _, failed, _ = run.app_once("app", OUTAGE_APP_SECONDS, (run.server,), denied=True, attempts=2, pause=1.0)
    obs["app_outage"] = failed
    obs["client1_exit"] = run.sup.wait(run.client, run.limit(45))
    contract.require(obs["client1_exit"] == 1, f"the outage Client exit status {obs['client1_exit']} is not the typed failure status")
    native, _ = dynamic.remove(run.cfg, run.tools, "native", run.limit(10))
    ygg, lifted_at = dynamic.remove(run.cfg, run.tools, "ygg", run.limit(10))
    obs["native_block_drops"], obs["ygg_block_drops"] = native, ygg
    contract.require(native["rtr_a"]["packets"] > 0 and ygg["rtr_a"]["packets"] > 0, "the outage never observed Native UDP and Ygg TCP attempts")
    run.client = run.product("client2", run.client_ns, str(run.work / "client.ktav"), binary="client")
    _, second, done = run.app_once("app2", RECOVERY_SECONDS, alive(run), denied=False, attempts=RECOVERY_ATTEMPTS, pause=3.0)
    obs["app2"] = second
    obs["recovery_seconds"] = round(done - lifted_at, 3)
    contract.require(obs["recovery_seconds"] <= contract.RECOVERY_SECONDS,
                     f"recovery after the outage took {obs['recovery_seconds']} s, above the {contract.RECOVERY_SECONDS} s bound")


def relay_full(run):
    """C5: both relay reservations are held by other Servers; the real Server must end by itself with the typed startup error."""
    obs = run.ev["observations"].setdefault("relay_full", {})
    obs["message"] = run.sup.mark(run.server, contract.RESERVE_FAIL, run.limit(RELAY_FULL_SECONDS))
    obs["server_exit"] = run.sup.wait(run.server, run.limit(20))
    obs["seconds"] = round(time.monotonic() - run.active_start, 3)
    contract.require(obs["server_exit"] == run.spec["server_exit"], f"Server exit status {obs['server_exit']} differs from the typed failure")
    contract.require(obs["seconds"] <= RELAY_FULL_SECONDS, f"typed Server failure took {obs['seconds']} s, above {RELAY_FULL_SECONDS} s")
    contract.require(all(not filler.exited for filler in run.fillers), "a relay filler ended before the Server's startup failure")
