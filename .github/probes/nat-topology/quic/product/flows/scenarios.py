"""Controller flows between bring-up and shutdown: one APP campaign, runtime failover/recovery, key denial."""

from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "runtime"))
import configs  # noqa: E402
import contract  # noqa: E402
import dynamic  # noqa: E402
import perturb  # noqa: E402
import worker  # noqa: E402

# Per-campaign transaction caps; the failover case sums to the contract maximum of 16 fresh APP transactions.
APP1_ATTEMPTS, APP2_ATTEMPTS, APP3_ATTEMPTS = 2, 4, 10
FAILOVER_APP_SECONDS = 15
SIGNAL_APP_SECONDS = 45
RECOVERY_APP_SECONDS = int(contract.RECOVERY_SECONDS)
DENIED_APP_SECONDS = 40


def alive(run, *extra):
    return (run.server, run.client, *extra)


def single(run):
    """One APP campaign: exact reply (accept case) or terminal failure without reply bytes (fail-closed case)."""
    spec, ev = run.spec, run.ev
    budget = int(min(worker.MAX_DEADLINE, run.active_end - time.monotonic()))
    contract.require(budget >= 10, "active budget exhausted before the APP campaign")
    guards = (run.server,) if spec["client_exit"] == 1 else (run.server, run.client)
    ready, result, _ = run.app_once("app", budget, guards, denied=spec["target_accepts"] == 0)
    ev["observations"]["app_ready"] = ready
    ev["observations"]["app"] = result


def growth(after, before, name):
    return after[name] - before[name]


def failover(run):
    """Native first, then a runtime Native UDP block; standby must continue over Ygg within the north-star bound."""
    spec, ev = run.spec, run.ev
    standby = spec["mode"] == "standby"
    obs = ev["observations"].setdefault("failover", {})
    start = run.counters("rtr_a")
    _, first, _ = run.app_once("app", FAILOVER_APP_SECONDS, alive(run), denied=False, attempts=APP1_ATTEMPTS, pause=1.0)
    ev["observations"]["app"] = first
    after_first = run.counters("rtr_a")
    # Ygg is reachable here, so Native carriage of APP 1 is policy plus counters, not path exclusion.
    obs["app1_native_snat_packets"] = growth(after_first, start, "native_snat")
    obs["app1_ygg_tcp_packets"] = growth(after_first, start, "ygg_tcp")
    contract.require(after_first["native_snat"] > 0 and after_first["udp_nat"] > 0, "no translated Native UDP before the block")
    blocked_at = dynamic.install(run.cfg, run.tools, "native", run.ports, run.limit(10))
    base = run.counters("rtr_a")
    if not standby:
        _, second, done = run.app_once("app2", SIGNAL_APP_SECONDS, (run.server,), denied=True, attempts=2, pause=1.0)
        obs["app2"] = second
        obs["fail_closed_seconds"] = round(done - blocked_at, 3)
        report_block(run, obs, base)
        return
    _, second, done = run.app_once("app2", FAILOVER_APP_SECONDS, alive(run), denied=False, attempts=APP2_ATTEMPTS, pause=1.5)
    obs["app2"] = second
    obs["failover_seconds"] = round(done - blocked_at, 3)
    report_block(run, obs, base, keep=True)
    contract.require(obs["failover_seconds"] <= contract.FAILOVER_SECONDS,
                     f"failover to Ygg took {obs['failover_seconds']} s, above the {contract.FAILOVER_SECONDS} s bound")
    contract.require(obs["block_ygg_tcp_packets"] > 0, "no Ygg TCP traffic while Native was blocked")
    recover(run, obs)


def report_block(run, obs, base, keep=False):
    """Counters while the Native block is installed; removes the block unless the caller continues with it."""
    now = run.counters("rtr_a")
    obs["block_native_snat_packets"] = growth(now, base, "native_snat")
    obs["block_ygg_tcp_packets"] = growth(now, base, "ygg_tcp")
    if not keep:
        seen, _ = dynamic.remove(run.cfg, run.tools, "native", run.limit(10))
        obs["native_block_drops"] = seen
        contract.require(seen["rtr_a"]["packets"] > 0, "the runtime block never observed a Native UDP attempt")
    contract.require(obs["block_native_snat_packets"] == 0, "translated Native UDP escaped the runtime block")


def recover(run, obs):
    """Native returns after the block is lifted; Ygg is then blocked so a later APP can only succeed over Native."""
    dynamic.install(run.cfg, run.tools, "ygg", run.ports, run.limit(10))
    seen, unblocked_at = dynamic.remove(run.cfg, run.tools, "native", run.limit(10))
    obs["native_block_drops"] = seen
    contract.require(seen["rtr_a"]["packets"] > 0, "the runtime block never observed a Native UDP attempt")
    before = run.counters("rtr_a")
    _, third, done = run.app_once("app3", RECOVERY_APP_SECONDS, alive(run), denied=False, attempts=APP3_ATTEMPTS, pause=3.0)
    obs["app3"] = third
    obs["recovery_seconds"] = round(done - unblocked_at, 3)
    after = run.counters("rtr_a")
    obs["recovery_native_snat_packets"] = growth(after, before, "native_snat")
    ygg, _ = dynamic.remove(run.cfg, run.tools, "ygg", run.limit(10))
    obs["ygg_block_drops"] = ygg
    contract.require(obs["recovery_seconds"] <= contract.RECOVERY_SECONDS,
                     f"Native recovery took {obs['recovery_seconds']} s, above the {contract.RECOVERY_SECONDS} s bound")
    contract.require(obs["recovery_native_snat_packets"] > 0, "no translated Native UDP after the block was lifted")


def denied_key(run):
    """Authorized control first, then a different key over the same blockade: no reply bytes, no target connection."""
    spec, ev, sup = run.spec, run.ev, run.sup
    ready, control, _ = run.app_once("app", DENIED_APP_SECONDS, alive(run), denied=False)
    ev["observations"]["app_ready"] = ready
    ev["observations"]["app"] = control
    sup.interrupt(run.client)
    code = sup.wait(run.client, run.limit(30))
    ev["observations"]["client1_exit"] = code
    contract.require(code == 0, f"authorized Client exit status {code} differs from the case")
    key_file = run.other_key()
    config = run.owned_file("client2.ktav", configs.client_text(
        run.case, run.server_key, key_file, run.ports, run.relay))
    run.client = run.product("client2", run.client_ns, config, binary="client")
    _, denied, _ = run.app_once("app2", DENIED_APP_SECONDS, (run.server,), denied=True, attempts=2, pause=1.0)
    ev["observations"]["denied_app"] = denied


FLOWS = {"single": single, "failover": failover, "denied-key": denied_key, "hole": perturb.hole, "switch": perturb.switch,
         "ipv6": perturb.ipv6, "outage-recovery": perturb.outage_recovery, "relay-full": perturb.relay_full}
