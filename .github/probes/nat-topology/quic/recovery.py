"""Physical inbound loss after WAN capture; only the case-owned routers are altered."""
import re


def rule(cfg, side, install):
    host = cfg["ip"][("host_a", "host_b")[side]]
    port = cfg["port"][("src_a", "src_b")[side]]
    operation = ["-I", "FORWARD", "1"] if install else ["-D", "FORWARD"]
    return ["iptables", *operation, "-d", host, "-p", "udp", "--dport", port,
            "-m", "comment", "--comment", "p03-recovery-inbound", "-j", "DROP"]


def validate(lost, recovered):
    if len(lost) != 2 or len(recovered) != 2:
        raise ValueError("recovery requires both peers")
    for side, (before, after) in enumerate(zip(lost, recovered)):
        if (after["stable_id"] != before["stable_id"] or after["old_path"] != before["old_path"]
                or after["new_path"] == before["old_path"] or after["sent_stream"] != before["sent_stream"]
                or after["received_stream"] != lost[1 - side]["sent_stream"]
                or after["lost_packets"] <= before["lost_before"]
                or before["stream_frames_lost"] <= before["stream_frames_before"]
                or after["stream_frames_recovered"] <= before["stream_frames_lost"]
                or after["payload"] != "recover!"):
            raise ValueError("recovery did not preserve connection/STREAM or prove physical loss/fresh path")


def run(cfg, root, children, core):
    for side, router in enumerate(("rtr_a", "rtr_b")):
        core.run(cfg, router, rule(cfg, side, True), root / f"recovery-drop-{router}.txt")
    # Packets reach the WAN observer before post-DNAT inbound FORWARD drops them.
    (root / "LOSS").touch(exist_ok=False)
    lost = core.wait_files([root / f"peer-{side}-lost.json" for side in range(2)], children)
    drops = []
    for side, router in enumerate(("rtr_a", "rtr_b")):
        rules = core.run(cfg, router, ["iptables-save", "-c"], root / f"recovery-counters-{router}.txt")
        count = sum(int(match.group(1)) for line in rules.splitlines()
                    if "p03-recovery-inbound" in line and (match := re.match(r"\[(\d+):\d+\]", line)))
        if count <= 0:
            raise ValueError("physical recovery loss rule never dropped a native packet")
        drops.append({"router": router, "dropped": count})
        core.run(cfg, router, rule(cfg, side, False), root / f"recovery-restore-{router}.txt")
    (root / "RESTORE").touch(exist_ok=False)
    recovered = core.wait_files([root / f"peer-{side}-recovered.json" for side in range(2)], children, seconds=95)
    validate(lost, recovered)
    evidence = {"status": "pass", "drops": drops, "lost": lost, "recovered": recovered}
    core.atomic(root / "recovery.json", evidence)
    return evidence
