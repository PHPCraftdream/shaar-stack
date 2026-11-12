"""CI-only syntax validation of every generated ruleset by the real nft tool, without root or installation."""

from pathlib import Path
import shutil
import subprocess
import sys
import unittest

RUNTIME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))
sys.path.insert(0, str(RUNTIME.parent))
import contract  # noqa: E402
import kernel  # noqa: E402
import network  # noqa: E402

PORTS = {"dht": 42001, "relay": 42002, "transit": 42003}
PREFIX = "snaabbcc"


def launchers():
    """Rootless namespace launchers, tried in order; each only creates a throwaway user+net namespace."""
    found = []
    unshare, bwrap = shutil.which("unshare"), shutil.which("bwrap")
    if unshare:
        found.append(("unshare", [unshare, "--user", "--map-root-user", "--net"]))
    if bwrap:
        found.append(("bwrap", [bwrap, "--unshare-user", "--unshare-net", "--uid", "0", "--gid", "0",
                                "--cap-add", "CAP_NET_ADMIN", "--dev-bind", "/", "/", "--"]))
    return found


def check(prefix, nft, text):
    """Dry-run validation inside a throwaway user+network namespace; the host namespace is never touched."""
    return subprocess.run([*prefix, nft, "--check", "--file", "-"],
                           input=text.encode("ascii"), capture_output=True, timeout=30,
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})


def restriction():
    path = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    return path.read_text(encoding="ascii").strip() if path.exists() else "absent"


@unittest.skipUnless(sys.platform == "linux", "nft exists only on the Linux plan runner; the Windows jobs cannot run it")
class RealNftSyntaxTests(unittest.TestCase):
    def tools(self):
        nft = shutil.which("nft")
        # Missing tools or userns support are loud failures: a silent skip would hide unvalidated rules.
        if nft is None or not launchers():
            self.fail(f"real nft syntax validation is unavailable: nft={nft} launchers={[name for name, _ in launchers()]}")
        reasons = []
        for name, prefix in launchers():
            probe = check(prefix, nft, "add table inet snprobe_check\n")
            if probe.returncode == 0:
                bad = check(prefix, nft, "add chain inet snprobe_check snat { type nat hook postrouting priority 100; policy accept; }\n")
                self.assertNotEqual(bad.returncode, 0, "the validator must reject the reserved chain name that real nft rejected")
                return prefix, nft
            reasons.append(name + ": " + probe.stderr.decode("utf-8", errors="replace")[:300])
        self.fail("unprivileged user+net namespace nft --check is unavailable on this runner (rules are NOT validated); "
                  f"apparmor_restrict_unprivileged_userns={restriction()}; " + " | ".join(reasons))

    def test_every_generated_product_and_fault_ruleset_and_the_calibration_ruleset_pass_real_nft_check(self):
        prefix, nft = self.tools()
        rulesets = []
        for case in sorted(network.CASES):
            for router in ("rtr_a", "rtr_b"):
                for purpose in ("product", "fault"):
                    rulesets.append((f"{case}/{router}/{purpose}", network.rules(PREFIX, router, case, PORTS, purpose)))
        for host in ("10.0.1.2", "10.0.2.2"):
            rulesets.append((f"calibration/{host}", kernel.probe_rules(PREFIX, host)[1]))
        self.assertEqual(len(rulesets), len(contract.CASES) * 2 * 2 + 2)
        for name, text in rulesets:
            with self.subTest(ruleset=name):
                result = check(prefix, nft, text)
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace")[:800])

    def test_a_mutated_ruleset_is_rejected_so_the_check_is_not_vacuous(self):
        prefix, nft = self.tools()
        text = network.rules(PREFIX, "rtr_a", "blocked-signal", PORTS)
        for broken in (text.replace("natout", "snat"), text.replace("drop comment", "dropp comment", 1),
                       text.replace("quota name phase_budget", "quota name missing_budget", 1)):
            self.assertNotEqual(check(prefix, nft, broken).returncode, 0)


if __name__ == "__main__":
    unittest.main()
