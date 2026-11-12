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


def check(unshare, nft, text):
    """Dry-run validation inside a throwaway user+network namespace; the host namespace is never touched."""
    return subprocess.run([unshare, "--user", "--map-root-user", "--net", nft, "--check", "--file", "-"],
                           input=text.encode("ascii"), capture_output=True, timeout=30,
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})


@unittest.skipUnless(sys.platform == "linux", "nft exists only on the Linux plan runner; the Windows jobs cannot run it")
class RealNftSyntaxTests(unittest.TestCase):
    def tools(self):
        unshare, nft = shutil.which("unshare"), shutil.which("nft")
        # Missing tools or userns support are loud failures: a silent skip would hide unvalidated rules.
        if unshare is None or nft is None:
            self.fail(f"real nft syntax validation is unavailable: unshare={unshare} nft={nft}")
        probe = check(unshare, nft, "add table inet snprobe_check\n")
        if probe.returncode != 0:
            self.fail("unprivileged user+net namespace nft --check is unavailable on this runner (rules are NOT validated): "
                      + probe.stderr.decode("utf-8", errors="replace")[:500])
        bad = check(unshare, nft, "add chain inet snprobe_check snat { type nat hook postrouting priority 100; policy accept; }\n")
        self.assertNotEqual(bad.returncode, 0, "the validator must reject the reserved chain name that real nft rejected")
        return unshare, nft

    def test_every_generated_product_and_fault_ruleset_and_the_calibration_ruleset_pass_real_nft_check(self):
        unshare, nft = self.tools()
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
                result = check(unshare, nft, text)
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace")[:800])

    def test_a_mutated_ruleset_is_rejected_so_the_check_is_not_vacuous(self):
        unshare, nft = self.tools()
        text = network.rules(PREFIX, "rtr_a", "blocked-signal", PORTS)
        for broken in (text.replace("natout", "snat"), text.replace("drop comment", "dropp comment", 1),
                       text.replace("quota name phase_budget", "quota name missing_budget", 1)):
            self.assertNotEqual(check(unshare, nft, broken).returncode, 0)


if __name__ == "__main__":
    unittest.main()
