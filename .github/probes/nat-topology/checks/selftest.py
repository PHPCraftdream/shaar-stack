#!/usr/bin/env python3
"""CI-only regression tests for the P03 NAT topology fixture.

Unit tests ONLY: ctparse parsing (both conntrack formats), fixture pure
helpers, the real negative oracles, validator/cleanup classification, and
the supervisor signal scoping — all with fakes/temp fixtures. NO network,
NO namespaces, NO fixture execution. Re-exports the CI-only JSON validators
and ROOT interruption supervisor (childman.py) as workflow CLI subcommands;
the default no-argument invocation runs the unittest suite.
"""

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

CHECKS = os.path.dirname(os.path.abspath(__file__))
HERE = os.path.dirname(CHECKS)
if CHECKS not in sys.path:
    sys.path.insert(0, CHECKS)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import ctparse  # noqa: E402
import childman  # noqa: E402
import fixture  # noqa: E402  (import-safe: no side effects at module level)
from supervisor import SupervisorSignalTests  # noqa: E402,F401

WAN = "203.0.113.10"
RA_WAN = "203.0.113.1"
HOST_A = "10.0.1.2"
CAL_PORT = 41000
SRC_A = 40001
T_PORT = 41012
# Pure-helper range bounds (fixture.translated_port_ok); not used by the
# find_translation tests, which require the exact translated port.
RANGE_LO, RANGE_HI = 41010, 41020

# conntrack -L -p udp style: padded proto name, both tuples, no flags.
LINE_CLI = ("udp      17 src=10.0.1.2 dst=203.0.113.10 sport=40001 "
            "dport=41000 src=203.0.113.10 dst=203.0.113.1 sport=41000 "
            "dport=41012 mark=0 use=1")
# /proc/net/nf_conntrack style: ipv4 + table id prefix, flags in brackets.
LINE_PROC = ("ipv4 2 udp 17 src=10.0.1.2 dst=203.0.113.10 sport=40001 "
             "dport=41000 [UNREPLIED] src=203.0.113.10 dst=203.0.113.1 "
             "sport=41000 dport=41012 [ASSURED] mark=0 use=2")

class EmbeddedPythonSyntaxTests(unittest.TestCase):
    def test_shell_embedded_python_is_valid(self):
        with open(os.path.join(HERE, "run.sh"), encoding="utf-8") as fh:
            shell = fh.read()
        snippets = re.findall(r"python3\s+-I\s+-c\s+'([^']*)'", shell)
        self.assertGreaterEqual(len(snippets), 5)
        for index, source in enumerate(snippets):
            with self.subTest(snippet=index):
                ast.parse(source, filename="run.sh:python-%d" % index)


class ParseLineTests(unittest.TestCase):
    def test_cli_line_fields(self):
        e = ctparse.parse_line(LINE_CLI)
        self.assertIsNotNone(e)
        self.assertEqual(e["proto"], "udp")
        self.assertEqual(e["orig"], {"src": HOST_A, "sport": SRC_A,
                                     "dst": WAN, "dport": CAL_PORT})
        self.assertEqual(e["reply"], {"src": WAN, "sport": CAL_PORT,
                                      "dst": RA_WAN, "dport": T_PORT})
        self.assertFalse(e["unreplied"])
        self.assertEqual(e["raw"], LINE_CLI)

    def test_proc_line_fields(self):
        e = ctparse.parse_line(LINE_PROC)
        self.assertIsNotNone(e)
        self.assertEqual(e["proto"], "udp")
        self.assertEqual(e["orig"]["dport"], CAL_PORT)
        self.assertEqual(e["reply"]["dport"], T_PORT)
        self.assertTrue(e["unreplied"])
        self.assertTrue(e["assured"])

    def test_key_order_variation_within_tuple(self):
        line = ("udp 17 sport=40001 dport=41000 src=10.0.1.2 dst=203.0.113.10 "
                "sport=41000 dport=41012 src=203.0.113.10 dst=203.0.113.1")
        e = ctparse.parse_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e["orig"], {"src": HOST_A, "sport": SRC_A,
                                     "dst": WAN, "dport": CAL_PORT})
        self.assertEqual(e["reply"], {"src": WAN, "sport": CAL_PORT,
                                      "dst": RA_WAN, "dport": T_PORT})

    def test_garbage_and_empty_lines(self):
        self.assertIsNone(ctparse.parse_line(""))
        self.assertIsNone(ctparse.parse_line("no tuples here"))
        self.assertIsNone(ctparse.parse_line(
            "udp 17 src=10.0.1.2 sport=40001 dport=41000"))  # incomplete

    def test_numeric_proto_only(self):
        line = LINE_CLI.replace("udp      17", "17", 1)
        e = ctparse.parse_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e["proto"], "udp")

    def test_tcp_detection(self):
        line = ("tcp 6 src=10.0.1.2 dst=203.0.113.10 sport=40001 "
                "dport=41000 src=203.0.113.10 dst=203.0.113.1 "
                "sport=41000 dport=41012")
        e = ctparse.parse_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e["proto"], "tcp")

class FindEntryTests(unittest.TestCase):
    def test_full_match(self):
        e = ctparse.find_entry([LINE_CLI], HOST_A, SRC_A, WAN, CAL_PORT)
        self.assertIsNotNone(e)

    def test_wrong_ip_no_match(self):
        self.assertIsNone(ctparse.find_entry([LINE_CLI], "10.0.1.3", SRC_A,
                                             WAN, CAL_PORT))

    def test_wrong_port_no_match(self):
        self.assertIsNone(ctparse.find_entry([LINE_CLI], HOST_A, 40002, WAN,
                                             CAL_PORT))

    def test_wrong_dst_port_no_match(self):
        self.assertIsNone(ctparse.find_entry([LINE_CLI], HOST_A, SRC_A, WAN,
                                             41001))

    def test_wrong_proto_line_not_matched(self):
        # A tcp line with identical endpoints parses as tcp but must NOT
        # satisfy either matcher under the default udp protocol (defect 6).
        tcp_line = LINE_CLI.replace("udp      17", "tcp      6", 1)
        e = ctparse.parse_line(tcp_line)
        self.assertIsNotNone(e)
        self.assertEqual(e["proto"], "tcp")
        self.assertIsNone(ctparse.find_entry([tcp_line], HOST_A, SRC_A, WAN,
                                             CAL_PORT))
        self.assertIsNone(
            ctparse.find_translation([tcp_line], HOST_A, SRC_A, WAN, CAL_PORT,
                                     WAN, CAL_PORT, RA_WAN, T_PORT))

    def test_missing_entry_returns_none(self):
        self.assertIsNone(ctparse.find_entry([], HOST_A, SRC_A, WAN, CAL_PORT))

class FindTranslationTests(unittest.TestCase):
    def _ok(self, lines):
        # Exact translated port RA_WAN/T_PORT: no lo/hi range parameters.
        return ctparse.find_translation(lines, HOST_A, SRC_A, WAN, CAL_PORT,
                                        WAN, CAL_PORT, RA_WAN, T_PORT)

    def test_translation_found(self):
        e = self._ok([LINE_CLI])
        self.assertIsNotNone(e)
        self.assertEqual(e["reply"]["dport"], T_PORT)

    def test_unreplied_rejected(self):
        self.assertIsNone(self._ok([LINE_PROC]))

    def test_wrong_translated_port_rejected(self):
        # Exact-int match required: any other reply dport is a mismatch,
        # not just ports outside a configured range.
        bad = LINE_CLI.replace("dport=41012", "dport=55000")
        self.assertIsNone(self._ok([bad]))

    def test_reply_dst_wrong_wan_ip_rejected(self):
        bad = LINE_CLI.replace("src=203.0.113.10 dst=203.0.113.1",
                               "src=203.0.113.10 dst=203.0.113.9")
        self.assertIsNone(self._ok([bad]))

    def test_reply_src_wrong_responder_port_rejected(self):
        bad = LINE_CLI.replace("sport=41000", "sport=41099")
        self.assertIsNone(self._ok([bad]))

    def test_missing_entry_returns_none(self):
        self.assertIsNone(self._ok([]))

    def test_second_candidate_with_correct_reply_is_found(self):
        # Defect 6: the FIRST entry matching the orig tuple has a wrong
        # reply tuple; find_translation must keep scanning and return the
        # SECOND entry whose reply matches exactly.
        stale = LINE_CLI.replace("dport=41012", "dport=55000")
        e = self._ok([stale, LINE_CLI])
        self.assertIsNotNone(e)
        self.assertEqual(e["raw"], LINE_CLI)

class HasRepliedEntryTests(unittest.TestCase):
    def test_replied_line_true(self):
        self.assertTrue(ctparse.has_replied_entry([LINE_CLI], HOST_A, SRC_A,
                                                  WAN, CAL_PORT))

    def test_unreplied_line_false(self):
        self.assertFalse(ctparse.has_replied_entry([LINE_PROC], HOST_A, SRC_A,
                                                   WAN, CAL_PORT))

    def test_empty_false(self):
        self.assertFalse(ctparse.has_replied_entry([], HOST_A, SRC_A, WAN,
                                                   CAL_PORT))

class PureLogicTests(unittest.TestCase):
    def test_translated_port_ok(self):
        self.assertTrue(fixture.translated_port_ok(41015, SRC_A,
                                                   RANGE_LO, RANGE_HI))
        self.assertFalse(fixture.translated_port_ok(SRC_A, SRC_A,
                                                    RANGE_LO, RANGE_HI))
        self.assertFalse(fixture.translated_port_ok(41009, SRC_A,
                                                    RANGE_LO, RANGE_HI))
        self.assertFalse(fixture.translated_port_ok(41021, SRC_A,
                                                    RANGE_LO, RANGE_HI))
        self.assertFalse(fixture.translated_port_ok(41010, 41010,
                                                    RANGE_LO, RANGE_HI))

    def test_expected_echo_payload(self):
        self.assertEqual(fixture.expected_echo_payload("t", 3), "ECHO|t|3")

    def test_echo_ok_exact_match_required(self):
        self.assertTrue(fixture.echo_ok("ECHO|tok|7", WAN, CAL_PORT, WAN,
                                        CAL_PORT, "tok", 7))
        # wrong token
        self.assertFalse(fixture.echo_ok("ECHO|other|7", WAN, CAL_PORT, WAN,
                                         CAL_PORT, "tok", 7))
        # wrong seq
        self.assertFalse(fixture.echo_ok("ECHO|tok|8", WAN, CAL_PORT, WAN,
                                         CAL_PORT, "tok", 7))
        # foreign source (right payload, wrong port)
        self.assertFalse(fixture.echo_ok("ECHO|tok|7", WAN, 9999, WAN,
                                         CAL_PORT, "tok", 7))
        # foreign source ip
        self.assertFalse(fixture.echo_ok("ECHO|tok|7", "1.2.3.4", CAL_PORT,
                                         WAN, CAL_PORT, "tok", 7))

from childman import (VALIDATORS, SETUP_REASON, supervise_interrupt,  # noqa: E402,F401
                      validate_cleanup, validate_evidence, validate_phase)  # noqa: E402,F401

# ---------------------------------------------------------------------------
# CI-only tests for the validators, the real oracles, and the child cleanup
# classification. These run in CI as part of the unittest suite (never
# locally); they use temp JSON fixtures / fake processes, no NAT, no network.
# ---------------------------------------------------------------------------

def _cleanup_obj(**over):
    obj = {
        "cleanup_failed": False, "namespace_processes_left": [],
        "interface_survivors": [], "cleanup_errors": [],
        "host_fw_capture_ok": True, "host_fw_canonical_changed": False,
        "host_ip_forward_changed": False, "host_firewall_changed": False,
        "namespaces_remaining": "0", "nonce": "cafe", "phase": "normal",
        "reason": "", "namespaces_created_count": 7,
        "namespaces_created": ["sn1-rtr-a"], "fault_inject_setup": False,
        "fault_inject_fixture": False,
    }
    obj.update(over)
    return obj

def _run_validator(func, obj, *flags):
    """Call a validator CLI with a temp JSON fixture file + argv array."""
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        json.dump(obj, fh)
        fh.close()
        return func([fh.name] + list(flags))
    finally:
        os.unlink(fh.name)

NS3 = ["sn1-wan", "sn1-host-a", "sn1-host-b"]  # exact injected ns list

def _ev_pass():
    # Minimal evidence fixture that PASSES validate-evidence(pass).
    return {"status": "pass", "failed_controls": [],
            "child_cleanup_errors": [],
            "child_cleanup": [{"name": "c", "rc": 0, "error": None}],
            "config": {"nonce": "n1"}}

class ValidatorCLITests(unittest.TestCase):
    def _accept(self, func, obj, *flags):
        self.assertEqual(_run_validator(func, obj, *flags), 0)

    def _reject(self, func, obj, *flags):
        with self.assertRaises(SystemExit):
            _run_validator(func, obj, *flags)

    def test_all_intended_cleanup_cases_accepted(self):
        sf = _cleanup_obj(phase="setup-injected", reason=SETUP_REASON,
                          namespaces_created_count=3,
                          namespaces_created=NS3,
                          fault_inject_setup=True, nonce="beef")
        ff = _cleanup_obj(fault_inject_fixture=True, nonce="f00d")
        for func, obj, flags in (
                (validate_cleanup, _cleanup_obj(),
                 ("--case", "normal", "--nonce", "cafe")),
                (validate_cleanup, sf,
                 ("--case", "setup-fault", "--nonce", "beef")),
                (validate_cleanup, ff,
                 ("--case", "fixture-fault", "--nonce", "f00d")),
                (validate_cleanup, _cleanup_obj(nonce="abcd"),
                 ("--case", "interrupt", "--nonce", "abcd"))):
            self._accept(func, obj, *flags)

    def test_numeric_boolean_flags_rejected(self):
        for key in ("cleanup_failed", "host_fw_capture_ok",
                    "host_fw_canonical_changed", "host_ip_forward_changed",
                    "host_firewall_changed", "fault_inject_setup",
                    "fault_inject_fixture"):
            self._reject(validate_cleanup, _cleanup_obj(**{key: 0}), "--case", "normal")

    def test_wrong_nonce_rejected(self):
        self._reject(validate_cleanup, _cleanup_obj(nonce="aaaa"),
                     "--case", "normal", "--nonce", "cafe")

    def test_wrong_injection_reason_rejected(self):
        # All OTHER setup-fault fields are valid; ONLY the reason differs,
        # so the rejection genuinely isolates the injected reason check.
        obj = _cleanup_obj(phase="setup-injected", reason="some other reason",
                           fault_inject_setup=True,
                           namespaces_created_count=3,
                           namespaces_created=NS3)
        self._reject(validate_cleanup, obj, "--case", "setup-fault")

    def test_missing_phase_rejected(self):
        obj = _cleanup_obj()
        del obj["phase"]
        self._reject(validate_cleanup, obj, "--case", "normal")

    def test_validate_phase_cases(self):
        good = {"nonce": "cafe", "pids": {"a": 11, "b": 22, "c": 33}}
        self._accept(validate_phase, good, "cafe")
        # Wrong nonce must reject.
        self._reject(validate_phase, good, "beef")
        # Missing file must reject (not silently pass).
        with self.assertRaises(SystemExit):
            validate_phase(["/nonexistent/children_started/missing.json",
                            "cafe"])

    def test_unsupported_option_rejected(self):
        # Unknown option WITH a value (not just a missing-value form).
        self._reject(validate_cleanup, _cleanup_obj(), "--bogus", "value")
        self._reject(validate_evidence, _ev_pass(), "--bogus", "value",
                     "--expect-status", "pass")
    def test_generic_failures_not_pass_as_injected(self):
        # VALID setup-fault fixture first; each rejection mutates EXACTLY
        # one field so a reject can never come from an unrelated defect.
        valid = _cleanup_obj(phase="setup-injected", reason=SETUP_REASON,
                             fault_inject_setup=True,
                             namespaces_created_count=3,
                             namespaces_created=NS3)
        self._accept(validate_cleanup, valid, "--case", "setup-fault",
                     "--nonce", "cafe")
        mutations = [
            {"namespaces_created_count": 5},            # count only
            {"phase": "normal"},                        # phase only
            {"reason": "boom"},                         # reason only
            {"namespaces_created": NS3 + ["sn1-rtr-a"]},          # extra ns
            {"namespaces_created": ["sn9-wan", NS3[1], NS3[2]]},  # prefixes
        ]
        for over in mutations:
            self._reject(validate_cleanup, dict(valid, **over),
                         "--case", "setup-fault", "--nonce", "cafe")

    def test_evidence_pass_and_fail(self):
        cc = [{"name": "c", "rc": 0, "error": None}]
        good_pass = _ev_pass()
        # Fault path: exception recorded, NO interruption object.
        good_fault = {"status": "fail", "failed_controls": ["x"],
                      "exception": "injected fixture failure after children",
                      "child_cleanup_errors": [], "child_cleanup": cc,
                      "config": {"nonce": "n1"}}
        # Interrupt path: explicit failing 'interrupted' control and
        # SystemExit/143 interruption record, NO exception.
        good_interrupt = {"status": "fail",
                          "failed_controls": ["interrupted"],
                          "child_cleanup_errors": [], "child_cleanup": cc,
                          "interruption": {"reason": "SystemExit",
                                           "code": "143"},
                          "controls": {"interrupted": {"status": "fail",
                                                       "reasons": []}},
                          "config": {"nonce": "n1"}}
        self._accept(validate_evidence, good_pass,
                     "--expect-status", "pass", "--nonce", "n1")
        # Exact workflow argument sets, one per intended case.
        self._accept(validate_evidence, good_fault, "--expect-status", "fail",
                     "--expect-exception-substr", "injected fixture failure",
                     "--nonce", "n1")
        self._accept(validate_evidence, good_interrupt,
                     "--expect-status", "fail", "--expect-interrupted",
                     "--nonce", "n1")
        # Wrong injected reason with all other fields valid must reject.
        self._reject(validate_evidence,
                     dict(good_fault, exception="some other boom"),
                     "--expect-status", "fail",
                     "--expect-exception-substr", "injected fixture failure",
                     "--nonce", "n1")
        # Numeric-style status / wrong expected status / wrong nonce /
        # empty failed_controls / bad child_cleanup entries.
        self._reject(validate_evidence, dict(good_fault, status=True), "--expect-status", "fail")
        self._reject(validate_evidence, good_pass, "--expect-status", "fail")
        self._reject(validate_evidence, good_fault,
                     "--expect-status", "fail", "--nonce", "other")
        self._reject(validate_evidence, dict(good_fault, failed_controls=[]), "--expect-status", "fail")
        self._reject(validate_evidence, dict(good_interrupt, child_cleanup=[]),
                     "--expect-status", "fail", "--expect-interrupted")
        self._reject(validate_evidence,
                     dict(good_interrupt, child_cleanup=[{"name": "c", "rc": "0", "error": None}]),
                     "--expect-status", "fail", "--expect-interrupted")
        # Interrupt validator: mixing exception into the interrupt record,
        # wrong code, or a passing interrupted control must all reject.
        self._reject(validate_evidence, dict(good_interrupt, exception="boom"),
                     "--expect-status", "fail", "--expect-interrupted")
        self._reject(validate_evidence,
                     dict(good_interrupt, interruption={"reason": "SystemExit", "code": "9"}),
                     "--expect-status", "fail", "--expect-interrupted")
        self._reject(validate_evidence,
                     dict(good_interrupt, controls={"interrupted": {"status": "pass", "reasons": []}}),
                     "--expect-status", "fail", "--expect-interrupted")

def _oracle_cfg():
    return {
        "tokens": {"wrong": "wtok", "off": "otok"},
        "ip": {"host_a": HOST_A, "host_off": "10.0.3.2", "wan": WAN},
        "port": {"src_wrong": 40011, "cal": CAL_PORT, "src_off": 40003,
                 "off": 41002},
    }

def _ct_line(src, sport, dst_port, replied):
    flag = "" if replied else "[UNREPLIED] "
    return ("udp 17 src=%s dst=%s sport=%d dport=%d %s"
            "src=%s dst=%s sport=%d dport=41013 mark=0"
            % (src, WAN, sport, dst_port, flag, WAN, RA_WAN, CAL_PORT))

class OracleTests(unittest.TestCase):
    """Later-unreplied-then-replied candidates must pass through the REAL
    fixture oracles (not just the parser): a stale UNREPLIED entry must not
    shadow a genuine reply, and fwd-off must refuse any REPLIED entry."""

    def _ev(self, key, raw):
        return {"conntrack": {key: {"source": "conntrack-cli", "raw": raw}}}

    def _recs(self, tok):
        return [{"token": tok, "seq": str(i), "src": [WAN, 41013],
                 "known": False} for i in range(2)]

    def test_wrong_token_later_replied_candidate_found(self):
        cfg = _oracle_cfg()
        ev = self._ev("rtr_a", [_ct_line(HOST_A, 40011, CAL_PORT, False),
                                _ct_line(HOST_A, 40011, CAL_PORT, True)])
        ctrl = fixture.oracle_wrong_token(cfg, ev, self._recs("wtok"))
        self.assertEqual(ctrl["status"], "pass", ctrl["reasons"])
        # Only-UNREPLIED candidates: no REPLIED entry -> control must fail.
        ev = self._ev("rtr_a", [_ct_line(HOST_A, 40011, CAL_PORT, False)])
        ctrl = fixture.oracle_wrong_token(cfg, ev, self._recs("wtok"))
        self.assertEqual(ctrl["status"], "fail")

    def test_fwd_off_refuses_replied_entry(self):
        cfg = _oracle_cfg()
        # fwd-off flow targets the OFF port (41002), not the cal port.
        ev = self._ev("rtr_off", [_ct_line("10.0.3.2", 40003, 41002, False)])
        self.assertEqual(
            fixture.oracle_fwd_off(cfg, ev, [], True)["status"], "pass")
        # A later REPLIED candidate on the same flow must fail the oracle.
        ev = self._ev("rtr_off", [_ct_line("10.0.3.2", 40003, 41002, False),
                                  _ct_line("10.0.3.2", 40003, 41002, True)])
        self.assertEqual(
            fixture.oracle_fwd_off(cfg, ev, [], True)["status"], "fail")

class _FakeProc:
    """Scripted Popen stand-in: graceful stop exits on its own; graceful
    False ignores STOP so TERM is required and wait() succeeds AFTER the
    TERM (genuine termination, action='term'); survive_kill ignores TERM
    and KILL entirely (a genuine survivor)."""

    def __init__(self, exits_immediately=False, rc=None, graceful=True,
                 survive_kill=False):
        self._exit, self._graceful, self._survive = (exits_immediately,
                                                     graceful, survive_kill)
        self.returncode = rc if exits_immediately else None

    def poll(self):
        if self.returncode is not None and (self._exit or not self._survive):
            return self.returncode
        return None

    def wait(self, timeout=None):
        if self.returncode is not None and not self._survive:
            return self.returncode
        if self._graceful:
            self.returncode = 0
            return 0
        raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)

    def terminate(self):
        if not self._survive:
            self.returncode = -15

    def kill(self):
        if not self._survive:
            self.returncode = -9

class _DummyFH:
    def close(self):
        pass

class ChildCleanupClassificationTests(unittest.TestCase):
    """Fake process lifecycle through fixture.cleanup_children: preexisting
    unexpected nonzero exits are failures; intentional TERM/KILL during
    abnormal teardown is expected; survivors are failures; escalation on the
    NORMAL path is a failure."""
    def _run(self, proc, escalation_expected):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        child = childman.Child("c", proc, _DummyFH(),
                               os.path.join(tmp.name, "c.stop"),
                               os.path.join(tmp.name, "c.results.json"))
        ev = {}
        fixture.cleanup_children([child], ev,
                                 escalation_expected=escalation_expected)
        return child, ev

    def test_classifications(self):
        # graceful cooperative stop: no error, STOP action recorded.
        child, ev = self._run(_FakeProc(graceful=True), False)
        self.assertEqual(ev["child_cleanup_errors"], [])
        self.assertEqual(ev["child_cleanup"][0]["action"], "stop")
        self.assertTrue(ev["child_cleanup"][0]["termination_requested"])
        # TERM/KILL during ABNORMAL teardown: expected, recorded, no error.
        child, ev = self._run(_FakeProc(graceful=False), True)
        self.assertEqual(ev["child_cleanup_errors"], [])
        self.assertEqual(ev["child_cleanup"][0]["action"], "term")
        self.assertTrue(ev["child_cleanup"][0]["escalated"])

    def test_failure_classifications(self):
        # Preexisting unexpected nonzero exit: failure.
        child, ev = self._run(_FakeProc(exits_immediately=True, rc=1), False)
        self.assertIn("unexpected nonzero",
                      ev["child_cleanup_errors"][0]["why"])
        # Escalation on the NORMAL path: failure (exact diagnostic).
        child, ev = self._run(_FakeProc(graceful=False), False)
        self.assertEqual(len(ev["child_cleanup_errors"]), 1)
        self.assertEqual(ev["child_cleanup_errors"][0]["why"],
                         "escalated to TERM/KILL on the normal path")
        # Survivor even when escalation is expected: failure.
        child, ev = self._run(_FakeProc(graceful=False, survive_kill=True),
                              True)
        self.assertEqual(len(ev["child_cleanup_errors"]), 1)
        self.assertEqual(child.action, "kill")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in VALIDATORS:
        sys.exit(VALIDATORS[sys.argv[1]](sys.argv[2:]))
    unittest.main(verbosity=2)  # default: the CI unittest suite
