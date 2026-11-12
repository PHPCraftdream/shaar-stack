"""CI-only supervisor contracts; runtime cases use unprivileged local child fixtures."""

from collections import deque
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest

spec = importlib.util.spec_from_file_location("shaar_product_processes", Path(__file__).with_name("processes.py"))
processes = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = processes
spec.loader.exec_module(processes)


class PrivilegeTests(unittest.TestCase):
    def test_privilege_receipt_requires_all_ids_caps_groups_and_no_new_privileges(self):
        fields = {"Pid": "42", "Uid": "1001 1001 1001 1001", "Gid": "1002 1002 1002 1002",
                  "CapInh": "0", "CapPrm": "0", "CapEff": "0", "CapAmb": "0", "CapBnd": "0", "Groups": "", "NoNewPrivs": "1"}
        render = lambda values: "\n".join(key + ":\t" + value for key, value in values.items())
        self.assertEqual(processes.privilege_evidence(render(fields), 42, 1001, 1002)["uid"], 1001)
        mutations = [("Pid", "43"), ("Uid", "1001 0 1001 1001"), ("Gid", "1002 1002 0 1002"),
                     ("Groups", "1002"), ("NoNewPrivs", "0")]
        mutations += [(name, "1") for name in ("CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd")]
        for key, value in mutations:
            changed = dict(fields)
            changed[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                processes.privilege_evidence(render(changed), 42, 1001, 1002)
        for key in fields:
            changed = dict(fields)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                processes.privilege_evidence(render(changed), 42, 1001, 1002)

    def test_namespace_launch_cannot_target_root_foreign_namespace_or_relative_tools(self):
        config = {"prefix": "snaabbcc", "ns": {"host_a": "snaabbcc-host-a"}, "helper_uid": 1001, "helper_gid": 1002}
        command = lambda cfg, role="host_a", product="/reviewed/client": processes.namespace_command(
            cfg, role, product, ["--config", "/owned/client.ktav"], "/usr/sbin/ip", "/usr/bin/setpriv")
        argv = command(config)
        self.assertIn("--no-new-privs", argv)
        self.assertIn("--bounding-set=-all", argv)
        self.assertIn("--ambient-caps=-all", argv)
        self.assertIn("--inh-caps=-all", argv)
        for changed in ({**config, "helper_uid": 0}, {**config, "helper_gid": True},
                        {**config, "prefix": "../../foreign"}, {**config, "ns": {"host_a": "default"}}):
            with self.assertRaises(ValueError):
                command(changed)
        with self.assertRaises(ValueError):
            command(config, role="rtr_a")
        with self.assertRaises(ValueError):
            command(config, product="relative-client")

    def test_environment_cannot_inherit_loader_or_interpreter_overrides(self):
        environment = processes.child_environment({"SHAAR_NAT_ROLE": "wan"})
        self.assertEqual(environment["SHAAR_NAT_ROLE"], "wan")
        self.assertEqual(set(environment), {"PATH", "LANG", "LC_ALL", "SHAAR_NAT_ROLE"})
        for extra in ({"LD_PRELOAD": "/foreign.so"}, {"PYTHONPATH": "/foreign"},
                      {"SHAAR_NAT_ROLE": "x" * 4097}, {"SHAAR_NAT_NONCE": "\0"}):
            with self.assertRaises(ValueError):
                processes.child_environment(extra)

    def test_helper_line_protocol_and_queue_are_bounded(self):
        supervisor = processes.Supervisor.__new__(processes.Supervisor)
        child = types.SimpleNamespace(events=deque(), markers={})
        line = b'SHAAR_NAT_READY {"pid":42}'
        for _ in range(processes.MAX_EVENTS):
            supervisor._line(child, "stdout", line)
        self.assertEqual(len(child.events), processes.MAX_EVENTS)
        with self.assertRaises(ValueError):
            supervisor._line(child, "stdout", line)
        for invalid in (b"x" * (processes.MAX_LINE + 1), b"SHAAR_NAT_UNKNOWN {}", b"SHAAR_NAT_READY []",
                        b"SHAAR_NAT_READY {", b'SHAAR_NAT_READY {"x":"\xff"}'):
            with self.subTest(line=invalid[:24]), self.assertRaises((ValueError, UnicodeError)):
                supervisor._line(types.SimpleNamespace(events=deque(), markers={}), "stdout", invalid)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd supervisor")
class SupervisorTests(unittest.TestCase):
    def create(self, directory):
        owner = processes.Supervisor(directory, time.monotonic() + 10)
        self.addCleanup(owner.close)
        return owner

    def child(self, owner, code):
        return owner.spawn("fixture", [sys.executable, "-I", "-c", code], {})

    def test_ready_terminal_reap_and_closed_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = self.create(directory)
            child = self.child(owner, 'print(\'SHAAR_NAT_READY {"pid":42}\', flush=True)')
            self.assertEqual(owner.event(child, "SHAAR_NAT_READY", owner.deadline), {"pid": 42})
            self.assertEqual(owner.wait(child, owner.deadline), 0)
            self.assertEqual(owner.close(), [])
            self.assertTrue(child.exited)
            self.assertTrue(child.process.stdout.closed)
            with self.assertRaises(TimeoutError):
                owner.spawn("later", [], {})
            self.assertEqual(owner.close(), [])

    def test_unexpected_exit_and_pipe_overrun_are_failures_and_children_are_reaped(self):
        for code, error in (("raise SystemExit(7)", RuntimeError),
                            ('print("x" * 9000, flush=True)', ValueError)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                owner = self.create(directory)
                child = self.child(owner, code)
                with self.assertRaises(error):
                    owner.event(child, "SHAAR_NAT_READY", owner.deadline)
                self.assertEqual(owner.close(), [])
                self.assertTrue(child.exited)
                self.assertIsNotNone(child.process.returncode)
                self.assertLessEqual((Path(directory) / "fixture.stdout").stat().st_size, processes.MAX_LOG)

    def test_kill_escalation_reaps_a_child_that_ignores_term(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = self.create(directory)
            child = self.child(owner, 'import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                               'print(\'SHAAR_NAT_READY {"pid":42}\', flush=True); input()')
            owner.event(child, "SHAAR_NAT_READY", owner.deadline)
            self.assertEqual(owner.close(), [])
            self.assertEqual(child.signals, ["TERM", "KILL"])
            self.assertEqual(child.returncode, -9)

    def test_missing_executable_and_child_cap_fail_before_leaking_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = self.create(directory)
            with self.assertRaises(OSError):
                owner.spawn("missing", [str(Path(directory) / "absent")], {})
            self.assertEqual(owner.children, [])
            self.assertEqual(len(owner.selector.get_map()), 0)
            owner.children = [None] * processes.MAX_CHILDREN
            try:
                with self.assertRaises(ValueError):
                    owner.spawn("capped", [], {})
            finally:
                owner.children.clear()
            self.assertFalse((Path(directory) / "capped.stdout").exists())

    def test_deadline_and_admission_failure_do_not_leak_children(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = self.create(directory)
            # An actual blocking input read, not a timing-based readiness marker.
            child = self.child(owner, 'print(\'SHAAR_NAT_READY {"pid":42}\', flush=True); input()')
            owner.event(child, "SHAAR_NAT_READY", owner.deadline)
            with self.assertRaises(TimeoutError):
                owner.step(time.monotonic() - 1)
            with self.assertRaises(ValueError):
                owner.spawn("fixture", [], {})
            self.assertEqual(owner.close(), [])
            self.assertTrue(child.exited)
            self.assertIn("TERM", child.signals)
            self.assertIsNotNone(child.process.returncode)

    def test_markers_console_interrupt_and_terminal_control_frame_use_owned_handles(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = self.create(directory)
            # SIGINT stays pending until sigwait; signal.pause() could lose an early signal.
            code = "; ".join((
                "import signal, sys",
                "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})",
                "print('composed startup: ready', flush=True)",
                "sys.stdin.readline()",
                "signal.sigwait({signal.SIGINT})",
                "print('stopped', flush=True)",
                "sys.exit(0)"))
            child = owner.spawn("marked", [sys.executable, "-I", "-c", code], {}, markers=[b"composed startup:"])
            self.assertIn("composed startup", owner.mark(child, b"composed startup:", owner.deadline))
            with self.assertRaises(ValueError):
                owner.send_stdin(child, b"x" * 129)
            owner.send_stdin(child, b"STOP" + bytes([10]))
            owner.interrupt(child)
            self.assertEqual(owner.wait(child, owner.deadline), 0)
            self.assertEqual(child.signals, [])
            with self.assertRaises(ValueError):
                owner.interrupt(child)
            self.assertEqual(owner.close(), [])

    def test_marker_wait_fails_when_the_child_exits_without_the_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = self.create(directory)
            child = owner.spawn("silent", [sys.executable, "-I", "-c", "print('other')"], {}, markers=[b"never"])
            with self.assertRaisesRegex(RuntimeError, "ended before marker"):
                owner.mark(child, b"never", owner.deadline)
            self.assertEqual(owner.close(), [])
