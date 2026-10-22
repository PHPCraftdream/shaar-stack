"""CI-only supervisor signal and reaping regression tests."""
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import childman

class _FakeSignalModule:
    """In-process signal stand-in; deliver() simulates OS delivery."""
    SIGTERM, SIGINT, SIG_BLOCK, SIG_SETMASK = 15, 2, 1, 3

    def __init__(self):
        self.handlers = {15: "orig-term", 2: "orig-int"}
        self.mask = []

    def pthread_sigmask(self, how, sigs):
        previous = list(self.mask)
        self.mask = sorted(set(self.mask) | set(sigs)) \
            if how == self.SIG_BLOCK else list(sigs)
        return previous

    def signal(self, num, handler):
        old = self.handlers[num]
        self.handlers[num] = handler
        return old

    def deliver(self, num):
        if num in self.mask:
            return "blocked"
        h = self.handlers[num]
        if callable(h):
            h(num, None)
        return h

class _FakeOwnedProc:
    """Owned run.sh stand-in: zombie=True polls as un-reaped (reaper runs);
    on_terminate injects signals DURING the reaper; reap_fails makes the
    first reaper wait time out so KILL escalation is exercised."""

    def __init__(self, reap_fails=False):
        self.pid, self.returncode, self.sent = 4242, None, []
        self.terminated = self.killed = self.zombie = False
        self.wait_calls, self.reap_fails = 0, reap_fails
        self.on_terminate = None

    def poll(self):
        return None if self.zombie else self.returncode

    def send_signal(self, signum):
        self.sent.append(signum)

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.zombie:
            if self.reap_fails and not self.killed:
                raise subprocess.TimeoutExpired("owned-run", timeout)
            self.zombie = False
            self.returncode = -9 if self.killed else -15
        elif self.returncode is None:
            self.returncode = 143 if self.sent else 0
        return self.returncode

    def terminate(self):
        self.terminated = True
        if self.on_terminate is not None:
            self.on_terminate()
        if not self.zombie:
            self.returncode = -15

    def kill(self):
        self.killed = True

class SupervisorSignalTests(unittest.TestCase):
    """CI-only: supervisor signal scoping, driven fully by fakes."""

    def _supervise(self, proc, sig, cleanup=None, evidence=None, popen=None):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        casedir = os.path.join(td.name, "case")
        rec = os.path.join(casedir, "records")
        os.makedirs(rec)
        marker = os.path.join(rec, "children_started")
        with open(marker, "w", encoding="utf-8") as fh:
            json.dump({"nonce": "cafe", "pids": {"a": 11, "b": 22, "c": 33}}, fh)
        run_sh = os.path.join(td.name, "run.sh")
        with open(run_sh, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/bash\nexit 143\n")
        z = mock.patch.object
        patches = [
            z(childman.os.path, "exists",
              side_effect=lambda p: p.endswith("children_started")),
            z(childman.os.path, "isfile", return_value=True),
            z(childman.os, "getuid", return_value=0),
            z(childman, "_proc_identity", side_effect=lambda p: (0, 1000 + p)),
            z(childman, "_descendants", return_value={proc.pid, 11, 22, 33}),
            (z(childman.subprocess, "Popen", return_value=proc)
             if popen is None else
             z(childman.subprocess, "Popen", side_effect=popen)),
            z(childman, "signal", sig),
            z(childman, "validate_cleanup",
              cleanup or mock.MagicMock(return_value=0)),
            z(childman, "validate_evidence",
              evidence or mock.MagicMock(return_value=0)),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return casedir, run_sh

    def test_signal_scope_modes(self):
        sig = _FakeSignalModule()
        sig.mask = [10]
        sc = childman.term_signal_scope(sig, mode="exit")
        sc.__enter__()
        self.assertEqual(sig.handlers[15], sc._handler)
        self.assertIn(15, sig.mask)
        sc.unblock()
        self.assertNotIn(15, sig.mask)
        with self.assertRaises(SystemExit):
            sig.deliver(15)
        sc.__exit__(None, None, None)
        self.assertEqual(sig.handlers[15], "orig-term")
        # defer mode: repeated signals are counted, never raised.
        d = childman.term_signal_scope(sig, mode="defer")
        d.__enter__()
        d.unblock()
        sig.deliver(15)
        sig.deliver(2)
        self.assertEqual(d.triggered, [15, 2])
        d.__exit__(None, None, None)
        self.assertEqual(sig.handlers, {15: "orig-term", 2: "orig-int"})
        self.assertEqual(sig.mask, [10])

    def test_supervisor_success_installs_and_restores(self):
        sig = _FakeSignalModule()
        proc = _FakeOwnedProc()
        casedir, run_sh = self._supervise(proc, sig)
        self.assertEqual(
            childman.supervise_interrupt([run_sh, casedir, "cafe"]), 0)
        self.assertEqual(proc.sent, [15])          # signalled via owned Popen
        self.assertEqual(proc.wait_calls, 1)       # waited exactly once
        self.assertEqual(sig.handlers, {15: "orig-term", 2: "orig-int"})
        self.assertEqual(sig.mask, [])             # restored, mask empty

    def test_injected_signal_after_body_unwinds_and_reaps(self):
        sig = _FakeSignalModule()
        proc = _FakeOwnedProc()

        def _fail_cleanup(path, **kw):
            proc.zombie = True          # force the final reaper path
            sig.deliver(15)
        casedir, run_sh = self._supervise(proc, sig, cleanup=_fail_cleanup)
        with self.assertRaises(SystemExit):
            childman.supervise_interrupt([run_sh, casedir, "cafe"])
        self.assertTrue(proc.terminated)       # reaped owned child...
        self.assertEqual(proc.wait_calls, 2)   # initial wait plus final reap
        self.assertEqual(sig.handlers, {15: "orig-term", 2: "orig-int"})

    def test_repeated_signals_during_final_reaper_deferred(self):
        sig = _FakeSignalModule()
        proc = _FakeOwnedProc(reap_fails=True)

        def _zombify(path, **kw):
            proc.zombie = True          # reaper will run on success path
        casedir, run_sh = self._supervise(proc, sig, cleanup=_zombify)
        proc.on_terminate = lambda: (sig.deliver(15), sig.deliver(2))
        # Repeated signals do not prevent timeout escalation and reaping.
        self.assertEqual(
            childman.supervise_interrupt([run_sh, casedir, "cafe"]), 0)
        self.assertTrue(proc.terminated)
        self.assertTrue(proc.killed)
        self.assertEqual(proc.wait_calls, 3)
        self.assertIsNotNone(proc.poll())
        self.assertEqual(sig.handlers, {15: "orig-term", 2: "orig-int"})

    def test_spawn_failure_restores_handlers(self):
        sig = _FakeSignalModule()
        casedir, run_sh = self._supervise(
            _FakeOwnedProc(), sig,
            popen=mock.MagicMock(side_effect=RuntimeError("boom")))
        with self.assertRaises(RuntimeError):
            childman.supervise_interrupt([run_sh, casedir, "cafe"])
        self.assertEqual(sig.handlers, {15: "orig-term", 2: "orig-int"})
        self.assertEqual(sig.mask, [])   # no handler/mask leak on spawn fail
