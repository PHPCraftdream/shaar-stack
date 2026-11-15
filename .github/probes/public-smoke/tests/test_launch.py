"""Pure CI-run tests of the one-command launcher: checks, single dispatch, polling floor, evidence collection."""

import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("smoke_launch_for_tests", HERE / "launch.py")
LAUNCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCH)

REPO, REF = "owner/repo", "integ-smoke-live"
SHA_A, SHA_B = "a" * 40, "b" * 40
CONTRACT = {"schema": 1, "scope": "public-smoke-v1", "approval": {"date": "2026-11-14"},
            "budgets": {"runs_per_dispatch": 1, "retries": 0}}
NOW = datetime(2026, 11, 15, 22, 0, 0, tzinfo=timezone.utc)


def contract_bytes(**changes):
    contract = json.loads(json.dumps(CONTRACT))
    contract["budgets"].update(changes.pop("budgets", {}))
    contract.update(changes)
    return json.dumps(contract).encode()


class FakeGh:
    """Stands in for the `gh` CLI: answers by endpoint and records every call."""

    def __init__(self, head=SHA_A, ci=({"name": "CI", "conclusion": "success"},), contract=None,
                 listed=(), state=None, evidence=None, missing=()):
        self.calls = []
        self.head, self.ci = head, list(ci)
        self.contract = contract_bytes() if contract is None else contract
        self.listed, self.missing = list(listed), set(missing)
        self.state = state or {"status": "completed", "conclusion": "success", "headSha": SHA_A}
        self.evidence = evidence or {}

    def __call__(self, args):
        self.calls.append(list(args))
        head = args[0] + " " + args[1]
        if head.startswith("api") and "/git/ref/heads/" in args[1]:
            return (self.head + "\n").encode()
        if head.startswith("api") and "/actions/runs?" in args[1]:
            return json.dumps(self.ci).encode()
        if head.startswith("api") and "/contents/" in args[1]:
            return self.contract
        if head == "workflow run":
            return b""
        if head == "run list":
            return json.dumps(self.listed).encode()
        if head == "run view":
            return json.dumps(self.state).encode()
        if head == "run download":
            name = args[args.index("-n") + 1]
            if name in self.missing:
                raise LAUNCH.Refusal("no artifact")
            target = Path(args[args.index("-D") + 1])
            target.mkdir(parents=True)
            body = self.evidence.get(name, {"role": name.split("-")[2], "status": "pass", "failures": []})
            (target / "evidence.json").write_text(json.dumps(body), encoding="utf-8")
            return b""
        raise AssertionError("unexpected gh call: " + " ".join(args))

    def count(self, head):
        return sum(1 for call in self.calls if call[0] + " " + call[1] == head)


def listed_row(run_id=77, sha=SHA_A, created=NOW):
    return {"databaseId": run_id, "headSha": sha, "createdAt": created.strftime("%Y-%m-%dT%H:%M:%SZ")}


class PlanTests(unittest.TestCase):
    def test_plan_binds_the_exact_sha_and_the_contract_digest(self):
        fake = FakeGh()
        plan = LAUNCH.make_plan(REPO, REF, None, fake)
        digest = hashlib.sha256(contract_bytes()).hexdigest()
        self.assertEqual(plan["inputs"], {"source_revision": SHA_A, "public_smoke": "true",
                                          "public_smoke_contract_sha256": digest})
        self.assertEqual(LAUNCH.make_plan(REPO, REF, SHA_A, FakeGh())["sha"], SHA_A)
        self.assertEqual(fake.count("workflow run"), 0, "planning never dispatches")

    def test_names_are_validated_before_any_call(self):
        for repo, ref, sha in (("owner", REF, None), ("owner/repo;x", REF, None), (REPO, "..", None),
                               (REPO, "a/../b", None), (REPO, "-bad", None), (REPO, REF, "abc"),
                               (REPO, REF, "A" * 40)):
            fake = FakeGh()
            with self.assertRaises(LAUNCH.Refusal, msg=(repo, ref, sha)):
                LAUNCH.make_plan(repo, ref, sha, fake)
            self.assertEqual(fake.calls, [])

    def test_a_moved_ref_is_refused(self):
        with self.assertRaisesRegex(LAUNCH.Refusal, "move the ref"):
            LAUNCH.make_plan(REPO, REF, SHA_B, FakeGh(head=SHA_A))

    def test_only_a_green_ordinary_ci_run_of_the_sha_allows_a_smoke(self):
        for rows in ([], [{"name": "CI", "conclusion": "failure"}], [{"name": "CI", "conclusion": None}],
                     [{"name": "Other", "conclusion": "success"}]):
            with self.assertRaisesRegex(LAUNCH.Refusal, "green ordinary CI", msg=rows):
                LAUNCH.make_plan(REPO, REF, None, FakeGh(ci=rows))
        LAUNCH.make_plan(REPO, REF, None, FakeGh(ci=[{"name": "CI", "conclusion": "failure"},
                                                      {"name": "CI", "conclusion": "success"}]))

    def test_a_contract_that_allows_repeats_or_lacks_approval_is_refused(self):
        bad = (b"not json", b"[]", contract_bytes(scope="other"), contract_bytes(approval=None),
               contract_bytes(budgets={"runs_per_dispatch": 2}), contract_bytes(budgets={"retries": 1}),
               json.dumps({"scope": "public-smoke-v1", "approval": {}}).encode())
        for raw in bad:
            with self.assertRaises(LAUNCH.Refusal, msg=raw):
                LAUNCH.make_plan(REPO, REF, None, FakeGh(contract=raw))


class DispatchTests(unittest.TestCase):
    def test_dispatch_passes_exactly_the_planned_inputs(self):
        fake = FakeGh()
        plan = LAUNCH.make_plan(REPO, REF, None, fake)
        fake.calls.clear()
        LAUNCH.dispatch(plan, fake)
        self.assertEqual(fake.calls, [["workflow", "run", "sdk-lock.yml", "--repo", REPO, "--ref", REF,
                                       "-f", f"source_revision={SHA_A}", "-f", "public_smoke=true",
                                       "-f", f"public_smoke_contract_sha256={plan['contract_sha256']}"]])

    def test_find_run_needs_exactly_one_fresh_run_on_the_sha(self):
        plan, since = {"repo": REPO, "ref": REF, "sha": SHA_A}, NOW - timedelta(seconds=120)
        old = listed_row(1, created=NOW - timedelta(hours=1))
        self.assertEqual(LAUNCH.find_run(plan, since, FakeGh(listed=[old, listed_row(2)])), 2)
        self.assertIsNone(LAUNCH.find_run(plan, since, FakeGh(listed=[old])))
        self.assertIsNone(LAUNCH.find_run(plan, since, FakeGh(listed=[listed_row(3, sha=SHA_B)])))
        self.assertIsNone(LAUNCH.find_run(plan, since, FakeGh(listed=[listed_row(4), listed_row(5)])))

    def test_the_watch_never_polls_faster_than_the_floor(self):
        seen = {}

        def run(args, **kwargs):
            seen.update(args=args, kwargs=kwargs)
            return types.SimpleNamespace(returncode=1)

        LAUNCH.wait_for(7, REPO, run=run)
        self.assertEqual(seen["args"], ["gh", "run", "watch", "7", "--repo", REPO, "-i", "300"])
        self.assertEqual(seen["kwargs"]["stdout"], subprocess.DEVNULL)
        self.assertGreaterEqual(LAUNCH.WATCH_INTERVAL_S, 300)

    def test_gh_failures_become_bounded_refusals(self):
        def run(args, **kwargs):
            return types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"x" * 5000)

        with self.assertRaises(LAUNCH.Refusal) as caught:
            LAUNCH.gh_cli(["run", "view", "1"], run=run)
        self.assertLess(len(str(caught.exception)), 400)
        ok = LAUNCH.gh_cli(["x", "y"], run=lambda args, **kw: types.SimpleNamespace(returncode=0, stdout=b"out"))
        self.assertEqual(ok, b"out")


class CollectTests(unittest.TestCase):
    def collect(self, fake, **kwargs):
        lines = []
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "evidence"
            code = LAUNCH.collect(REPO, 77, kwargs.pop("sha", SHA_A), out, fake, wait=lambda run_id, repo: None,
                                  say=lines.append)
            return code, lines, sorted(path.name for path in out.iterdir())

    def test_a_clean_run_downloads_only_the_two_evidence_artifacts(self):
        fake = FakeGh()
        code, lines, names = self.collect(fake)
        self.assertEqual(code, 0)
        self.assertEqual(names, ["public-smoke-client-evidence", "public-smoke-server-evidence"])
        self.assertEqual(fake.count("run download"), 2)
        self.assertTrue(all("-n" in call for call in fake.calls if call[:2] == ["run", "download"]))
        self.assertIn("both roles passed", lines[-1])

    def test_a_failed_role_or_missing_artifact_is_not_a_clean_pass(self):
        failing = {"public-smoke-client-evidence": {"role": "client", "status": "fail", "failures": ["no APP reply"]}}
        code, lines, _ = self.collect(FakeGh(evidence=failing))
        self.assertEqual(code, 1)
        self.assertTrue(any("no APP reply" in line for line in lines))
        code, lines, names = self.collect(FakeGh(missing=["public-smoke-server-evidence"]))
        self.assertEqual(code, 1)
        self.assertEqual(names, ["public-smoke-client-evidence"])
        self.assertTrue(any("evidence not available: public-smoke-server-evidence" in line for line in lines))
        state = {"status": "completed", "conclusion": "failure", "headSha": SHA_A}
        self.assertEqual(self.collect(FakeGh(state=state))[0], 1)

    def test_an_unfinished_run_or_a_foreign_sha_is_refused_without_a_download(self):
        for state, sha in (({"status": "in_progress", "conclusion": None, "headSha": SHA_A}, SHA_A),
                           ({"status": "completed", "conclusion": "success", "headSha": SHA_B}, SHA_A)):
            fake = FakeGh(state=state)
            with self.assertRaises(LAUNCH.Refusal):
                self.collect(fake, sha=sha)
            self.assertEqual(fake.count("run download"), 0)

    def test_a_non_empty_out_directory_is_refused_before_waiting(self):
        waited = []
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "old.txt").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(LAUNCH.Refusal, "new or empty"):
                LAUNCH.collect(REPO, 77, SHA_A, tmp, FakeGh(), wait=lambda *a: waited.append(a), say=print)
        self.assertEqual(waited, [])

    def test_the_summary_keeps_selected_observations_and_bounds_the_rest(self):
        evidence = {"role": "client", "status": "pass", "failures": ["f"] * 40, "product_stderr_tail": "SECRET-ISH",
                    "observed": {"route_sequence": ["ygg-standby"], "punch": {"attempts": 8}, "extra": 1,
                                 "offers": {"received": 0}, "reflexive": {"windows": {}, "exposed_ms": None}},
                    "claims": {"direct_path": "x" * 1000}}
        summary = LAUNCH.summarize(evidence)
        self.assertEqual(summary["route_sequence"], ["ygg-standby"])
        self.assertEqual(len(summary["failures"]), 10)
        self.assertEqual(len(summary["direct_path"]), 300)
        self.assertNotIn("product_stderr_tail", json.dumps(summary))
        self.assertEqual(LAUNCH.summarize({"observed": "bad", "claims": 3, "failures": "x"})["failures"], [])

    def test_unreadable_evidence_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.assertIsNone(LAUNCH.read_evidence(directory))
            (directory / "evidence.json").write_text("not json", encoding="utf-8")
            self.assertIsNone(LAUNCH.read_evidence(directory))
            (directory / "evidence.json").write_text("[1]", encoding="utf-8")
            self.assertIsNone(LAUNCH.read_evidence(directory))
            (directory / "evidence.json").write_text(" " * (LAUNCH.EVIDENCE_MAX + 1), encoding="utf-8")
            self.assertIsNone(LAUNCH.read_evidence(directory))


class RunCommandTests(unittest.TestCase):
    def run_flow(self, fake, out_dir):
        waits, sleeps, lines = [], [], []
        args = argparse.Namespace(repo=REPO, ref=REF, sha=None, out=out_dir)
        code = LAUNCH.run_command(args, fake, wait=lambda run_id, repo: waits.append((run_id, repo)),
                                  now=lambda: NOW, sleep=sleeps.append, say=lines.append)
        return code, waits, sleeps, lines

    def test_one_dispatch_one_lookup_one_watch_then_the_evidence(self):
        fake = FakeGh(listed=[listed_row(77)])
        with tempfile.TemporaryDirectory() as tmp:
            code, waits, sleeps, _ = self.run_flow(fake, str(Path(tmp) / "out"))
        self.assertEqual(code, 0)
        self.assertEqual((fake.count("workflow run"), fake.count("run list"), waits), (1, 1, [(77, REPO)]))
        self.assertEqual(sleeps, [LAUNCH.FIND_DELAY_S])

    def test_an_unlisted_run_is_reported_without_a_second_dispatch_or_lookup(self):
        fake = FakeGh(listed=[])
        with tempfile.TemporaryDirectory() as tmp:
            code, waits, _, lines = self.run_flow(fake, str(Path(tmp) / "out"))
        self.assertEqual((code, waits, fake.count("workflow run"), fake.count("run list")), (3, [], 1, 1))
        self.assertIn("collect --repo", lines[-1])

    def test_a_refused_check_dispatches_nothing(self):
        fake = FakeGh(ci=[])
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(LAUNCH.Refusal):
            self.run_flow(fake, str(Path(tmp) / "out"))
        self.assertEqual(fake.count("workflow run"), 0)
        busy = FakeGh()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "old.txt").write_text("x", encoding="utf-8")
            with self.assertRaises(LAUNCH.Refusal):
                self.run_flow(busy, tmp)
        self.assertEqual(busy.count("workflow run"), 0, "an unusable --out must not spend the single run")

    def test_main_maps_refusals_and_plans_to_exit_codes(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(LAUNCH.main(["plan", "--repo", REPO, "--ref", REF], gh=FakeGh()), 0)
            self.assertEqual(LAUNCH.main(["plan", "--repo", REPO, "--ref", REF], gh=FakeGh(ci=[])), 2)
            self.assertEqual(LAUNCH.main(["collect", "--repo", REPO, "--run", "1", "--sha", "zz", "--out", "x"],
                                         gh=FakeGh()), 2)
        self.assertEqual(json.loads(out.getvalue())["sha"], SHA_A)
        self.assertIn("launch refused", err.getvalue())
        for argv in (["plan", "--repo", REPO], ["run", "--repo", REPO, "--ref", REF],
                     ["collect", "--repo", REPO, "--out", "x"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                LAUNCH.main(argv, gh=FakeGh())


if __name__ == "__main__":
    unittest.main()
