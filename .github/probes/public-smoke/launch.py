"""One-command entry to the live public smoke (leaf PUNCH-SMOKE): check, dispatch once, wait, collect.

Compilation and execution stay in CI: this script only drives the `gh` CLI. It runs no product,
contacts no public target itself and dispatches at most once per call. The smoke contract (exact
targets, budgets, one run per dispatch, zero retries) is enforced inside the dispatched workflow.

  python -I launch.py plan    --repo OWNER/NAME --ref BRANCH [--sha SHA]
  python -I launch.py run     --repo OWNER/NAME --ref BRANCH [--sha SHA] --out DIR
  python -I launch.py collect --repo OWNER/NAME --run ID [--sha SHA] --out DIR

Exit codes: 0 both roles passed; 1 the run or a role did not pass (evidence is still collected);
2 a check refused (nothing was dispatched); 3 dispatched, but the run id was not found yet.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

WORKFLOW = "sdk-lock.yml"
CI_NAME = "CI"
CONTRACT_PATH = ".github/probes/public-smoke/contract.json"
SCOPE = "public-smoke-v1"
ARTIFACTS = ("public-smoke-client-evidence", "public-smoke-server-evidence")
WATCH_INTERVAL_S = 300  # the GitHub polling floor: never watch faster
FIND_DELAY_S = 20  # the dispatched run needs a moment to become listed; one lookup only
CLOCK_MARGIN_S = 120  # local clock versus GitHub clock
EVIDENCE_MAX = 1 << 20
SUMMARY_MAX = 4000
SHA = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*")


class Refusal(Exception):
    """A check failed; the message says whether anything was dispatched."""


def gh_cli(args, run=subprocess.run):
    """Run `gh` and return stdout bytes; a failure becomes a bounded refusal."""
    done = run(["gh", *args], capture_output=True, timeout=120, check=False)
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip()[:300]
        raise Refusal(f"gh {' '.join(args[:2])} failed: {detail}")
    return done.stdout


def validate_names(repo, ref, sha):
    if not REPO.fullmatch(repo):
        raise Refusal("--repo must look like OWNER/NAME")
    if not REF.fullmatch(ref) or ".." in ref:
        raise Refusal("--ref must be a plain branch name")
    if sha is not None and not SHA.fullmatch(sha):
        raise Refusal("--sha must be an exact 40-hex SHA")


def remote_head(repo, ref, gh):
    head = gh(["api", f"repos/{repo}/git/ref/heads/{ref}", "--jq", ".object.sha"]).decode("utf-8", "replace").strip()
    if not SHA.fullmatch(head):
        raise Refusal("the ref does not resolve to a commit")
    return head


def ordinary_ci_green(repo, sha, gh):
    text = gh(["api", f"repos/{repo}/actions/runs?head_sha={sha}&per_page=100",
               "--jq", "[.workflow_runs[] | {name, conclusion}]"])
    return any(row["name"] == CI_NAME and row["conclusion"] == "success" for row in json.loads(text))


def contract_digest(repo, sha, gh):
    """SHA-256 of the contract bytes at the SHA, after checking the bounds that keep a run single and final."""
    raw = gh(["api", f"repos/{repo}/contents/{CONTRACT_PATH}?ref={sha}", "-H", "Accept: application/vnd.github.raw"])
    try:
        contract = json.loads(raw)
        budgets = contract["budgets"]
        scoped = contract["scope"] == SCOPE and isinstance(contract["approval"], dict)
        single = budgets["runs_per_dispatch"] == 1 and budgets["retries"] == 0
    except (ValueError, KeyError, TypeError):
        raise Refusal("the contract at the SHA is missing or malformed") from None
    if not (scoped and single):
        raise Refusal("the contract at the SHA is not an approved single-run, zero-retry public smoke")
    return hashlib.sha256(raw).hexdigest()


def make_plan(repo, ref, sha, gh):
    validate_names(repo, ref, sha)
    head = remote_head(repo, ref, gh)
    sha = sha or head
    if head != sha:
        raise Refusal(f"ref {ref} is at {head[:12]}, not at {sha[:12]}: move the ref to the SHA first")
    if not ordinary_ci_green(repo, sha, gh):
        raise Refusal("no green ordinary CI run for this SHA: the smoke runs only on an exact green SHA")
    digest = contract_digest(repo, sha, gh)
    return {"repo": repo, "ref": ref, "sha": sha, "contract_sha256": digest,
            "inputs": {"source_revision": sha, "public_smoke": "true", "public_smoke_contract_sha256": digest}}


def dispatch(plan, gh):
    args = ["workflow", "run", WORKFLOW, "--repo", plan["repo"], "--ref", plan["ref"]]
    for name, value in plan["inputs"].items():
        args += ["-f", f"{name}={value}"]
    gh(args)


def find_run(plan, since, gh):
    """The one dispatched run created after `since` on the planned SHA, or None when absent or ambiguous."""
    rows = json.loads(gh(["run", "list", "--repo", plan["repo"], "--workflow", WORKFLOW, "--branch", plan["ref"],
                          "--event", "workflow_dispatch", "--limit", "5", "--json", "databaseId,headSha,createdAt"]))
    fresh = [row["databaseId"] for row in rows
             if row["headSha"] == plan["sha"] and datetime.fromisoformat(row["createdAt"].replace("Z", "+00:00")) >= since]
    return fresh[0] if len(fresh) == 1 else None


def wait_for(run_id, repo, run=subprocess.run):
    run(["gh", "run", "watch", str(run_id), "--repo", repo, "-i", str(WATCH_INTERVAL_S)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def prepare_out(path):
    out = Path(path)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise Refusal("--out must be a new or empty directory")
    out.mkdir(parents=True, exist_ok=True)
    return out


def download(run_id, repo, out, gh):
    """Download only the two evidence artifacts (no keys, no configs); return the names that could not be fetched."""
    missing = []
    for name in ARTIFACTS:
        try:
            gh(["run", "download", str(run_id), "--repo", repo, "-n", name, "-D", str(out / name)])
        except Refusal:
            missing.append(name)
    return missing


def read_evidence(directory):
    path = directory / "evidence.json"
    if not path.is_file() or path.stat().st_size > EVIDENCE_MAX:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def clip(value, limit=300):
    return value[:limit] if isinstance(value, str) else value


def summarize(evidence):
    """Selected observations only; the downloaded evidence is untrusted DATA and is never executed."""
    observed = evidence.get("observed") if isinstance(evidence.get("observed"), dict) else {}
    claims = evidence.get("claims") if isinstance(evidence.get("claims"), dict) else {}
    failures = evidence.get("failures") if isinstance(evidence.get("failures"), list) else []
    return {"role": clip(evidence.get("role")), "status": clip(evidence.get("status")),
            "failures": [clip(item) for item in failures[:10]],
            "route_sequence": observed.get("route_sequence"), "punch": observed.get("punch"),
            "offers": observed.get("offers"), "reflexive": observed.get("reflexive"),
            "direct_path": clip(claims.get("direct_path"))}


def collect(repo, run_id, sha, out, gh, wait=wait_for, say=print):
    """Wait for the run, fetch the evidence, print what was observed; return the process exit code."""
    out = prepare_out(out)
    wait(run_id, repo)
    state = json.loads(gh(["run", "view", str(run_id), "--repo", repo, "--json", "status,conclusion,headSha"]))
    if state["status"] != "completed":
        raise Refusal("the run has not completed yet: collect again later")
    if sha is not None and state["headSha"] != sha:
        raise Refusal("the run belongs to a different SHA")
    missing = download(run_id, repo, out, gh)
    summaries = []
    for name in ARTIFACTS:
        evidence = read_evidence(out / name)
        if evidence is not None:
            summaries.append(summarize(evidence))
            say(json.dumps(summaries[-1], sort_keys=True)[:SUMMARY_MAX])
    for name in missing:
        say(f"evidence not available: {name}")
    passed = (state["conclusion"] == "success" and not missing and len(summaries) == len(ARTIFACTS)
              and all(item["status"] == "pass" for item in summaries))
    say(f"run {run_id}: conclusion={state['conclusion']}; evidence in {out}; "
        + ("both roles passed" if passed else "NOT a clean pass: read the evidence"))
    return 0 if passed else 1


def run_command(args, gh, wait=wait_for, now=lambda: datetime.now(timezone.utc), sleep=time.sleep, say=print):
    """Check, dispatch exactly once, find the run, then collect."""
    plan = make_plan(args.repo, args.ref, args.sha, gh)
    prepare_out(args.out)  # fail before spending the single run
    say(json.dumps(plan, sort_keys=True))
    since = now() - timedelta(seconds=CLOCK_MARGIN_S)
    dispatch(plan, gh)
    sleep(FIND_DELAY_S)
    run_id = find_run(plan, since, gh)
    if run_id is None:
        say("dispatched once; the run id is not visible yet. Find it with `gh run list` and continue with: "
            f"launch.py collect --repo {plan['repo']} --run <id> --sha {plan['sha']} --out <new dir>")
        return 3
    say(f"dispatched run {run_id}; watching every {WATCH_INTERVAL_S} s")
    return collect(plan["repo"], run_id, plan["sha"], args.out, gh, wait, say)


def parse(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=("plan", "run", "collect"))
    parser.add_argument("--repo", required=True)
    parser.add_argument("--ref")
    parser.add_argument("--run", type=int)
    parser.add_argument("--sha")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    if args.mode in ("plan", "run") and args.ref is None:
        parser.error(f"{args.mode} needs --ref")
    if args.mode in ("run", "collect") and args.out is None:
        parser.error(f"{args.mode} needs --out")
    if args.mode == "collect" and args.run is None:
        parser.error("collect needs --run")
    return args


def main(argv, gh=gh_cli):
    args = parse(argv)
    try:
        if args.mode == "plan":
            print(json.dumps(make_plan(args.repo, args.ref, args.sha, gh), sort_keys=True))
            return 0
        if args.mode == "run":
            return run_command(args, gh)
        validate_names(args.repo, "x", args.sha)
        return collect(args.repo, args.run, args.sha, args.out, gh)
    except Refusal as refusal:
        print(f"launch refused: {refusal}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
