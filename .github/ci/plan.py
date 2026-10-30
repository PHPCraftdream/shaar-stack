"""Read GitHub event data and emit an auditable, shell-independent CI plan."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

SPEC = importlib.util.spec_from_file_location("ci_policy", Path(__file__).with_name("policy.py"))
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
SHA = re.compile(r"[0-9a-f]{40}\Z")


def git(*args):
    return subprocess.run(["git", *args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=60).stdout


def commit(value):
    if not isinstance(value, str) or not SHA.fullmatch(value) or value == "0" * 40:
        raise ValueError("event does not establish a commit")
    git("cat-file", "-e", value + "^{commit}")
    return value


def changes(event_name, event, head):
    head = commit(head)
    if event_name == "pull_request":
        pull = event["pull_request"]
        base = commit(pull["base"]["sha"])
        end = commit(pull["head"]["sha"])
        base = commit(git("merge-base", base, end).decode("ascii").strip())
    elif event_name == "push":
        end = commit(event["after"])
        if end != head:
            raise ValueError("push head differs from checkout identity")
        if event.get("ref") != "refs/heads/develop":
            try:
                reference = commit(git("rev-parse", "--verify", "refs/remotes/ci-upstream/develop^{commit}").decode("ascii").strip())
            except subprocess.CalledProcessError:
                reference = commit(git("rev-parse", "--verify", "refs/remotes/origin/develop^{commit}").decode("ascii").strip())
            base = commit(git("merge-base", reference, end).decode("ascii").strip())
        else:
            base = commit(event["before"])
    elif event_name == "workflow_dispatch":
        base = commit(event.get("inputs", {}).get("base", ""))
        end = head
    else:
        raise ValueError("unsupported event")
    # Disabling rename detection classifies both removed and added paths.
    raw = git("diff", "--no-renames", "--name-only", "-z", base, end, "--")
    return [part.decode("utf-8", errors="strict") for part in raw.split(b"\0") if part], base, end


def plan(event_name, event, head):
    scope = event.get("inputs", {}).get("scope", "targeted") if event_name == "workflow_dispatch" else "targeted"
    if scope not in {"targeted", "full"}:
        raise ValueError("unsupported CI scope")
    paths, base, end, fallback = [], None, head, None
    try:
        paths, base, end = changes(event_name, event, head)
    except (ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
        fallback = "comparison unavailable: " + type(error).__name__
    if event_name == "workflow_dispatch" and event.get("inputs", {}).get("p08_graph") in {True, "true"}:
        fallback = "explicit P08 graph requires prepared product domains"
    result = POLICY.select(paths, full=scope == "full", fallback=fallback)
    result.update(scope=scope, event=event_name, base=base, head=end, checkout=head)
    return result


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    result = plan(os.environ["GITHUB_EVENT_NAME"], event, os.environ["GITHUB_SHA"])
    serialized = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
    Path("ci-plan.json").write_text(serialized, encoding="utf-8")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("selection=" + json.dumps(result["selection"], separators=(",", ":")) + "\n")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write("## CI selection\n\nScope: **" + result["scope"] + "**\n\n")
        summary.write("Selected: " + ", ".join(k for k in POLICY.DOMAINS if result["selection"][k]) + "\n\n")
        summary.write("Full receipt: `ci-plan.json`. Skipped domains were not tested.\n")
    print(serialized, end="")


if __name__ == "__main__":
    main()
