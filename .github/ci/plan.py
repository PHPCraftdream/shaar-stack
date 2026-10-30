"""Read trusted event identities; select exact diff owners or an explicit full trigger."""

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
FULL_MARKER = re.compile(r"(?m)^\[ci:full\]\r?$")


def git(*args):
    return subprocess.run(["git", *args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=60).stdout


def commit(value):
    if not isinstance(value, str) or not SHA.fullmatch(value) or value == "0" * 40:
        raise ValueError("event does not establish a commit")
    git("cat-file", "-e", value + "^{commit}")
    return value


def integration_base(head):
    try:
        ref = commit(git("rev-parse", "--verify", "refs/remotes/ci-upstream/develop^{commit}").decode("ascii").strip())
    except subprocess.CalledProcessError:
        ref = commit(git("rev-parse", "--verify", "refs/remotes/origin/develop^{commit}").decode("ascii").strip())
    return commit(git("merge-base", ref, head).decode("ascii").strip())


def candidate_head(event_name, event, checkout):
    checkout = commit(checkout)
    if event_name == "pull_request":
        return commit(event["pull_request"]["head"]["sha"])
    if event_name == "push":
        if commit(event["after"]) != checkout:
            raise ValueError("push head differs from checkout identity")
    elif event_name != "workflow_dispatch":
        raise ValueError("unsupported event")
    return checkout


def changes(event_name, event, head, reference=""):
    end = candidate_head(event_name, event, head)
    ref = (reference or event.get("ref")) if event_name == "workflow_dispatch" else (event.get("ref") or reference)
    if ref and not ref.startswith("refs/"):
        ref = "refs/heads/" + ref
    if event_name == "pull_request":
        base = commit(event["pull_request"]["base"]["sha"])
        base = commit(git("merge-base", base, end).decode("ascii").strip())
    elif event_name == "push":
        base = commit(event["before"]) if ref == "refs/heads/develop" else integration_base(end)
    else:
        explicit = event.get("inputs", {}).get("base", "")
        if explicit:
            base = commit(explicit)
        elif ref == "refs/heads/develop":
            base = commit(git("rev-parse", end + "^").decode("ascii").strip())
        else:
            base = integration_base(end)
    raw = git("diff", "--no-renames", "--name-only", "-z", base, end, "--")
    return [part.decode("utf-8", errors="strict") for part in raw.split(b"\0") if part], base, end


def plan(event_name, event, head, reference=""):
    requested = event.get("inputs", {}).get("scope", "targeted") if event_name == "workflow_dispatch" else "targeted"
    if requested not in {"targeted", "full"}:
        raise ValueError("unsupported CI scope")
    candidate = candidate_head(event_name, event, head)
    message = git("show", "-s", "--format=%B", candidate).decode("utf-8", errors="strict")
    marker = bool(FULL_MARKER.search(message))
    full = requested == "full" or marker
    if event_name == "workflow_dispatch" and event.get("inputs", {}).get("p08_graph") in {True, "true"} and not full:
        raise ValueError("The reviewed P08 graph requires an explicit full trigger")
    paths, base = [], None
    if not full:
        try:
            paths, base, candidate = changes(event_name, event, head, reference)
        except (ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
            raise ValueError("Targeted comparison unavailable; provide a valid base; no automatic full fallback") from error
    result = POLICY.select(paths, full=full)
    result.update(scope="full" if full else "targeted", event=event_name, base=base,
                  head=candidate, checkout=head,
                  trigger="manual-full" if requested == "full" else "commit-marker" if marker else "diff")
    return result


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    result = plan(os.environ["GITHUB_EVENT_NAME"], event, os.environ["GITHUB_SHA"], os.environ.get("GITHUB_REF", ""))
    serialized = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
    Path("ci-plan.json").write_text(serialized, encoding="utf-8")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("selection=" + json.dumps(result["selection"], separators=(",", ":")) + "\n")
        output.write("targets=" + json.dumps(result["targets"], separators=(",", ":")) + "\n")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write("## CI selection\n\nScope: **" + result["scope"] + "**; trigger: **" + result["trigger"] + "**\n\n")
        summary.write("Suites: " + ", ".join(result["suites"]) + "\n\n")
        summary.write("The receipt lists exact project selectors. Skipped suites were not tested.\n")
    print(serialized, end="")


if __name__ == "__main__":
    main()
