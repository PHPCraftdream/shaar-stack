# Fine-grained diff CI and explicit sprint acceptance

## Execution contract

Ordinary CI selects project test cases automatically from changed module ownership,
not from commit suite labels and not from a transitive all-P2P/all-SDK rule.
The fixed map lives in `.github/ci/policy.py`. A module selects its own test
prefixes; shared constructor/dispatcher changes add a small Carrier contract set.
Unmodified dependency proof campaigns and unrelated packages remain skipped.
A public crate entry point or a binary crate can require that crate's whole test
target, but never automatically the entire workspace.

For example, discovery protocol changes select `carrier::driver::protocols::`
and the owned `infrastructure::tests::identification::` cases. Shared Carrier
wiring adds its core/boundary cases; infrastructure lifecycle changes add that
lifecycle's tests. They do not automatically rerun relay archive counterfactuals,
resolver matrices, Kademlia archive fixtures, SDK suites or application packages.

Feature revisions compare integration merge-base to head cumulatively; pull
requests use their base/head merge base; `develop` integration uses before/after.
Both sides of renames and deleted paths participate. Missing history or unmapped
source ownership fails with an actionable error, not a broad/full fallback.
Documentation-only cumulative changes run lightweight CI policy/structural checks.

## Exactly two full-run triggers

A full run is requested only by either:

1. The exact standalone line `[ci:full]` in the **current candidate commit message**.
2. **Actions → CI → Run workflow → scope: full**.

Use these explicit triggers at the end of a sprint. The marker is case-sensitive,
may be in the subject or body as its own line, and is not inherited from earlier
commits. Inline references such as `docs: explain [ci:full]` and quoted/indented
examples do not trigger full scope. Pull requests read the real head commit,
not a synthetic merge message. Commit text is data, never shell source.

Example commit message:

```text
chore: end-of-sprint acceptance

[ci:full]
```

Normal manual runs remain available with `scope: targeted`; no comparison SHA is
required for the ordinary branch comparison. An optional `base` SHA selects an
explicit comparison. A full marker in the current commit still requests full
scope, even when the manual input is targeted.

```sh
gh workflow run ci.yml --repo rmyva/shaar-stack --ref feature-branch -f scope=targeted
gh workflow run ci.yml --repo rmyva/shaar-stack --ref sprint-candidate -f scope=full
```

Install one finite `gh run watch RUN_ID --repo rmyva/shaar-stack --exit-status`
watcher after dispatch. Candidate CI still runs in the fork first, with the
existing pre-push guard and authorized upstream fallback on refusal.

## Inventory and failure handling

The selected-target runner builds only selected Cargo targets, obtains their
actual binary inventories, excludes explicitly ignored cases from runnable
coverage, and computes the union of mapped selectors. Overlapping selectors do
not execute a case twice. Every selector must match runnable cases.

Execution uses bounded batches of exact test names through Cargo. Executed events
and summaries are compared with the exact selected inventory; unexpected,
duplicate, missing, failed or unexpectedly ignored cases fail CI. Build, listing,
execution and identity-scanner errors are propagated. Ignored cases are listed
as not executed and never claimed as coverage. Special ignored permission probes
have a separate explicit rule; full CI preserves them.

`ci-plan.json` records the comparison SHA, trigger, owners and exact selectors;
`target/ci-selected/receipt.json` records executed case names. Inspect both OS
conclusions and receipts. A targeted green check is not full-sprint acceptance.
A later code change invalidates a previous full run's final acceptance SHA.

## Preparation is not a proof campaign

The workspace's fixed Cargo patches still require reviewed source preparation
and graph/hash verification before a Rust build. Those steps do not execute
unrelated dependency tests. Dependency self-tests and isolated fixtures run only
when their owning patch/proof changes, or during an explicit full campaign.
Compilation may still compile shared dependencies and a whole unit-test binary:
Rust does not compile individual test functions independently. Only the selected
case inventory is executed.

Mandatory structural limits, CI selector tests, formatting and selected-target
lint are not hidden workspace test campaigns. The CI-policy suite additionally
runs a tiny stdlib libtest fixture on both operating systems to prove exact
multi-case filtering while an unselected and an ignored failing case stay unrun.

## Full campaign and unchanged gates

Full scope preserves the existing workspace lint/tests, archive/product proofs,
negative controls and repeated Windows lifecycle checks. It does not also execute
the targeted runner, avoiding duplicate case execution through that path.
The reviewed optional P08 graph requires explicit full scope and its manual
checkbox. Other public-network/NAT probes, Yggdrasil, TUN/root and release gates
are not granted by either full trigger and remain separately controlled.
