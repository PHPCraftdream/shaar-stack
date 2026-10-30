# Change-scoped CI and the sprint gate

## Contract

Feature and integration pushes run change-scoped CI, not the full workspace campaign.
A sprint is accepted only after an explicit `workflow_dispatch` of CI with
`scope: full` on the final integrated commit. No calendar is inferred and no full
campaign is scheduled automatically. A targeted pass is not a full-sprint receipt.
The existing running DNS repair campaign is not cancelled by this change.

## Selection

A stdlib-only planner selects the union of domains affected by changed paths.
Integration pushes to `develop` compare the event's `before` and `after` commits.
Every feature-branch revision compares its integration merge base with its head;
pull requests compare the merge base of the event's base and head with that head.
This cumulative feature range preserves unverified obligations after failed or
cancelled runs: a runner fix or documentation follow-up cannot erase the original
feature's required suites. Both sides of renames are included; deletions use their
old paths. CI fetches integration `develop` on every feature push from the fixed
project upstream into `refs/remotes/ci-upstream/develop`, so a fork without its own
`develop` does not force a broad campaign. A local `origin/develop` is the secondary
option; when neither comparison can be established the planner falls back
conservatively. Missing history, unknown paths
and shared build/CI configuration select a broad targeted campaign, never an empty
success and never an automatic full run.
Documentation-only cumulative diffs run policy and structural checks without building Rust.
No untrusted path or event value becomes shell source or a Cargo argument.

Domains and required dependent coverage:

| Changed area | Required domains |
| --- | --- |
| Owned DNS and wire decoder | DNS, p2p product, discovery/Carrier integration |
| Discovery grammar, roles and guards | Discovery, p2p product, Carrier wire proof |
| Carrier, relay, bridge and packet protocol | Relay, discovery, p2p product, SDK |
| Kademlia prepared sources | Kademlia, discovery, p2p product, SDK |
| Resolver prepared sources | Resolver, DNS, discovery, p2p product, SDK |
| Native backend prepared sources and driver proofs | Backend, SDK, applications |
| SDK networking | SDK, applications; signaling also p2p and relay |
| Identity, config, platform, Server and Client | SDK, applications, privileged identity control |
| Dependency graph and shared CI runner/inventory code | All domains and license gate |
| License policy/collector | License gate and its script tests |
| Unknown executable/source path | All domains conservatively |

Selected domain suites retain their assertions, failure propagation, dynamic test
inventories and applicable negative controls. Selection is by subsystem, not by
individual test names inferred from a diff. Both Linux and Windows remain required
for selected Rust/network suites. Rust compilation may still compile shared
workspace dependencies: bounded test execution is not isolated dependency building.

All Cargo invocations need the workspace's patched sources. Download/hash/source
preparation remains available whenever any product Rust suite runs. Creating and
compiling isolated dependency fixtures is gated separately by its owning domain.
A product DNS fixture change does not rerun resolver archive feature matrices,
relay dependency counterfactuals or Noq counterfactuals.

## Sprint gate

`scope: full` preserves the complete existing CI campaign, including full workspace
lint/tests, archive/product feature proofs, counterfactuals and repeated Windows
lifecycle diagnostics. Existing opt-in P08 graph and separate NAT/probe workflows
keep their explicit gates; this change grants no public-network permission.
The full run records the tested SHA and selected domains. Any later code change
invalidates that SHA's status as the final sprint acceptance point.

## Implementation and acceptance

1. Add a deterministic planner and policy tests, including docs-only, unions,
   rename/deletion, new/missing base, unknown paths, malformed events and full mode.
2. Gate the current workflow's proof groups without rewriting their command bodies.
   Add targeted package test execution with real inventory verification; never
   accept a zero-test filter as coverage.
3. Record selection and reasons in the job summary and artifact. Require the
   planning job and all selected matrix checks to succeed; skipped work must be
   visible and never described as executed.
4. Verify the planner and workflow wiring in GitHub CI. Inspect exact receipts and
   unchanged proofs before delivery. Do not run local project scripts/tests/builds.
5. At sprint completion explicitly run the full gate; there is no automatic full
   rerun after each feature's upstream transfer.

Initial domains are intentionally conservative. Narrow them only with an explicit
cross-layer coverage argument and a regression in the selection policy tests.
Caching and parallel sharding are separate optimizations, not prerequisites and
not substitutes for selecting the correct tests.

## Operator commands

Normal feature pushes and upstream integration pushes select their domains
without a manual dispatch. Branches whose cumulative diff is documentation-only
still run planner policy regressions and structural checks on both operating
systems, but skip Rust installation, source preparation, lint and product/proof
execution. A documentation follow-up on an unmerged code feature retains that
feature's suites; successful checks are not cached or inferred from earlier runs.

For an explicit targeted comparison, replace `feature-branch` and `BASE_SHA`
with the published candidate branch and the full comparison commit SHA:

```sh
gh workflow run ci.yml --repo rmyva/shaar-stack --ref feature-branch -f scope=targeted -f base=BASE_SHA
```

At the end of a sprint, replace `sprint-candidate` with its published branch:

```sh
gh workflow run ci.yml --repo rmyva/shaar-stack --ref sprint-candidate -f scope=full
```

Install a finite `gh run watch RUN_ID --repo rmyva/shaar-stack --exit-status`
watcher after dispatch. Inspect the selection receipt and both OS conclusions;
never infer full acceptance from the workflow name or a targeted green check.
Candidate `3aca1b3` passed the initial broad targeted migration validation on
Linux and Windows in fork run `40967908637`; no full sprint run was requested.
