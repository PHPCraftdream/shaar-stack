# SDK configuration and identity baseline

Date: 2026-10-22. Status: configuration acceptance passed; identity functional
baseline passed, but full P04/security acceptance remains open. Networking,
Server/Client operation, and transport acceptance are not established.

## Observed CI evidence

[Run 39717053225](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39717053225)
completed successfully at source revision
`f82e0134830e53a480846f5762cc868aa77cc3e7` on Linux and Windows:

| Check | Linux | Windows |
|---|---:|---:|
| SDK unit tests | 11 | 11 |
| Pure configuration integration tests | 22 | 22 |
| Configuration file-loading integration tests | 10 | 10 |
| Identity integration tests | 21 | 19 |
| Native platform unit tests | not applicable | 5 |
| Native platform integration tests | not applicable | 5 |
| Rust tests in total, excluding empty harnesses | 64 | 72 |

Rust reported zero failed and zero ignored tests. Both jobs also passed
formatting, workspace/all-target clippy with warnings denied, the structural
guard, and its 53-case Python suite. Empty harnesses are not counted as
behavioral evidence. No local compilation or test execution was performed.

## Canonical dependency graph

The first candidate check correctly rejected the old local-only lockfile.
[Resolver run 39711993507](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39711993507)
checked out exact candidate `2bc9a2f1021bacbb5f0c04c2ea69e2c445720c41` and
ran `cargo generate-lockfile` in CI. Its text artifact was inspected as data,
not executed, and committed in `48df2db` before locked checks were repeated.

The graph contains 126 packages. All external sources are crates.io; the six
local packages retain version `0.1.0`. Initial direct pins and checksums were
independently checked against the registry: ktav 0.8.0, iroh-base 1.3.0,
serde 1.0.229, tokio 1.54.1, zeroize 1.9.1, libp2p-identity 0.3.0 (test
reference), and windows-sys 0.61.2 (Windows only). Pinning/checksums establish
source identity, not a complete dependency security audit.

## Configuration acceptance

- Separate Server/Client ktav schemas reject unknown fields and invalid input.
- CLI values replace file values before semantic validation; syntax/schema
  rejection occurs before merging and cannot be repaired by overrides.
- Required fields, defaults, loopback restrictions, port rules, empty paths,
  fallback values, public-key decoding, and distinct RFC key vectors passed.
- Errors retain static classes/known field names and numeric parser locations,
  not raw document values or unknown-field names.
- File and pure APIs enforce the same 1 MiB byte limit. A counting reader
  verifies consumption stops at the limit plus one; UTF-8 rejection passed.
- A byte limit is not a proof of every ktav recursion/destruction bound.
  These APIs are not advertised as an arbitrary-document sandbox.

The failed syntax fixture was corrected rather than its assertion weakened:
ktav accepts the original separator-free text as a root scalar, which fails
schema validation. That case remains a separate negative test. The syntax
case now uses a stray closing brace, backed by upstream 0.8.0 parser tests.
The oversized fixture uses one `repeat` allocation instead of overflowing the
standard formatter's width argument.

## Identity baseline and boundaries

RFC 8032 seed/public-key vectors, PeerId framing against libp2p's independent
implementation, and a source-derived Yggdrasil address vector passed. Crypto
and OS entropy are delegated to the pinned libraries; no signing, curve, or
random-number implementation was added. Secret Debug output is redacted;
seed staging uses best-effort zeroization, not an OS/swap/compiler-proof claim.

Creation uses exclusive create, never replacement. Unix mode 0600 and the
Windows protected Owner Rights DACL are installed before seed bytes. Tests
cover reloading without rewriting, malformed lengths, insecure existing
permissions, races, and preservation of existing files. Only an open-time
`NotFound` permits creation; metadata/read errors never authorize regeneration.

Private fault injection executes real exclusive creation and cleanup after
partial-write/sync failures. The cancellation test retains and joins the
worker while dropping a borrowed waiter after an observed partial write.
It does not establish cancellation of the public API: running native I/O can
finish after its async waiter is dropped. Creation is not crash-atomic
publication and does not promise parent-directory power-loss durability.

Own unsafe code is confined to the native platform FFI module. The SDK and
Yggdrasil adapter forbid unsafe. The structural exception names only the
platform library's exact package/path and rejects reuse as another target
kind; ordinary targets in that package still require forbid. Windows native
memory uses pointer-aligned bounded storage and checked byte spans, with
owned HANDLE/LocalAlloc lifetimes. No manual unsafe Send/Sync was added.

## Explicitly open acceptance

- Controlled NULL, empty, and inherited-only Windows ACL fixtures.
- Effective access by a different principal, independently of sharing flags
  or directory traversal restrictions; full SEC-KEY/P04 closure is not claimed.
- Whole-public-API cancellation/resource-lifecycle acceptance beyond the
  documented native-I/O limitations.
- P03 strict signaling-only, direct migration, and real NAT traversal.
- Rust Yggdrasil backend adoption and its unresolved ownership/shutdown gate.
- Functional networking, allowlist-before-target connection, and the running
  Server/Client applications.

The standalone P03 probe is a different workspace and was not run by this
SDK workflow. Its yanked Tokio 1.54.0 pin is not silently changed by adopting
Tokio 1.54.1 as an initial SDK dependency.
