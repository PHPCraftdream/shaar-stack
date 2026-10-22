# SDK configuration and identity baseline

Date: 2026-10-22. Status: configuration acceptance passed; identity functional
baseline passed, and Windows private-file ACL evidence now includes file-object
denial under the anonymous identity plus SID-only Authz oracle checks, while
full P04/security acceptance remains open. Networking, Server/Client operation,
and transport acceptance are not established.

## Observed CI evidence

[Run 39724028825](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39724028825)
completed successfully at source revision
`c63f84dfda353b3b38a389f020f1862172b41afb` on Linux and Windows:

| Check | Linux | Windows |
|---|---:|---:|
| SDK unit tests | 11 | 11 |
| Pure configuration integration tests | 22 | 22 |
| Configuration file-loading integration tests | 10 | 10 |
| Identity integration tests | 21 | 19 |
| Native platform unit tests | not applicable | 12 |
| Native platform integration tests | not applicable | 5 |
| Rust tests in total, excluding empty harnesses | 64 | 79 |

Rust reported zero failed and zero ignored tests. Both jobs also passed
formatting, workspace/all-target clippy with warnings denied, the structural
guard, and its 53-case Python suite. Empty harnesses are not counted as
behavioral evidence. No local compilation or test execution was performed.

The immediately preceding run
[39722906408](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39722906408)
at `dccc09d` failed: its anonymous `File::open` positive control was denied
with OS error 5, and the cause was not established. Revision `c63f84d`
replaced that harness.

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
owned HANDLE/LocalAlloc lifetimes. No manual unsafe Send/Sync was added; the
guards are neither Send nor Sync.

## Windows ACL evidence at c63f84d

`validate_dacl` was extracted: ACL/ACE extents (the ACL size field against the
buffer length, a truncated header, and missing or oversized ACEs) are checked
before use and fail with `InvalidData`.

Native fixture tests fail closed: a valid NULL DACL (an
`IsValidSecurityDescriptor`-validated fixture), an empty ACL, a deny-only ACL,
an inherited ACE flag, and a non-owner allow SID all yield `PermissionDenied`;
zero mask, malformed SID, and unknown ACE type also fail closed; truncated or
oversized extents yield `InvalidData`. A positive owner-allow control using
S-1-3-4 (Owner Rights) passes.

A test-only `authz.rs` oracle calls AuthzInitializeResourceManager (NO_AUDIT),
AuthzInitializeContextFromSid with AUTHZ_SKIP_TOKEN_GROUPS and a synthetic
World SID S-1-1-0, and AuthzAccessCheck with FILE_GENERIC_READ, with full
cleanup. On a private owner-only file the World-SID decision is denial; on a
broad `D:P(A;;FA;;;WD)` positive control it grants read. This is a SID-only
Authz decision, not an actual `File::open` under another OS account.

A test-only `anonymous.rs` opens an owner reference handle, then inside a
scoped OS thread impersonates the built-in anonymous token
(ImpersonateAnonymousToken on an OpenThread THREAD_IMPERSONATE handle;
RevertToSelf in Drop, with `process::abort` on restore failure) and reopens by
the reference handle for a fresh GENERIC_READ handle (all share modes, no
backup/security-bypass flags), reading up to 33 bytes. No ancestor or name
lookup is performed by that reopen. No account, process token, registry, or
parent-directory ACL is changed; the impersonation is scoped to the worker
thread and restored by RevertToSelf.

Test `anonymous_principal_cannot_read_before_or_after_seed_write`: an
anonymous-readable positive control (Owner Rights allow plus AN allow, reading
`readable`) succeeds both before and after; an initially empty private file created via
`create_private_new_raw` denies anonymous read with exact raw OS error 5 both
before and after a 32-byte owner seed write, with the owner handle dropped
first so sharing cannot masquerade as denial.

Scope of proof: the anonymous-reopen denial proves file-object denial under
the anonymous identity; it does not prove full-path/ancestor-directory lookup
enforcement, nor a second-account logon. The Authz check is a synthetic
World-SID decision, not a real different-principal read. Public API
cancellation cannot stop already-running blocking native I/O; cancellation
coverage at this revision only establishes narrower waiter/backend cleanup.
Full P04/security acceptance remains open pending the public-future tests
and final acceptance audit.

## Unix second-UID read evidence

[Run 39730112320](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39730112320)
passed on both operating systems at exact source revision
`a4b13a290a9d8f60c400d4cb78454a5d7f03120b`. The explicit Ubuntu
SEC-KEY-02 step logged `running 1 test` and the successful fully qualified
`identity::store::tests::unprivileged_reader::identity_unprivileged_uid_cannot_read_seed_file`
test. The ordinary Linux suite intentionally ignores this sudo-dependent
test; the separate step runs it explicitly and requires its exact success
line, so zero selected tests cannot pass the step.

The production exclusive-create helper is held before its first write. A
child Python interpreter, isolated with `-I` and run as `nobody`, checks its
effective UID is neither zero nor the file owner's UID, then attempts a
bounded read. The empty private file and the file after 32 synthetic seed
bytes both yield exact `EACCES` (13). A readable 0644 control in the same
fixture directory is read successfully before and after those denials.
Only the newly created fixture directory and control file are chmodded;
existing ancestors and the private file are not modified. No local native
execution or tests were performed for this proof.

The first run, 39729592357, correctly failed its positive control: the
readable file itself returned `EACCES`, so no privacy proof was accepted.
The corrected fixture uses a fresh directory under the system temporary
root rather than workspace descendants, excluding inaccessible workspace
ancestors without weakening either control. The exact offending ancestor
was not identified. This run establishes actual second-UID reads on Linux;
it does not add claims about every Unix platform or root/admin protection.

## Explicitly open acceptance

- Windows anonymous coverage proves file-object denial, not full-path lookup
  or a second-account logon; the Authz evidence is a synthetic SID decision,
  not a real different-principal read.
- Whole-public-API cancellation/resource-lifecycle acceptance beyond the
  documented native-I/O limitations.
- P03 strict signaling-only, direct migration, and real NAT traversal.
- Rust Yggdrasil backend adoption and its unresolved ownership/shutdown gate.
- Functional networking, allowlist-before-target connection, and the running
  Server/Client applications.

The standalone P03 probe is a different workspace and was not run by this
SDK workflow. Its yanked Tokio 1.54.0 pin is not silently changed by adopting
Tokio 1.54.1 as an initial SDK dependency.
