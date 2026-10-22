# SDK configuration and identity baseline

Date: 2026-10-22. Status: P04 identity/key-storage and P05 configuration
acceptance passed for Linux and Windows within the documented boundaries.
Evidence includes exclusive creation across OS processes, foreign-principal
read denial, public-future cancellation, and known-fixture diagnostic scans.
Networking, Server/Client operation, and transport acceptance are not
established.

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
cancellation cannot stop already-running blocking native I/O. Subsequent
public-future tests below extend the original waiter/backend coverage;
they do not promise aborting arbitrary native operations.

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

## Public-future cancellation evidence

[Run 39731282976](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39731282976)
passed at `def08d68fc6905b010cbe9d42dfa7bd900b3ddc2` on Linux and Windows.
The logs contain successful execution of all three genuine public-future
cancellation tests in `identity::store::tests`:

- `cancelled_create_new_worker_still_completes_a_valid_private_file`:
  cancelled creation can finish; a public load matches the public key
  independently derived from the zeroizing on-disk seed staging.
- `cancelled_load_never_modifies_the_existing_private_file`:
  cancelling a queued read leaves known fixture bytes unchanged.
- `cancelled_load_or_create_on_absent_path_never_creates_the_file`:
  dropping the future during its initial read prevents its creation
  continuation from running.

A retained blocker occupies the fixture runtime's only blocking thread.
Each actual public future is polled to Pending and dropped before releasing
that blocker. A subsequently queued sentinel observes completion inside the
live runtime; both owned handles are joined. FIFO ordering is a fixture
assumption checked against the pinned Tokio 1.54.1 implementation, not a
public Tokio scheduling guarantee. Runtime destruction alone is not used as
proof: queued, never-started nonmandatory jobs can be discarded at shutdown.
These cases cover queued public-future cancellation and eventual worker
completion, not interruption of arbitrary in-flight OS I/O. The earlier
partial-write failure test separately covers worker-owned cleanup after its
borrowed waiter is dropped.

## Two-OS-process creation evidence

[Run 39735254047](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39735254047)
passed at `109c43c251c8e0ea3d85cdbbd3fc82d3e2bfc6de` on Linux and Windows.
Both logs contain
`test process::two_process_create_new_race_same_fresh_key ... ok`.

The normal integration test launches two actual copies of its test harness
before releasing either through piped stdin. Each exactly selected ignored
helper invokes public `Identity::create_new` on the same path. The parent
requires one creation and one `AlreadyExists` result, encoded as exit codes
0 and 42; every other result fails. Selecting zero helper tests would yield
two zero exits and therefore fail. Immediate owned-child guards kill and
wait on parent unwind. Metadata checks the 32-byte file without reading the
secret; two public loads produce the same public key. This is a
launch-before-release interleaving, not a claim that both children reached
a readiness barrier. Blocking waits rely on the CI job's 30-minute timeout.

## Captured diagnostic-output evidence and P04 acceptance

[Run 39736676155](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39736676155)
passed at `f92bdf94f596669e492c0440ae15290755f9fbf1` on Linux and Windows.
Both jobs passed formatting, clippy, Rust tests, the structural guard, and
87 Python checks covering the guard and scanner. The ordinary test outputs
on both systems and the explicit Ubuntu foreign-reader output were scanned
and reported `identity output scan: clean` before being displayed. Cargo
failure statuses are preserved; a failed scan suppresses the captured log.

The bounded 4 MiB oracle covers listed public RFC 8032 seeds and deterministic
key-file payload fixtures in raw bytes, case-insensitive hexadecimal, and
32-value decimal Debug arrays. It rejects unreadable or oversized input with
static diagnostics, without printing matched material or input paths.
Regression cases cover every listed representation, clean public keys,
near misses, read bounds, and redacted error output. They also explicitly
cover a representation collision: forty ASCII `3` bytes are a valid raw
32-byte `0x33` fixture occurrence, even though they are only a prefix of its
hexadecimal form. The detector was not weakened to make that input clean.

This is a known-fixture regression oracle for captured cargo-test stdout
and stderr, not discovery of arbitrary runtime-generated secrets. No build
artifacts are uploaded by this workflow, and no arbitrary-artifact scan is
claimed. Earlier local ad-hoc scanner executions by a delegated worker were
outside the task's allowed checks and are not used as acceptance evidence;
the final source was validated by the cited GitHub CI run.

P04 closes with the conversion vectors, unchanged loading, malformed and
insecure files, exclusive/no-overwrite behavior, task and process races,
creation-time permissions, actual foreign-principal denial, cancellation
boundaries, and captured diagnostic checks described above. This acceptance
does not imply the networking stages are implemented.

## Limits and remaining project acceptance

- The output oracle covers known test fixtures, not unknown random secrets
  or every possible textual representation.
- Windows anonymous coverage proves file-object denial, not full-path lookup
  or a second-account logon; the Authz evidence is a synthetic SID decision,
  not a real different-principal read.
- Native operations remain cancel-unsafe as documented; arbitrary in-flight
  OS I/O interruption is not promised.
- P03 strict signaling-only, direct migration, and real NAT traversal.
- Rust Yggdrasil backend adoption and its unresolved ownership/shutdown gate.
- Functional networking, allowlist-before-target connection, and the running
  Server/Client applications.

The standalone P03 probe is a different workspace and was not run by this
SDK workflow. Its yanked Tokio 1.54.0 pin is not silently changed by adopting
Tokio 1.54.1 as an initial SDK dependency.
