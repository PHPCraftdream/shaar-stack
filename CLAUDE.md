# Sha’ar Stack — Development Rules

One repository `shaar-stack`, several crates in a Cargo workspace.
These rules are mandatory for all crates: SDK, Server, Client, and transports,
including tests, examples, auxiliary code, and build scripts.
New crates inherit these rules without exceptions.

English is the language of repository content. All maintained repository
content — comments, docstrings, diagnostics, and new commit/PR text — must be
written in English. The directory `docs/checkpoints/` may remain in Russian.

## 1. No unsafe outside the FFI boundary

- Our own Rust code contains no `unsafe` except the minimal code required at
  an isolated native FFI boundary (for example the Windows key ACL).
  The Yggdrasil adapter uses a safe Rust API and receives no unsafe exception.
- FFI is isolated in a dedicated module or low-level crate and provides a safe
  interface to the rest of the Rust code.
- All ordinary crate roots, binary roots, examples, integration tests, and
  `build.rs` must contain `#![forbid(unsafe_code)]`.
- In a crate with an FFI module, `#![deny(unsafe_code)]` applies, and the
  `#[allow(unsafe_code)]` permission is granted only for the isolated FFI
  boundary. `forbid` cannot be locally overridden via `allow`.
- Every unsafe block and unsafe impl at the FFI boundary is accompanied by a
  brief `SAFETY:` comment justifying that the invariants are upheld.
- The wrapper must guarantee correct pointers, lengths, ownership, and buffer
  lifetimes, thread safety, error handling, and shutdown. Panics and
  exceptions must not cross the ABI boundary unhandled.
- FFI tests cover errors, boundary sizes, lifecycles, and permitted concurrent
  calls. The safe API must not allow invariants to be violated.
- The exception does not permit unsafe optimizations or rule workarounds via
  macros, code generation, or separate crates outside FFI tasks.
- A dependency with a safe public API does not make its internal
  implementation vetted: the safety and maintenance of such a dependency are
  evaluated separately. `forbid(unsafe_code)` does not check dependency code.

## 2. No more than 700 lines per code file

- Every code file maintained in the project contains no more than 700 lines,
  including blank lines and comments. The rule also applies to tests,
  examples, FFI shims, and scripts.
- Documentation is not subject to the 700-line limit, including documents
  with embedded code examples.
- As a code file approaches the limit, it is split by responsibility.
- The limit must not be circumvented by minification or by joining independent
  expressions into a single line.

## 3. No more than 7 items per directory

- Each directory contains at most 7 directly nested items: files and
  subdirectories combined. Hidden project items count too.
- The rule applies to the repository root as well as to test and
  documentation directories.
- Direct Markdown snapshots in `docs/checkpoints/` are exempt from the item
  count. The directory itself, its subdirectories, and non-Markdown files
  remain subject to the limit.
- Tool service data and generated artifacts that are not project sources do
  not count: for example, `.git` and `target`.
- Structure must be planned in advance; new directory levels must reflect the
  purpose of components, not mask a violation of the limit.

## 4. All cases covered by tests

- For every behavior, verifiable expected results are specified.
- Tests cover success paths, boundaries, invalid input, and errors.
- For network and concurrent code, additionally cover timeouts, cancellation,
  connection loss and recovery, backpressure, shutdown, and significant
  interleavings of operations.
- Every fixed defect gets a regression test.
- A test verifies the contract, not a re-implementation of the algorithm.
- A line-coverage percentage by itself does not prove scenario coverage.
- Untested scenarios must not be declared covered. Adding tests and actually
  running them are reported separately.

## 5. Minimal algorithmic complexity

- Choose the minimal justified time and space complexity for the required
  semantics and expected data sizes.
- On hot paths, eliminate extra passes, linear search where an index is
  needed, and recomputation of immutable values.
- Estimate the worst case and state growth, especially for untrusted input.
- When time and memory conflict, explicitly record the chosen trade-off.
- Optimization must not break correctness, safety, or the API contract.

## 6. Minimal allocations

- Do not create needless `String`, `Vec`, `Box`, `Arc`, or buffer copies.
- Prefer borrowing, buffer reuse, and transfer of ownership where it preserves
  a clear and safe lifecycle.
- Do not allocate per packet when safe reuse is possible.
- Bound queue, cache, and buffer sizes; backpressure is mandatory.
- Do not trade allocations for unbounded stack consumption or memory holds.

## 7. Maximum async and lock-free

- Network I/O, waiting, and coordination are performed asynchronously.
- Blocking operations and long computations are not run on async executor
  threads; use a suitable isolated executor for them.
- Do not make pure computations asynchronous without need.
- Prefer single-task ownership of state and message passing over shared
  mutable state; for shared structures use proven lock-free solutions where
  they are genuinely applicable.
- Do not assume a channel or atomic type automatically constitutes a proven
  lock-free solution.
- Do not hold a lock across `.await`; avoid busy waiting.
- If no correct lock-free solution is available, the necessity of locking,
  the scope of the critical section, and the contention impact must be
  explicitly justified.
- Correctness, absence of races, bounded resources, and correct cancellation
  matter more than formal lock-freedom.

## Runtime configuration

- Server and Client can be started with configuration files.
- The configuration file format is **ktav 0.8.***.
- Server and Client schemas must conform to that format version; a different
  format or a switch to another version branch requires coordination.
- Keep configuration loading separate from the SDK's networking logic.
- Validate configuration before starting network services; errors must
  identify the offending field and must not disclose secrets.
- Test valid configs, default values, invalid syntax, and invalid parameter
  values.

## Working procedure

- Do not run local tests, builds, or compilations without an explicit user
  request. By default, checks run in GitHub CI.
- Of local checks, only `cargo clippy`, `cargo fmt`, and syntax checks are
  allowed. Do not run `cargo check`, `cargo build`, `cargo test`, or Go
  builds/tests locally: builds and tests run only in GitHub CI; local checks
  are clippy, formatting, and syntax only. A local smoke run is allowed only
  at the very end of the entire project and without local build/test —
  binaries are taken from verified CI artifacts. If a check triggers a build
  of third-party code via `build.rs`, a separate permission for that build is
  required first.
- Do not bump project or dependency versions without an explicit user request.
- Do not commit, push, or run subagents without an explicit user request.
- Comments in code are concise and written in English.

## Consequence for the architectural draft

`docs/architecture/keypipe.md` is an architectural draft. Its Go shim for
Yggdrasil is superseded by the native Rust backend decision
(Yggdrasil-ng): integration with the native Yggdrasil core is done as an
isolated Rust adapter meeting the same isolation and safety requirements.
Historical Go-FFI sketches remain superseded reference; sketches do not
exempt one from verifying isolation invariants or from the other rules.
