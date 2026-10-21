# Limited Go c-archive ↔ Rust ABI check

Task #28. Status: passed on Linux and Windows in GitHub CI.
No Go/Rust compilation or probe execution was performed locally.

## Observed result

[Run 39678188652](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39678188652),
commit `b3a7089`, completed successfully on both matrix targets. Each job
compiled the Go c-archive, linked the Rust executable, and reported
`ABI probe passed: 51 foreign-call vectors`. The Windows job also confirmed
an LF working-tree checkout of the Go source (`i/lf w/lf`). The common
workspace CI [run 39678195069](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39678195069)
passed on both operating systems at the same commit.

## Scope and oracle

The probe uses only our own Go/Rust code and standard libraries. It imports
no Yggdrasil code or other application dependencies and resolves no modules.

- `GoAbiMix64(value, salt)` rotates the first 64-bit argument left by 13
  bits, then adds the second modulo 2^64. The argument order is asymmetric.
- `GoAbiRot32(value, shift)` rotates a 32-bit argument left modulo 32.
- Rust computes expected results using its standard integer operations,
  not a callback into Go or a hand-written inverse algorithm.
- Sixteen 64-bit argument pairs and thirty-five 32-bit/shift combinations
  exercise zero, all bits set, the high bit, asymmetric patterns, wrapping,
  and shift reduction. Any mismatch returns a nonzero exit status.

A constant-zero Go implementation fails for the selected `value=0, salt=1`
vector; swapping the two arguments also fails that vector. Truncating 64-bit arguments or results fails the high-bit and
asymmetric vectors. A missing archive or wrong symbol fails at link time.
These are counterfactual checks of the oracle, not separately executed
mutation-test results.

## FFI invariants

The generated C header and Rust imports use `uint64_t`/`uint32_t` and
`u64`/`u32`. Every integer bit pattern is valid. No pointers, callbacks,
buffers, handles, or allocation ownership cross this boundary. The functions
retain no application state; calls in the Rust program are sequential.
The Go runtime initializes through c-archive linkage and may run its own
runtime threads. The probe itself starts no application goroutines.

Rust starts with `#![deny(unsafe_code)]`; only the FFI module permits unsafe,
with explicit SAFETY comments on declarations and calls. Rust does not export
panic-capable callbacks. Miri cannot execute these native Go calls; this
check is not a Miri or general memory-safety proof.

## CI configuration

- Rust is pinned to 1.99.1, already observed in the baseline CI.
- Go is pinned to the verified stable 1.27.3 release; `GOTOOLCHAIN=local`
  prevents implicit upgrades, and `GO111MODULE=off` avoids module resolution.
- Checkout and setup-go actions use independently verified full commit SHAs.
  Dependency caching is disabled because there are no Go modules.
- Linux uses `x86_64-unknown-linux-gnu`; Windows explicitly installs the
  `x86_64-pc-windows-gnu` Rust target and uses the hosted image's GCC from
  `C:/mingw64/bin`, not the separate MSYS2 installation.
- The Windows compiler location follows the official runner-image script:
  https://github.com/actions/runner-images/blob/main/images/windows/scripts/build/Install-Mingw64.ps1
- Bash is explicit on both OSes. Link/search/library flags are passed to
  `rustc` directly; standalone rustc does not consume Cargo's `RUSTFLAGS`.
- Archives, headers, and executables remain under ignored `target/abi/`.
  No binaries or releases are published. Compiler versions are recorded;
  hosted-image/GCC drift means this is not a bit-for-bit reproducibility claim.

## Unproven boundaries

The successful CI run confirms linking and all 51 foreign-call vectors on
both tested targets. This does **not** establish Yggdrasil Core initialization,
MTU, shutdown, concurrency, datagram delivery, NAT traversal, or the P07 safe
wrapper. Those remain separate obligations. MSVC compatibility is not claimed.
