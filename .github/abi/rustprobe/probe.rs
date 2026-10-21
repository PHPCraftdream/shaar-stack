#![deny(unsafe_code)]
//! Standalone numeric ABI probe; built and executed only in GitHub CI.

use std::process::ExitCode;

#[allow(unsafe_code)]
mod ffi {
    // SAFETY: goprobe/main.go exports these exact C symbols with stdint.h
    // uint64_t/uint32_t parameters and results. Rust u64/u32 match those
    // widths on both supported targets. No pointers or ownership cross the
    // boundary; Go's c-archive initializes its runtime before exported calls.
    unsafe extern "C" {
        fn GoAbiMix64(value: u64, salt: u64) -> u64;
        fn GoAbiRot32(value: u32, shift: u32) -> u32;
    }

    pub(super) fn mix64(value: u64, salt: u64) -> u64 {
        // SAFETY: all integer bit patterns are valid; the Go function is total,
        // retains no state, and has the exact declaration above. Calls in main
        // are sequential; there are no callbacks or foreign buffers.
        unsafe { GoAbiMix64(value, salt) }
    }

    pub(super) fn rot32(value: u32, shift: u32) -> u32 {
        // SAFETY: the same numeric ABI contract applies; the Go function masks
        // shift to 0..31 before conversion, so every u32 input is valid.
        unsafe { GoAbiRot32(value, shift) }
    }
}

fn main() -> ExitCode {
    let wide = [0, u64::MAX, 1_u64 << 63, 0x0123_4567_89ab_cdef];
    let salts = [0, 1, u64::MAX, 0xfedc_ba98_7654_3210];
    let narrow = [0, u32::MAX, 1_u32 << 31, 0x0123_4567, 0x89ab_cdef];
    let shifts = [0, 1, 4, 31, 32, 33, u32::MAX];
    let mut checks = 0;

    for value in wide {
        for salt in salts {
            let expected = value.rotate_left(13).wrapping_add(salt);
            let actual = ffi::mix64(value, salt);
            if actual != expected {
                eprintln!(
                    "mix64 mismatch: value={value:#018x} salt={salt:#018x} \
                     actual={actual:#018x} expected={expected:#018x}"
                );
                return ExitCode::FAILURE;
            }
            checks += 1;
        }
    }

    for value in narrow {
        for shift in shifts {
            let expected = value.rotate_left(shift);
            let actual = ffi::rot32(value, shift);
            if actual != expected {
                eprintln!(
                    "rot32 mismatch: value={value:#010x} shift={shift} \
                     actual={actual:#010x} expected={expected:#010x}"
                );
                return ExitCode::FAILURE;
            }
            checks += 1;
        }
    }

    println!("ABI probe passed: {checks} foreign-call vectors");
    ExitCode::SUCCESS
}
