// Standard-library-only Go c-archive probe.
package main

// #include <stdint.h>
import "C"

import "math/bits"

func main() {}

// GoAbiMix64 checks two asymmetric 64-bit arguments and wrapping arithmetic.
//
//export GoAbiMix64
func GoAbiMix64(value C.uint64_t, salt C.uint64_t) C.uint64_t {
	return C.uint64_t(bits.RotateLeft64(uint64(value), 13) + uint64(salt))
}

// GoAbiRot32 accepts every uint32_t shift; rotation is modulo 32.
//
//export GoAbiRot32
func GoAbiRot32(value C.uint32_t, shift C.uint32_t) C.uint32_t {
	return C.uint32_t(bits.RotateLeft32(uint32(value), int(uint32(shift)&31)))
}
