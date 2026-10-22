//! Yggdrasil v0.5.14 node address derivation (`address.AddrForKey`).
//!
//! This is a deterministic bit-truncation of the public key — **not a
//! hash and not invertible**: the 16-byte address carries only 112 bits
//! of key material after the leading-zero prefix and can never be turned
//! back into the 32-byte key. Linkability of the address to the key (and
//! therefore to the iroh/libp2p identities) remains by observation; no
//! anonymity is claimed (threat model §5).

/// Computes `AddrForKey` exactly as yggdrasil-go v0.5.14 does:
/// byte 0 is `0x02`; byte 1 is the number of leading ONE bits of the
/// bitwise-inverted key; the next 14 bytes are the 112 bits of the
/// inverted key that follow the leading ones and the first zero bit,
/// MSB-first (missing tail bits read as zero, matching upstream
/// truncation semantics).
///
/// This is a byte projection, not curve-point or signing-key validation.
/// For all-zero input the ones count reaches 256 and byte 1 wraps to 0,
/// matching the Go byte-conversion behavior.
///
/// Oracle: yggdrasil-go v0.5.14 `src/address/address_test.go`,
/// `TestAddress_AddrForKey`.
pub fn addr_for_key(key: &[u8; 32]) -> std::net::Ipv6Addr {
    let mut inverted = [0u8; 32];
    for (i, b) in key.iter().enumerate() {
        inverted[i] = !b;
    }

    // Count leading one bits across the inverted key, byte-wise exactly
    // like upstream. For a non-all-zero key this is at most 255 (255
    // ones followed by at least one zero bit).
    let mut ones = 0usize;
    for b in &inverted {
        if *b == 0xff {
            ones += 8;
        } else {
            ones += b.leading_ones() as usize;
            break;
        }
    }

    // Skip the leading ones plus the first zero bit, then take 112 bits.
    // `start` may reach 256 for a key whose inverted form has 255 ones
    // then a zero (e.g. inverted = FF*31 || FE): every bit position is
    // then past the end and the tail contributes zeros, matching the
    // upstream truncation.
    let start = ones + 1;
    let mut out = [0u8; 16];
    out[0] = 0x02;
    // For all-zero input `ones` is 256 and
    // this byte wraps to 0, exactly as a Go `byte` conversion would.
    out[1] = (ones & 0xFF) as u8;
    for i in 0..112 {
        let pos = start + i;
        if pos >= 256 {
            break;
        }
        let bit = (inverted[pos / 8] >> (7 - pos % 8)) & 1;
        out[2 + i / 8] |= bit << (7 - i % 8);
    }
    std::net::Ipv6Addr::from(out)
}

#[cfg(test)]
mod tests {
    use super::addr_for_key;

    /// Golden vector from yggdrasil-go v0.5.14 address_test.go
    /// (TestAddress_AddrForKey). Yggdrasil addresses are derived from
    /// the RAW public key bytes (not curve points), so the upstream
    /// public-key hex is exactly the right input.
    #[test]
    fn upstream_golden_vector() {
        const KEY: [u8; 32] =
            hex32("bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb");
        const fn hex32(h: &str) -> [u8; 32] {
            let h = h.as_bytes();
            let mut out = [0u8; 32];
            let mut i = 0;
            while i < 32 {
                let hi = (h[2 * i] as char).to_digit(16).unwrap() as u8;
                let lo = (h[2 * i + 1] as char).to_digit(16).unwrap() as u8;
                out[i] = (hi << 4) | lo;
                i += 1;
            }
            out
        }
        let addr = addr_for_key(&KEY);
        assert_eq!(
            addr.octets(),
            [
                2, 0, 132, 138, 96, 79, 187, 126, 67, 132, 101, 219, 141, 182, 104, 149
            ]
        );
        assert_eq!(addr.to_string(), "200:848a:604f:bb7e:4384:65db:8db6:6895");
    }

    /// Truncation edge: inverted key = FF*31 || FE has 255 leading one
    /// bits, so `start = 256` and all 112 tail bits come out zero
    /// (derived by hand; the production algorithm is NOT used as oracle).
    #[test]
    fn inverted_255_ones_truncates_to_zero_tail() {
        let mut key = [0x00u8; 32];
        key[31] = 0x01; // inverted: FF*31 || FE
        let addr = addr_for_key(&key);
        let mut expected = [0u8; 16];
        expected[0] = 0x02;
        expected[1] = 0xFF;
        assert_eq!(addr.octets(), expected);
        assert_eq!(addr.to_string(), "2ff::");
    }

    /// Degenerate all-zero bytes: ones = 256, byte 1 wraps to 0 like a
    /// Go `byte`, and
    /// every tail bit is past the end (zero). Documented wrap behavior.
    #[test]
    fn all_zero_key_wrap_is_documented() {
        let addr = addr_for_key(&[0x00u8; 32]);
        assert_eq!(
            addr.octets(),
            [0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
