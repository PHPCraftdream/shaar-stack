//! Key-to-address derivation of the pinned core.

/// The 16-byte Yggdrasil IPv6 address that the pinned core derives from a
/// public key. The address is a pure function of the key.
pub fn address_for_key(key: &[u8; 32]) -> [u8; 16] {
    yggdrasil::address::addr_for_key(key).0
}

#[cfg(test)]
mod tests {
    use super::address_for_key;

    fn key_from_hex(hex: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).expect("hex digit pair");
        }
        key
    }

    /// Golden vector from yggdrasil-go v0.5.14 `TestAddress_AddrForKey`.
    #[test]
    fn matches_the_upstream_golden_vector() {
        let key = key_from_hex("bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb");
        assert_eq!(
            address_for_key(&key),
            [
                2, 0, 132, 138, 96, 79, 187, 126, 67, 132, 101, 219, 141, 182, 104, 149
            ]
        );
    }

    /// Inverted key FF*31 || FE has 255 leading one bits and an empty tail.
    #[test]
    fn a_key_with_255_leading_ones_has_a_zero_tail() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let mut expected = [0u8; 16];
        expected[0] = 0x02;
        expected[1] = 0xFF;
        assert_eq!(address_for_key(&key), expected);
    }

    /// The all-zero key has 256 leading ones; the pinned core clamps the count
    /// to 255, where yggdrasil-go's `byte` arithmetic would wrap it to 0. The
    /// key is not a usable identity; the divergence is recorded, not endorsed.
    #[test]
    fn the_all_zero_key_clamps_its_leading_ones() {
        let mut expected = [0u8; 16];
        expected[0] = 0x02;
        expected[1] = 0xFF;
        assert_eq!(address_for_key(&[0u8; 32]), expected);
    }

    #[test]
    fn the_address_is_a_pure_function_of_the_key() {
        let key = [0x5a; 32];
        assert_eq!(address_for_key(&key), address_for_key(&key));
        assert_ne!(address_for_key(&key), address_for_key(&[0x5b; 32]));
    }
}
