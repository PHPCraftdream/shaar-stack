use super::valid;

pub(super) fn header(queries: u16, answers: u16, authorities: u16, additionals: u16) -> [u8; 12] {
    let mut bytes = [0; 12];
    for (slot, count) in bytes[4..].as_chunks_mut::<2>().0.iter_mut().zip([
        queries,
        answers,
        authorities,
        additionals,
    ]) {
        slot.copy_from_slice(&count.to_be_bytes());
    }
    bytes
}

#[test]
fn wire_dns_profile_length_boundaries_exclude_tcp_prefix() {
    for length in [0, 11, 4097, 65535] {
        assert!(!valid(length, &[0; 12]), "accepted length {length}");
    }
    for length in [12, 4096] {
        assert!(valid(length, &[0; 12]));
    }
}

#[test]
fn wire_dns_profile_questions_and_combined_record_limits() {
    for counts in [
        (0, 0, 0, 0),
        (1, 64, 0, 0),
        (1, 0, 64, 0),
        (1, 0, 0, 64),
        (1, 21, 21, 22),
    ] {
        assert!(valid(4096, &header(counts.0, counts.1, counts.2, counts.3)));
    }
    for counts in [
        (2, 0, 0, 0),
        (65535, 0, 0, 0),
        (1, 65, 0, 0),
        (1, 21, 22, 22),
    ] {
        assert!(!valid(
            4096,
            &header(counts.0, counts.1, counts.2, counts.3)
        ));
    }
}

#[test]
fn wire_dns_profile_widens_before_summing_counts() {
    for counts in [(65535, 1, 0), (65535, 65535, 2), (65535, 65535, 65535)] {
        assert!(!valid(4096, &header(1, counts.0, counts.1, counts.2)));
    }
}

#[test]
fn wire_dns_profile_rejects_every_truncated_header() {
    for length in 0..12 {
        assert!(!valid(12, &[0; 12][..length]));
    }
    // Flag interpretation remains upstream's policy, not an invented opcode allowlist.
    let mut bytes = header(1, 0, 0, 0);
    bytes[2] = 0x82;
    assert!(valid(12, &bytes), "TC fallback must survive the envelope");
}
