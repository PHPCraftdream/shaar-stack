use std::net::IpAddr;

/// Fixed conservative profile; see discovery/address-scope.md for snapshot provenance.
pub(super) fn discovery_ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !matches!(
            ip.octets(),
            [0 | 10 | 127, _, _, _]
                | [100, 64..=127, _, _]
                | [169, 254, _, _]
                | [172, 16..=31, _, _]
                | [192, 0, 0 | 2, _]
                | [192, 31, 196, _]
                | [192, 52, 193, _]
                | [192, 88, 99, _]
                | [192, 168, _, _]
                | [192, 175, 48, _]
                | [198, 18 | 19, _, _]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
                | [224..=255, _, _, _]
        ),
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            (0x2000..=0x3fff).contains(&segments[0])
                && !matches!(
                    segments,
                    [0x2001, 0..=0x01ff | 0x0db8, _, _, _, _, _, _]
                        | [0x2002, _, _, _, _, _, _, _]
                        | [0x2620, 0x004f, 0x8000, _, _, _, _, _]
                        | [0x3fff, 0..=0x0fff, _, _, _, _, _, _]
                )
        }
    }
}
