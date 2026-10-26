//! Private input envelope; output serialization remains Hickory's responsibility.

mod tcp;
mod udp;
pub(super) use tcp::Input;
pub(super) use udp::receive;

use hickory_resolver::proto::{
    op::Header,
    serialize::binary::{BinDecodable, BinDecoder},
};

const HEADER: usize = 12;
const MAX: usize = 4096;

fn valid(length: usize, bytes: &[u8]) -> bool {
    if !(HEADER..=MAX).contains(&length) {
        return false;
    }
    let Ok(header) = Header::read(&mut BinDecoder::new(bytes)) else {
        return false;
    };
    let counts = header.counts;
    counts.queries <= 1
        && u32::from(counts.answers) + u32::from(counts.authorities) + u32::from(counts.additionals)
            <= 64
}

#[cfg(test)]
mod native_tests;
#[cfg(test)]
mod profile_tests;
#[cfg(test)]
mod tcp_tests;
#[cfg(test)]
mod udp_tests;
