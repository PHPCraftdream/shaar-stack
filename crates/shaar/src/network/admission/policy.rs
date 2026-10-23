use std::net::{IpAddr, SocketAddr};

use iroh_base::PublicKey;

use super::NetworkError;

/// Immutable allowlist. At most 256 input entries, including duplicates.
/// Construction costs O(n log n); each authenticated lookup costs O(log n).
#[derive(Debug, Default)]
pub struct Allowlist {
    keys: Box<[PublicKey]>,
}

impl Allowlist {
    pub fn new(keys: &[PublicKey]) -> Result<Self, NetworkError> {
        if keys.len() > 256 {
            return Err(NetworkError::AllowlistTooLarge);
        }
        let mut keys = keys.to_vec();
        keys.sort_unstable();
        keys.dedup();
        Ok(Self {
            keys: keys.into_boxed_slice(),
        })
    }

    pub(crate) fn contains(&self, key: &PublicKey) -> bool {
        self.keys.binary_search(key).is_ok()
    }
}

/// Cap shared by pending outbound handshakes, accepted handshakes and live handles.
/// Closed handles retain their slot until dropped; protocol drain has a separate cap.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub(crate) sessions: usize,
}

impl Limits {
    pub fn new(sessions: usize) -> Result<Self, NetworkError> {
        if !(1..=32).contains(&sessions) {
            return Err(NetworkError::InvalidLimits);
        }
        Ok(Self { sessions })
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self { sessions: 32 }
    }
}

pub(crate) fn native_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(_) => true,
        // Conservative denial only, never custom-transport authorization.
        IpAddr::V6(ip) => ip.octets()[..6] != [0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b],
    }
}

pub(crate) fn dial_address(address: SocketAddr) -> bool {
    let ip = address.ip().to_canonical();
    address.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        && native_ip(ip)
}
