//! The fixed set of ports that the products prefer, and the order in which one client uses it
//! (leaf PORT-1).
//!
//! A device that can ask its router for a port mapping binds its QUIC socket on a free port of the
//! set and asks for the same external port, so the endpoint it publishes is known in advance. The
//! set is the same in every product, so a peer that knows no better address can probe it. The
//! order depends on the public key of the client: two clients behind one router do not contend for
//! the same first port, and the Server, which knows the key of the client, tries the ports in the
//! same order without any message.

use sha2::{Digest, Sha256};

/// How many ports the set holds.
pub const PORT_COUNT: usize = 100;

/// First port of the range the set was drawn from.
pub const RANGE_START: u16 = 30_000;

/// The set, ascending. It was drawn once, uniformly at random, from 30000 to 65535 and cleared of
/// ports of well-known services, of multiples of 1000 and of ports made of one repeated digit.
/// Changing it changes the order of every client, so it is a constant that all products share.
pub const PORTS: [u16; PORT_COUNT] = [
    30061, 30742, 30935, 30983, 31063, 31864, 32143, 32465, 32717, 32803, 33148, 33193, 34135,
    34189, 35790, 36238, 36386, 36410, 36585, 37328, 38006, 38036, 38206, 38517, 38693, 40204,
    40553, 40768, 40770, 41061, 41354, 41647, 41838, 43083, 43870, 44309, 44482, 44582, 44640,
    44863, 45106, 45579, 45809, 46449, 46524, 46666, 46735, 47051, 47143, 47569, 47880, 47950,
    48055, 48254, 48378, 48896, 49133, 49787, 50668, 51432, 51621, 52013, 52213, 53126, 53928,
    54226, 54684, 54867, 55030, 55069, 55216, 55442, 55612, 55722, 55745, 56058, 56594, 56885,
    57276, 57325, 57780, 58112, 59564, 59642, 59860, 61769, 61964, 62320, 62459, 62601, 62721,
    62785, 63196, 63414, 63736, 63737, 63953, 64125, 64207, 65113,
];

/// Domain tag of the hash that orders the set.
const ORDER_DOMAIN: &[u8] = b"shaar-port-order/1";

/// The set in the order that the client with this public key uses it: ascending by
/// `SHA-256("shaar-port-order/1" || client key || port as two big-endian bytes)`.
#[must_use]
pub fn order(client_key: &[u8; 32]) -> [u16; PORT_COUNT] {
    let mut ranked = PORTS.map(|port| (rank(client_key, port), port));
    ranked.sort_unstable();
    ranked.map(|(_, port)| port)
}

fn rank(client_key: &[u8; 32], port: u16) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ORDER_DOMAIN);
    hasher.update(client_key);
    hasher.update(port.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests;
