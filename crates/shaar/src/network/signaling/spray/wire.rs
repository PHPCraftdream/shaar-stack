//! Control messages of the birthday trial. They ride the signaling that already carries the punch
//! offers (the authenticated Yggdrasil bridge or the libp2p carrier link), so the peer of a
//! message is the authenticated link's peer and never a claim of the bytes. The codec is strict:
//! an exact length, known enums, an IPv4 address that the probe policy allows, and planned counts
//! within the caps; anything else decodes to `None` and never panics.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::{MAX_PROBES, MAX_SOCKETS, Role, TOKEN_LEN, Token};
use crate::network::signaling::punch::peer_claimed_probe_allowed;

/// Wire magic: `"spr1"` and version byte 1.
const MAGIC: [u8; 5] = [b's', b'p', b'r', b'1', 1];
/// Kind, epoch, token, role, IPv4 address and port, planned count.
const BODY_LEN: usize = 1 + 4 + TOKEN_LEN + 1 + 4 + 2 + 2;
/// Exact length of every message.
pub(crate) const MESSAGE_LEN: usize = MAGIC.len() + BODY_LEN;
const _: () = assert!(MESSAGE_LEN <= crate::network::signaling::punch::MAX_MESSAGE_BYTES);

/// What the sender says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The initiator proposes a trial: its role, its endpoint (an easy side names its spray
    /// socket's external endpoint, a hard side only its public address with port zero), the
    /// token and the count it plans.
    Offer,
    /// The peer accepts and names its own side the same way.
    Answer,
    /// The sender saw a hit; the address is the peer endpoint it hit.
    Hit,
}

/// One control message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SprayMessage {
    pub kind: Kind,
    pub epoch: u32,
    pub token: Token,
    /// The sender's own role.
    pub role: Role,
    pub address: SocketAddrV4,
    /// Sockets (hard) or probes (easy) the sender plans.
    pub planned: u16,
}

fn address_allowed(message: &SprayMessage) -> bool {
    let probe_port = |port: u16| if port == 0 { 1 } else { port };
    let allowed = peer_claimed_probe_allowed(SocketAddr::new(
        (*message.address.ip()).into(),
        probe_port(message.address.port()),
    ));
    match (message.kind, message.role) {
        // A hard side cannot tell its port; an easy side must.
        (Kind::Offer | Kind::Answer, Role::Hard) => allowed && message.address.port() == 0,
        (Kind::Offer | Kind::Answer, Role::Easy) => allowed && message.address.port() != 0,
        (Kind::Hit, _) => allowed && message.address.port() != 0,
    }
}

fn planned_allowed(message: &SprayMessage) -> bool {
    let cap = match message.role {
        Role::Hard => MAX_SOCKETS,
        Role::Easy => MAX_PROBES,
    };
    usize::from(message.planned) <= cap
}

/// Serializes a message; `None` when its address or count is one the product never uses.
pub(crate) fn encode(message: &SprayMessage) -> Option<Vec<u8>> {
    if !address_allowed(message) || !planned_allowed(message) {
        return None;
    }
    let mut bytes = Vec::with_capacity(MESSAGE_LEN);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(match message.kind {
        Kind::Offer => 1,
        Kind::Answer => 2,
        Kind::Hit => 3,
    });
    bytes.extend_from_slice(&message.epoch.to_le_bytes());
    bytes.extend_from_slice(&message.token);
    bytes.push(match message.role {
        Role::Hard => 1,
        Role::Easy => 2,
    });
    bytes.extend_from_slice(&message.address.ip().octets());
    bytes.extend_from_slice(&message.address.port().to_be_bytes());
    bytes.extend_from_slice(&message.planned.to_le_bytes());
    Some(bytes)
}

/// Parses a message; `None` on any malformed, oversized, hostile or policy-violating input.
pub(crate) fn decode(bytes: &[u8]) -> Option<SprayMessage> {
    if bytes.len() != MESSAGE_LEN || bytes[..MAGIC.len()] != MAGIC {
        return None;
    }
    let body = &bytes[MAGIC.len()..];
    let kind = match body[0] {
        1 => Kind::Offer,
        2 => Kind::Answer,
        3 => Kind::Hit,
        _ => return None,
    };
    let epoch = u32::from_le_bytes(body[1..5].try_into().ok()?);
    let mut token = [0_u8; TOKEN_LEN];
    token.copy_from_slice(&body[5..5 + TOKEN_LEN]);
    let at = 5 + TOKEN_LEN;
    let role = match body[at] {
        1 => Role::Hard,
        2 => Role::Easy,
        _ => return None,
    };
    let ip = Ipv4Addr::new(body[at + 1], body[at + 2], body[at + 3], body[at + 4]);
    let port = u16::from_be_bytes([body[at + 5], body[at + 6]]);
    let planned = u16::from_le_bytes([body[at + 7], body[at + 8]]);
    let message = SprayMessage {
        kind,
        epoch,
        token,
        role,
        address: SocketAddrV4::new(ip, port),
        planned,
    };
    (address_allowed(&message) && planned_allowed(&message)).then_some(message)
}
