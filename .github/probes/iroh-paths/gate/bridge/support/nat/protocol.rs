#![forbid(unsafe_code)]
//! Public per-run correlation envelope, not authentication; QUIC/TLS authenticates peers.

use std::io;

pub const PAYLOAD_MAX: usize = 1500;
pub const HEADER: usize = 38;
pub const FRAME_MAX: usize = HEADER + PAYLOAD_MAX;
pub type Nonce = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Register,
    Ready,
    Data,
    Stop,
}

pub struct Frame<'a> {
    pub kind: Kind,
    pub side: u8,
    pub payload: &'a [u8],
}

pub fn nonce(text: &str) -> io::Result<Nonce> {
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nonce must be 32 public hex bytes",
        ));
    }
    text.as_bytes().try_into().map_err(io::Error::other)
}

fn valid_fields(kind: Kind, side: u8, length: usize) -> bool {
    match kind {
        Kind::Data => side < 2 && (1..=PAYLOAD_MAX).contains(&length),
        Kind::Register | Kind::Ready => side < 2 && length == 0,
        Kind::Stop => side == 255 && length == 0,
    }
}

/// Returned slice borrows the supplied output buffer, never the payload or nonce.
pub fn encode<'a>(
    output: &'a mut [u8; FRAME_MAX],
    nonce: &Nonce,
    kind: Kind,
    side: u8,
    payload: &[u8],
) -> io::Result<&'a [u8]> {
    if !valid_fields(kind, side, payload.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid fixture envelope shape",
        ));
    }
    output[..4].copy_from_slice(b"SN54");
    output[4] = match kind {
        Kind::Register => 0,
        Kind::Ready => 1,
        Kind::Data => 2,
        Kind::Stop => 3,
    };
    output[5] = side;
    output[6..HEADER].copy_from_slice(nonce);
    output[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    Ok(&output[..HEADER + payload.len()])
}

/// Frame payload is an intentional borrowed view of the validated input.
pub fn decode<'a>(bytes: &'a [u8], nonce: &Nonce) -> io::Result<Frame<'a>> {
    if bytes.len() < HEADER
        || bytes.len() > FRAME_MAX
        || &bytes[..4] != b"SN54"
        || &bytes[6..HEADER] != nonce
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture envelope",
        ));
    }
    let kind = match bytes[4] {
        0 => Kind::Register,
        1 => Kind::Ready,
        2 => Kind::Data,
        3 => Kind::Stop,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown fixture envelope kind",
            ));
        }
    };
    let side = bytes[5];
    let payload = &bytes[HEADER..];
    if !valid_fields(kind, side, payload.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture envelope fields",
        ));
    }
    Ok(Frame {
        kind,
        side,
        payload,
    })
}
