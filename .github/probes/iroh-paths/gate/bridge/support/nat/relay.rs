#![forbid(unsafe_code)]
//! Disposable CI relay: two address slots and bounded opaque ciphertext observations.

use super::protocol::{self, FRAME_MAX, Kind, Nonce};
use std::{io, net::SocketAddr, time::Duration};
use tokio::net::UdpSocket;

pub type Captures = [Vec<Vec<u8>>; 2];
const CAPTURE_CAP: usize = 256;
const MESSAGE_CAP: usize = 4096;

pub struct Relay {
    socket: UdpSocket,
    nonce: Nonce,
    peers: [Option<SocketAddr>; 2],
    captures: Captures,
}

impl Relay {
    pub async fn bind(address: SocketAddr, nonce: Nonce) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(address).await?,
            nonce,
            peers: [None, None],
            captures: Default::default(),
        })
    }
    pub fn addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// cancel-safe: NO — deadline terminates the entire relay and closes its owned socket.
    pub async fn run(self) -> io::Result<(Captures, [Option<SocketAddr>; 2])> {
        tokio::time::timeout(Duration::from_secs(120), self.run_inner())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay lifetime deadline"))?
    }

    async fn run_inner(mut self) -> io::Result<(Captures, [Option<SocketAddr>; 2])> {
        let mut input = [0; FRAME_MAX + 1];
        let mut output = [0; FRAME_MAX];
        let mut icmp_errors = 0;
        for _ in 0..MESSAGE_CAP {
            let (length, source) = match self.socket.recv_from(&mut input).await {
                Ok(received) => received,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    icmp_errors += 1;
                    eprintln!("relay: closing-peer ICMP {:?}", error.kind());
                    if icmp_errors > 16 {
                        return Err(error);
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            let frame = protocol::decode(&input[..length], &self.nonce)?;
            match frame.kind {
                Kind::Register => {
                    let side = usize::from(frame.side);
                    if self.peers[side].is_some_and(|registered| registered != source) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "fixture side address changed",
                        ));
                    }
                    self.peers[side] = Some(source);
                    if self.peers.iter().all(Option::is_some) {
                        for (side, peer) in self.peers.iter().enumerate() {
                            let side = u8::try_from(side).expect("two fixture peers");
                            let ready =
                                protocol::encode(&mut output, &self.nonce, Kind::Ready, side, &[])?;
                            if self
                                .socket
                                .send_to(ready, peer.expect("both registered"))
                                .await?
                                != ready.len()
                            {
                                return Err(io::Error::other("partial relay readiness"));
                            }
                        }
                    }
                }
                Kind::Data => {
                    let side = usize::from(frame.side);
                    if self.peers[side] != Some(source) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "unregistered relay source",
                        ));
                    }
                    let destination = self.peers[1 - side].ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, "other fixture peer missing")
                    })?;
                    if self.captures[side].len() == CAPTURE_CAP {
                        return Err(io::Error::other("relay capture limit"));
                    }
                    self.captures[side].push(frame.payload.to_vec());
                    if self.socket.send_to(&input[..length], destination).await? != length {
                        return Err(io::Error::other("partial relay datagram"));
                    }
                }
                Kind::Stop => {
                    if self.peers.iter().any(Option::is_none) {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "relay stopped before both peers registered",
                        ));
                    }
                    return Ok((self.captures, self.peers));
                }
                Kind::Ready => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "client sent relay readiness",
                    ));
                }
            }
        }
        Err(io::Error::other("relay message limit"))
    }
}

/// Public run marker only; caller must own the disposable relay and its lifecycle.
pub async fn stop(address: SocketAddr, nonce: Nonce) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut output = [0; FRAME_MAX];
    let bytes = protocol::encode(&mut output, &nonce, Kind::Stop, 255, &[])?;
    if socket.send_to(bytes, address).await? != bytes.len() {
        return Err(io::Error::other("partial relay stop"));
    }
    Ok(())
}
