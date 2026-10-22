#![forbid(unsafe_code)]
//! Owned loopback UDP forwarder: observations come from the OS receive boundary.

use std::{io, net::SocketAddr};
use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle};

type Captures = [Vec<Vec<u8>>; 2];
const CAP: usize = 256;
const MAX_DATAGRAM: usize = 65535;

pub struct UdpCapture {
    pub addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<Captures>>>,
}

fn record(
    captures: &mut Captures,
    peers: &[SocketAddr; 2],
    source: SocketAddr,
    bytes: &[u8],
) -> io::Result<usize> {
    let side = peers
        .iter()
        .position(|peer| *peer == source)
        .ok_or_else(|| io::Error::other("unexpected UDP capture source"))?;
    if captures[side].len() == CAP {
        return Err(io::Error::other("UDP capture limit"));
    }
    captures[side].push(bytes.to_vec());
    Ok(side)
}

impl UdpCapture {
    /// cancel-safe: yes — no spawned task exists before the only bind await completes.
    pub async fn bind(peers: [SocketAddr; 2]) -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut captures: Captures = Default::default();
            let mut buffer = vec![0; MAX_DATAGRAM];
            loop {
                let received = tokio::select! {
                    _ = &mut stopped => break,
                    received = socket.recv_from(&mut buffer) => received,
                }?;
                let (length, source) = received;
                let side = record(&mut captures, &peers, source, &buffer[..length])?;
                let sent = socket.send_to(&buffer[..length], peers[1 - side]).await?;
                if sent != length {
                    return Err(io::Error::other("partial UDP forward"));
                }
            }
            // Endpoint close has joined both send drivers. Drain already queued OS datagrams.
            loop {
                match socket.try_recv_from(&mut buffer) {
                    Ok((length, source)) => {
                        record(&mut captures, &peers, source, &buffer[..length])?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            Ok(captures)
        });
        Ok(Self {
            addr,
            stop: Some(stop),
            task: Some(task),
        })
    }

    /// cancel-safe: NO — fixture termination aborts the owned task; finish is not retried.
    pub async fn finish(mut self) -> io::Result<Captures> {
        if let Some(stop) = self.stop.take() {
            // A stopped/erroring receiver is diagnosed by awaiting the retained task below.
            let _ = stop.send(());
        }
        self.task
            .as_mut()
            .expect("owned capture task")
            .await
            .map_err(io::Error::other)?
    }
}

impl Drop for UdpCapture {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_rejects_unknown_sources_and_overflow() {
        let peers = [
            "127.0.0.1:10".parse().unwrap(),
            "127.0.0.1:11".parse().unwrap(),
        ];
        let mut captures = Default::default();
        assert!(record(&mut captures, &peers, "127.0.0.1:12".parse().unwrap(), b"x").is_err());
        for _ in 0..CAP {
            record(&mut captures, &peers, peers[0], b"x").unwrap();
        }
        assert!(record(&mut captures, &peers, peers[0], b"x").is_err());
        assert_eq!(captures[0].len(), CAP);
        assert!(captures[1].is_empty());
    }

    #[tokio::test]
    async fn real_socket_forwarding_preserves_datagrams_and_direction() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy = UdpCapture::bind([a.local_addr().unwrap(), b.local_addr().unwrap()])
            .await
            .unwrap();
        let mut bytes = [0; 16];
        for message in [b"".as_slice(), b"positive".as_slice()] {
            a.send_to(message, proxy.addr).await.unwrap();
            let (length, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), b.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&bytes[..length], message);
            b.send_to(message, proxy.addr).await.unwrap();
            let (length, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), a.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&bytes[..length], message);
        }
        let captures = proxy.finish().await.unwrap();
        assert_eq!(captures[0], vec![Vec::<u8>::new(), b"positive".to_vec()]);
        assert_eq!(captures[1], captures[0]);
    }
}
