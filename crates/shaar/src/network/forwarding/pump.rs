use iroh::endpoint::{RecvStream, SendStream, VarInt};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use super::ForwardError;

/// Bytes relative to the local TCP side, excluding the one-byte request/status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardStats {
    pub to_peer: u64,
    pub from_peer: u64,
}

pub(super) struct Stream {
    pub send: SendStream,
    pub recv: RecvStream,
    pub finished: bool,
}

impl Stream {
    pub fn new((send, recv): (SendStream, RecvStream)) -> Self {
        Self {
            send,
            recv,
            finished: false,
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.finished {
            let code = VarInt::from_u32(3);
            let _ = self.send.reset(code);
            let _ = self.recv.stop(code);
        }
    }
}

/// cancel-safe: NO — terminal cancellation resets both QUIC directions and drops
/// the owned TCP stream. Partially copied data must never be replayed on this pair.
pub(super) async fn pump(
    mut stream: Stream,
    mut tcp: TcpStream,
) -> Result<ForwardStats, ForwardError> {
    let (mut read, mut write) = tcp.split();
    let (send, recv) = (&mut stream.send, &mut stream.recv);
    let up = async {
        let bytes = tokio::io::copy(&mut read, &mut *send)
            .await
            .map_err(ForwardError::from_io)?;
        send.finish().map_err(|_| ForwardError::StreamReset)?;
        match send.stopped().await {
            Ok(None) => Ok(bytes),
            Ok(Some(_)) => Err(ForwardError::StreamReset),
            Err(_) => Err(ForwardError::PathUnavailable),
        }
    };
    let down = async {
        let bytes = tokio::io::copy(&mut *recv, &mut write)
            .await
            .map_err(ForwardError::from_io)?;
        write.shutdown().await.map_err(ForwardError::from_io)?;
        Ok(bytes)
    };
    let (to_peer, from_peer) = tokio::try_join!(up, down)?;
    stream.finished = true;
    Ok(ForwardStats { to_peer, from_peer })
}
