use std::{net::SocketAddr, time::Duration};

use iroh::endpoint::Connection;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::{ForwardError, pump::Stream};

const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const OPEN: u8 = 1;
const READY: u8 = 0;
const TARGET_FAILED: u8 = 1;
const BAD_REQUEST: u8 = 2;

/// cancel-safe: NO — any allocated stream is reset by its ownership guard.
pub(super) async fn open(connection: &Connection) -> Result<Stream, ForwardError> {
    tokio::time::timeout(SETUP_TIMEOUT, async {
        let pair = connection
            .open_bi()
            .await
            .map_err(|_| ForwardError::PathUnavailable)?;
        let mut stream = Stream::new(pair);
        AsyncWriteExt::write_all(&mut stream.send, &[OPEN])
            .await
            .map_err(ForwardError::from_io)?;
        let mut status = [0];
        AsyncReadExt::read_exact(&mut stream.recv, &mut status)
            .await
            .map_err(ForwardError::from_io)?;
        match status[0] {
            READY => Ok(stream),
            TARGET_FAILED => Err(ForwardError::TargetUnavailable),
            _ => Err(ForwardError::Protocol),
        }
    })
    .await
    .map_err(|_| ForwardError::Deadline)?
}

/// cancel-safe: NO — consumed request bytes are not replayed; the caller owns
/// and resets this stream on timeout/cancellation. The target is never peer supplied.
pub(super) async fn target(
    stream: &mut Stream,
    target: SocketAddr,
) -> Result<TcpStream, ForwardError> {
    tokio::time::timeout(SETUP_TIMEOUT, async {
        let mut request = [0];
        AsyncReadExt::read_exact(&mut stream.recv, &mut request)
            .await
            .map_err(ForwardError::from_io)?;
        if request != [OPEN] {
            reject(stream, BAD_REQUEST).await?;
            return Err(ForwardError::Protocol);
        }
        let tcp = match TcpStream::connect(target).await {
            Ok(tcp) => tcp,
            Err(_) => {
                reject(stream, TARGET_FAILED).await?;
                return Err(ForwardError::TargetUnavailable);
            }
        };
        AsyncWriteExt::write_all(&mut stream.send, &[READY])
            .await
            .map_err(ForwardError::from_io)?;
        Ok(tcp)
    })
    .await
    .map_err(|_| ForwardError::Deadline)?
}

/// cancel-safe: NO — a partial status write is terminal, never replayed.
async fn reject(stream: &mut Stream, status: u8) -> Result<(), ForwardError> {
    AsyncWriteExt::write_all(&mut stream.send, &[status])
        .await
        .map_err(ForwardError::from_io)?;
    stream
        .send
        .finish()
        .map_err(|_| ForwardError::StreamReset)?;
    // Preserve queued status/FIN; the ordinary receive-stream drop stops extra input.
    stream.finished = true;
    Ok(())
}
