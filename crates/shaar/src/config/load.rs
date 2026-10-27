//! Bounded asynchronous configuration file loading.
//!
//! Loading never buffers more than [`MAX_CONFIG_BYTES`] plus one byte:
//! the reader is wrapped in [`tokio::io::AsyncReadExt::take`] BEFORE
//! any read is issued, so the read requests themselves are bounded —
//! an oversized file is rejected without its tail ever being pulled
//! through the reader. The text is validated as UTF-8 before parsing.
//! The pure [`ClientConfig::from_text`](super::ClientConfig::from_text)
//! and [`ServerConfig::from_text`](super::ServerConfig::from_text)
//! enforce the same byte bound on their `text` argument before
//! invoking the parser, so the pure API cannot bypass the limit.
//!
//! Cancellation: cancelling the returned future before the read
//! starts abandons the file cleanly, but an already-started OS read
//! is not interrupted; the partial buffer is simply dropped. The
//! filesystem is trusted for metadata only — a file may change
//! between load and use; this layer performs no writes and no
//! locking.
//!
//! The byte limit bounds input buffering, not every parser resource.
//! ktav 0.8.0 uses an iterative document parser and caps inline compound
//! recursion at 128. These facts alone do not establish a depth bound
//! for deserialization or destruction of every document shape.

use std::path::Path;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::MAX_CONFIG_BYTES;
use super::client::{ClientConfig, ClientEndpointOverrides, ClientOverrides};
use super::error::{ConfigError, LoadKind};
use super::server::{ServerConfig, ServerEndpointOverrides, ServerOverrides};

/// Load and validate a server configuration file, applying legacy overrides.
pub async fn load_server(
    path: impl AsRef<Path>,
    over: &ServerOverrides,
) -> Result<ServerConfig, ConfigError> {
    let path = path.as_ref();
    let file = open(path).await?;
    let text = read_bounded(file)
        .await
        .map_err(|kind| ConfigError::loading(path.to_path_buf(), kind))?;
    ServerConfig::from_text(&text, over)
}

/// Load and validate a server configuration file with endpoint overrides.
pub async fn load_server_with_endpoint_overrides(
    path: impl AsRef<Path>,
    over: &ServerOverrides,
    endpoint_overrides: &ServerEndpointOverrides,
) -> Result<ServerConfig, ConfigError> {
    let path = path.as_ref();
    let file = open(path).await?;
    let text = read_bounded(file)
        .await
        .map_err(|kind| ConfigError::loading(path.to_path_buf(), kind))?;
    ServerConfig::from_text_with_endpoint_overrides(&text, over, endpoint_overrides)
}

/// Load and validate a client configuration file, applying overrides.
pub async fn load_client(
    path: impl AsRef<Path>,
    over: &ClientOverrides,
) -> Result<ClientConfig, ConfigError> {
    let path = path.as_ref();
    let file = open(path).await?;
    let text = read_bounded(file)
        .await
        .map_err(|kind| ConfigError::loading(path.to_path_buf(), kind))?;
    ClientConfig::from_text(&text, over)
}

/// Load and validate a client configuration file with endpoint overrides.
pub async fn load_client_with_endpoint_overrides(
    path: impl AsRef<Path>,
    over: &ClientOverrides,
    endpoint_overrides: &ClientEndpointOverrides,
) -> Result<ClientConfig, ConfigError> {
    let path = path.as_ref();
    let file = open(path).await?;
    let text = read_bounded(file)
        .await
        .map_err(|kind| ConfigError::loading(path.to_path_buf(), kind))?;
    ClientConfig::from_text_with_endpoint_overrides(&text, over, endpoint_overrides)
}

async fn open(path: &Path) -> Result<tokio::fs::File, ConfigError> {
    tokio::fs::File::open(path)
        .await
        .map_err(|_| ConfigError::loading(path.to_path_buf(), LoadKind::Io))
}

/// Private generic bounded reader: reads at most `MAX_CONFIG_BYTES`
/// plus one byte by wrapping the source in `take(...)` before any
/// read request is issued, so no read ever returns more than one byte
/// past the accepted bound and no larger input is consumed further.
async fn read_bounded<R: AsyncRead + Unpin>(reader: R) -> Result<String, LoadKind> {
    let mut buf = Vec::new();
    reader
        .take((MAX_CONFIG_BYTES as u64) + 1)
        .read_to_end(&mut buf)
        .await
        .map_err(|_| LoadKind::Io)?;
    if buf.len() > MAX_CONFIG_BYTES {
        return Err(LoadKind::TooLarge);
    }
    String::from_utf8(buf).map_err(|_| LoadKind::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    /// CI-only counting reader: records exactly how many bytes were
    /// actually handed to the caller across all read requests, so the
    /// tests below assert consumed-byte bounds, not just the error
    /// classification. No unsafe.
    struct CountingReader {
        data: std::io::Cursor<Vec<u8>>,
        consumed: Arc<AtomicUsize>,
    }

    impl CountingReader {
        fn new(data: Vec<u8>) -> (Self, Arc<AtomicUsize>) {
            let consumed = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    data: std::io::Cursor::new(data),
                    consumed: Arc::clone(&consumed),
                },
                consumed,
            )
        }
    }

    impl AsyncRead for CountingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            let pinned = Pin::new(&mut self.data);
            match AsyncRead::poll_read(pinned, cx, buf) {
                Poll::Ready(Ok(())) => {
                    self.consumed
                        .fetch_add(buf.filled().len() - before, Ordering::SeqCst);
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    #[tokio::test]
    async fn exact_bound_is_accepted_and_fully_consumed() {
        let data = vec![b'#'; MAX_CONFIG_BYTES];
        let (reader, consumed) = CountingReader::new(data);
        let text = read_bounded(reader).await.unwrap();
        assert_eq!(text.len(), MAX_CONFIG_BYTES);
        assert_eq!(consumed.load(Ordering::SeqCst), MAX_CONFIG_BYTES);
    }

    #[tokio::test]
    async fn bound_plus_one_is_rejected_with_bounded_consumption() {
        let data = vec![b'#'; MAX_CONFIG_BYTES + 1];
        let (reader, consumed) = CountingReader::new(data);
        let err = read_bounded(reader).await.unwrap_err();
        assert_eq!(err, LoadKind::TooLarge);
        assert!(consumed.load(Ordering::SeqCst) <= MAX_CONFIG_BYTES + 1);
    }

    #[tokio::test]
    async fn oversized_input_consumption_is_capped_at_bound_plus_one() {
        // Far larger than the bound: the take() wrapper must stop the
        // read requests at bound + 1 bytes regardless of input size.
        let data = vec![b'#'; 4 * MAX_CONFIG_BYTES];
        let (reader, consumed) = CountingReader::new(data);
        let err = read_bounded(reader).await.unwrap_err();
        assert_eq!(err, LoadKind::TooLarge);
        assert!(consumed.load(Ordering::SeqCst) <= MAX_CONFIG_BYTES + 1);
    }
}
