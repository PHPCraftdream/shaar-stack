//! In-process service streams: the application, not a TCP target, is the
//! other end of an admitted QUIC stream.
//!
//! Server side: [`Session::serve_streams`] hands every admitted stream and the
//! authenticated peer key to a handler. Client side: [`Session::open_stream`]
//! opens one stream after the same one-byte request/status exchange that
//! `forward` uses, so the wire protocol `shaar/tcp/1` is unchanged.

use std::{
    future::Future,
    io,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::FutureExt;
use iroh_base::PublicKey;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use super::{ForwardError, ForwardStats, ServeReport, protocol, pump::Stream};
use crate::network::Session;

/// One bidirectional byte stream to the service.
///
/// Reads end with end-of-file when the other side finishes its direction;
/// `shutdown` (or `AsyncWriteExt::shutdown`) finishes ours and keeps the
/// already written bytes deliverable. Dropping a stream that was not shut
/// down resets it: unsent bytes are discarded and the peer sees a reset.
pub struct ServiceStream {
    inner: Inner,
}

enum Inner {
    Quic(Stream),
    /// Loopback hop of the client facade (`shaar::Client::connect`).
    Tcp(TcpStream),
}

impl ServiceStream {
    pub(super) fn from_quic(stream: Stream) -> Self {
        Self {
            inner: Inner::Quic(stream),
        }
    }

    pub(crate) fn from_tcp(stream: TcpStream) -> Self {
        Self {
            inner: Inner::Tcp(stream),
        }
    }
}

impl std::fmt::Debug for ServiceStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceStream").finish_non_exhaustive()
    }
}

impl AsyncRead for ServiceStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Inner::Quic(stream) => AsyncRead::poll_read(Pin::new(&mut stream.recv), cx, buf),
            Inner::Tcp(stream) => AsyncRead::poll_read(Pin::new(stream), cx, buf),
        }
    }
}

impl AsyncWrite for ServiceStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            Inner::Quic(stream) => AsyncWrite::poll_write(Pin::new(&mut stream.send), cx, buf),
            Inner::Tcp(stream) => AsyncWrite::poll_write(Pin::new(stream), cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Inner::Quic(stream) => AsyncWrite::poll_flush(Pin::new(&mut stream.send), cx),
            Inner::Tcp(stream) => AsyncWrite::poll_flush(Pin::new(stream), cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Inner::Quic(stream) => {
                let result = AsyncWrite::poll_shutdown(Pin::new(&mut stream.send), cx);
                // A finished send side must not be reset when the handle is dropped.
                if matches!(result, Poll::Ready(Ok(()))) {
                    stream.finished = true;
                }
                result
            }
            Inner::Tcp(stream) => AsyncWrite::poll_shutdown(Pin::new(stream), cx),
        }
    }
}

impl Session {
    /// Opens one service stream after the request/status exchange; the Server
    /// must serve this session with [`Session::serve_streams`] or `serve`.
    /// At most 16 streams may be in setup at once (`ForwardError::Capacity`
    /// otherwise, no queue); the transport caps open streams at 16 as well.
    /// cancel-safe: NO — cancellation resets the QUIC stream being set up.
    pub async fn open_stream(&self) -> Result<ServiceStream, ForwardError> {
        let permit = self
            .streams
            .try_acquire()
            .map_err(|_| ForwardError::Capacity)?;
        // The permit bounds concurrent streams; a returned stream outlives
        // this call, so the bound covers the setup only, like `forward`.
        let result = protocol::open(&self.connection).await;
        drop(permit);
        match result {
            Ok(stream) => Ok(ServiceStream::from_quic(stream)),
            Err(error) => Err(match self.connection.close_reason() {
                Some(reason) => ForwardError::from_connection_error(reason),
                None => error,
            }),
        }
    }

    /// Serves every admitted stream of this session to `handler`, with the
    /// authenticated peer key. At most 16 handlers run at once; a panicking
    /// handler is counted in `failed` and never ends the session. `stop`
    /// closes the QUIC session, aborts the running handlers and joins them.
    /// The report's byte counters stay zero: the handler owns the bytes.
    /// cancel-safe: NO — see [`Session::serve`].
    pub async fn serve_streams<H, F>(
        &mut self,
        handler: H,
        stop: impl Future<Output = ()>,
    ) -> Result<ServeReport, ForwardError>
    where
        H: Fn(PublicKey, ServiceStream) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let peer = self.peer_id();
        let handler = Arc::new(handler);
        self.serve_loop(stop, move |tasks, pair| {
            let handler = Arc::clone(&handler);
            tasks.spawn(async move {
                let mut stream = Stream::new(pair);
                protocol::admit(&mut stream).await?;
                let service = ServiceStream::from_quic(stream);
                AssertUnwindSafe(async move { handler(peer, service).await })
                    .catch_unwind()
                    .await
                    .map_err(|_| ForwardError::TaskFailure)?;
                Ok(ForwardStats {
                    to_peer: 0,
                    from_peer: 0,
                })
            });
        })
        .await
    }
}
