use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::io::{AsyncRead, AsyncWrite};
use hickory_resolver::net::runtime::{
    DnsTcpStream, DnsUdpSocket, TokioTime, iocompat::AsyncIoTokioAsStd,
};
use tokio::net::{TcpStream, UdpSocket};

use super::lifetime::Gate;

/// Private socket capabilities are polled only inside Gate::during owned futures.
pub(super) struct Udp {
    pub(super) socket: UdpSocket,
    pub(super) server: SocketAddr,
    pub(super) gate: Gate,
    #[cfg(test)]
    pub(super) observed: Option<tokio::sync::mpsc::Sender<super::runtime::UdpObservation>>,
    // Declared after the socket: losing the last witness means socket Drop already ran.
    #[cfg(test)]
    pub(super) witness: Option<std::sync::Arc<()>>,
}

impl DnsUdpSocket for Udp {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.gate.check()?;
        super::wire::receive(cx, buffer, self.server, |cx, bytes| {
            let mut buffer = tokio::io::ReadBuf::new(bytes);
            self.socket
                .poll_recv_from(cx, &mut buffer)
                .map_ok(|peer| (buffer.filled().len(), peer))
        })
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.gate.check()?;
        if target != self.server {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS UDP target differs from configured endpoint",
            )));
        }
        let sent = std::task::ready!(self.socket.poll_send_to(cx, buffer, target))?;
        #[cfg(test)]
        if let (Some(observed), Some(live)) = (&self.observed, &self.witness) {
            // Passive post-send evidence binds query identity to this exact socket generation.
            let message =
                hickory_resolver::proto::op::Message::from_vec(buffer).map_err(io::Error::other)?;
            let query = message
                .queries
                .first()
                .ok_or_else(|| io::Error::other("UDP witness has no query"))?;
            observed
                .try_send(super::runtime::UdpObservation {
                    local: self.socket.local_addr()?,
                    name: query.name.to_ascii(),
                    id: message.metadata.id,
                    live: std::sync::Arc::downgrade(live),
                })
                .map_err(io::Error::other)?;
        }
        Poll::Ready(Ok(sent))
    }
}

pub(super) struct Tcp {
    pub(super) stream: AsyncIoTokioAsStd<TcpStream>,
    pub(super) input: super::wire::Input,
    pub(super) gate: Gate,
}

impl DnsTcpStream for Tcp {
    type Time = TokioTime;
}

impl AsyncRead for Tcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.gate.check()?;
        let this = &mut *self;
        this.input.poll_read(&mut this.stream, cx, buffer)
    }
}

impl AsyncWrite for Tcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.gate.check()?;
        Pin::new(&mut self.stream).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.gate.check()?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.gate.check()?;
        Pin::new(&mut self.stream).poll_close(cx)
    }
}
