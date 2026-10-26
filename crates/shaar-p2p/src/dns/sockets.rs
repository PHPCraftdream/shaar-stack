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
/// Wire/header envelopes are the next unit, not a property of these lifetime wrappers.
pub(super) struct Udp {
    pub(super) socket: UdpSocket,
    pub(super) server: SocketAddr,
    pub(super) gate: Gate,
}

impl DnsUdpSocket for Udp {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.gate.check()?;
        let mut buffer = tokio::io::ReadBuf::new(buffer);
        self.socket
            .poll_recv_from(cx, &mut buffer)
            .map_ok(|peer| (buffer.filled().len(), peer))
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
        self.socket.poll_send_to(cx, buffer, target)
    }
}

pub(super) struct Tcp {
    pub(super) stream: AsyncIoTokioAsStd<TcpStream>,
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
        Pin::new(&mut self.stream).poll_read(cx, buffer)
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
