use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use hickory_resolver::net::runtime::{
    RuntimeProvider, Spawn, TokioTime, iocompat::AsyncIoTokioAsStd,
};
use libp2p_swarm::Executor;
use tokio::net::{TcpSocket, UdpSocket};

use super::{
    lifetime::Gate,
    sockets::{Tcp, Udp},
};
use crate::ExecutorHandle;

#[derive(Clone)]
pub(super) struct Provider {
    pub(super) gate: Gate,
    executor: ExecutorHandle,
    nameservers: Arc<[SocketAddr]>,
    #[cfg(test)]
    pub(super) pause_connect: Option<ConnectPause>,
    #[cfg(test)]
    pub(super) udp_bound: Option<tokio::sync::mpsc::Sender<UdpObservation>>,
}

#[cfg(test)]
#[derive(Debug)]
pub(super) struct UdpObservation {
    pub(super) local: SocketAddr,
    pub(super) name: String,
    pub(super) id: u16,
    pub(super) live: std::sync::Weak<()>,
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct ConnectPause {
    pub(super) started: tokio::sync::mpsc::Sender<SocketAddr>,
    pub(super) released: tokio::sync::watch::Receiver<bool>,
}

impl Provider {
    pub(super) fn new(gate: Gate, executor: ExecutorHandle, nameservers: &[SocketAddr]) -> Self {
        Self {
            gate,
            executor,
            nameservers: nameservers.into(),
            #[cfg(test)]
            pause_connect: None,
            #[cfg(test)]
            udp_bound: None,
        }
    }

    fn endpoint(&self, server: SocketAddr) -> io::Result<()> {
        self.gate.check()?;
        if self.nameservers.contains(&server) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS endpoint is not configured",
            ))
        }
    }
}

#[derive(Clone)]
pub(super) struct Handle {
    gate: Gate,
    executor: ExecutorHandle,
}

impl Spawn for Handle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        if self.gate.check().is_err() {
            return; // The rejected future is destroyed without any gate/executor guard.
        }
        let gate = self.gate.clone();
        // Exactly the Swarm executor's handle; no TokioHandle, JoinSet or detached root.
        self.executor.exec(Box::pin(async move {
            let _ = gate.during(future).await; // Close is cancellation, not lookup success.
        }));
    }
}

impl RuntimeProvider for Provider {
    type Handle = Handle;
    type Timer = TokioTime;
    type Udp = Udp;
    type Tcp = Tcp;

    fn create_handle(&self) -> Self::Handle {
        Handle {
            gate: self.gate.clone(),
            executor: self.executor.clone(),
        }
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Tcp>> + Send>> {
        let provider = self.clone();
        Box::pin(async move {
            provider.endpoint(server)?;
            provider
                .gate
                .during(async {
                    let socket = match server {
                        SocketAddr::V4(_) => TcpSocket::new_v4(),
                        SocketAddr::V6(_) => TcpSocket::new_v6(),
                    }?;
                    if let Some(bind) = bind {
                        provider.gate.check()?;
                        socket.bind(bind)?;
                    }
                    socket.set_nodelay(true)?;
                    provider.gate.check()?;
                    #[cfg(test)]
                    let local = provider
                        .pause_connect
                        .as_ref()
                        .map(|_| socket.local_addr())
                        .transpose()?;
                    let connect = socket.connect(server);
                    #[cfg(test)]
                    if let (Some(pause), Some(local)) = (&provider.pause_connect, local) {
                        // The real connect future owns the native socket while the barrier is held.
                        pause.started.send(local).await.map_err(io::Error::other)?;
                        let mut released = pause.released.clone();
                        released
                            .wait_for(|ready| *ready)
                            .await
                            .map_err(io::Error::other)?;
                    }
                    let stream =
                        tokio::time::timeout(timeout.unwrap_or(Duration::from_secs(5)), connect)
                            .await
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::TimedOut, "DNS TCP connect deadline")
                            })??;
                    provider.gate.check()?;
                    Ok(Tcp {
                        stream: AsyncIoTokioAsStd(stream),
                        gate: provider.gate.clone(),
                    })
                })
                .await?
        })
    }

    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Udp>> + Send>> {
        let provider = self.clone();
        Box::pin(async move {
            provider.endpoint(server)?;
            provider
                .gate
                .during(async {
                    let socket = UdpSocket::bind(local).await?;
                    provider.gate.check()?;
                    #[cfg(test)]
                    let witness = provider.udp_bound.as_ref().map(|_| Arc::new(()));
                    Ok(Udp {
                        socket,
                        server,
                        gate: provider.gate.clone(),
                        #[cfg(test)]
                        observed: provider.udp_bound.clone(),
                        #[cfg(test)]
                        witness,
                    })
                })
                .await?
        })
    }
    // The trait default quic_binder is None; this provider has only UDP/TCP capabilities.
}
