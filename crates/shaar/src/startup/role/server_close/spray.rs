//! The birthday trial on the Server side (leaf BDAY-1b, slice 4a-2). The punch responder hands every
//! datagram of its link to [`Spray`] first: a message of the trial is handled here, anything else is
//! left to the punch code as before. When this device is the easy side, an Offer of the allowlisted
//! peer is answered with the endpoint of a fresh spray socket (learned from one DHT ping) and the
//! easy side of the trial runs in a task the responder owns; it is aborted with the responder, so
//! nothing outlives the composition. One trial at a time, one per peer per 600 s.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::network::signaling::punch::{EXCHANGE_BUDGET, PunchLink};
use crate::network::signaling::spray::{
    self, Agreement, Cooldown, Counters, DISCOVER_WINDOW, Kind, Rng, Role, Side,
};

/// What the responder needs from the world, so the cases can stand in for it.
pub(super) trait Ground: Send + 'static {
    /// A spray socket.
    type Port: Send + 'static;

    /// The role this device plays now; `None` while its own walks have not shown it.
    fn role(&self) -> Option<Role>;

    /// A fresh spray socket and the external endpoint it has; `None` when that cannot be learned.
    fn open(&mut self) -> impl Future<Output = Option<(Self::Port, SocketAddrV4)>> + Send;

    /// The easy side of an agreement, to its end, on the socket `open` gave.
    fn run(
        &self,
        agreement: Agreement,
        port: Self::Port,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

/// The real world: the role from the DHT votes, the endpoint from the DHT hosts the process was
/// configured with, the trial over a UDP socket, one operator line per step.
pub(super) struct Real;

impl Ground for Real {
    type Port = UdpSocket;

    fn role(&self) -> Option<Role> {
        spray::local_role()
    }

    async fn open(&mut self) -> Option<(UdpSocket, SocketAddrV4)> {
        let nodes = spray::known_nodes();
        if nodes.is_empty() {
            return None;
        }
        let mut socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
        let counters = Counters::new();
        let found = spray::discover(
            &mut socket,
            &nodes,
            &mut Rng::from_os(),
            &counters,
            Instant::now() + DISCOVER_WINDOW,
        )
        .await;
        let report = counters.report();
        eprintln!(
            "shaar: spray discover pings={} sent_bytes={} recv_bytes={} found={}",
            report.sent_datagrams,
            report.sent_bytes,
            report.recv_bytes,
            if found.is_some() { "yes" } else { "no" }
        );
        Some((socket, found?))
    }

    fn run(
        &self,
        agreement: Agreement,
        mut port: UdpSocket,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async move {
            // The task is aborted to cancel; the sender stays alive for the whole run.
            let (_keep, cancel) = watch::channel(false);
            let done =
                spray::run_easy_agreed(&mut port, &agreement, &mut Rng::from_os(), cancel).await;
            eprintln!("{}", done.line(Role::Easy));
        })
    }
}

/// The responder's state for the trial of one peer.
pub(super) struct Spray<G: Ground> {
    ground: G,
    cooldown: Cooldown,
    trials: JoinSet<()>,
    /// The Answer of the last Offer, for a copy of it that arrives later.
    answered: Option<(u32, Vec<u8>)>,
}

impl<G: Ground> Spray<G> {
    pub(super) fn new(ground: G) -> Self {
        Self {
            ground,
            cooldown: Cooldown::new(),
            trials: JoinSet::new(),
            answered: None,
        }
    }

    /// Trials running now.
    #[cfg(test)]
    pub(super) fn running(&mut self) -> usize {
        while self.trials.try_join_next().is_some() {}
        self.trials.len()
    }

    /// Handles one datagram of the link. `false` when it is no message of the trial, so the punch
    /// code reads it; `true` when it was one, whether it was answered or not.
    pub(super) async fn handle<L: PunchLink>(
        &mut self,
        raw: &[u8],
        peer: [u8; 32],
        link: &mut L,
    ) -> bool {
        let Some(message) = spray::decode(raw) else {
            return false;
        };
        if message.kind != Kind::Offer {
            return true;
        }
        // Only the easy side answers in this slice; the hard side of a Server is slice 4b.
        if self.ground.role() != Some(Role::Easy) {
            return true;
        }
        let now = Instant::now();
        let Some(admitted) = spray::prepare(raw, Role::Easy, peer, &self.cooldown, now) else {
            return true;
        };
        if !admitted.fresh {
            // A copy of an Offer already answered: the same Answer again, and nothing else.
            if let Some((epoch, bytes)) = &self.answered
                && *epoch == admitted.offer.epoch
            {
                let _ = link.send_raw(bytes, EXCHANGE_BUDGET).await;
            }
            return true;
        }
        while self.trials.try_join_next().is_some() {}
        if !self.trials.is_empty() {
            return true;
        }
        let Some((port, endpoint)) = self.ground.open().await else {
            return true;
        };
        let side = Side {
            role: Role::Easy,
            address: endpoint,
            planned: spray::DEFAULT_PROBES,
        };
        let Some(response) =
            spray::answer(&admitted, side, peer, &mut self.cooldown, Instant::now())
        else {
            return true;
        };
        let _ = link.send_raw(&response.answer, EXCHANGE_BUDGET).await;
        self.answered = Some((admitted.offer.epoch, response.answer));
        if let Some(agreement) = response.start {
            self.trials.spawn(self.ground.run(agreement, port));
        }
        true
    }
}
