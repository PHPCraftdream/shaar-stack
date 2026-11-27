//! The birthday trial on the Client side (leaf BDAY-1b, slice 4a-3). After the honest punch rounds
//! have failed, a hard Client offers the trial to the Server over its punch link and, on an Answer,
//! hands its side to a detached task; the dial goes on at once and its result is not touched. One
//! Offer per peer per 600 s, so the exchange costs the dial its window (3 s) at most once in ten
//! minutes, and the trial of 20 s never overlaps another.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::pin::Pin;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::network::signaling::punch::PunchLink;
use crate::network::signaling::spray::{
    self, Admit, Agreement, Cooldown, DEFAULT_SOCKETS, OverPunch, Rng, Role, Side, UdpOpener,
};
use crate::startup::resources::SharedResources;

/// What the dial needs from the world, so the cases can stand in for it.
pub(in crate::startup::role) trait Ground: Send + 'static {
    /// The role this device plays now; `None` while its own walks have not shown it.
    fn role(&self) -> Option<Role>;

    /// The public IPv4 address of this device, from its DHT votes.
    fn public_ip(&self) -> Option<Ipv4Addr>;

    /// The hard side of an agreement, to its end.
    fn run(&self, agreement: Agreement) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

/// The real world: the role from the DHT votes, the address from the reflexive hint, the trial
/// over UDP sockets, one operator line at its end.
pub(in crate::startup::role) struct Real {
    pub(in crate::startup::role) resources: SharedResources,
}

impl Ground for Real {
    fn role(&self) -> Option<Role> {
        spray::local_role()
    }

    fn public_ip(&self) -> Option<Ipv4Addr> {
        match self.resources.punch_address()? {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        }
    }

    fn run(&self, agreement: Agreement) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async move {
            // The sender stays alive for the whole run: dropping it would cancel the trial.
            let (_keep, cancel) = watch::channel(false);
            let done = spray::run_hard_agreed(&mut UdpOpener, &agreement, cancel).await;
            eprintln!("{}", done.line(Role::Hard));
        })
    }
}

/// The dial's state for the trial: the cooldown per peer.
pub(in crate::startup::role) struct SprayDial<G: Ground> {
    ground: G,
    cooldown: Cooldown,
}

impl<G: Ground> SprayDial<G> {
    pub(in crate::startup::role) fn new(ground: G) -> Self {
        Self {
            ground,
            cooldown: Cooldown::new(),
        }
    }

    /// Offers the trial over `link` and starts this side when it is answered. `false` when no
    /// trial started: the role is not hard or unknown, no public address is known, the peer had an
    /// Offer lately, the peer did not answer inside the window or `deadline`, or its Answer does
    /// not fit. The cooldown is booked with the Offer, so a silent peer costs the dial its window
    /// once in ten minutes and not at every dial.
    pub(in crate::startup::role) async fn attempt<L: PunchLink + Send>(
        &mut self,
        link: &mut L,
        peer: [u8; 32],
        epoch: u32,
        deadline: Instant,
    ) -> bool {
        if self.ground.role() != Some(Role::Hard) {
            return false;
        }
        let Some(ip) = self.ground.public_ip() else {
            return false;
        };
        if self.cooldown.admit(peer, epoch, Instant::now()) != Admit::Fresh {
            return false;
        }
        let side = Side {
            role: Role::Hard,
            address: SocketAddrV4::new(ip, 0),
            planned: DEFAULT_SOCKETS,
        };
        let token = Rng::from_os().token();
        let Some(agreement) =
            spray::initiate(&mut OverPunch(link), side, epoch, token, deadline).await
        else {
            return false;
        };
        tokio::spawn(self.ground.run(agreement));
        true
    }
}
