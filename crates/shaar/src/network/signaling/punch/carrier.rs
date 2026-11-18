//! Punch coordination over the authenticated libp2p carrier link (leaf L4b).
//!
//! With a pinned relay the Client and the Server share an authenticated carrier link (Noise through
//! the relay circuit). The punch messages ride it as side-channel datagrams next to the QUIC
//! packets (`shaar_p2p::PunchPort`): the relay still carries signaling only, never application
//! data, and the candidates are probed over direct QUIC exactly as in the Yggdrasil exchange.
//! The peer of every message is the authenticated link's peer, never a claim of the bytes.

use std::{future::Future, net::IpAddr, sync::Arc, time::Duration};

use iroh_base::PublicKey;
use libp2p_identity::PeerId;
use shaar_p2p::{PunchPort, PunchSender, RelayAddr};
use tokio::{
    sync::mpsc,
    time::{Instant, timeout},
};

use super::{
    PunchLink, PunchMessage, SendError, client_attempt, encode, local_candidates, scan_ring,
    scan_then_connect,
};
use crate::network::{NetworkError, Session, SignaledEndpoint, signaling::peer_id};

/// Queued inbound messages per allowlisted peer; a full queue drops the message because the
/// peer repeats its Offer.
const PEER_QUEUE: usize = 8;

/// Encodes and sends one message on the peer's current carrier link. No link yet, a saturated
/// queue and a timeout are transient (the link can come back and the Offer is repeated); only
/// a closed carrier is permanent.
async fn send_encoded(
    sender: &PunchSender,
    peer: PeerId,
    message: &PunchMessage,
    budget: Duration,
) -> Result<(), SendError> {
    let bytes = encode(message).ok_or(SendError::Closed)?;
    match timeout(budget, sender.send(peer, &bytes)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(match error.kind() {
            std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut => SendError::Refused,
            _ => SendError::Closed,
        }),
        Err(_) => Err(SendError::Refused),
    }
}

/// The Client's punch link: the whole port, filtered to the one Server peer.
pub(crate) struct CarrierPunch {
    sender: PunchSender,
    port: PunchPort,
    peer: PeerId,
}

impl CarrierPunch {
    /// `None` when the service key is not a valid signaling key.
    pub(crate) fn new(port: PunchPort, service: &PublicKey) -> Option<Self> {
        Some(Self {
            sender: port.sender(),
            peer: peer_id(service).ok()?,
            port,
        })
    }
}

impl PunchLink for CarrierPunch {
    async fn send(&self, message: &PunchMessage, budget: Duration) -> Result<(), SendError> {
        send_encoded(&self.sender, self.peer, message, budget).await
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        loop {
            let inbound = self.port.recv().await?;
            if inbound.peer == self.peer {
                return Some(inbound.payload().to_vec());
            }
        }
    }
}

/// One allowlisted peer of the Server: its routed inbound queue and the shared send half.
pub(crate) struct CarrierPeerLink {
    sender: PunchSender,
    peer: PeerId,
    inbound: mpsc::Receiver<Vec<u8>>,
}

impl PunchLink for CarrierPeerLink {
    async fn send(&self, message: &PunchMessage, budget: Duration) -> Result<(), SendError> {
        send_encoded(&self.sender, self.peer, message, budget).await
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }
}

/// Splits the Server's port into one link per allowlisted peer plus the router that feeds them.
/// The router ends when the transport is gone, which closes every link. Messages from a peer
/// outside the list are dropped; the carrier admits only allowlisted peers anyway.
pub(crate) fn route(
    port: PunchPort,
    peers: &[([u8; 32], PeerId)],
) -> (
    Vec<([u8; 32], CarrierPeerLink)>,
    impl Future<Output = ()> + Send + use<>,
) {
    let sender = port.sender();
    let mut queues = Vec::with_capacity(peers.len());
    let mut links = Vec::with_capacity(peers.len());
    for (key, peer) in peers {
        let (queue, inbound) = mpsc::channel(PEER_QUEUE);
        queues.push((*peer, queue));
        links.push((
            *key,
            CarrierPeerLink {
                sender: sender.clone(),
                peer: *peer,
                inbound,
            },
        ));
    }
    let router = async move {
        let mut port = port;
        while let Some(inbound) = port.recv().await {
            if let Some((_, queue)) = queues.iter().find(|(peer, _)| *peer == inbound.peer) {
                let _ = queue.try_send(inbound.payload().to_vec());
            }
        }
    };
    (links, router)
}

/// Relay negotiation; with a carrier punch link, a punch exchange runs between the carrier link
/// and the QUIC negotiation. The punch gets half of the remaining attempt, so the negotiation
/// keeps the rest; a punched session is a direct Native one, any failure falls through to the
/// unchanged negotiation.
/// cancel-safe: NO — admitted circuit and handshake work may finish after waiter cancellation.
pub(crate) async fn connect_via_punched(
    endpoint: &Arc<SignaledEndpoint>,
    link: Option<&mut CarrierPunch>,
    peer: PublicKey,
    relay: RelayAddr,
    epoch: u32,
    reflexive: Option<IpAddr>,
    deadline: Instant,
) -> Result<Session, NetworkError> {
    let Some(link) = link else {
        return endpoint.connect_via(peer, relay).await;
    };
    endpoint.link_via(peer, relay).await?;
    let now = Instant::now();
    let punch_deadline = now + deadline.saturating_duration_since(now) / 2;
    let candidates = local_candidates(endpoint.local_addr(), reflexive);
    let dialer = Arc::clone(endpoint);
    let punched = client_attempt(
        link,
        move |address| {
            let endpoint = Arc::clone(&dialer);
            async move {
                scan_then_connect(
                    address,
                    scan_ring(epoch),
                    |probe_address| {
                        let probes = endpoint.probe_handle();
                        async move { probes.probe_answer(peer, probe_address).await }
                    },
                    |dial_address| endpoint.connect(peer, dial_address),
                )
                .await
            }
        },
        candidates,
        epoch,
        punch_deadline,
        "client",
    )
    .await;
    match punched {
        Some(session) => {
            #[cfg(test)]
            PUNCHED_FOR_TESTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(session)
        }
        None => endpoint.connect_linked(peer).await,
    }
}

#[cfg(test)]
static PUNCHED_FOR_TESTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many sessions a carrier punch has produced in this process (test observable).
#[cfg(test)]
pub(crate) fn carrier_punched_for_tests() -> usize {
    PUNCHED_FOR_TESTS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use tokio::time::timeout;

    use super::*;
    use crate::network::signaling::punch::{Kind, decode};
    use crate::{identity::Identity, network::Limits};

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn key(identity: &Identity) -> PublicKey {
        identity.transport_key().public()
    }

    async fn endpoint(identity: &Identity, peers: &[PublicKey]) -> SignaledEndpoint {
        SignaledEndpoint::bind(identity, loopback(), loopback(), peers, Limits::default())
            .await
            .unwrap()
    }

    fn offer(epoch: u32) -> PunchMessage {
        PunchMessage {
            kind: Kind::Offer,
            epoch,
            candidates: vec!["10.0.0.1:4433".parse().unwrap()],
        }
    }

    /// The whole exchange over real carrier links: the Client offers, the routed per-peer link
    /// of the Server answers with its mapped endpoint, and the probe completes a direct session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_carrier_exchange_completes_a_direct_session() {
        timeout(Duration::from_secs(30), async {
            let (a_id, b_id) = (Identity::generate(), Identity::generate());
            let (a_key, b_key) = (key(&a_id), key(&b_id));
            let client = endpoint(&a_id, &[b_key]).await;
            let mut server = endpoint(&b_id, &[a_key]).await;
            client
                .link_direct_for_tests(b_key, server.signaling_addr())
                .await
                .unwrap();

            let mut link = CarrierPunch::new(client.punch_port().unwrap(), &b_key).unwrap();
            let peers = [(*a_key.as_bytes(), peer_id(&a_key).unwrap())];
            let (links, router) = route(server.punch_port().unwrap(), &peers);
            tokio::spawn(router);
            let mapped = SocketAddr::from((Ipv4Addr::LOCALHOST, server.local_addr().port()));
            tokio::spawn(async move {
                for (_, mut peer_link) in links {
                    while let Some(raw) = peer_link.recv_raw().await {
                        let Some(PunchMessage {
                            kind: Kind::Offer,
                            epoch,
                            ..
                        }) = decode(&raw)
                        else {
                            continue;
                        };
                        let answer = PunchMessage {
                            kind: Kind::Answer,
                            epoch,
                            candidates: vec![mapped],
                        };
                        peer_link
                            .send(&answer, Duration::from_secs(1))
                            .await
                            .unwrap();
                    }
                }
            });

            let dial = client_attempt(
                &mut link,
                |address| client.connect(b_key, address),
                vec![client.local_addr()],
                7,
                Instant::now() + Duration::from_secs(10),
                "client",
            );
            let (session, accepted) = tokio::join!(dial, server.accept());
            let session = session.expect("the exchange over the carrier yields a session");
            let accepted = accepted.expect("the server accepts the probe");
            assert_eq!(session.peer_id(), server.id());
            assert_eq!(accepted.peer_id(), client.id());
            drop((session, accepted));
            client.close().await.unwrap();
            server.close().await.unwrap();
        })
        .await
        .expect("carrier exchange deadline");
    }

    /// No link yet is transient (the Offer is repeated and the link may come back); a message
    /// the codec refuses is permanent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_missing_link_is_a_transient_refusal_and_an_unencodable_message_is_permanent() {
        timeout(Duration::from_secs(20), async {
            let (a_id, b_id) = (Identity::generate(), Identity::generate());
            let b_key = key(&b_id);
            let client = endpoint(&a_id, &[b_key]).await;
            let link = CarrierPunch::new(client.punch_port().unwrap(), &b_key).unwrap();
            let budget = Duration::from_millis(500);
            assert_eq!(link.send(&offer(1), budget).await, Err(SendError::Refused));
            let unencodable = PunchMessage {
                kind: Kind::Offer,
                epoch: 1,
                candidates: vec!["0.0.0.0:0".parse().unwrap()],
            };
            assert_eq!(
                link.send(&unencodable, budget).await,
                Err(SendError::Closed)
            );
            assert!(client.punch_port().is_none(), "the port has one owner");
            client.close().await.unwrap();
        })
        .await
        .expect("refusal deadline");
    }

    /// The router feeds listed peers only; a full per-peer queue drops instead of blocking, the
    /// router keeps serving, and it ends with the transport, which closes every link.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_router_feeds_listed_peers_only_and_drops_on_overflow() {
        timeout(Duration::from_secs(40), async {
            let (a_id, c_id, b_id) = (
                Identity::generate(),
                Identity::generate(),
                Identity::generate(),
            );
            let (a_key, c_key, b_key) = (key(&a_id), key(&c_id), key(&b_id));
            let server = endpoint(&b_id, &[a_key, c_key]).await;
            let a = endpoint(&a_id, &[b_key]).await;
            let c = endpoint(&c_id, &[b_key]).await;
            a.link_direct_for_tests(b_key, server.signaling_addr())
                .await
                .unwrap();
            c.link_direct_for_tests(b_key, server.signaling_addr())
                .await
                .unwrap();
            let from_a = CarrierPunch::new(a.punch_port().unwrap(), &b_key).unwrap();
            let from_c = CarrierPunch::new(c.punch_port().unwrap(), &b_key).unwrap();

            let peers = [(*a_key.as_bytes(), peer_id(&a_key).unwrap())];
            let (mut links, router) = route(server.punch_port().unwrap(), &peers);
            let router = tokio::spawn(router);
            assert_eq!(links.len(), 1);
            let (routed_key, mut link) = links.pop().unwrap();
            assert_eq!(routed_key, *a_key.as_bytes());
            let budget = Duration::from_secs(1);
            let epoch_of = |raw: Vec<u8>| decode(&raw).expect("a punch message").epoch;

            // The stranger's message is dropped; the listed peer's arrives.
            from_c.send(&offer(1), budget).await.unwrap();
            from_a.send(&offer(2), budget).await.unwrap();
            let first = timeout(Duration::from_secs(5), link.recv_raw())
                .await
                .expect("the listed peer's message is routed")
                .expect("link open");
            assert_eq!(epoch_of(first), 2);

            // Flood without reading: at most one queue of messages is kept, nothing blocks.
            for epoch in 10..10 + 3 * PEER_QUEUE as u32 {
                let _ = from_a.send(&offer(epoch), budget).await;
            }
            let mut kept = 0;
            while timeout(Duration::from_millis(500), link.recv_raw())
                .await
                .is_ok_and(|raw| raw.is_some())
            {
                kept += 1;
            }
            assert!(
                (1..=PEER_QUEUE).contains(&kept),
                "kept {kept} of {} flooded messages",
                3 * PEER_QUEUE
            );

            // The router still serves after the overflow.
            from_a.send(&offer(99), budget).await.unwrap();
            let after = timeout(Duration::from_secs(5), link.recv_raw())
                .await
                .expect("the router survived the overflow")
                .expect("link open");
            assert_eq!(epoch_of(after), 99);

            // The transport going away ends the router and closes the link.
            server.close().await.unwrap();
            timeout(Duration::from_secs(10), router)
                .await
                .expect("the router ends with the transport")
                .unwrap();
            assert!(link.recv_raw().await.is_none());
            a.close().await.unwrap();
            c.close().await.unwrap();
        })
        .await
        .expect("router deadline");
    }
}
