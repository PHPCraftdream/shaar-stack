#![forbid(unsafe_code)]
//! Real HOP reservation replies; this fixture is not a general relay server.

mod codec;

use std::{
    error::Error,
    io,
    time::{Duration, Instant, SystemTime},
};

use codec::{Hop, HopCodec, Limit, Reservation};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport,
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    identity::Keypair,
    multiaddr::Protocol,
    noise, relay, request_response as rpc,
    swarm::SwarmEvent,
    tcp, yamux,
};
use shaar_p2p::OwnedExecutor;

#[derive(Clone, Copy, Debug)]
enum Case {
    Valid,
    Omitted,
    Zero,
    Past,
    TooFar,
    Huge,
}

enum Observation {
    Accepted,
    Rejected,
}

fn native(key: &Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(5))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed()
}

fn invalid_expiry(mut error: &(dyn Error + 'static)) -> bool {
    for _ in 0..16 {
        if matches!(
            error.downcast_ref::<relay::outbound::hop::ProtocolViolation>(),
            Some(relay::outbound::hop::ProtocolViolation::InvalidReservationExpiration)
        ) {
            return true;
        }
        if let Some(inner) = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
        {
            error = inner;
            continue;
        }
        let Some(inner) = error.source() else {
            return false;
        };
        error = inner;
    }
    false
}

async fn exercise(
    case: Case,
    server: &mut Swarm<rpc::Behaviour<HopCodec>>,
    client: &mut Swarm<relay::client::Behaviour>,
    server_tasks: &mut OwnedExecutor,
    client_tasks: &mut OwnedExecutor,
) -> io::Result<Observation> {
    let server_id = *server.local_peer_id();
    let client_id = *client.local_peer_id();
    let mut address: Option<Multiaddr> = None;
    let mut requests = 0;
    let mut expiry_upper = None;
    let mut expiry_lower = None;
    let mut accepted = false;
    let mut advertised = false;
    loop {
        tokio::select! {
            result = server_tasks.next_result() => result?,
            result = client_tasks.next_result() => result?,
            event = server.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address: listen, .. } => {
                    let relay_address = listen.with(Protocol::P2p(server_id));
                    client.listen_on(relay_address.clone().with(Protocol::P2pCircuit)).map_err(io::Error::other)?;
                    address = Some(relay_address);
                }
                SwarmEvent::Behaviour(rpc::Event::Message { peer, message: rpc::Message::Request { request, channel, .. }, .. }) => {
                    assert_eq!(peer, client_id);
                    assert_eq!(request.kind, Some(0)); // RESERVE, not a mocked client method.
                    assert!(request.reservation.is_none());
                    requests += 1;
                    assert_eq!(requests, 1);
                    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                    expiry_lower = Some(Instant::now() + Duration::from_secs(1));
                    expiry_upper = Some(Instant::now() + Duration::from_secs(60));
                    let expire = match case {
                        Case::Valid => Some(now.as_secs().checked_add(60).unwrap()),
                        Case::Omitted => None,
                        Case::Zero => Some(0),
                        Case::Past => Some(now.as_secs().checked_sub(1).unwrap()),
                        Case::TooFar => Some(now.as_secs().checked_add(172_800).unwrap()),
                        Case::Huge => Some(u64::MAX),
                    };
                    let response = Hop {
                        kind: Some(2), status: Some(100),
                        reservation: Some(Reservation { expire, addresses: vec![address.as_ref().unwrap().to_vec()] }),
                        // Circuit duration is deliberately unrelated to the 60-second reservation.
                        limit: Some(Limit { duration: Some(1), data: Some(4096) }),
                    };
                    server.behaviour_mut().send_response(channel, response).unwrap();
                }
                SwarmEvent::ListenerError { error, .. } => return Err(error),
                _ => {} // Closed fixture world: one authenticated connection, one request.
            },
            event = client.select_next_some() => match event {
                SwarmEvent::Behaviour(relay::client::Event::ReservationReqAccepted { relay_peer_id, renewal, limit, expires_at }) => {
                    assert!(matches!(case, Case::Valid), "hostile reservation accepted: {case:?}");
                    assert_eq!(requests, 1);
                    assert_eq!(relay_peer_id, server_id);
                    assert!(!renewal);
                    assert_eq!(limit.unwrap().duration(), Some(Duration::from_secs(1)));
                    assert!(expires_at > expiry_lower.unwrap());
                    assert!(expires_at <= expiry_upper.unwrap());
                    accepted = true;
                }
                SwarmEvent::NewListenAddr { address: listen, .. } => {
                    assert!(matches!(case, Case::Valid), "hostile reservation advertised: {case:?}");
                    assert_eq!(listen, address.as_ref().unwrap().clone().with(Protocol::P2pCircuit).with(Protocol::P2p(client_id)));
                    advertised = true;
                }
                SwarmEvent::ListenerError { error, .. } => {
                    assert_eq!(requests, 1);
                    assert!(!accepted && !advertised);
                    if invalid_expiry(&error) { return Ok(Observation::Rejected); }
                    return Err(error);
                }
                SwarmEvent::ListenerClosed { reason, .. } => {
                    assert_eq!(requests, 1);
                    assert!(!accepted && !advertised);
                    let error = reason.err().ok_or_else(|| io::Error::other("reservation closed without typed rejection"))?;
                    if invalid_expiry(&error) { return Ok(Observation::Rejected); }
                    return Err(error);
                }
                _ => {}
            },
        }
        if accepted && advertised {
            return Ok(Observation::Accepted);
        }
    }
}

async fn run_case(case: Case) -> Observation {
    let server_key = Keypair::generate_ed25519();
    let client_key = Keypair::generate_ed25519();
    let mut server_tasks = OwnedExecutor::new();
    let mut client_tasks = OwnedExecutor::new();
    let server_id = server_key.public().to_peer_id();
    let client_id = client_key.public().to_peer_id();
    let mut server = Swarm::new(
        native(&server_key),
        rpc::Behaviour::with_codec(
            HopCodec,
            [(relay::HOP_PROTOCOL_NAME, rpc::ProtocolSupport::Full)],
            rpc::Config::default()
                .with_request_timeout(Duration::from_secs(5))
                .with_max_concurrent_streams(1),
        ),
        server_id,
        libp2p::swarm::Config::with_executor(server_tasks.handle()),
    );
    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let (relay_transport, relay_behaviour) = relay::client::new(client_id);
    let relay_transport = relay_transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&client_key).unwrap())
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(5))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));
    let transport = relay_transport
        .or_transport(native(&client_key))
        .map(|either, _| either.into_inner())
        .boxed();
    let mut client = Swarm::new(
        transport,
        relay_behaviour,
        client_id,
        libp2p::swarm::Config::with_executor(client_tasks.handle()),
    );
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        exercise(
            case,
            &mut server,
            &mut client,
            &mut server_tasks,
            &mut client_tasks,
        ),
    )
    .await;
    // Drop both protocol owners before awaiting every task's destruction, including rejection.
    drop(client);
    drop(server);
    let (client_joined, server_joined) =
        tokio::join!(client_tasks.shutdown(), server_tasks.shutdown());
    client_joined.unwrap();
    server_joined.unwrap();
    result.expect("HOP reservation wire deadline").unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn actual_hop_reply_preserves_monotonic_lease_not_circuit_duration() {
    assert!(matches!(run_case(Case::Valid).await, Observation::Accepted));
}

#[tokio::test(flavor = "current_thread")]
async fn actual_hostile_hop_expiries_are_typed_rejections_without_task_panic_or_advertisement() {
    for case in [
        Case::Omitted,
        Case::Zero,
        Case::Past,
        Case::TooFar,
        Case::Huge,
    ] {
        assert!(matches!(run_case(case).await, Observation::Rejected));
    }
}
