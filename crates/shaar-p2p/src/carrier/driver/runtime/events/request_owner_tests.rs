use std::{io, time::Duration};

use libp2p::{StreamProtocol, identity, request_response as rpc, swarm::ConnectionId};
use tokio::{sync::oneshot, time::Instant};

use super::{Owner, Pending};
use crate::{
    CONTROL_PROTOCOL, Datagram, DatagramCodec,
    carrier::{Link, REQUEST_LIMIT, driver::Reply},
};

fn link(connection: usize) -> Link {
    Link {
        peer: identity::Keypair::generate_ed25519().public().to_peer_id(),
        connection: ConnectionId::new_unchecked(connection),
        route: crate::carrier::Route::Direct,
    }
}

fn pending(link: Link, reply: Reply<()>, deadline: Instant) -> Pending {
    Pending {
        peer: link.peer,
        expected: link,
        packet: Datagram::new(b"x").unwrap(),
        deadline,
        reply: Some(reply),
    }
}

// This passes the complete current-link authority, not a chosen request selector:
// an absent link means production will reject and purge that request as stale.
fn promote(owner: &mut Owner, authority: &[Link], now: Instant) -> Option<Pending> {
    owner.take_next_eligible(now, |request| authority.contains(&request.expected))
}

#[tokio::test]
async fn changed_route_generation_is_stale_and_remove_role_is_connection_scoped() {
    let old = link(40);
    let changed_route = Link {
        route: crate::carrier::Route::Relayed {
            relay: None,
            generation: 1,
        },
        ..old
    };
    let now = Instant::now();
    let mut owner = Owner::default();
    let (tx, rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(old, tx, now + Duration::from_secs(5)))
            .is_ok()
    );
    assert!(promote(&mut owner, &[changed_route], now).is_none());
    assert_eq!(
        rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );

    let successor = Link {
        connection: ConnectionId::new_unchecked(41),
        ..old
    };
    let another_route = Link {
        route: crate::carrier::Route::Relayed {
            relay: None,
            generation: 2,
        },
        ..successor
    };
    let (stale_tx, route_rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(
                another_route,
                stale_tx,
                now + Duration::from_secs(5)
            ))
            .is_ok()
    );
    let (tx, mut successor_rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(successor, tx, now + Duration::from_secs(5)))
            .is_ok()
    );
    let survivor = promote(&mut owner, &[successor], now).unwrap();
    assert_eq!(
        route_rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(survivor.expected, successor);
    assert!(owner.admit(survivor).is_ok());

    owner.remove_role(old.peer, old.connection);
    assert_eq!(owner.queued_len(), 1);
    assert_eq!(
        successor_rx.try_recv().unwrap_err(),
        oneshot::error::TryRecvError::Empty
    );
    let successor_request = promote(&mut owner, &[successor], now).unwrap();
    assert_eq!(successor_request.expected, successor);
}

#[tokio::test]
async fn charges_queue_and_submission_until_terminal_and_enforces_exact_connection() {
    let link = link(1);
    let stale = Link {
        connection: ConnectionId::new_unchecked(2),
        ..link
    };
    let now = Instant::now();
    let mut owner = Owner::default();
    let (initial_tx, initial_rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(link, initial_tx, now + Duration::from_secs(10)))
            .is_ok()
    );
    // Deliberately reject the queued request under the complete authority view.
    assert!(promote(&mut owner, &[stale], now).is_none());
    assert_eq!(
        initial_rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );

    // Recreate valid work after the stale-authority probe, then fill to the bound.
    let (active_tx, active_rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(link, active_tx, now + Duration::from_secs(10)))
            .is_ok()
    );
    let active = active_rx;
    let mut waiters = Vec::new();
    for _ in 1..REQUEST_LIMIT {
        let (tx, rx) = oneshot::channel();
        assert!(
            owner
                .admit(pending(link, tx, now + Duration::from_secs(10)))
                .is_ok()
        );
        waiters.push(rx);
    }
    assert_eq!(owner.len(), REQUEST_LIMIT);
    let (overflow_tx, mut overflow_rx) = oneshot::channel();
    let overflow_reply = owner.admit(pending(link, overflow_tx, now));
    let Err(Some(overflow_reply)) = overflow_reply else {
        panic!("full owner must return the overflow reply");
    };
    let _ = overflow_reply.send(Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "carrier admission limit reached",
    )));
    assert_eq!(owner.len(), REQUEST_LIMIT);
    assert_eq!(
        overflow_rx.try_recv().unwrap().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let admitted = promote(&mut owner, &[link], now).unwrap();
    let mut rpc = rpc::Behaviour::with_codec(
        DatagramCodec,
        [(
            StreamProtocol::new(CONTROL_PROTOCOL),
            rpc::ProtocolSupport::Full,
        )],
        rpc::Config::default(),
    );
    let id = rpc.send_request(&link.peer, Datagram::new(b"inert").unwrap());
    owner.submitted(
        id,
        link.peer,
        link.connection,
        now + Duration::from_secs(10),
        admitted.reply,
    );
    assert!(promote(&mut owner, &[link], now).is_none());
    let (queued_tx, queued_rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(link, queued_tx, now + Duration::from_secs(10)))
            .is_err()
    );
    drop(queued_rx);
    drop(waiters.pop().unwrap());
    owner.cancel_queued();
    assert_eq!(owner.len(), REQUEST_LIMIT - 1);
    assert_eq!(owner.submitted_len(), 1);
    assert_eq!(owner.queued_len(), REQUEST_LIMIT - 2);
    owner.expire_queued(now + Duration::from_secs(11));
    assert_eq!(owner.len(), 1);
    owner.retain_submitted(now + Duration::from_secs(11));
    assert_eq!(owner.len(), 1);
    assert_eq!(
        active.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    for waiter in waiters {
        assert_eq!(
            waiter.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    assert!(owner.finish(&id, Err(io::Error::other("terminal"))));
    assert!(owner.is_empty());
}

#[tokio::test]
async fn queued_peer_does_not_head_of_line_block_another_connection() {
    let first = link(4);
    let mut second = link(5);
    while second.peer == first.peer {
        second.peer = identity::Keypair::generate_ed25519().public().to_peer_id();
    }
    let now = Instant::now();
    let authority = [first, second];
    let mut owner = Owner::default();
    let (first_tx, first_rx) = oneshot::channel();
    let (blocked_tx, mut blocked_rx) = oneshot::channel();
    let (second_tx, mut second_rx) = oneshot::channel();
    let first_deadline = now + Duration::from_secs(10);
    let blocked_deadline = now + Duration::from_secs(12);
    let second_deadline = now + Duration::from_secs(14);
    assert!(
        owner
            .admit(pending(first, first_tx, first_deadline))
            .is_ok()
    );
    assert!(
        owner
            .admit(pending(first, blocked_tx, blocked_deadline))
            .is_ok()
    );
    assert!(
        owner
            .admit(pending(second, second_tx, second_deadline))
            .is_ok()
    );
    let head = promote(&mut owner, &authority, now).unwrap();
    assert_eq!(head.expected, first);
    assert!(owner.queued().any(|request| request.expected == first));
    assert!(owner.queued().any(|request| request.expected == second));
    let mut rpc = rpc::Behaviour::with_codec(
        DatagramCodec,
        [(
            StreamProtocol::new(CONTROL_PROTOCOL),
            rpc::ProtocolSupport::Full,
        )],
        rpc::Config::default(),
    );
    let first_id = rpc.send_request(&first.peer, Datagram::new(b"first").unwrap());
    owner.submitted(
        first_id,
        first.peer,
        first.connection,
        head.deadline,
        head.reply,
    );
    let other = promote(&mut owner, &authority, now).unwrap();
    assert_eq!(other.expected, second);
    assert_eq!(other.deadline, second_deadline);
    assert!(owner.queued().any(|request| request.expected == first));
    assert_eq!(
        second_rx.try_recv().unwrap_err(),
        oneshot::error::TryRecvError::Empty
    );
    let second_id = rpc.send_request(&second.peer, Datagram::new(b"second").unwrap());
    owner.submitted(
        second_id,
        second.peer,
        second.connection,
        other.deadline,
        other.reply,
    );
    assert_eq!(
        owner.len(),
        3,
        "take-to-submit promotion preserves total charge"
    );
    assert!(owner.finish(&second_id, Err(io::Error::other("terminal"))));
    assert_eq!(
        owner.len(),
        2,
        "submitted first request and queued work stay charged"
    );
    assert!(owner.queued().any(|request| request.expected == first));
    assert_eq!(
        blocked_rx.try_recv().unwrap_err(),
        oneshot::error::TryRecvError::Empty
    );
    assert!(promote(&mut owner, &authority, now).is_none());
    assert!(owner.finish(&first_id, Err(io::Error::other("terminal"))));
    let unblocked = promote(&mut owner, &authority, now).unwrap();
    assert_eq!(unblocked.expected, first);
    assert_eq!(unblocked.deadline, blocked_deadline);
    let unblocked_id = rpc.send_request(&first.peer, Datagram::new(b"unblocked").unwrap());
    owner.submitted(
        unblocked_id,
        first.peer,
        first.connection,
        unblocked.deadline,
        unblocked.reply,
    );
    assert_eq!(owner.len(), 1);
    assert!(owner.finish(&unblocked_id, Ok(())));
    blocked_rx.await.unwrap().unwrap();
    assert_eq!(
        first_rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::Other
    );
    assert_eq!(
        second_rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::Other
    );
    assert!(owner.is_empty());
}

#[tokio::test]
async fn concurrent_submissions_keep_peer_scoped_and_total_capacity_bounded() {
    let first = link(10);
    let mut second = link(11);
    while second.peer == first.peer {
        second.peer = identity::Keypair::generate_ed25519().public().to_peer_id();
    }
    let peers = [first, second];
    let authority = peers;
    let now = Instant::now();
    let mut owner = Owner::default();
    let (tx, rx) = oneshot::channel();
    let (ty, ry) = oneshot::channel();
    assert!(
        owner
            .admit(pending(peers[0], tx, now + Duration::from_secs(10)))
            .is_ok()
    );
    assert!(
        owner
            .admit(pending(peers[1], ty, now + Duration::from_secs(10)))
            .is_ok()
    );
    let first = promote(&mut owner, &authority, now).unwrap();
    assert_eq!(first.expected, peers[0]);
    let second = promote(&mut owner, &authority, now).unwrap();
    assert_eq!(second.expected, peers[1]);
    assert_ne!(first.peer, second.peer);
    let mut rpc = rpc::Behaviour::with_codec(
        DatagramCodec,
        [(
            StreamProtocol::new(CONTROL_PROTOCOL),
            rpc::ProtocolSupport::Full,
        )],
        rpc::Config::default(),
    );
    let first_id = rpc.send_request(&first.peer, Datagram::new(b"first").unwrap());
    owner.submitted(
        first_id,
        first.peer,
        first.expected.connection,
        first.deadline,
        first.reply,
    );
    let second_id = rpc.send_request(&second.peer, Datagram::new(b"second").unwrap());
    owner.submitted(
        second_id,
        second.peer,
        second.expected.connection,
        second.deadline,
        second.reply,
    );
    assert_eq!(owner.len(), 2);
    assert!(promote(&mut owner, &authority, now).is_none());
    for _ in 2..REQUEST_LIMIT {
        let (tx, _rx) = oneshot::channel();
        assert!(
            owner
                .admit(pending(peers[0], tx, now + Duration::from_secs(10)))
                .is_ok()
        );
    }
    assert_eq!(owner.len(), REQUEST_LIMIT);
    let (overflow, mut overflow_rx) = oneshot::channel();
    let Err(Some(overflow)) = owner.admit(pending(peers[1], overflow, now)) else {
        panic!("full owner must return the overflow reply");
    };
    let _ = overflow.send(Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "carrier admission limit reached",
    )));
    assert_eq!(owner.len(), REQUEST_LIMIT);
    assert_eq!(
        overflow_rx.try_recv().unwrap().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    owner.finish(&first_id, Err(io::Error::other("terminal")));
    owner.finish(&second_id, Err(io::Error::other("terminal")));
    assert_eq!(owner.len(), REQUEST_LIMIT - 2);
    drop(rx);
    drop(ry);
}

#[tokio::test]
async fn terminal_failure_promotes_next_and_stale_or_withdrawn_work_is_replied() {
    let link = link(30);
    let now = Instant::now();
    let mut owner = Owner::default();
    let (active_tx, active_rx) = oneshot::channel();
    let (queued_tx, queued_rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(link, active_tx, now + Duration::from_secs(5)))
            .is_ok()
    );
    assert!(
        owner
            .admit(pending(link, queued_tx, now + Duration::from_secs(5)))
            .is_ok()
    );
    let active = promote(&mut owner, &[link], now).unwrap();
    let mut rpc = rpc::Behaviour::with_codec(
        DatagramCodec,
        [(
            StreamProtocol::new(CONTROL_PROTOCOL),
            rpc::ProtocolSupport::Full,
        )],
        rpc::Config::default(),
    );
    let first_id = rpc.send_request(&link.peer, Datagram::new(b"active").unwrap());
    owner.submitted(
        first_id,
        link.peer,
        link.connection,
        active.deadline,
        active.reply,
    );
    drop(active_rx);
    owner.cancel_queued();
    assert_eq!(
        owner.len(),
        2,
        "cancelled submitted work stays charged until terminal"
    );
    assert!(promote(&mut owner, &[link], now).is_none());
    assert!(owner.finish(&first_id, Err(io::Error::other("failed"))));
    let promoted = promote(&mut owner, &[link], now).unwrap();
    assert_eq!(promoted.deadline, now + Duration::from_secs(5));
    let second_id = rpc.send_request(&link.peer, Datagram::new(b"promoted").unwrap());
    owner.submitted(
        second_id,
        link.peer,
        link.connection,
        promoted.deadline,
        promoted.reply,
    );
    assert!(owner.finish(&second_id, Ok(())));
    queued_rx.await.unwrap().unwrap();
    assert!(owner.is_empty());

    let (stale_tx, stale_rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(link, stale_tx, now + Duration::from_secs(5)))
            .is_ok()
    );
    let successor = Link {
        connection: ConnectionId::new_unchecked(31),
        ..link
    };
    assert!(promote(&mut owner, &[successor], now).is_none());
    assert_eq!(
        stale_rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    let (role_tx, role_rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(successor, role_tx, now + Duration::from_secs(5)))
            .is_ok()
    );
    owner.remove_role(successor.peer, successor.connection);
    assert_eq!(
        role_rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(owner.is_empty());
}

#[tokio::test]
async fn close_and_shutdown_purge_unsent_and_detach_submitted_waiter() {
    let link = link(3);
    let mut owner = Owner::default();
    let (tx, rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(link, tx, Instant::now() + Duration::from_secs(10)))
            .is_ok()
    );
    owner.close_connection(link.peer, link.connection);
    assert_eq!(
        rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );

    let (tx, rx) = oneshot::channel();
    assert!(
        owner
            .admit(pending(link, tx, Instant::now() + Duration::from_secs(10)))
            .is_ok()
    );
    let request = promote(&mut owner, &[link], Instant::now()).unwrap();
    let mut rpc = rpc::Behaviour::with_codec(
        DatagramCodec,
        [(
            StreamProtocol::new(CONTROL_PROTOCOL),
            rpc::ProtocolSupport::Full,
        )],
        rpc::Config::default(),
    );
    let id = rpc.send_request(&link.peer, Datagram::new(b"inert").unwrap());
    owner.submitted(
        id,
        link.peer,
        request.expected.connection,
        request.deadline,
        request.reply,
    );
    owner.shutdown();
    assert!(rx.await.is_err());
    assert_eq!(owner.len(), 1);
}
