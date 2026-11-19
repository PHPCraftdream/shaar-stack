//! Tests of the nodes learned from the bootstrap hosts (leaf NAT-7): the `find_node` wire format, the
//! reply walker, the address filter and the learning against fake bootstrap hosts on the loopback.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::super::{
    LEARNED, find_node_packet, learn_nodes, plausible, reply_nodes, top_level_bytes,
};
use super::{WAIT, host, reply};

/// One compact node entry of a `find_node` reply: an id, an address and a port.
fn node(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut entry = vec![5_u8; 20];
    entry.extend_from_slice(&ip);
    entry.extend_from_slice(&port.to_be_bytes());
    entry
}

/// A response that names the compact `nodes`, with the `ip` key in front when `ip_first`.
fn nodes_reply(transaction: [u8; 2], nodes: &[u8], ip_first: bool) -> Vec<u8> {
    let mut packet = b"d".to_vec();
    if ip_first {
        packet.extend_from_slice(b"2:ip6:\x01\x02\x03\x04\x25\xB5");
    }
    packet.extend_from_slice(b"1:rd2:id20:");
    packet.extend_from_slice(&[7; 20]);
    packet.extend_from_slice(format!("5:nodes{}:", nodes.len()).as_bytes());
    packet.extend_from_slice(nodes);
    packet.extend_from_slice(b"e1:t2:");
    packet.extend_from_slice(&transaction);
    packet.extend_from_slice(b"1:y1:re");
    packet
}

/// A fake bootstrap host that answers every query with the compact `nodes`.
async fn naming(nodes: Vec<u8>) -> (SocketAddrV4, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("host");
    let SocketAddr::V4(address) = socket.local_addr().expect("host address") else {
        panic!("an IPv4 socket");
    };
    let serve = async move {
        let mut buffer = [0_u8; 1500];
        while let Ok((length, from)) = socket.recv_from(&mut buffer).await {
            let Some(transaction) = top_level_bytes(&buffer[..length], b"t") else {
                continue;
            };
            let reply = nodes_reply([transaction[0], transaction[1]], &nodes, false);
            let _ = socket.send_to(&reply, from).await;
        }
    };
    (address, tokio::spawn(serve))
}

#[test]
fn the_find_node_query_names_the_id_the_target_and_the_transaction() {
    let packet = find_node_packet(&[9; 20], &[8; 20], [1, 2]);
    let mut expected = b"d1:ad2:id20:".to_vec();
    expected.extend_from_slice(&[9; 20]);
    expected.extend_from_slice(b"6:target20:");
    expected.extend_from_slice(&[8; 20]);
    expected.extend_from_slice(b"e1:q9:find_node1:t2:\x01\x021:y1:qe");
    assert_eq!(packet, expected);
}

#[test]
fn a_reply_names_its_compact_nodes_and_drops_a_cut_entry_and_port_zero() {
    let mut nodes = node([192, 0, 2, 1], 6881);
    nodes.extend(node([192, 0, 2, 2], 0));
    nodes.extend(node([192, 0, 2, 3], 6883));
    nodes.extend_from_slice(&[1; 10]);
    let at = |last: u8, port: u16| SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, last), port);
    for ip_first in [false, true] {
        let packet = nodes_reply([3, 4], &nodes, ip_first);
        let found: Vec<SocketAddrV4> = reply_nodes(&packet, [3, 4]).expect("nodes").collect();
        assert_eq!(found, vec![at(1, 6881), at(3, 6883)]);
    }
    let empty = nodes_reply([3, 4], &[], false);
    assert_eq!(reply_nodes(&empty, [3, 4]).expect("nodes").count(), 0);
}

#[test]
fn a_packet_that_is_no_whole_response_to_this_transaction_names_no_nodes() {
    let nodes = node([192, 0, 2, 1], 6881);
    let packet = nodes_reply([3, 4], &nodes, false);
    assert!(
        reply_nodes(&packet, [3, 5]).is_none(),
        "another transaction"
    );
    assert!(reply_nodes(&packet[..packet.len() - 1], [3, 4]).is_none());
    let mut padded = packet.clone();
    padded.push(b'x');
    assert!(reply_nodes(&padded, [3, 4]).is_none());
    let mut query = packet.clone();
    let at = query.len() - 2;
    query[at] = b'q';
    assert!(
        reply_nodes(&query, [3, 4]).is_none(),
        "a query, not a response"
    );
    let without = reply([3, 4], Ipv4Addr::new(1, 2, 3, 4), 9653);
    assert!(reply_nodes(&without, [3, 4]).is_none(), "no nodes key");
    assert!(reply_nodes(&[], [3, 4]).is_none());
    assert!(reply_nodes(b"garbage", [3, 4]).is_none());
}

#[test]
fn own_networks_and_group_addresses_are_not_worth_a_ping() {
    for ip in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(10, 1, 2, 3),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(169, 254, 1, 1),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::BROADCAST,
    ] {
        assert!(!plausible(ip), "{ip}");
    }
    assert!(plausible(Ipv4Addr::new(192, 0, 2, 1)));
    assert!(plausible(Ipv4Addr::new(87, 98, 162, 88)));
}

#[tokio::test]
async fn learned_nodes_skip_own_networks_and_repeated_addresses() {
    let mut nodes = node([192, 0, 2, 1], 6881);
    for private in [[10, 0, 0, 1], [127, 0, 0, 2], [192, 168, 1, 1]] {
        nodes.extend(node(private, 6881));
    }
    nodes.extend(node([192, 0, 2, 1], 6882));
    nodes.extend(node([192, 0, 2, 2], 6881));
    let (address, one) = naming(nodes).await;
    let learned = learn_nodes(&[address], WAIT).await;
    let at = |last: u8, port: u16| SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, last), port);
    assert_eq!(learned, vec![at(1, 6881), at(2, 6881)]);
    one.abort();
}

#[tokio::test]
async fn learning_stops_at_the_cap() {
    let mut nodes = Vec::new();
    for last in 1..=30 {
        nodes.extend(node([198, 51, 100, last], 6881));
    }
    let (address, one) = naming(nodes).await;
    let learned = learn_nodes(&[address], WAIT).await;
    assert_eq!(learned.len(), LEARNED);
    assert_eq!(learned[0].ip(), &Ipv4Addr::new(198, 51, 100, 1));
    one.abort();
}

#[tokio::test]
async fn a_silent_host_or_no_host_teaches_nothing_within_the_wait() {
    assert!(learn_nodes(&[], WAIT).await.is_empty());
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("silent host");
    let SocketAddr::V4(silent_address) = silent.local_addr().expect("address") else {
        panic!("an IPv4 socket");
    };
    let (answering, one) = host(0, false).await;
    let started = std::time::Instant::now();
    let learned = learn_nodes(&[silent_address, answering], WAIT).await;
    assert!(
        learned.is_empty(),
        "a host that names no nodes teaches nothing"
    );
    assert!(started.elapsed() < WAIT + Duration::from_secs(2));
    one.abort();
}
