//! Tests of the NAT port measurement: the wire format, the reply walker, the summary and the
//! whole run against fake bootstrap hosts on the loopback.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::{
    MAX_SOCKETS, distinct_hosts, external_endpoint, learn_external, measure, ping_packet, summary,
    top_level_bytes,
};

const WAIT: Duration = Duration::from_millis(400);

fn external_port(packet: &[u8], transaction: [u8; 2]) -> Option<u16> {
    external_endpoint(packet, transaction).map(|seen| seen.port())
}

/// A response of a bootstrap node that reports `ip:port` for the sender.
fn reply(transaction: [u8; 2], ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut packet = b"d2:ip6:".to_vec();
    packet.extend_from_slice(&ip.octets());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(b"1:rd2:id20:");
    packet.extend_from_slice(&[7; 20]);
    packet.extend_from_slice(b"e1:t2:");
    packet.extend_from_slice(&transaction);
    packet.extend_from_slice(b"1:y1:re");
    packet
}

#[test]
fn the_ping_is_a_bencoded_query_with_the_id_and_the_transaction() {
    let packet = ping_packet(&[9; 20], [1, 2]);
    let mut expected = b"d1:ad2:id20:".to_vec();
    expected.extend_from_slice(&[9; 20]);
    expected.extend_from_slice(b"e1:q4:ping1:t2:\x01\x021:y1:qe");
    assert_eq!(packet, expected);
}

#[test]
fn a_matching_response_reports_the_external_port() {
    let packet = reply([3, 4], Ipv4Addr::new(1, 2, 3, 4), 9653);
    assert_eq!(external_port(&packet, [3, 4]), Some(9653));
}

#[test]
fn a_matching_response_reports_the_external_address_too() {
    let packet = reply([3, 4], Ipv4Addr::new(1, 2, 3, 4), 9653);
    assert_eq!(
        external_endpoint(&packet, [3, 4]),
        Some(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 9653))
    );
}

#[test]
fn a_response_to_another_transaction_is_not_taken() {
    let packet = reply([3, 4], Ipv4Addr::new(1, 2, 3, 4), 9653);
    assert_eq!(external_port(&packet, [3, 5]), None);
    assert_eq!(external_port(&packet, [4, 4]), None);
}

#[test]
fn a_query_a_missing_ip_a_wrong_length_or_port_zero_are_refused() {
    let mut query = reply([3, 4], Ipv4Addr::new(1, 2, 3, 4), 9653);
    let last = query.len() - 2;
    query[last] = b'q';
    assert_eq!(external_port(&query, [3, 4]), None);

    let mut no_ip = b"d1:rd2:id20:".to_vec();
    no_ip.extend_from_slice(&[7; 20]);
    no_ip.extend_from_slice(b"e1:t2:\x03\x041:y1:re");
    assert_eq!(external_port(&no_ip, [3, 4]), None);

    let short = b"d2:ip4:\x01\x02\x03\x041:t2:\x03\x041:y1:re";
    assert_eq!(external_port(short, [3, 4]), None);

    let zero = reply([3, 4], Ipv4Addr::new(1, 2, 3, 4), 0);
    assert_eq!(external_port(&zero, [3, 4]), None);
}

#[test]
fn truncated_garbled_and_empty_packets_are_refused_without_panic() {
    let packet = reply([3, 4], Ipv4Addr::new(1, 2, 3, 4), 9653);
    for cut in 0..packet.len() {
        assert_eq!(external_port(&packet[..cut], [3, 4]), None, "cut at {cut}");
    }
    assert_eq!(external_port(b"", [3, 4]), None);
    assert_eq!(external_port(b"l1:ae", [3, 4]), None);
    assert_eq!(external_port(b"d99999:xe", [3, 4]), None);
    assert_eq!(external_port(b"d1:a99:short", [3, 4]), None);
}

#[test]
fn keys_after_nested_values_are_found_and_a_deep_nest_is_refused() {
    let mut packet = b"d1:rd2:id3:abc1:ai-5e1:bl1:xli1eeee2:ip6:".to_vec();
    packet.extend_from_slice(&[1, 2, 3, 4, 0x25, 0xB5]);
    packet.extend_from_slice(b"1:t2:\x03\x041:y1:re");
    assert_eq!(external_port(&packet, [3, 4]), Some(9653));

    let mut deep = b"d1:a".to_vec();
    deep.extend(std::iter::repeat_n(b'l', 200));
    deep.extend(std::iter::repeat_n(b'e', 200));
    deep.extend_from_slice(b"1:y1:re");
    assert_eq!(top_level_bytes(&deep, b"y"), None);
}

#[test]
fn only_the_first_two_distinct_addresses_are_kept() {
    let at = |last: u8, port: u16| SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, last), port);
    let found = vec![at(1, 6881), at(1, 6882), at(2, 6881), at(3, 6881)];
    assert_eq!(distinct_hosts(found), vec![at(1, 6881), at(2, 6881)]);
    assert!(distinct_hosts(Vec::new()).is_empty());
}

#[test]
fn the_summary_names_the_steps_independence_and_preserved_ports() {
    let seen = vec![
        vec![Some(9000), Some(9000)],
        vec![Some(9001), Some(9001)],
        vec![Some(9003), Some(9003)],
    ];
    assert_eq!(
        summary(&[100, 101, 102], &seen),
        "nat-ports summary sockets=3 answered=6 endpoint_independent=yes preserved_ports=0 \
         external_steps=[1,2]"
    );
    let kept = vec![vec![Some(100), Some(100)], vec![Some(101), Some(101)]];
    assert!(summary(&[100, 101], &kept).contains("preserved_ports=2 external_steps=[1]"));
}

#[test]
fn a_port_that_depends_on_the_host_is_reported_as_dependent() {
    let seen = vec![vec![Some(9000), Some(9100)], vec![Some(9001), Some(9001)]];
    assert!(summary(&[1, 2], &seen).contains("endpoint_independent=no"));
}

#[test]
fn one_host_or_no_answers_leave_independence_unknown_and_steps_open() {
    let seen = vec![
        vec![Some(9000), None],
        vec![None, None],
        vec![Some(9002), None],
    ];
    let line = summary(&[1, 2, 3], &seen);
    assert!(line.contains("answered=2 endpoint_independent=unknown"));
    assert!(line.contains("external_steps=[?,?]"));
}

/// A fake bootstrap host: it reports the sender's address with the port moved by `shift`; with
/// `noise` it first sends a reply with the wrong transaction and, from another socket, one for the
/// right transaction, both reporting port 1.
async fn serve(socket: UdpSocket, shift: u16, noise: bool) {
    let forger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("forger");
    let mut buffer = [0_u8; 1500];
    loop {
        let Ok((length, from)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        let Some(transaction) = top_level_bytes(&buffer[..length], b"t") else {
            continue;
        };
        let transaction = [transaction[0], transaction[1]];
        let SocketAddr::V4(from) = from else {
            continue;
        };
        if noise {
            let wrong = [transaction[0].wrapping_add(1), transaction[1]];
            let _ = socket.send_to(&reply(wrong, *from.ip(), 1), from).await;
            let _ = forger
                .send_to(&reply(transaction, *from.ip(), 1), from)
                .await;
        }
        let port = from.port().wrapping_add(shift);
        let _ = socket
            .send_to(&reply(transaction, *from.ip(), port), from)
            .await;
    }
}

async fn host(shift: u16, noise: bool) -> (SocketAddrV4, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("host");
    let SocketAddr::V4(address) = socket.local_addr().expect("host address") else {
        panic!("an IPv4 socket");
    };
    (address, tokio::spawn(serve(socket, shift, noise)))
}

fn field(line: &str, name: &str) -> String {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} in {line}"))
        .to_owned()
}

#[tokio::test]
async fn every_socket_is_measured_against_both_hosts_and_the_ports_are_printed() {
    let (first, one) = host(0, false).await;
    let (second, two) = host(0, false).await;
    let lines = measure(&[first, second], 3, WAIT, false)
        .await
        .expect("measured");
    assert_eq!(
        lines.len(),
        3 * 2 + 1,
        "a line per socket and host, then the summary"
    );
    for line in &lines[..6] {
        assert!(line.starts_with("nat-ports socket="));
        assert_eq!(
            field(line, "local_port"),
            field(line, "external_port"),
            "the loopback keeps the port"
        );
        assert!(!line.contains("127.0.0.1"), "no address is printed: {line}");
    }
    let last = lines.last().expect("summary");
    assert!(last.contains("sockets=3 answered=6 endpoint_independent=yes preserved_ports=3"));
    one.abort();
    two.abort();
}

#[tokio::test]
async fn a_host_that_moves_the_port_makes_the_mapping_dependent() {
    let (first, one) = host(0, false).await;
    let (second, two) = host(1000, false).await;
    let lines = measure(&[first, second], 2, WAIT, false)
        .await
        .expect("measured");
    let last = lines.last().expect("summary");
    assert!(last.contains("endpoint_independent=no"), "{last}");
    one.abort();
    two.abort();
}

#[tokio::test]
async fn replies_with_a_wrong_transaction_or_from_another_socket_are_ignored() {
    let (first, one) = host(0, true).await;
    let lines = measure(&[first], 2, WAIT, false).await.expect("measured");
    for line in &lines[..2] {
        assert_eq!(
            field(line, "local_port"),
            field(line, "external_port"),
            "{line}"
        );
    }
    one.abort();
}

#[tokio::test]
async fn a_silent_host_is_reported_as_none_within_the_wait() {
    let (answering, one) = host(0, false).await;
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("silent host");
    let SocketAddr::V4(silent_address) = silent.local_addr().expect("address") else {
        panic!("an IPv4 socket");
    };
    let started = std::time::Instant::now();
    let lines = measure(&[answering, silent_address], 2, WAIT, false)
        .await
        .expect("measured");
    assert!(started.elapsed() < WAIT * 2 * 2 + Duration::from_secs(2));
    assert!(
        lines
            .iter()
            .any(|line| line.contains("host=2 external_port=none"))
    );
    assert!(
        lines
            .last()
            .expect("summary")
            .contains("answered=2 endpoint_independent=unknown")
    );
    one.abort();
}

#[tokio::test]
async fn no_hosts_and_a_bad_socket_count_are_refused() {
    let (address, one) = host(0, false).await;
    assert!(measure(&[], 3, WAIT, false).await.is_err());
    assert!(measure(&[address], 0, WAIT, false).await.is_err());
    assert!(
        measure(&[address], MAX_SOCKETS + 1, WAIT, false)
            .await
            .is_err()
    );
    one.abort();
}

#[tokio::test]
async fn the_external_address_is_printed_only_when_asked() {
    let (first, one) = host(0, false).await;
    let hidden = measure(&[first], 2, WAIT, false).await.expect("measured");
    assert!(hidden.iter().all(|line| !line.contains("external_ip")));
    let shown = measure(&[first], 2, WAIT, true).await.expect("measured");
    for line in &shown[..2] {
        assert_eq!(field(line, "external_ip"), "127.0.0.1", "{line}");
    }
    assert!(!shown.last().expect("summary").contains("127.0.0.1"));
    one.abort();
}

#[tokio::test]
async fn an_answering_host_names_the_external_endpoint_of_the_socket() {
    let (silent_host, quiet) = {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("silent host");
        let SocketAddr::V4(address) = socket.local_addr().expect("address") else {
            panic!("an IPv4 socket");
        };
        (address, socket)
    };
    let (answering, one) = host(0, false).await;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");
    let local = socket.local_addr().expect("local").port();
    let seen = learn_external(&socket, &[silent_host, answering], WAIT)
        .await
        .expect("the answering host is enough");
    assert_eq!((*seen.ip(), seen.port()), (Ipv4Addr::LOCALHOST, local));
    one.abort();
    drop(quiet);
}

#[tokio::test]
async fn no_answer_in_any_round_leaves_the_external_endpoint_unknown() {
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("silent host");
    let SocketAddr::V4(silent_address) = silent.local_addr().expect("address") else {
        panic!("an IPv4 socket");
    };
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");
    let started = std::time::Instant::now();
    assert_eq!(
        learn_external(&socket, &[silent_address], Duration::from_millis(100)).await,
        None
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}
