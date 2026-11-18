//! Tests of the NAT filtering measurement: the datagram format and the listener and the prober
//! against fake bootstrap hosts on the loopback.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::{Knock, Listen, datagram, listen_on, parse, probe};
use crate::network::forwarding::observe::nat_ports::top_level_bytes;

const ANSWER: Duration = Duration::from_millis(300);

/// A fake bootstrap host: it answers a ping with the sender's address and port.
async fn bootstrap_host() -> (SocketAddrV4, JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("host");
    let SocketAddr::V4(address) = socket.local_addr().expect("host address") else {
        panic!("an IPv4 socket");
    };
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        while let Ok((length, from)) = socket.recv_from(&mut buffer).await {
            let (Some(transaction), SocketAddr::V4(from)) =
                (top_level_bytes(&buffer[..length], b"t"), from)
            else {
                continue;
            };
            let mut reply = b"d2:ip6:".to_vec();
            reply.extend_from_slice(&from.ip().octets());
            reply.extend_from_slice(&from.port().to_be_bytes());
            reply.extend_from_slice(b"1:rd2:id20:");
            reply.extend_from_slice(&[7; 20]);
            reply.extend_from_slice(b"e1:t2:");
            reply.extend_from_slice(transaction);
            reply.extend_from_slice(b"1:y1:re");
            let _ = socket.send_to(&reply, from).await;
        }
    });
    (address, task)
}

fn listening(window_ms: u64, knock: Option<Knock>, show_address: bool) -> Listen {
    Listen {
        answer_wait: ANSWER,
        window: Duration::from_millis(window_ms),
        knock,
        show_address,
    }
}

/// Runs a listener in a task; its lines arrive on the returned channel.
fn spawn_listener(
    host: SocketAddrV4,
    options: Listen,
) -> (UnboundedReceiver<String>, JoinHandle<Result<(), String>>) {
    let (sender, lines) = unbounded_channel();
    let task = tokio::spawn(async move {
        let mut emit = |line: String| {
            let _ = sender.send(line);
        };
        listen_on(&[host], &options, &mut emit).await
    });
    (lines, task)
}

fn field(line: &str, name: &str) -> String {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} in {line}"))
        .to_owned()
}

fn drain(lines: &mut UnboundedReceiver<String>, into: &mut Vec<String>) {
    while let Ok(line) = lines.try_recv() {
        into.push(line);
    }
}

async fn external_target(lines: &mut UnboundedReceiver<String>) -> (String, SocketAddrV4) {
    let first = lines.recv().await.expect("the endpoint line");
    let port: u16 = field(&first, "external_port").parse().expect("a port");
    (first, SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

#[test]
fn a_datagram_carries_the_tag_a_label_and_a_sequence_number() {
    assert_eq!(datagram(b'A', 7), b"shaar-nat-filter/1 A 7".to_vec());
    assert_eq!(parse(&datagram(b'B', 3)), Some((b'B', 3)));
    assert_eq!(parse(&datagram(b'K', 255)), Some((b'K', 255)));
}

#[test]
fn other_datagrams_are_not_taken_for_probes() {
    for packet in [
        &b""[..],
        b"shaar-nat-filter/1 ",
        b"shaar-nat-filter/1 A",
        b"shaar-nat-filter/1 A ",
        b"shaar-nat-filter/1 a 1",
        b"shaar-nat-filter/1 A x",
        b"shaar-nat-filter/1 A 1234",
        b"shaar-nat-filter/1 A 256",
        b"shaar-nat-filter/1 A 1 ",
        b"shaar-nat-filter/1 AB 1",
        b"shaar-nat-filter/2 A 1",
        b"xshaar-nat-filter/1 A 1",
        b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:xx1:y1:qe",
    ] {
        assert_eq!(parse(packet), None, "{:?}", String::from_utf8_lossy(packet));
    }
}

#[tokio::test]
async fn every_probe_of_both_phases_comes_from_its_own_socket_and_is_counted() {
    let (host, bootstrap) = bootstrap_host().await;
    let (mut lines, listener) = spawn_listener(host, listening(1500, None, false));
    let (first, target) = external_target(&mut lines).await;
    assert!(
        first.starts_with("nat-filter listen local_port="),
        "{first}"
    );
    assert!(!first.contains("external_ip"), "{first}");

    let mut sent = Vec::new();
    probe(target, Duration::from_millis(150), &mut |line| {
        sent.push(line)
    })
    .await
    .expect("probed");
    assert_eq!(
        sent,
        [
            "nat-filter probe phase=A sent=3",
            "nat-filter probe phase=B sent=3"
        ]
    );
    listener.await.expect("joined").expect("listened");

    let mut all = Vec::new();
    drain(&mut lines, &mut all);
    let received: Vec<&String> = all.iter().filter(|line| line.contains(" recv ")).collect();
    assert_eq!(received.len(), 6, "{all:?}");
    for (index, label) in ["A", "A", "A", "B", "B", "B"].into_iter().enumerate() {
        assert_eq!(field(received[index], "label"), label, "{all:?}");
    }
    let mut ports: Vec<String> = received.iter().map(|l| field(l, "from_port")).collect();
    ports.sort();
    ports.dedup();
    assert_eq!(
        ports.len(),
        6,
        "every probe has its own source port: {all:?}"
    );
    let summary = all.last().expect("summary");
    assert!(
        summary.ends_with("summary received=6 a=3 b=3 other=0 knocks_sent=0"),
        "{summary}"
    );
    assert!(
        all.iter().all(|line| !line.contains("127.0.0.1")),
        "{all:?}"
    );
    bootstrap.abort();
}

#[tokio::test]
async fn the_external_address_is_printed_only_when_asked() {
    let (host, bootstrap) = bootstrap_host().await;
    let (mut lines, listener) = spawn_listener(host, listening(200, None, true));
    let first = lines.recv().await.expect("the endpoint line");
    assert_eq!(field(&first, "external_ip"), "127.0.0.1", "{first}");
    listener.await.expect("joined").expect("listened");
    bootstrap.abort();
}

#[tokio::test]
async fn the_listener_knocks_from_its_socket_only_after_the_delay() {
    let (host, bootstrap) = bootstrap_host().await;
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("knock target");
    let SocketAddr::V4(target) = receiver.local_addr().expect("address") else {
        panic!("an IPv4 socket");
    };
    let knock = Knock {
        target,
        after: Duration::from_millis(500),
        every: Duration::from_millis(100),
    };
    let (mut lines, listener) = spawn_listener(host, listening(1000, Some(knock), false));
    let (first, _) = external_target(&mut lines).await;
    let local: u16 = field(&first, "local_port").parse().expect("a port");

    let mut knocks = Vec::new();
    let mut buffer = [0_u8; 64];
    let window_end = Instant::now() + Duration::from_millis(1300);
    while let Ok(Ok((length, from))) =
        tokio::time::timeout_at(window_end, receiver.recv_from(&mut buffer)).await
    {
        assert_eq!(from.port(), local, "knocks leave the listening socket");
        knocks.push(parse(&buffer[..length]).expect("a knock"));
    }
    listener.await.expect("joined").expect("listened");

    assert!(!knocks.is_empty(), "no knock arrived");
    assert!(
        knocks.len() <= 6,
        "knocks started before the delay: {knocks:?}"
    );
    let expected: Vec<(u8, u8)> = (1..=u8::try_from(knocks.len()).expect("few knocks"))
        .map(|seq| (b'K', seq))
        .collect();
    assert_eq!(knocks, expected);
    let mut all = Vec::new();
    drain(&mut lines, &mut all);
    let summary = all.last().expect("summary");
    assert_eq!(
        field(summary, "knocks_sent"),
        knocks.len().to_string(),
        "{summary}"
    );
    bootstrap.abort();
}

#[tokio::test]
async fn datagrams_that_are_not_probes_are_ignored() {
    let (host, bootstrap) = bootstrap_host().await;
    let (mut lines, listener) = spawn_listener(host, listening(600, None, false));
    let (_, target) = external_target(&mut lines).await;
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("sender");
    sender.send_to(b"hello", target).await.expect("noise");
    sender
        .send_to(b"d1:rd2:id20:aaaaaaaaaaaaaaaaaaaae1:t2:xx1:y1:re", target)
        .await
        .expect("reply");
    sender
        .send_to(&datagram(b'Z', 9), target)
        .await
        .expect("other label");
    listener.await.expect("joined").expect("listened");

    let mut all = Vec::new();
    drain(&mut lines, &mut all);
    assert_eq!(all.len(), 2, "one probe line and the summary: {all:?}");
    assert_eq!(field(&all[0], "label"), "Z");
    assert!(
        all[1].ends_with("summary received=1 a=0 b=0 other=1 knocks_sent=0"),
        "{all:?}"
    );
    bootstrap.abort();
}

#[tokio::test]
async fn a_silent_bootstrap_host_or_none_is_an_error_and_nothing_is_printed() {
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("silent host");
    let SocketAddr::V4(address) = silent.local_addr().expect("address") else {
        panic!("an IPv4 socket");
    };
    let mut printed = Vec::new();
    let options = Listen {
        answer_wait: Duration::from_millis(80),
        ..listening(500, None, false)
    };
    let error = listen_on(&[address], &options, &mut |line| printed.push(line))
        .await
        .expect_err("no endpoint");
    assert!(error.contains("no bootstrap host answered"), "{error}");
    let none = listen_on(&[], &options, &mut |line| printed.push(line))
        .await
        .expect_err("no hosts");
    assert!(none.contains("no DHT bootstrap hosts"), "{none}");
    assert!(printed.is_empty(), "{printed:?}");
}

#[tokio::test]
async fn windows_and_knocks_that_cannot_work_are_refused_before_any_traffic() {
    let (host, bootstrap) = bootstrap_host().await;
    let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
    let knock = |after: u64, every: u64| Knock {
        target,
        after: Duration::from_millis(after),
        every: Duration::from_millis(every),
    };
    for options in [
        listening(0, None, false),
        listening(500, Some(knock(100, 0)), false),
        listening(500, Some(knock(500, 100)), false),
        listening(500, Some(knock(900, 100)), false),
    ] {
        let mut printed = Vec::new();
        let result = listen_on(&[host], &options, &mut |line| printed.push(line)).await;
        assert!(result.is_err(), "{options:?}");
        assert!(printed.is_empty(), "{printed:?}");
    }
    bootstrap.abort();
}

#[tokio::test]
async fn the_prober_refuses_targets_that_cannot_be_probed_and_pauses_between_phases() {
    for target in [
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5000),
        SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 5000),
        SocketAddrV4::new(Ipv4Addr::BROADCAST, 5000),
    ] {
        let mut printed = Vec::new();
        let result = probe(target, Duration::from_millis(1), &mut |line| {
            printed.push(line)
        })
        .await;
        assert!(result.is_err(), "{target}");
        assert!(printed.is_empty(), "{printed:?}");
    }
    let sink = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("sink");
    let SocketAddr::V4(target) = sink.local_addr().expect("address") else {
        panic!("an IPv4 socket");
    };
    let started = std::time::Instant::now();
    let mut printed = Vec::new();
    probe(target, Duration::from_millis(250), &mut |line| {
        printed.push(line)
    })
    .await
    .expect("probed");
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert_eq!(printed.len(), 2);
}
