//! Tests of the NAT measurements: the datagram format, the listener (probes, knocks, sweep), the
//! prober and the catcher against fake bootstrap hosts and fake peers on the loopback.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::{Catch, Knock, Listen, Sweep, catch, datagram, listen_on, parse, probe};
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
        sweep: None,
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

/// Runs a catcher in a task; its lines arrive on the returned channel.
fn spawn_catcher(options: Catch) -> (UnboundedReceiver<String>, JoinHandle<Result<(), String>>) {
    let (sender, lines) = unbounded_channel();
    let task = tokio::spawn(async move {
        let mut emit = |line: String| {
            let _ = sender.send(line);
        };
        catch(&options, &mut emit).await
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

/// A loopback socket and its address.
async fn loopback_socket() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");
    let SocketAddr::V4(address) = socket.local_addr().expect("address") else {
        panic!("an IPv4 socket");
    };
    (socket, address)
}

/// `count` loopback sockets on consecutive ports. Holding the whole run means no other socket of
/// the test process can sit inside a sweep over it, so a stray datagram cannot disturb a test.
async fn consecutive_receivers(count: u16) -> Vec<(UdpSocket, u16)> {
    for _ in 0..200 {
        let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("socket");
        let port = first.local_addr().expect("address").port();
        let mut run = vec![(first, port)];
        for offset in 1..count {
            let Some(next) = port.checked_add(offset) else {
                break;
            };
            match UdpSocket::bind((Ipv4Addr::LOCALHOST, next)).await {
                Ok(socket) => run.push((socket, next)),
                Err(_) => break,
            }
        }
        if run.len() == usize::from(count) {
            return run;
        }
    }
    panic!("no run of {count} consecutive free ports");
}

#[test]
fn a_datagram_carries_the_tag_a_label_and_a_sequence_number() {
    assert_eq!(datagram(b'A', 7), b"shaar-nat-filter/1 A 7".to_vec());
    assert_eq!(parse(&datagram(b'B', 3)), Some((b'B', 3)));
    assert_eq!(parse(&datagram(b'K', 255)), Some((b'K', 255)));
    assert_eq!(parse(&datagram(b'S', 1024)), Some((b'S', 1024)));
    assert_eq!(parse(&datagram(b'S', u16::MAX)), Some((b'S', u16::MAX)));
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
        b"shaar-nat-filter/1 A 65536",
        b"shaar-nat-filter/1 A 123456",
        b"shaar-nat-filter/1 A -1",
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
        summary.ends_with("summary received=6 a=3 b=3 c=0 other=0 knocks_sent=0 sweep_sent=0"),
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
    let (receiver, target) = loopback_socket().await;
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
    let expected: Vec<(u8, u16)> = (1..=u16::try_from(knocks.len()).expect("few knocks"))
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
        all[1].ends_with("summary received=1 a=0 b=0 c=0 other=1 knocks_sent=0 sweep_sent=0"),
        "{all:?}"
    );
    bootstrap.abort();
}

#[tokio::test]
async fn a_silent_bootstrap_host_or_none_is_an_error_and_nothing_is_printed() {
    let (silent, address) = loopback_socket().await;
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
    drop(silent);
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
    let (sink, target) = loopback_socket().await;
    let started = std::time::Instant::now();
    let mut printed = Vec::new();
    probe(target, Duration::from_millis(250), &mut |line| {
        printed.push(line)
    })
    .await
    .expect("probed");
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert_eq!(printed.len(), 2);
    drop(sink);
}

#[tokio::test]
async fn the_sweep_sends_one_datagram_to_every_port_of_its_range_from_the_listening_socket() {
    let (host, bootstrap) = bootstrap_host().await;
    // The receivers are bound first and hold the whole range, so the sweep reaches only them.
    let receivers = consecutive_receivers(3).await;
    let sweep = Sweep {
        ip: Ipv4Addr::LOCALHOST,
        from: receivers[0].1,
        to: receivers[2].1,
        after: Duration::from_millis(300),
        rate: 1000,
    };
    let options = Listen {
        sweep: Some(sweep),
        ..listening(1500, None, false)
    };
    let (mut lines, listener) = spawn_listener(host, options);
    let (first, _) = external_target(&mut lines).await;
    let local: u16 = field(&first, "local_port").parse().expect("a port");
    let opened = Instant::now();

    let mut buffer = [0_u8; 64];
    for (index, (receiver, port)) in receivers.iter().enumerate() {
        let (length, from) =
            tokio::time::timeout(Duration::from_millis(1200), receiver.recv_from(&mut buffer))
                .await
                .expect("the sweep reached the port")
                .expect("received");
        if index == 0 {
            assert!(
                opened.elapsed() >= Duration::from_millis(250),
                "the sweep started before its delay: {:?}",
                opened.elapsed()
            );
        }
        assert_eq!(from.port(), local, "the sweep leaves the listening socket");
        assert_eq!(
            parse(&buffer[..length]),
            Some((b'S', *port)),
            "the datagram carries its destination port"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), receiver.recv_from(&mut buffer))
                .await
                .is_err(),
            "one datagram per port"
        );
    }
    listener.await.expect("joined").expect("listened");

    let mut all = Vec::new();
    drain(&mut lines, &mut all);
    let swept = all
        .iter()
        .find(|line| line.contains(" swept "))
        .unwrap_or_else(|| panic!("no swept line: {all:?}"));
    assert_eq!(field(swept, "sent"), "3", "{swept}");
    assert_eq!(field(swept, "errors"), "0", "{swept}");
    assert_eq!(field(swept, "from"), sweep.from.to_string());
    assert_eq!(field(swept, "to"), sweep.to.to_string());
    let summary = all.last().expect("summary");
    assert_eq!(field(summary, "sweep_sent"), "3", "{summary}");
    bootstrap.abort();
}

#[tokio::test]
async fn the_sweep_keeps_its_rate() {
    let (host, bootstrap) = bootstrap_host().await;
    // Low ports: no ephemeral socket of this process is ever there, and the test reads only the
    // completion line, so whatever answers there changes nothing.
    let sweep = Sweep {
        ip: Ipv4Addr::LOCALHOST,
        from: 2000,
        to: 2019,
        after: Duration::from_millis(50),
        rate: 100,
    };
    let options = Listen {
        sweep: Some(sweep),
        ..listening(3000, None, false)
    };
    let (mut lines, listener) = spawn_listener(host, options);
    listener.await.expect("joined").expect("listened");

    let mut all = Vec::new();
    drain(&mut lines, &mut all);
    let swept = all
        .iter()
        .find(|line| line.contains(" swept "))
        .unwrap_or_else(|| panic!("no swept line: {all:?}"));
    let elapsed: u64 = field(swept, "elapsed_ms").parse().expect("a time");
    // 20 datagrams at 100 per second: the last one is due 190 ms after the first.
    assert!(
        (180..1700).contains(&elapsed),
        "20 datagrams at 100 per second took {elapsed} ms: {swept}"
    );
    assert_eq!(field(swept, "sent"), "20", "{swept}");
    bootstrap.abort();
}

#[tokio::test]
async fn a_sweep_that_cannot_work_is_refused_before_any_traffic() {
    let (host, bootstrap) = bootstrap_host().await;
    let good = Sweep {
        ip: Ipv4Addr::LOCALHOST,
        from: 5000,
        to: 5010,
        after: Duration::from_millis(100),
        rate: 100,
    };
    let bad = [
        Sweep { from: 0, ..good },
        Sweep {
            from: 6000,
            to: 5999,
            ..good
        },
        Sweep { rate: 0, ..good },
        Sweep {
            rate: super::MAX_SWEEP_RATE + 1,
            ..good
        },
        Sweep {
            ip: Ipv4Addr::UNSPECIFIED,
            ..good
        },
        Sweep {
            ip: Ipv4Addr::new(224, 0, 0, 1),
            ..good
        },
        Sweep {
            ip: Ipv4Addr::BROADCAST,
            ..good
        },
        // The delay alone fills the window.
        Sweep {
            after: Duration::from_millis(1000),
            ..good
        },
        // 11 datagrams at one per second do not fit in one second.
        Sweep { rate: 1, ..good },
        // The whole range at the default rate needs about 43 s.
        Sweep {
            from: super::DEFAULT_SWEEP_FROM,
            to: super::DEFAULT_SWEEP_TO,
            rate: super::DEFAULT_SWEEP_RATE,
            ..good
        },
    ];
    for sweep in bad {
        let mut printed = Vec::new();
        let options = Listen {
            sweep: Some(sweep),
            ..listening(1000, None, false)
        };
        let result = listen_on(&[host], &options, &mut |line| printed.push(line)).await;
        assert!(result.is_err(), "{sweep:?}");
        assert!(printed.is_empty(), "{printed:?}");
    }
    let mut printed = Vec::new();
    let options = Listen {
        sweep: Some(good),
        ..listening(1000, None, false)
    };
    listen_on(&[host], &options, &mut |line| printed.push(line))
        .await
        .expect("the good sweep runs");
    assert!(printed.iter().any(|line| line.contains(" swept ")));
    bootstrap.abort();
}

#[test]
fn the_whole_default_range_fits_the_default_window() {
    let sweep = Sweep {
        ip: Ipv4Addr::LOCALHOST,
        from: super::DEFAULT_SWEEP_FROM,
        to: super::DEFAULT_SWEEP_TO,
        after: Duration::from_secs(u64::from(super::DEFAULT_SWEEP_AFTER_SECONDS)),
        rate: super::DEFAULT_SWEEP_RATE,
    };
    let window = Duration::from_secs(u64::from(super::DEFAULT_LISTEN_SECONDS));
    sweep.check(window).expect("the defaults fit together");
    assert_eq!(sweep.ports(), 64_512);
}

#[tokio::test]
async fn the_catcher_probes_until_it_catches_a_sweep_datagram_and_then_sends_c() {
    let (phone, target) = loopback_socket().await;
    let options = Catch {
        target,
        window: Duration::from_millis(900),
        every: Duration::from_millis(100),
    };
    let (mut lines, catcher) = spawn_catcher(options);

    let mut buffer = [0_u8; 64];
    let (length, catcher_at) = phone.recv_from(&mut buffer).await.expect("the first probe");
    assert_eq!(parse(&buffer[..length]), Some((b'A', 1)));
    // The sweep hits the port the catcher's NAT uses: it arrives from the listener's endpoint.
    phone
        .send_to(&datagram(b'S', catcher_at.port()), catcher_at)
        .await
        .expect("a sweep datagram");

    let mut labels = Vec::new();
    let end = Instant::now() + Duration::from_millis(1100);
    while let Ok(Ok((length, from))) =
        tokio::time::timeout_at(end, phone.recv_from(&mut buffer)).await
    {
        assert_eq!(from, catcher_at, "every probe leaves the same socket");
        labels.push(parse(&buffer[..length]).expect("a probe"));
    }
    catcher.await.expect("joined").expect("caught");

    assert!(labels.len() >= 3, "{labels:?}");
    let expected: Vec<(u8, u16)> = (1..=u16::try_from(labels.len()).expect("few probes"))
        .map(|seq| (b'C', seq))
        .collect();
    assert_eq!(labels, expected, "after the catch only C probes follow");
    let mut all = Vec::new();
    drain(&mut lines, &mut all);
    assert_eq!(all.len(), 2, "{all:?}");
    assert!(all[0].starts_with("nat-filter catch caught "), "{all:?}");
    assert_eq!(
        field(&all[0], "external_port"),
        catcher_at.port().to_string()
    );
    assert_eq!(field(&all[0], "from_port"), target.port().to_string());
    assert_eq!(field(&all[0], "from_target"), "true");
    assert_eq!(field(&all[1], "caught"), "true");
    assert_eq!(
        field(&all[1], "external_port"),
        catcher_at.port().to_string()
    );
    assert_eq!(field(&all[1], "sweep_seen"), "1");
    assert_eq!(field(&all[1], "a_sent"), "1");
    assert_eq!(field(&all[1], "c_sent"), labels.len().to_string());
}

#[tokio::test]
async fn the_catcher_that_catches_nothing_keeps_sending_a_and_says_so() {
    let (phone, target) = loopback_socket().await;
    let options = Catch {
        target,
        window: Duration::from_millis(450),
        every: Duration::from_millis(100),
    };
    let (mut lines, catcher) = spawn_catcher(options);
    let mut buffer = [0_u8; 64];
    let (_, catcher_at) = phone.recv_from(&mut buffer).await.expect("the first probe");
    // Noise that is not a sweep datagram changes nothing.
    phone.send_to(b"hello", catcher_at).await.expect("noise");
    phone
        .send_to(&datagram(b'K', 1), catcher_at)
        .await
        .expect("a knock");
    phone
        .send_to(&datagram(b'A', 1), catcher_at)
        .await
        .expect("a probe");
    catcher.await.expect("joined").expect("finished");

    let mut all = Vec::new();
    drain(&mut lines, &mut all);
    assert_eq!(all.len(), 1, "only the summary: {all:?}");
    assert_eq!(field(&all[0], "caught"), "false");
    assert_eq!(field(&all[0], "external_port"), "none");
    assert_eq!(field(&all[0], "sweep_seen"), "0");
    assert_eq!(field(&all[0], "c_sent"), "0");
    let a_sent: u32 = field(&all[0], "a_sent").parse().expect("a count");
    assert!((3..=6).contains(&a_sent), "{all:?}");
}

#[tokio::test]
async fn the_catcher_refuses_targets_and_windows_that_cannot_work() {
    let (sink, target) = loopback_socket().await;
    let good = Catch {
        target,
        window: Duration::from_millis(100),
        every: Duration::from_millis(50),
    };
    let bad = [
        Catch {
            target: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            ..good
        },
        Catch {
            target: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5000),
            ..good
        },
        Catch {
            target: SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 5000),
            ..good
        },
        Catch {
            window: Duration::ZERO,
            ..good
        },
        Catch {
            every: Duration::ZERO,
            ..good
        },
    ];
    for options in bad {
        let mut printed = Vec::new();
        let result = catch(&options, &mut |line| printed.push(line)).await;
        assert!(result.is_err(), "{options:?}");
        assert!(printed.is_empty(), "{printed:?}");
    }
    drop(sink);
}
