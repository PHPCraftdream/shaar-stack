//! Tests of the `diag` subcommands: parsing, defaults, bounds, and the commands that need no
//! network.

use shaar::network::observe::{
    DEFAULT_CATCH_SECONDS, DEFAULT_DESTINATIONS, DEFAULT_KNOCK_AFTER_SECONDS,
    DEFAULT_LISTEN_SECONDS, DEFAULT_PROBE_WAIT_SECONDS, DEFAULT_RATE, DEFAULT_SWEEP_AFTER_SECONDS,
    DEFAULT_SWEEP_FROM, DEFAULT_SWEEP_RATE, DEFAULT_SWEEP_TO, MAX_CATCH_SECONDS, MAX_DESTINATIONS,
    MAX_LISTEN_SECONDS, MAX_PROBE_WAIT_SECONDS, MAX_RATE, MAX_SOCKETS,
};

use super::tests::{Fixture, parsed, refused, run};
use super::*;

const PEER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

fn listen_with(sweep: Option<SweepArgs>, seconds: u16) -> Invocation {
    Invocation::DiagNatFilterListen {
        place: Place::default(),
        seconds,
        knock: None,
        sweep,
        show_address: false,
    }
}

#[test]
fn diag_nat_ports_takes_a_default_and_a_bounded_socket_count() {
    let place = |dir: Option<&str>| Place {
        config: None,
        dir: dir.map(PathBuf::from),
    };
    assert_eq!(
        parsed(&["diag", "nat-ports"]),
        Invocation::DiagNatPorts {
            place: place(None),
            sockets: shaar::network::observe::DEFAULT_SOCKETS,
            show_address: false,
            map: false,
        }
    );
    assert_eq!(
        parsed(&["diag", "nat-ports", "--sockets", "3", "--dir", "d"]),
        Invocation::DiagNatPorts {
            place: place(Some("d")),
            sockets: 3,
            show_address: false,
            map: false,
        }
    );
    assert_eq!(
        parsed(&["diag", "--dir", "d", "nat-ports", "--sockets", "16"]),
        Invocation::DiagNatPorts {
            place: place(Some("d")),
            sockets: MAX_SOCKETS,
            show_address: false,
            map: false,
        }
    );
    for bad in [
        &["diag"][..],
        &["diag", "other"],
        &["diag", "nat-ports", "--sockets", "0"],
        &["diag", "nat-ports", "--sockets", "17"],
        &["diag", "nat-ports", "--sockets", "many"],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
}

#[test]
fn diag_nat_fanout_takes_defaults_and_bounded_numbers() {
    let place = |dir: Option<&str>| Place {
        config: None,
        dir: dir.map(PathBuf::from),
    };
    assert_eq!(
        parsed(&["diag", "nat-fanout"]),
        Invocation::DiagNatFanout {
            place: place(None),
            destinations: DEFAULT_DESTINATIONS,
            rate: DEFAULT_RATE,
        }
    );
    assert_eq!(
        parsed(&[
            "diag",
            "--dir",
            "d",
            "nat-fanout",
            "--destinations",
            "8000",
            "--rate",
            "200",
        ]),
        Invocation::DiagNatFanout {
            place: place(Some("d")),
            destinations: MAX_DESTINATIONS,
            rate: MAX_RATE,
        }
    );
    for bad in [
        &["diag", "nat-fanout", "--destinations", "0"][..],
        &["diag", "nat-fanout", "--destinations", "8001"],
        &["diag", "nat-fanout", "--rate", "0"],
        &["diag", "nat-fanout", "--rate", "201"],
        &["diag", "nat-fanout", "--rate", "fast"],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
}

#[tokio::test]
async fn diag_nat_fanout_needs_the_bootstrap_hosts_of_a_public_configuration() {
    let fixture = Fixture::new();
    run(&["init", "--dir", fixture.dir(), "--private"])
        .await
        .unwrap();
    let direct_only = run(&["diag", "nat-fanout", "--dir", fixture.dir()])
        .await
        .unwrap_err();
    assert!(
        direct_only.contains("no DHT bootstrap hosts"),
        "{direct_only}"
    );
}

#[tokio::test]
async fn diag_nat_ports_needs_the_bootstrap_hosts_of_a_public_configuration() {
    let fixture = Fixture::new();
    run(&["init", "--dir", fixture.dir(), "--private"])
        .await
        .unwrap();
    let direct_only = run(&["diag", "nat-ports", "--dir", fixture.dir()])
        .await
        .unwrap_err();
    assert!(
        direct_only.contains("no DHT bootstrap hosts"),
        "{direct_only}"
    );
    let missing = run(&["diag", "nat-ports", "--config", "no-such-file.ktav"])
        .await
        .unwrap_err();
    assert!(missing.starts_with("configuration: "), "{missing}");
}

#[test]
fn diag_nat_ports_shows_the_address_only_when_asked() {
    let shown = parsed(&["diag", "nat-ports", "--show-address"]);
    assert!(matches!(
        shown,
        Invocation::DiagNatPorts {
            show_address: true,
            ..
        }
    ));
}

#[test]
fn diag_nat_ports_asks_the_router_only_with_map() {
    let mapped = parsed(&["diag", "nat-ports", "--map", "--sockets", "2"]);
    assert!(matches!(
        mapped,
        Invocation::DiagNatPorts {
            sockets: 2,
            map: true,
            show_address: false,
            ..
        }
    ));
    let plain = parsed(&["diag", "nat-ports", "--show-address"]);
    assert!(matches!(plain, Invocation::DiagNatPorts { map: false, .. }));
}

#[test]
fn diag_nat_filter_listen_takes_defaults_a_bounded_window_and_an_optional_knock() {
    assert_eq!(
        parsed(&["diag", "nat-filter", "listen"]),
        listen_with(None, DEFAULT_LISTEN_SECONDS)
    );
    assert_eq!(
        parsed(&[
            "diag",
            "nat-filter",
            "listen",
            "--seconds",
            "60",
            "--knock-ip",
            "203.0.113.7",
            "--knock-after",
            "10",
            "--show-address",
            "--dir",
            "d",
        ]),
        Invocation::DiagNatFilterListen {
            place: Place {
                config: None,
                dir: Some(PathBuf::from("d")),
            },
            seconds: 60,
            knock: Some((PEER, 10)),
            sweep: None,
            show_address: true,
        }
    );
    // The default first knock applies when only the address is given.
    assert_eq!(
        parsed(&["diag", "nat-filter", "listen", "--knock-ip", "203.0.113.7"]),
        Invocation::DiagNatFilterListen {
            place: Place::default(),
            seconds: DEFAULT_LISTEN_SECONDS,
            knock: Some((PEER, DEFAULT_KNOCK_AFTER_SECONDS)),
            sweep: None,
            show_address: false,
        }
    );
    let longest = MAX_LISTEN_SECONDS.to_string();
    assert!(matches!(
        parsed(&["diag", "nat-filter", "listen", "--seconds", &longest]),
        Invocation::DiagNatFilterListen { seconds, .. } if seconds == MAX_LISTEN_SECONDS
    ));
    for bad in [
        &["diag", "nat-filter"][..],
        &["diag", "nat-filter", "other"],
        &["diag", "nat-filter", "listen", "--seconds", "0"],
        &["diag", "nat-filter", "listen", "--seconds", "111"],
        &["diag", "nat-filter", "listen", "--seconds", "soon"],
        &["diag", "nat-filter", "listen", "--knock-ip", "not-an-ip"],
        &[
            "diag",
            "nat-filter",
            "listen",
            "--knock-ip",
            "1.2.3.4",
            "--knock-after",
            "110",
        ],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
    let orphan = refused(&["diag", "nat-filter", "listen", "--knock-after", "5"]);
    assert!(
        matches!(&orphan, ParseError::Value(message) if message.contains("--knock-ip")),
        "{orphan:?}"
    );
    // A first knock that would come after the window ends is refused with a message.
    let late = refused(&[
        "diag",
        "nat-filter",
        "listen",
        "--seconds",
        "20",
        "--knock-ip",
        "1.2.3.4",
    ]);
    assert!(
        matches!(&late, ParseError::Value(message) if message.contains("--knock-after")),
        "{late:?}"
    );
}

#[test]
fn diag_nat_filter_listen_sweeps_with_defaults_or_the_given_range_and_rate() {
    assert_eq!(
        parsed(&["diag", "nat-filter", "listen", "--sweep-ip", "203.0.113.7"]),
        listen_with(
            Some(SweepArgs {
                ip: PEER,
                after: DEFAULT_SWEEP_AFTER_SECONDS,
                rate: DEFAULT_SWEEP_RATE,
                from: DEFAULT_SWEEP_FROM,
                to: DEFAULT_SWEEP_TO,
            }),
            DEFAULT_LISTEN_SECONDS
        )
    );
    assert_eq!(
        parsed(&[
            "diag",
            "nat-filter",
            "listen",
            "--seconds",
            "100",
            "--sweep-ip",
            "203.0.113.7",
            "--sweep-after",
            "5",
            "--sweep-rate",
            "500",
            "--sweep-from",
            "20000",
            "--sweep-to",
            "30000",
        ]),
        listen_with(
            Some(SweepArgs {
                ip: PEER,
                after: 5,
                rate: 500,
                from: 20000,
                to: 30000,
            }),
            100
        )
    );
    // A knock and a sweep can run together.
    assert!(matches!(
        parsed(&[
            "diag",
            "nat-filter",
            "listen",
            "--knock-ip",
            "203.0.113.7",
            "--sweep-ip",
            "203.0.113.7",
        ]),
        Invocation::DiagNatFilterListen {
            knock: Some(_),
            sweep: Some(_),
            ..
        }
    ));
    for bad in [
        &["diag", "nat-filter", "listen", "--sweep-ip", "not-an-ip"][..],
        &[
            "diag",
            "nat-filter",
            "listen",
            "--sweep-ip",
            "1.2.3.4",
            "--sweep-rate",
            "0",
        ],
        &[
            "diag",
            "nat-filter",
            "listen",
            "--sweep-ip",
            "1.2.3.4",
            "--sweep-rate",
            "5001",
        ],
        &[
            "diag",
            "nat-filter",
            "listen",
            "--sweep-ip",
            "1.2.3.4",
            "--sweep-from",
            "0",
        ],
        &[
            "diag",
            "nat-filter",
            "listen",
            "--sweep-ip",
            "1.2.3.4",
            "--sweep-to",
            "65536",
        ],
        &[
            "diag",
            "nat-filter",
            "listen",
            "--sweep-ip",
            "1.2.3.4",
            "--sweep-after",
            "110",
        ],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
}

#[test]
fn a_sweep_that_cannot_work_is_refused_with_a_message_that_names_the_flags() {
    let value = |parts: &[&str]| match refused(parts) {
        ParseError::Value(message) => message,
        other => panic!("{parts:?}: {other:?}"),
    };
    let orphan = value(&["diag", "nat-filter", "listen", "--sweep-rate", "100"]);
    assert!(orphan.contains("--sweep-ip"), "{orphan}");
    let inverted = value(&[
        "diag",
        "nat-filter",
        "listen",
        "--sweep-ip",
        "1.2.3.4",
        "--sweep-from",
        "30000",
        "--sweep-to",
        "20000",
    ]);
    assert!(inverted.contains("first port"), "{inverted}");
    // The whole range at the default rate needs about 43 s after the 8 s delay.
    let long = value(&[
        "diag",
        "nat-filter",
        "listen",
        "--seconds",
        "40",
        "--sweep-ip",
        "1.2.3.4",
    ]);
    assert!(
        long.contains("finish inside the listening window"),
        "{long}"
    );
    assert!(long.contains("--sweep-rate"), "{long}");
    let multicast = value(&["diag", "nat-filter", "listen", "--sweep-ip", "224.0.0.1"]);
    assert!(multicast.contains("unicast"), "{multicast}");
}

#[test]
fn diag_nat_filter_probe_needs_a_target_and_takes_a_bounded_pause() {
    assert_eq!(
        parsed(&[
            "diag",
            "nat-filter",
            "probe",
            "--target",
            "203.0.113.7:4000"
        ]),
        Invocation::DiagNatFilterProbe {
            target: "203.0.113.7:4000".parse().unwrap(),
            wait: DEFAULT_PROBE_WAIT_SECONDS,
        }
    );
    let longest = MAX_PROBE_WAIT_SECONDS.to_string();
    assert!(matches!(
        parsed(&[
            "diag",
            "nat-filter",
            "probe",
            "--target",
            "203.0.113.7:4000",
            "--wait",
            &longest,
        ]),
        Invocation::DiagNatFilterProbe { wait, .. } if wait == MAX_PROBE_WAIT_SECONDS
    ));
    for bad in [
        &["diag", "nat-filter", "probe"][..],
        &["diag", "nat-filter", "probe", "--target", "203.0.113.7"],
        &["diag", "nat-filter", "probe", "--target", "[::1]:4000"],
        &[
            "diag",
            "nat-filter",
            "probe",
            "--target",
            "1.2.3.4:4000",
            "--wait",
            "0",
        ],
        &[
            "diag",
            "nat-filter",
            "probe",
            "--target",
            "1.2.3.4:4000",
            "--wait",
            "101",
        ],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
}

#[test]
fn diag_nat_filter_catch_needs_a_target_and_takes_a_bounded_window() {
    assert_eq!(
        parsed(&[
            "diag",
            "nat-filter",
            "catch",
            "--target",
            "203.0.113.7:4000"
        ]),
        Invocation::DiagNatFilterCatch {
            target: "203.0.113.7:4000".parse().unwrap(),
            seconds: DEFAULT_CATCH_SECONDS,
        }
    );
    let longest = MAX_CATCH_SECONDS.to_string();
    assert!(matches!(
        parsed(&[
            "diag",
            "nat-filter",
            "catch",
            "--target",
            "203.0.113.7:4000",
            "--seconds",
            &longest,
        ]),
        Invocation::DiagNatFilterCatch { seconds, .. } if seconds == MAX_CATCH_SECONDS
    ));
    for bad in [
        &["diag", "nat-filter", "catch"][..],
        &["diag", "nat-filter", "catch", "--target", "203.0.113.7"],
        &["diag", "nat-filter", "catch", "--target", "[::1]:4000"],
        &[
            "diag",
            "nat-filter",
            "catch",
            "--target",
            "1.2.3.4:4000",
            "--seconds",
            "0",
        ],
        &[
            "diag",
            "nat-filter",
            "catch",
            "--target",
            "1.2.3.4:4000",
            "--seconds",
            "111",
        ],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
}

#[tokio::test]
async fn diag_nat_filter_probe_reports_both_phases_and_refuses_a_target_with_port_zero() {
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = sink.local_addr().unwrap().to_string();
    let lines = run(&[
        "diag",
        "nat-filter",
        "probe",
        "--target",
        &target,
        "--wait",
        "1",
    ])
    .await
    .unwrap();
    assert_eq!(
        lines,
        [
            "nat-filter probe phase=A sent=3",
            "nat-filter probe phase=B sent=3"
        ]
    );
    let refused = run(&["diag", "nat-filter", "probe", "--target", "127.0.0.1:0"])
        .await
        .unwrap_err();
    assert!(refused.contains("unicast IPv4 address"), "{refused}");
}

#[tokio::test]
async fn diag_nat_filter_catch_reports_a_summary_and_refuses_a_target_with_port_zero() {
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = sink.local_addr().unwrap().to_string();
    let lines = run(&[
        "diag",
        "nat-filter",
        "catch",
        "--target",
        &target,
        "--seconds",
        "1",
    ])
    .await
    .unwrap();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0]
            .starts_with("nat-filter catch summary caught=false external_port=none sweep_seen=0"),
        "{lines:?}"
    );
    let refused = run(&["diag", "nat-filter", "catch", "--target", "127.0.0.1:0"])
        .await
        .unwrap_err();
    assert!(refused.contains("unicast IPv4 address"), "{refused}");
}

#[tokio::test]
async fn diag_nat_filter_listen_needs_the_bootstrap_hosts_of_a_public_configuration() {
    let fixture = Fixture::new();
    run(&["init", "--dir", fixture.dir(), "--private"])
        .await
        .unwrap();
    let direct_only = run(&["diag", "nat-filter", "listen", "--dir", fixture.dir()])
        .await
        .unwrap_err();
    assert!(
        direct_only.contains("no DHT bootstrap hosts"),
        "{direct_only}"
    );
}

#[test]
fn diag_port_map_takes_the_first_port_of_the_set_by_default_or_a_given_port() {
    assert_eq!(
        parsed(&["diag", "port-map"]),
        Invocation::DiagPortMap {
            port: shaar::network::ports::PORTS[0],
            show_address: false,
        }
    );
    assert_eq!(
        parsed(&["diag", "port-map", "--port", "48896", "--show-address"]),
        Invocation::DiagPortMap {
            port: 48_896,
            show_address: true,
        }
    );
    for bad in [
        &["diag", "port-map", "--port", "0"][..],
        &["diag", "port-map", "--port", "65536"],
        &["diag", "port-map", "--port", "many"],
        &["diag", "port-map", "extra"],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
}
