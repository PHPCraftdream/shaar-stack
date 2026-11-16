//! Oracle unit checks, not substitutes for the real two-session forwarding case.

use super::*;

fn role_history_with_controls() -> RoleHistory {
    let mut history = RoleHistory::new();
    history.path(
        iroh::endpoint::PathId::ZERO,
        &TransportAddr::Relay("https://relay.invalid".parse().expect("fixture relay URL")),
    );
    history.path(
        iroh::endpoint::PathId::from(1_u32),
        &TransportAddr::Custom(iroh_base::CustomAddr::from_parts(7, &[1])),
    );
    let native = history.path(
        iroh::endpoint::PathId::from(2_u32),
        &TransportAddr::Ip("127.0.0.1:443".parse().expect("fixture native address")),
    );
    let mut stats = PathStats::default();
    stats.frame_tx.stream = 1;
    stats.frame_rx.stream = 1;
    history.stats(native, &stats);
    history
}

fn terminal_paths_with_control_native() -> Vec<(iroh::endpoint::PathId, PathStats)> {
    let mut relay = PathStats::default();
    relay.frame_tx.crypto = 1;
    let mut native = PathStats::default();
    native.frame_tx.stream = 1;
    native.frame_rx.stream = 1;
    vec![
        (iroh::endpoint::PathId::ZERO, relay),
        (iroh::endpoint::PathId::from(1_u32), PathStats::default()),
        (iroh::endpoint::PathId::from(2_u32), native),
    ]
}

#[test]
fn unknown_terminal_control_path_is_retained_with_independent_controls() {
    let mut history = role_history_with_controls();
    let mut unknown = PathStats::default();
    unknown.frame_tx.crypto = 1;
    history.terminal_parts(
        terminal_paths_with_control_native()
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(3_u32), unknown)]),
        1,
        0,
    );
    assert_eq!(history.paths.len(), 4);
    let unclassified = history
        .paths
        .iter()
        .find(|path| path.id == iroh::endpoint::PathId::from(3_u32))
        .expect("terminal receipt path retained");
    assert!(unclassified.remote.is_none());
    assert!(unclassified.terminal_seen);
    assert!(history.custom && history.native_tx && history.native_rx);
}

#[test]
#[should_panic(expected = "application frames crossed unclassified path")]
fn unknown_terminal_stream_tx_is_rejected() {
    let mut history = role_history_with_controls();
    let mut unknown = PathStats::default();
    unknown.frame_tx.stream = 1;
    history.terminal_parts(
        terminal_paths_with_control_native()
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(3_u32), unknown)]),
        2,
        0,
    );
}

#[test]
#[should_panic(expected = "application frames crossed unclassified path")]
fn unknown_terminal_datagram_tx_is_rejected() {
    let mut history = role_history_with_controls();
    let mut unknown = PathStats::default();
    unknown.frame_tx.datagram = 1;
    history.terminal_parts(
        terminal_paths_with_control_native()
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(3_u32), unknown)]),
        1,
        1,
    );
}

#[test]
fn unknown_terminal_rx_is_the_peers_tx_and_is_not_rejected() {
    // Regression of FLAKE-W1: a path that closed before iroh registered its address carries
    // only RX in its terminal snapshot; the peer's own oracle bounds the matching TX.
    for (stream_rx, datagram_rx) in [(75, 0), (0, 3), (75, 3)] {
        let mut history = role_history_with_controls();
        let mut unknown = PathStats::default();
        unknown.frame_rx.stream = stream_rx;
        unknown.frame_rx.datagram = datagram_rx;
        history.terminal_parts(
            terminal_paths_with_control_native()
                .into_iter()
                .chain([(iroh::endpoint::PathId::from(3_u32), unknown)]),
            1,
            0,
        );
        assert!(history.paths[3].remote.is_none() && history.paths[3].terminal_seen);
    }
}

#[test]
fn unknown_terminal_stream_rx_supplies_the_native_receive_half() {
    // The observed FLAKE-W1 shape: the classified native path only transmitted.
    let mut history = RoleHistory::new();
    history.path(
        iroh::endpoint::PathId::ZERO,
        &TransportAddr::Custom(iroh_base::CustomAddr::from_parts(7, &[1])),
    );
    history.path(
        iroh::endpoint::PathId::from(1_u32),
        &TransportAddr::Ip("127.0.0.1:443".parse().expect("fixture native address")),
    );
    let mut sent = PathStats::default();
    sent.frame_tx.stream = 5;
    let mut received = PathStats::default();
    received.frame_rx.stream = 75;
    history.terminal_parts(
        [
            (iroh::endpoint::PathId::ZERO, PathStats::default()),
            (iroh::endpoint::PathId::from(1_u32), sent),
            (iroh::endpoint::PathId::from(2_u32), received),
        ],
        5,
        0,
    );
    assert!(history.native_tx && history.native_rx);
}

#[test]
#[should_panic(expected = "no native STREAM round trip observed")]
fn unknown_terminal_datagram_rx_is_not_native_stream_evidence() {
    let mut history = RoleHistory::new();
    history.path(
        iroh::endpoint::PathId::ZERO,
        &TransportAddr::Custom(iroh_base::CustomAddr::from_parts(7, &[1])),
    );
    history.path(
        iroh::endpoint::PathId::from(1_u32),
        &TransportAddr::Ip("127.0.0.1:443".parse().expect("fixture native address")),
    );
    let mut sent = PathStats::default();
    sent.frame_tx.stream = 5;
    let mut received = PathStats::default();
    received.frame_rx.datagram = 9;
    history.terminal_parts(
        [
            (iroh::endpoint::PathId::ZERO, PathStats::default()),
            (iroh::endpoint::PathId::from(1_u32), sent),
            (iroh::endpoint::PathId::from(2_u32), received),
        ],
        5,
        0,
    );
}

#[test]
#[should_panic(expected = "duplicate terminal path statistics")]
fn duplicate_terminal_path_id_is_rejected() {
    let mut history = role_history_with_controls();
    let receipt = terminal_paths_with_control_native();
    history.terminal_parts(
        receipt
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(2_u32), PathStats::default())]),
        1,
        0,
    );
}

#[test]
#[should_panic(expected = "observed path has no final statistics")]
fn observed_path_without_any_final_stats_is_rejected() {
    let mut history = role_history_with_controls();
    history.terminal_parts(
        terminal_paths_with_control_native().into_iter().take(2),
        1,
        0,
    );
}

#[test]
#[should_panic(expected = "incomplete STREAM TX history")]
fn terminal_path_tx_must_conserve_connection_stream_total() {
    let mut history = role_history_with_controls();
    history.terminal_parts(terminal_paths_with_control_native(), 2, 0);
}

#[test]
#[should_panic(expected = "no actual custom signaling path was observed")]
fn unknown_terminal_control_stats_cannot_supply_custom_evidence() {
    let mut history = RoleHistory::new();
    history.path(
        iroh::endpoint::PathId::ZERO,
        &TransportAddr::Relay("https://relay.invalid".parse().expect("fixture relay URL")),
    );
    let native_index = history.path(
        iroh::endpoint::PathId::from(1_u32),
        &TransportAddr::Ip("127.0.0.1:443".parse().expect("fixture native address")),
    );
    let mut native_stats = PathStats::default();
    native_stats.frame_tx.stream = 1;
    native_stats.frame_rx.stream = 1;
    history.stats(native_index, &native_stats);
    let mut unknown = PathStats::default();
    unknown.frame_tx.crypto = 1;
    history.terminal_parts(
        [
            (iroh::endpoint::PathId::ZERO, PathStats::default()),
            (iroh::endpoint::PathId::from(1_u32), native_stats),
            (iroh::endpoint::PathId::from(2_u32), unknown),
        ],
        1,
        0,
    );
}

#[test]
#[should_panic(expected = "no native STREAM round trip observed")]
fn unknown_terminal_control_stats_cannot_supply_native_evidence() {
    let mut history = RoleHistory::new();
    history.path(
        iroh::endpoint::PathId::ZERO,
        &TransportAddr::Custom(iroh_base::CustomAddr::from_parts(7, &[1])),
    );
    history.path(
        iroh::endpoint::PathId::from(1_u32),
        &TransportAddr::Relay("https://relay.invalid".parse().expect("fixture relay URL")),
    );
    let mut unknown = PathStats::default();
    unknown.frame_tx.crypto = 1;
    history.terminal_parts(
        [
            (iroh::endpoint::PathId::ZERO, PathStats::default()),
            (iroh::endpoint::PathId::from(1_u32), PathStats::default()),
            (iroh::endpoint::PathId::from(2_u32), unknown),
        ],
        0,
        0,
    );
}

#[test]
fn closed_event_final_stats_cover_path_absent_from_terminal_receipt() {
    let mut history = role_history_with_controls();
    let mut closed = PathStats::default();
    closed.frame_tx.crypto = 1;
    let closed_index = history.path(
        iroh::endpoint::PathId::from(3_u32),
        &TransportAddr::Relay("https://closed.invalid".parse().expect("fixture relay URL")),
    );
    history.stats(closed_index, &closed);
    history.paths[closed_index].final_stats = Some(closed);
    let receipt = terminal_paths_with_control_native();
    history.terminal_parts(receipt, 1, 0);
    assert_eq!(
        history.paths[closed_index].final_stats,
        Some(closed),
        "previous close-event stats remain available when terminal receipt omits that ID"
    );
}

#[test]
#[should_panic(expected = "incomplete DATAGRAM TX history")]
fn terminal_path_tx_must_conserve_connection_datagram_total() {
    let mut history = role_history_with_controls();
    history.terminal_parts(terminal_paths_with_control_native(), 1, 1);
}

#[test]
#[should_panic(expected = "path-history bound exceeded")]
fn terminal_history_bound_includes_unknown_paths() {
    let mut history = role_history_with_controls();
    let paths = terminal_paths_with_control_native()
        .into_iter()
        .chain((3_u32..17_u32).map(|id| (iroh::endpoint::PathId::from(id), PathStats::default())))
        .collect::<Vec<_>>();
    history.terminal_parts(paths, 1, 0);
}

#[test]
#[should_panic(expected = "application frames crossed signaling path")]
fn role_frame_oracle_rejects_relay_stream_tx() {
    let mut stats = PathStats::default();
    stats.frame_tx.stream = 1;
    role_history_with_controls().stats(0, &stats);
}

#[test]
#[should_panic(expected = "application frames crossed signaling path")]
fn role_frame_oracle_rejects_relay_datagram_rx() {
    let mut stats = PathStats::default();
    stats.frame_rx.datagram = 1;
    role_history_with_controls().stats(0, &stats);
}

#[test]
fn role_frame_oracle_accepts_control_only_stats() {
    let mut stats = PathStats::default();
    stats.frame_tx.crypto = 1;
    stats.frame_rx.acks = 1;
    role_history_with_controls().stats(0, &stats);
}

#[test]
fn unclassified_path_failure_names_the_path_its_stats_and_the_known_paths() {
    let mut history = role_history_with_controls();
    let mut unknown = PathStats::default();
    unknown.frame_tx.stream = 12;
    let id = iroh::endpoint::PathId::from(3_u32);
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        history.terminal_parts(
            terminal_paths_with_control_native()
                .into_iter()
                .chain([(id, unknown)]),
            12,
            0,
        );
    }))
    .expect_err("APP frames on an unclassified path are rejected");
    let message = failure
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            failure
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
        })
        .expect("assertion message");
    assert!(
        message.contains("application frames crossed unclassified path"),
        "{message}"
    );
    assert!(message.contains(&format!("{id:?}")), "{message}");
    assert!(message.contains("known paths"), "{message}");
    assert!(
        message.contains(&format!("{:?}", iroh::endpoint::PathId::ZERO)),
        "{message}"
    );
}
