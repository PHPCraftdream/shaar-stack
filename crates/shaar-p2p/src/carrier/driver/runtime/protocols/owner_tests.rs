use super::*;
use tokio::sync::oneshot;

#[tokio::test(flavor = "current_thread")]
async fn discovery_dial_preserves_original_options_and_rejects_wrong_root_before_io() {
    let seed = Keypair::generate_ed25519().public().to_peer_id();
    let candidate = Keypair::generate_ed25519().public().to_peer_id();
    let config = DiscoveryConfig::new(
        vec![(seed, "/dns4/owned.example./tcp/4001".parse().unwrap())],
        vec!["127.0.0.1:53".parse().unwrap()],
    )
    .unwrap();
    let (mut carrier, _handle, _incoming) = Carrier::bind_with_discovery(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        config,
    )
    .unwrap();
    let (reply, result) = oneshot::channel();
    carrier.core.start_discovery(reply);
    let operation = carrier.core.discovery_operation.as_ref().unwrap();
    let epoch = operation.epoch;
    let deadline = operation.deadline;
    let root = format!("/dns4/owned.example./tcp/4002/p2p/{candidate}")
        .parse()
        .unwrap();
    let wrong = format!("/dns4/other.example./tcp/4002/p2p/{candidate}")
        .parse()
        .unwrap();
    let options = DialOpts::peer_id(candidate).addresses(vec![wrong]).build();
    let connection = options.connection_id();
    let key = carrier
        .core
        .stage_discovery_dial(&options, &root, epoch, deadline)
        .unwrap();
    assert_eq!(key.connection, connection);
    assert!(carrier.core.submit_native(options, Some(key)).is_err());
    assert!(
        carrier
            .core
            .discovery_matching_control(epoch, candidate, connection)
            .is_none()
    );
    let view = carrier
        .core
        .swarm
        .behaviour()
        .inner
        .admission
        .roles_view()
        .unwrap();
    assert!(view.attempt_for_connection(connection).is_none());
    assert_eq!(view.role(candidate), None);
    drop(result);
    carrier.run(async {}).await.unwrap();
    view.join_infrastructure_release().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn discovery_completion_retires_expired_epoch_before_reply_even_without_timer_dispatch() {
    let seed = Keypair::generate_ed25519().public().to_peer_id();
    let config = DiscoveryConfig::new(
        vec![(seed, "/dns4/owned.example./tcp/4001".parse().unwrap())],
        vec!["127.0.0.1:53".parse().unwrap()],
    )
    .unwrap();
    let (mut carrier, _handle, _incoming) = Carrier::bind_with_discovery(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        config,
    )
    .unwrap();
    let (reply, mut result) = oneshot::channel();
    carrier.core.start_discovery(reply);
    let operation = carrier.core.discovery_operation.as_ref().unwrap();
    let epoch = operation.epoch;
    let deadline = operation.deadline;
    let view = carrier
        .core
        .swarm
        .behaviour()
        .inner
        .admission
        .roles_view()
        .unwrap();
    carrier.core.complete_discovery_if_ready();
    assert!(matches!(
        result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    tokio::time::advance(deadline - Instant::now()).await;
    // A selected protocol event may run before the ready timer branch.
    carrier.core.complete_discovery_if_ready();
    assert_eq!(
        result.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(carrier.core.discovery_operation.is_none());
    assert!(!view.discovery_epoch_active(epoch, Instant::now()));
    assert!(
        carrier
            .core
            .discovery_owned_controls(epoch)
            .into_iter()
            .flatten()
            .all(|control| !control.live && !control.pending)
    );
    carrier.run(async {}).await.unwrap();
    view.join_infrastructure_release().await;
}
