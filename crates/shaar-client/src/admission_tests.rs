use super::*;

#[tokio::test]
async fn admission_gate_prefers_closed_session_when_both_branches_are_ready() {
    let client_identity = Identity::from_seed([111; 32]);
    let server_identity = Identity::from_seed([112; 32]);
    let client = Endpoint::bind(
        &client_identity,
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::default(),
        Limits::new(1).unwrap(),
    )
    .await
    .unwrap();
    let mut server = Endpoint::bind(
        &server_identity,
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::new(&[client.id()]).unwrap(),
        Limits::new(1).unwrap(),
    )
    .await
    .unwrap();
    let (client_session, server_session) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::try_join!(
            client.connect(server.id(), server.local_addr()),
            server.accept(),
        )
        .unwrap()
    })
    .await
    .expect("concurrent SDK handshake deadline");

    // Observe the SDK event first, then poll the exact production admission gate.
    // At that point both gate branches are ready; biased selection must reject.
    server_session.close();
    assert!(matches!(
        client_session.closed().await,
        NetworkError::Closed
    ));
    assert!(!admission_live(&client_session).await);

    client_session.close();
    client.close().await;
    server.close().await;
}
