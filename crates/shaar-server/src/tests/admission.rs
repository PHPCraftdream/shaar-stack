use std::time::Duration;

use iroh_base::PublicKey;
use shaar::{
    identity::Identity,
    network::{Allowlist, Endpoint, ForwardError, Limits, NetworkError},
};
use tokio::time::timeout;

fn key(seed: u8) -> PublicKey {
    PublicKey::from_bytes(&Identity::from_seed([seed; 32]).public_key_bytes()).unwrap()
}

#[tokio::test]
async fn denied_authenticated_peer_never_gets_a_session() {
    timeout(Duration::from_secs(10), async {
        let identity = Identity::from_seed([91; 32]);
        let mut server = Endpoint::bind(
            &identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::new(&[]).unwrap(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let client = Endpoint::bind(
            &Identity::from_seed([92; 32]),
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::new(&[]).unwrap(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let address = server.local_addr();
        let (accepted, connected) = tokio::join!(server.accept(), client.connect(key(91), address));
        assert!(matches!(accepted, Err(NetworkError::AccessDenied)));
        match connected {
            Ok(session) => {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let (app, bridge) = tokio::join!(
                    tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
                    listener.accept()
                );
                assert!(matches!(
                    session.forward(bridge.unwrap().0).await,
                    Err(ForwardError::AccessDenied)
                ));
                drop(app.unwrap());
            }
            Err(error) => assert!(matches!(error, NetworkError::AccessDenied)),
        }
        server.close().await;
        client.close().await;
    })
    .await
    .expect("admission deadline");
}
