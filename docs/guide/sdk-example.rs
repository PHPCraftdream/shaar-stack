#![forbid(unsafe_code)]
//! The SDK in one function: a Server with an in-process handler, a Client that reaches it by
//! the Server's key, and one exact exchange (direct shape, loopback).
//!
//! The tests of `shaar` compile and run this file verbatim
//! (`startup::facade::tests::guide`). In an application the identities come from key files
//! (`Identity::load_or_create`) and the Server address is handed to the Client's operator.

use shaar::identity::Identity;
use shaar::{AllowList, Client, PeerKey, SdkError, Server, ServiceStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Starts a Server and a Client, sends `ping`, and returns the Server's reply.
pub async fn echo() -> Result<String, SdkError> {
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();
    let server_address = PeerKey::of(&server_identity);
    let client_key = PeerKey::of(&client_identity);

    // The Server admits exactly one Client key and answers every stream itself.
    let server = Server::builder(server_identity)
        .allow(AllowList::new([client_key])?)
        .bind("127.0.0.1:0".parse().expect("a socket address"))
        .handler(|peer: PeerKey, mut stream: ServiceStream| async move {
            let mut request = Vec::new();
            if stream.read_to_end(&mut request).await.is_ok() {
                let reply = format!("hello {peer}: {}", String::from_utf8_lossy(&request));
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        })
        .build()?
        .start()
        .await?;

    // The Client knows the Server's key and, in the direct shape, where to dial.
    let client = Client::builder(client_identity, server_address)
        .server_address(
            server
                .local_addr()
                .expect("a started Server has an address"),
        )
        .build()?
        .start()
        .await?;

    let mut stream = client.connect().await?;
    stream.write_all(b"ping").await?;
    stream.shutdown().await?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await?;

    client.shutdown().await?;
    server.shutdown().await?;
    Ok(reply)
}
