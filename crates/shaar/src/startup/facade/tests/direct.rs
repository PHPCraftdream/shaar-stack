//! The direct shape end to end over loopback QUIC: a handler and a fixed TCP target
//! serve exact bytes, and a key outside the allowlist reaches neither.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

use super::identity;
use crate::network::ServiceStream;
use crate::startup::facade::{
    AllowList, Client, PeerKey, RunningClient, RunningServer, SdkError, Server,
};

const WAIT: Duration = Duration::from_secs(20);

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn key(seed: u8) -> PeerKey {
    PeerKey::of(&identity(seed))
}

/// Server seed 1 admits client seed 2 only.
fn server_builder() -> crate::startup::facade::ServerBuilder {
    Server::builder(identity(1))
        .allow(AllowList::new([key(2)]).unwrap())
        .bind(loopback())
}

async fn client_of(seed: u8, server: &RunningServer) -> Result<RunningClient, SdkError> {
    let address = server
        .local_addr()
        .expect("a started Server has an address");
    Client::builder(identity(seed), server.address())
        .server_address(address)
        .build()
        .expect("client builds")
        .start()
        .await
}

/// One request/response on a fresh stream: write and finish while reading to the end,
/// so a reply larger than the flow-control window cannot deadlock the exchange.
async fn exchange(client: &RunningClient, request: &[u8]) -> Vec<u8> {
    let stream = timeout(WAIT, client.connect())
        .await
        .expect("stream opens in time")
        .expect("stream opens");
    let (mut read, mut write) = tokio::io::split(stream);
    let writing = async {
        write.write_all(request).await.unwrap();
        write.shutdown().await.unwrap();
    };
    let reading = async {
        let mut reply = Vec::new();
        read.read_to_end(&mut reply).await.unwrap();
        reply
    };
    let ((), reply) = timeout(WAIT, async { tokio::join!(writing, reading) })
        .await
        .expect("exchange in time");
    reply
}

/// A TCP echo service; the counter records accepted connections.
async fn echo_target() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(loopback()).await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let (mut read, mut write) = stream.into_split();
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    (address, accepted)
}

/// A handler that answers `pong:<request>:<peer key>` and counts its calls.
fn pong_handler(
    calls: Arc<AtomicUsize>,
) -> impl Fn(PeerKey, ServiceStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
+ Send
+ Sync
+ 'static {
    move |peer, mut stream| {
        let calls = Arc::clone(&calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            let mut reply = b"pong:".to_vec();
            reply.extend(request);
            reply.extend(format!(":{peer}").bytes());
            stream.write_all(&reply).await.unwrap();
            stream.shutdown().await.unwrap();
        })
    }
}

#[test]
fn the_handles_can_move_between_threads() {
    fn assert_send<T: Send>() {}
    assert_send::<RunningServer>();
    assert_send::<RunningClient>();
    assert_send::<Server>();
    assert_send::<Client>();
}

#[tokio::test]
async fn a_handler_answers_an_admitted_client_with_the_authenticated_key() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_builder()
        .handler(pong_handler(Arc::clone(&calls)))
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    assert_eq!(server.address(), key(1));
    let client = client_of(2, &server).await.unwrap();
    assert_eq!(client.server(), key(1));
    assert_eq!(
        exchange(&client, b"ping").await,
        format!("pong:ping:{}", key(2)).into_bytes()
    );
    // A second stream on the same session, sequentially and concurrently.
    assert_eq!(
        exchange(&client, b"").await,
        format!("pong::{}", key(2)).into_bytes()
    );
    let (a, b) = tokio::join!(exchange(&client, b"a"), exchange(&client, b"b"));
    assert_eq!(a, format!("pong:a:{}", key(2)).into_bytes());
    assert_eq!(b, format!("pong:b:{}", key(2)).into_bytes());
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_fixed_target_echoes_the_exact_bytes() {
    let (target, accepted) = echo_target().await;
    let server = server_builder()
        .forward_to(target)
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    let client = client_of(2, &server).await.unwrap();
    let payload: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
    assert_eq!(exchange(&client, &payload).await, payload);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_key_outside_the_allowlist_reaches_neither_the_handler_nor_the_target() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (target, accepted) = echo_target().await;
    let handled = server_builder()
        .handler(pong_handler(Arc::clone(&calls)))
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    let forwarded = server_builder()
        .forward_to(target)
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    for server in [&handled, &forwarded] {
        // Client seed 3 is not allowlisted: the start or the first stream is refused.
        match client_of(3, server).await {
            Err(error) => assert!(matches!(error, SdkError::Network(_)), "{error}"),
            Ok(client) => {
                let result = timeout(WAIT, client.connect()).await.expect("answers");
                assert!(result.is_err(), "a denied client must not get a stream");
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    // The allowlisted client still works on the same Servers.
    let client = client_of(2, &forwarded).await.unwrap();
    assert_eq!(exchange(&client, b"ok").await, b"ok");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    handled.shutdown().await.unwrap();
    forwarded.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_panicking_handler_ends_its_stream_only() {
    let first = Arc::new(AtomicBool::new(true));
    let server = server_builder()
        .handler(move |_peer: PeerKey, mut stream: ServiceStream| {
            let first = Arc::clone(&first);
            async move {
                assert!(!first.swap(false, Ordering::SeqCst), "first stream panics");
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                stream.write_all(&request).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        })
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    let mut server = server;
    let client = client_of(2, &server).await.unwrap();
    // The first stream is reset by the handler's panic; its outcome is not asserted.
    let _ = timeout(WAIT, async {
        let mut stream = client.connect().await.unwrap();
        stream.write_all(b"x").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink).await;
    })
    .await;
    assert_eq!(exchange(&client, b"alive").await, b"alive");
    assert!(
        timeout(Duration::from_millis(300), server.wait())
            .await
            .is_err(),
        "the Server must keep running"
    );
    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_ends_the_server_and_later_streams_fail() {
    let (target, _) = echo_target().await;
    let server = server_builder()
        .forward_to(target)
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    let client = client_of(2, &server).await.unwrap();
    assert_eq!(exchange(&client, b"up").await, b"up");
    server.shutdown().await.unwrap();
    let late = timeout(WAIT, client.connect()).await.expect("answers");
    assert!(late.is_err(), "a stopped Server serves nothing");
    // The Client notices the lost session and ends with an error.
    let mut client = client;
    let outcome = timeout(WAIT, client.wait()).await.expect("ends");
    assert!(outcome.is_err());
}

#[tokio::test]
async fn run_serves_on_the_callers_runtime_until_the_shutdown_future_completes() {
    let (target, _) = echo_target().await;
    let server = server_builder().forward_to(target).build().unwrap();
    let outcome = timeout(
        WAIT,
        server.run(tokio::time::sleep(Duration::from_millis(300))),
    )
    .await
    .expect("ends at the shutdown future");
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn the_direct_client_can_also_listen_for_local_tcp_connections() {
    let (target, accepted) = echo_target().await;
    let server = server_builder()
        .forward_to(target)
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    let client = Client::builder(identity(2), server.address())
        .server_address(server.local_addr().unwrap())
        .listen(loopback())
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    let listen = client.local_addr().expect("a listener was requested");
    assert!(listen.ip().is_loopback() && listen.port() != 0);
    let mut local = timeout(WAIT, tokio::net::TcpStream::connect(listen))
        .await
        .expect("connects in time")
        .unwrap();
    local.write_all(b"via tcp").await.unwrap();
    local.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(WAIT, local.read_to_end(&mut reply))
        .await
        .expect("reply")
        .unwrap();
    assert_eq!(reply, b"via tcp");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}
