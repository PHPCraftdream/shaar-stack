use super::profile_tests::header;
use crate::{
    OwnedExecutor,
    dns::{
        Lifetime, OwnedResolver,
        runtime::Provider,
        sockets::Tcp,
        tests::support::{Server, bounded, loopback, response},
    },
};
use futures::{
    FutureExt, StreamExt,
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
};
use hickory_resolver::{
    net::runtime::{DnsUdpSocket, RuntimeProvider, Spawn, iocompat::AsyncIoTokioAsStd},
    proto::{
        op::ResponseCode,
        rr::{RData, rdata::A},
    },
};
use libp2p::dns::Resolver as _;
use std::{future::poll_fn, io, pin::Pin, task::Poll};
use tokio::net::{TcpListener, UdpSocket};

fn setup(address: std::net::SocketAddr) -> (OwnedExecutor, Lifetime, Provider) {
    let executor = OwnedExecutor::new();
    let lifetime = Lifetime::new();
    let provider = Provider::new(lifetime.gate(), executor.handle(), &[address]);
    (executor, lifetime, provider)
}

/// cancel-safe: yes — owns the unpublished connected sockets until returning both.
async fn pair(
    provider: &Provider,
    listener: &TcpListener,
) -> (Tcp, AsyncIoTokioAsStd<tokio::net::TcpStream>) {
    let address = listener.local_addr().unwrap();
    let (client, accepted) =
        futures::join!(provider.connect_tcp(address, None, None), listener.accept());
    (client.unwrap(), AsyncIoTokioAsStd(accepted.unwrap().0))
}

/// cancel-safe: yes — consumed bytes remain in the production socket's staging.
async fn stage(socket: &mut Tcp, expected: usize, prefix: &mut [u8; 2]) {
    poll_fn(|cx| {
        assert!(Pin::new(&mut *socket).poll_read(cx, prefix).is_pending());
        if socket.input.staged_len() == expected {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

fn frame(length: u16) -> Vec<u8> {
    let mut bytes = vec![0; usize::from(length) + 2];
    bytes[..2].copy_from_slice(&length.to_be_bytes());
    bytes
}

#[tokio::test]
async fn wire_dns_native_udp_length_count_and_kernel_truncation_boundaries() {
    bounded(
        async {
            for local in ["127.0.0.1:0", "[::1]:0"] {
                let server = UdpSocket::bind(local).await.unwrap();
                let address = server.local_addr().unwrap();
                let (executor, _lifetime, provider) = setup(address);
                let socket = provider
                    .bind_udp(local.parse().unwrap(), address)
                    .await
                    .unwrap();
                let destination = socket.socket.local_addr().unwrap();
                // 8192 exceeds the 4097-byte receive buffer: WSAEMSGSIZE on Windows,
                // successful truncation on Linux. Neither may poison the next response.
                for bad in [
                    vec![0; 11],
                    vec![0; 4097],
                    vec![0; 8192],
                    header(2, 0, 0, 0).to_vec(),
                    header(1, 65535, 1, 0).to_vec(),
                ] {
                    server.send_to(&bad, destination).await.unwrap();
                    let mut valid = header(0, 0, 0, 0);
                    valid[0] = 42;
                    server.send_to(&valid, destination).await.unwrap();
                    let mut output = [0x55; 4096];
                    let (length, source) = socket.recv_from(&mut output).await.unwrap();
                    assert_eq!(source, address);
                    assert_eq!(length, 12);
                    assert_eq!(&output[..length], valid);
                }
                for length in [12, 4096] {
                    let mut valid = vec![0; length];
                    valid[0] = 99;
                    server.send_to(&valid, destination).await.unwrap();
                    let mut output = [0; 4096];
                    let (received, source) = socket.recv_from(&mut output).await.unwrap();
                    assert_eq!(received, length);
                    assert_eq!(source, address);
                    assert_eq!(&output[..received], valid);
                }
                drop(socket);
                executor.shutdown().await.unwrap();
            }
        },
        "WIRE_NATIVE_UDP_BOUNDARY_DEADLINE",
    )
    .await;
}

const SOURCE_PAIR_ATTEMPTS: usize = 16;

/// cancel-safe: yes — retains the first socket until the second bind completes.
async fn source_pair<F: std::future::Future<Output = io::Result<UdpSocket>>>(
    mut bind_second: impl FnMut(std::net::SocketAddr) -> F,
) -> io::Result<(UdpSocket, UdpSocket)> {
    for _ in 0..SOURCE_PAIR_ATTEMPTS {
        let first = match UdpSocket::bind(loopback()).await {
            Ok(socket) => socket,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => return Err(error),
        };
        let second = std::net::SocketAddr::from((
            std::net::Ipv4Addr::new(127, 0, 0, 2),
            first.local_addr()?.port(),
        ));
        match bind_second(second).await {
            Ok(second) => return Ok((first, second)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "DNS source fixture UDP pair allocation exhausted",
    ))
}

#[tokio::test]
async fn wire_dns_native_udp_pair_retries_real_second_address_collision() {
    bounded(
        async {
            let forced = std::cell::Cell::new(false);
            let attempts = std::cell::Cell::new(0);
            let (first, second) = source_pair(|address| {
                attempts.set(attempts.get() + 1);
                let forced = &forced;
                async move {
                    let first_address =
                        std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, address.port()));
                    assert_eq!(
                        UdpSocket::bind(first_address).await.unwrap_err().kind(),
                        io::ErrorKind::AddrInUse,
                        "SOURCE_PAIR_FIRST_SOCKET_RELEASED_EARLY",
                    );
                    if !forced.get() {
                        let occupied = UdpSocket::bind(address).await?;
                        let result = UdpSocket::bind(address).await;
                        assert_eq!(
                            result.as_ref().unwrap_err().kind(),
                            io::ErrorKind::AddrInUse
                        );
                        forced.set(true);
                        drop(occupied);
                        result
                    } else {
                        UdpSocket::bind(address).await
                    }
                }
            })
            .await
            .unwrap();
            assert!(forced.get(), "SECOND_ADDRESS_COLLISION_NOT_EXERCISED");
            assert!((2..=SOURCE_PAIR_ATTEMPTS).contains(&attempts.get()));
            assert_eq!(
                first.local_addr().unwrap().port(),
                second.local_addr().unwrap().port()
            );
            assert_eq!(
                first.local_addr().unwrap().ip(),
                std::net::Ipv4Addr::LOCALHOST
            );
            assert_eq!(
                second.local_addr().unwrap().ip(),
                std::net::Ipv4Addr::new(127, 0, 0, 2)
            );
        },
        "WIRE_SOURCE_PAIR_COLLISION_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn wire_dns_native_udp_pair_bounds_exhaustion_and_propagates_other_errors() {
    bounded(
        async {
            for kind in [
                io::ErrorKind::AddrInUse,
                io::ErrorKind::PermissionDenied,
                io::ErrorKind::AddrNotAvailable,
            ] {
                let attempts = std::cell::Cell::new(0);
                let result = source_pair(|address| {
                    attempts.set(attempts.get() + 1);
                    async move {
                        let first_address = std::net::SocketAddr::from((
                            std::net::Ipv4Addr::LOCALHOST,
                            address.port(),
                        ));
                        assert_eq!(
                            UdpSocket::bind(first_address).await.unwrap_err().kind(),
                            io::ErrorKind::AddrInUse
                        );
                        Err(io::Error::new(kind, "controlled second-address bind error"))
                    }
                })
                .await;
                let error = result.unwrap_err();
                assert_eq!(error.kind(), kind);
                if kind == io::ErrorKind::AddrInUse {
                    assert_eq!(attempts.get(), SOURCE_PAIR_ATTEMPTS);
                    assert_eq!(
                        error.to_string(),
                        "DNS source fixture UDP pair allocation exhausted"
                    );
                } else {
                    assert_eq!(attempts.get(), 1, "RETRIED_NON_COLLISION_BIND_ERROR");
                    assert_eq!(error.to_string(), "controlled second-address bind error");
                }
            }
        },
        "WIRE_SOURCE_PAIR_ERROR_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn wire_dns_native_udp_wrong_port_and_wrong_ip_are_discarded() {
    bounded(
        async {
            let (server, wrong_ip) = source_pair(UdpSocket::bind).await.unwrap();
            let address = server.local_addr().unwrap();
            let wrong_port = UdpSocket::bind(loopback()).await.unwrap();
            let (executor, _lifetime, provider) = setup(address);
            let socket = provider.bind_udp(loopback(), address).await.unwrap();
            let destination = socket.socket.local_addr().unwrap();
            for spoof in [&wrong_port, &wrong_ip] {
                spoof
                    .send_to(&header(0, 0, 0, 0), destination)
                    .await
                    .unwrap();
                spoof.send_to(&[0; 8192], destination).await.unwrap();
                let mut valid = header(0, 0, 0, 0);
                valid[0] = 77;
                server.send_to(&valid, destination).await.unwrap();
                let mut output = [0; 4096];
                let (length, source) = socket.recv_from(&mut output).await.unwrap();
                assert_eq!((length, source), (12, address));
                assert_eq!(&output[..length], valid);
            }
            drop(socket);
            executor.shutdown().await.unwrap();
        },
        "WIRE_NATIVE_UDP_SOURCE_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn wire_dns_native_tcp_consecutive_min_max_and_output_unchanged() {
    bounded(
        async {
            let listener = TcpListener::bind(loopback()).await.unwrap();
            let (executor, _lifetime, provider) = setup(listener.local_addr().unwrap());
            let (mut socket, mut peer) = pair(&provider, &listener).await;
            let expected = [frame(12), frame(4096), frame(12)].concat();
            let ((), ()) = futures::join!(
                async {
                    for fragment in expected.chunks(7) {
                        peer.write_all(fragment).await.unwrap();
                    }
                    peer.close().await.unwrap();
                    let mut sent = [0; 5];
                    peer.read_exact(&mut sent).await.unwrap();
                    assert_eq!(&sent, b"\0\x03out");
                },
                async {
                    socket.write_all(b"\0\x03out").await.unwrap();
                    socket.flush().await.unwrap();
                    let mut actual = Vec::new();
                    socket.read_to_end(&mut actual).await.unwrap();
                    assert_eq!(actual, expected);
                }
            );
            drop(socket);
            executor.shutdown().await.unwrap();
        },
        "WIRE_NATIVE_TCP_FRAMES_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn wire_dns_native_tcp_rejects_before_hickory_frame_materialization() {
    bounded(
        async {
            let listener = TcpListener::bind(loopback()).await.unwrap();
            let address = listener.local_addr().unwrap();
            let (executor, _lifetime, provider) = setup(address);
            for (length, counts) in [
                (11u16, header(0, 0, 0, 0)),
                (4097, header(0, 0, 0, 0)),
                (4096, header(1, 65535, 1, 0)),
            ] {
                let (socket, mut peer) = pair(&provider, &listener).await;
                let (mut stream, handle) =
                    hickory_resolver::net::tcp::TcpStream::from_stream(socket, address);
                peer.write_all(&length.to_be_bytes()).await.unwrap();
                if length == 4096 {
                    peer.write_all(&counts).await.unwrap();
                }
                // No body or EOF is supplied: waiting for an unchecked body cannot pass.
                let error = stream.next().await.unwrap().unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                drop(stream);
                drop(handle);
                let mut byte = [0];
                assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
            }
            executor.shutdown().await.unwrap();
        },
        "WIRE_HICKORY_PREALLOCATION_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn wire_dns_native_tcp_canceled_read_retains_staged_prefix_and_header() {
    bounded(
        async {
            let listener = TcpListener::bind(loopback()).await.unwrap();
            let (executor, _lifetime, provider) = setup(listener.local_addr().unwrap());
            for split in [1, 2, 7, 13] {
                let (mut socket, mut peer) = pair(&provider, &listener).await;
                let expected = frame(12);
                peer.write_all(&expected[..split]).await.unwrap();
                let mut prefix = [0x55; 2];
                stage(&mut socket, split, &mut prefix).await;
                assert_eq!(prefix, [0x55; 2], "NATIVE_PREFIX_EXPOSED_BEFORE_HEADER");
                assert_eq!(socket.read(&mut []).await.unwrap(), 0);
                peer.write_all(&expected[split..]).await.unwrap();
                let mut actual = [0; 14];
                socket.read_exact(&mut actual).await.unwrap();
                assert_eq!(actual.as_slice(), expected);
                peer.close().await.unwrap();
                assert_eq!(socket.read(&mut prefix).await.unwrap(), 0);
            }
            executor.shutdown().await.unwrap();
        },
        "WIRE_NATIVE_TCP_CANCELLATION_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn wire_dns_native_tcp_gate_closure_with_staged_header_releases_socket_on_join() {
    bounded(
        async {
            let listener = TcpListener::bind(loopback()).await.unwrap();
            let (executor, lifetime, provider) = setup(listener.local_addr().unwrap());
            let retained = provider.clone();
            let (mut socket, mut peer) = pair(&provider, &listener).await;
            peer.write_all(&frame(12)[..7]).await.unwrap();
            let (started, waiting) = tokio::sync::oneshot::channel();
            provider.create_handle().spawn_bg(async move {
                let mut prefix = [0x55; 2];
                stage(&mut socket, 7, &mut prefix).await;
                assert_eq!(prefix, [0x55; 2]);
                started.send(()).unwrap();
                let _ = socket.read(&mut prefix).await;
            });
            waiting.await.unwrap();
            lifetime.close();
            executor.shutdown().await.unwrap();
            let mut byte = [0];
            assert_eq!(
                peer.read(&mut byte).await.unwrap(),
                0,
                "STAGED_TCP_SOCKET_RETAINED"
            );
            assert_eq!(
                retained
                    .connect_tcp(listener.local_addr().unwrap(), None, None)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
        },
        "WIRE_STAGED_TCP_JOIN_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn wire_dns_native_udp_discard_wait_is_canceled_and_binding_released_on_join() {
    bounded(
        async {
            let server = UdpSocket::bind(loopback()).await.unwrap();
            let address = server.local_addr().unwrap();
            let (executor, lifetime, provider) = setup(address);
            let retained = provider.clone();
            let socket = provider.bind_udp(loopback(), address).await.unwrap();
            let local = socket.socket.local_addr().unwrap();
            assert_eq!(
                UdpSocket::bind(local).await.unwrap_err().kind(),
                io::ErrorKind::AddrInUse
            );
            server.send_to(&[0; 11], local).await.unwrap();
            socket.socket.readable().await.unwrap();
            let (started, waiting) = tokio::sync::oneshot::channel();
            provider.create_handle().spawn_bg(async move {
                let mut output = [0x55; 4096];
                poll_fn(|cx| {
                    assert!(socket.poll_recv_from(cx, &mut output).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert!(output.iter().all(|byte| *byte == 0x55));
                started.send(()).unwrap();
                let _ = socket.recv_from(&mut output).await;
            });
            waiting.await.unwrap();
            lifetime.close();
            executor.shutdown().await.unwrap();
            let rebound = UdpSocket::bind(local).await.unwrap();
            assert_eq!(rebound.local_addr().unwrap(), local);
            assert_eq!(
                retained
                    .bind_udp(loopback(), address)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
        },
        "WIRE_DISCARD_UDP_JOIN_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn wire_dns_native_closed_gate_does_not_release_prevalidated_staging() {
    bounded(
        async {
            let listener = TcpListener::bind(loopback()).await.unwrap();
            let (executor, lifetime, provider) = setup(listener.local_addr().unwrap());
            let (mut socket, mut peer) = pair(&provider, &listener).await;
            peer.write_all(&frame(12)).await.unwrap();
            let mut byte = [0];
            socket.read_exact(&mut byte).await.unwrap();
            lifetime.close();
            let mut output = [0x55; 32];
            assert_eq!(
                socket.read(&mut output).await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(output, [0x55; 32]);
            assert_eq!(
                socket.write(b"late").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            drop(socket);
            assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
            executor.shutdown().await.unwrap();
        },
        "WIRE_VALIDATED_GATE_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn wire_dns_native_resolver_invalid_before_valid_does_not_trigger_tcp_fallback() {
    bounded(
        async {
            let server = Server::new().await;
            let executor = OwnedExecutor::new();
            let (lifetime, resolver) =
                OwnedResolver::new(&[server.address], executor.handle()).unwrap();
            let retained = resolver.clone();
            let (answer, ()) =
                futures::join!(resolver.ipv4_lookup("wire.example.".into()), async {
                    let (query, destination) = server.question().await;
                    for mut bytes in [vec![0; 11], vec![0; 8192], header(1, 65535, 1, 0).to_vec()] {
                        bytes[..2].copy_from_slice(&query.metadata.id.to_be_bytes());
                        server.udp.send_to(&bytes, destination).await.unwrap();
                    }
                    // A malformed body with an unrelated ID must not poison this lookup.
                    let mut malformed = header(1, 0, 0, 0);
                    malformed[..2].copy_from_slice(&(query.metadata.id ^ 1).to_be_bytes());
                    server.udp.send_to(&malformed, destination).await.unwrap();
                    let valid = response(
                        &query,
                        Some(RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 42)))),
                        ResponseCode::NoError,
                    );
                    server
                        .udp
                        .send_to(&valid.to_vec().unwrap(), destination)
                        .await
                        .unwrap();
                });
            let answer = answer.unwrap();
            assert_eq!(
                answer.answers()[0].data,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 42)))
            );
            assert!(
                server.tcp.accept().now_or_never().is_none(),
                "INVALID_UDP_POISONED_LOOKUP"
            );
            lifetime.close();
            executor.shutdown().await.unwrap();
            assert!(retained.ipv4_lookup("late.example.".into()).await.is_err());
        },
        "WIRE_INVALID_BEFORE_VALID_LOOKUP_DEADLINE",
    )
    .await;
}
