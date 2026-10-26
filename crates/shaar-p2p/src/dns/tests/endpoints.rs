use super::{support::*, *};
use hickory_resolver::net::runtime::DnsUdpSocket;

#[tokio::test]
async fn owned_dns_same_port_different_ip_is_denied_at_bind_connect_and_every_send() {
    bounded(
        async {
            let server = Server::new().await;
            let other = SocketAddr::new("127.0.0.2".parse().unwrap(), server.address.port());
            assert_ne!(other.ip(), server.address.ip());
            assert_eq!(other.port(), server.address.port());
            let (executor, lifetime, _resolver, provider) = setup(server.address);
            assert_eq!(
                provider
                    .bind_udp(loopback(), other)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::PermissionDenied,
                "DNS_BIND_CHECKED_ONLY_PORT"
            );
            assert_eq!(
                provider
                    .connect_tcp(other, None, None)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::PermissionDenied,
                "DNS_CONNECT_CHECKED_ONLY_PORT"
            );
            let socket = provider.bind_udp(loopback(), server.address).await.unwrap();
            let mut buffer = [0; 32];
            for _ in 0..2 {
                assert_eq!(
                    socket.send_to(b"denied", other).await.unwrap_err().kind(),
                    io::ErrorKind::PermissionDenied,
                    "DNS_SEND_CHECKED_ONLY_PORT"
                );
                socket.send_to(b"approved", server.address).await.unwrap();
                let (size, _) = server.udp.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..size], b"approved");
            }
            lifetime.close();
            drop(socket);
            executor.shutdown().await.unwrap();
            server.quiet();
        },
        "OWNED_DNS_ENDPOINT_IP_DENIAL_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_occupied_local_binds_and_incompatible_socket_families_fail() {
    bounded(
        async {
            let v6: SocketAddr = "[::1]:0".parse().unwrap();
            for (local, incompatible) in [(loopback(), v6), (v6, loopback())] {
                let server = Server::bind(local).await.unwrap();
                let occupied = Server::bind(local).await.unwrap();
                let (executor, lifetime, _resolver, provider) = setup(server.address);
                assert_eq!(
                    provider
                        .bind_udp(occupied.address, server.address)
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::AddrInUse,
                    "DNS_UDP_OCCUPIED_BIND_ACCEPTED"
                );
                assert_eq!(
                    provider
                        .connect_tcp(server.address, Some(occupied.address), None)
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::AddrInUse,
                    "DNS_TCP_OCCUPIED_BIND_ACCEPTED"
                );
                let error = provider
                    .connect_tcp(server.address, Some(incompatible), None)
                    .await
                    .err()
                    .expect("incompatible TCP local family accepted");
                assert_ne!(error.kind(), io::ErrorKind::TimedOut);
                assert_ne!(error.kind(), io::ErrorKind::PermissionDenied);
                // UDP bind is unconnected; the incompatible family fails at its actual send.
                let socket = provider
                    .bind_udp(incompatible, server.address)
                    .await
                    .unwrap();
                assert_ne!(
                    socket.socket.local_addr().unwrap().is_ipv4(),
                    server.address.is_ipv4()
                );
                let error = socket
                    .send_to(b"incompatible family", server.address)
                    .await
                    .unwrap_err();
                assert_ne!(error.kind(), io::ErrorKind::PermissionDenied);
                assert_ne!(error.kind(), io::ErrorKind::TimedOut);
                lifetime.close();
                drop(socket);
                executor.shutdown().await.unwrap();
                server.quiet();
            }
        },
        "OWNED_DNS_LOCAL_BIND_FAILURE_DEADLINE",
    )
    .await;
}
