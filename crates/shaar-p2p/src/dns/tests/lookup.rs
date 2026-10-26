use super::{support::*, *};
use futures::io::AsyncReadExt;
use hickory_resolver::{
    net::runtime::iocompat::AsyncIoTokioAsStd,
    proto::{
        op::ResponseCode,
        rr::{
            RData,
            rdata::{A, AAAA, TXT},
        },
    },
};
use libp2p::dns::Resolver as _;
use std::net::{Ipv4Addr, Ipv6Addr};

#[tokio::test]
async fn owned_dns_udp_a_aaaa_txt_and_zero_cache_use_only_the_custom_server() {
    bounded(
        async {
            let server = Server::new().await;
            let (executor, lifetime, resolver, _provider) = setup(server.address);
            let options = resolver.resolver.options();
            assert_eq!(options.cache_size, 0);
            assert!(matches!(options.use_hosts_file, ResolveHosts::Never));
            assert_eq!(options.attempts, 1);
            assert_eq!(options.num_concurrent_reqs, 1);
            assert_eq!(options.max_active_requests, 4);
            assert!(options.trust_anchor.is_none());
            server.quiet();
            for ip in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)] {
                let (result, _) = tokio::join!(
                    resolver.ipv4_lookup("owned.example.".into()),
                    server.answer(RData::A(A(ip)))
                );
                let result = result.unwrap();
                assert_eq!(
                    result.answers()[0].data,
                    RData::A(A(ip)),
                    "DISABLED_CACHE_REUSED_RESPONSE"
                );
            }
            let data = RData::AAAA(AAAA(Ipv6Addr::LOCALHOST));
            let (result, _) = tokio::join!(
                resolver.ipv6_lookup("v6.example.".into()),
                server.answer(data.clone())
            );
            assert_eq!(result.unwrap().answers()[0].data, data);
            let data = RData::TXT(TXT::new(vec!["dnsaddr=/ip4/127.0.0.1/tcp/4001".into()]));
            let (result, _) = tokio::join!(
                resolver.txt_lookup("_dnsaddr.owned.example.".into()),
                server.answer(data.clone())
            );
            assert_eq!(result.unwrap().answers()[0].data, data);
            lifetime.close();
            executor.shutdown().await.unwrap();
        },
        "OWNED_DNS_UDP_FIXTURE_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_truncated_udp_falls_back_to_pooled_tcp_and_join_closes_retained_provider() {
    bounded(
        async {
            let server = Server::new().await;
            let (executor, lifetime, resolver, provider) = setup(server.address);
            let clone = resolver.clone();
            let handle = provider.create_handle();
            let reply = async {
                let (query, source) = server.question().await;
                let mut truncated = response(&query, None, ResponseCode::NoError);
                truncated.metadata.truncation = true;
                server
                    .udp
                    .send_to(&truncated.to_vec().unwrap(), source)
                    .await
                    .unwrap();
                let (stream, _) = server.tcp.accept().await.unwrap();
                let mut stream = AsyncIoTokioAsStd(stream);
                let query = tcp_question(&mut stream).await;
                tcp_answer(
                    &mut stream,
                    response(&query, Some(a()), ResponseCode::NoError),
                )
                .await;
                stream
            };
            let (result, mut stream) =
                tokio::join!(resolver.ipv4_lookup("fallback.example.".into()), reply);
            assert_eq!(result.unwrap().answers()[0].data, a());
            assert!(executor.active_tasks().unwrap() > 0);
            lifetime.close();
            // Resolver/provider/submission clones are deliberately retained across the join.
            executor.shutdown().await.unwrap();
            let mut byte = [0];
            assert_tcp_closed(stream.read(&mut byte).await);
            assert!(clone.ipv4_lookup("again.example.".into()).await.is_err());
            assert!(
                provider
                    .connect_tcp(server.address, None, None)
                    .await
                    .is_err()
            );
            drop(handle);
            server.quiet();
        },
        "OWNED_DNS_FALLBACK_CLOSE_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_lookup_error_is_not_background_task_failure() {
    bounded(
        async {
            let server = Server::new().await;
            let (executor, lifetime, resolver, _) = setup(server.address);
            let reply = async {
                let (query, source) = server.question().await;
                let answer = response(&query, None, ResponseCode::NXDomain);
                server
                    .udp
                    .send_to(&answer.to_vec().unwrap(), source)
                    .await
                    .unwrap();
            };
            let (result, ()) = tokio::join!(resolver.ipv4_lookup("absent.example.".into()), reply);
            assert!(
                result.unwrap_err().is_nx_domain(),
                "LOOKUP_ERROR_REPLACED_BY_TASK_SUCCESS"
            );
            lifetime.close();
            // A DNS NXDOMAIN is not a panic, runtime loss or executor admission failure.
            executor.shutdown().await.unwrap();
        },
        "OWNED_DNS_NXDOMAIN_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_pending_tcp_lookup_cancellation_joins_socket_with_resolver_retained() {
    bounded(
        async {
            let server = Server::new().await;
            let (executor, lifetime, resolver, provider) = setup(server.address);
            let retained = resolver.clone();
            let handle = provider.create_handle();
            let mut lookup = Box::pin(resolver.ipv4_lookup("pending-tcp.example.".into()));
            let waiting = async {
                let (query, source) = server.question().await;
                let mut truncated = response(&query, None, ResponseCode::NoError);
                truncated.metadata.truncation = true;
                server
                    .udp
                    .send_to(&truncated.to_vec().unwrap(), source)
                    .await
                    .unwrap();
                let (stream, _) = server.tcp.accept().await.unwrap();
                let mut stream = AsyncIoTokioAsStd(stream);
                let query = tcp_question(&mut stream).await;
                assert_eq!(query.queries[0].name.to_ascii(), "pending-tcp.example.");
                stream
            };
            let mut stream = tokio::select! {
                result = &mut lookup => panic!("TCP_LOOKUP_DID_NOT_REMAIN_PENDING: {result:?}"),
                stream = waiting => stream,
            };
            assert_eq!(resolver.calls.available_permits(), 3);
            lifetime.close();
            assert_eq!(
                resolver.calls.available_permits(),
                3,
                "TCP_CANCEL_RELEASED_LIVE_CALL"
            );
            drop(lookup);
            executor.shutdown().await.unwrap();
            let mut byte = [0];
            assert_tcp_closed(stream.read(&mut byte).await);
            assert!(retained.ipv4_lookup("late.example.".into()).await.is_err());
            assert!(
                provider
                    .connect_tcp(server.address, None, None)
                    .await
                    .is_err()
            );
            drop(handle);
        },
        "OWNED_DNS_PENDING_TCP_JOIN_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_silent_server_returns_lookup_timeout_not_executor_failure() {
    bounded(
        async {
            let server = Server::new().await;
            let (executor, lifetime, resolver, _) = setup(server.address);
            let mut lookup = Box::pin(resolver.ipv4_lookup("silent.example.".into()));
            let mut buffer = [0; 4096];
            let mut requests = 0;
            let mut streams = Vec::with_capacity(4);
            let error = loop {
                tokio::select! {
                    result = &mut lookup => break result.unwrap_err(),
                    received = server.udp.recv_from(&mut buffer) => {
                        received.unwrap();
                        requests += 1;
                    }
                    accepted = server.tcp.accept() => {
                        assert!(streams.len() < 4, "SILENT_DNS_CONNECTION_GROWTH");
                        streams.push(accepted.unwrap().0);
                    }
                }
            };
            assert!(requests > 0, "SILENT_DNS_REQUEST_NOT_OBSERVED");
            assert!(
                matches!(error, NetError::Timeout),
                "SILENCE_NOT_REPORTED_AS_LOOKUP_TIMEOUT: {error}"
            );
            drop(lookup);
            lifetime.close();
            executor.shutdown().await.unwrap();
        },
        "OWNED_DNS_SILENCE_FIXTURE_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_ipv6_nameserver_uses_real_udp_and_tcp_sockets() {
    bounded(
        async {
            let server = Server::bind("[::1]:0".parse().unwrap()).await.unwrap();
            assert!(server.address.is_ipv6());
            assert_ne!(server.address.port(), 0);
            let (executor, lifetime, resolver, provider) = setup(server.address);
            let retained = resolver.clone();
            // IPv4 answer data over IPv6 transport separates record type from socket family.
            let (result, source) = tokio::join!(
                resolver.ipv4_lookup("ipv6-server.example.".into()),
                server.answer(a())
            );
            assert_eq!(result.unwrap().answers()[0].data, a());
            assert!(source.is_ipv6(), "DNS_UDP_DID_NOT_USE_IPV6");
            assert_eq!(source.ip(), server.address.ip());
            let data = RData::AAAA(AAAA(Ipv6Addr::LOCALHOST));
            let reply = async {
                let (query, source) = server.question().await;
                assert!(source.is_ipv6(), "DNS_FALLBACK_UDP_DID_NOT_USE_IPV6");
                let mut truncated = response(&query, None, ResponseCode::NoError);
                truncated.metadata.truncation = true;
                server
                    .udp
                    .send_to(&truncated.to_vec().unwrap(), source)
                    .await
                    .unwrap();
                let (stream, peer) = server.tcp.accept().await.unwrap();
                assert!(peer.is_ipv6(), "DNS_TCP_DID_NOT_USE_IPV6");
                assert_eq!(stream.local_addr().unwrap(), server.address);
                let mut stream = AsyncIoTokioAsStd(stream);
                let query = tcp_question(&mut stream).await;
                tcp_answer(
                    &mut stream,
                    response(&query, Some(data.clone()), ResponseCode::NoError),
                )
                .await;
                stream
            };
            let (result, mut stream) =
                tokio::join!(resolver.ipv6_lookup("ipv6-fallback.example.".into()), reply);
            assert_eq!(result.unwrap().answers()[0].data, data);
            lifetime.close();
            executor.shutdown().await.unwrap();
            assert_tcp_closed(stream.read(&mut [0]).await);
            assert!(retained.ipv6_lookup("late.example.".into()).await.is_err());
            assert!(
                provider
                    .connect_tcp(server.address, None, None)
                    .await
                    .is_err()
            );
        },
        "OWNED_DNS_IPV6_UDP_TCP_DEADLINE",
    )
    .await;
}

fn assert_tcp_closed(result: io::Result<usize>) {
    match result {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) => {}
        other => panic!("POOLED_DNS_TCP_STILL_OPEN: {other:?}"),
    }
}

#[tokio::test]
async fn owned_dns_relative_lookup_is_rejected_without_search_or_hosts_io() {
    let server = Server::new().await;
    let (executor, lifetime, resolver, _) = setup(server.address);
    for name in ["localhost", "relative.example", ".", "bad..example."] {
        assert!(resolver.ipv4_lookup(name.into()).await.is_err());
    }
    assert_eq!(executor.active_tasks().unwrap(), 0);
    server.quiet();
    lifetime.close();
    executor.shutdown().await.unwrap();
}
