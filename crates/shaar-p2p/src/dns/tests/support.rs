use futures::io::{AsyncReadExt, AsyncWriteExt};
use hickory_resolver::{
    net::runtime::iocompat::AsyncIoTokioAsStd,
    proto::{
        op::{Message, ResponseCode},
        rr::{RData, Record, rdata::A},
    },
};
use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub(crate) async fn bounded<T>(future: impl Future<Output = T>, marker: &'static str) -> T {
    match tokio::time::timeout(Duration::from_secs(15), future).await {
        Ok(value) => value,
        Err(_) => panic!("{marker}"),
    }
}

pub(crate) fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

pub(crate) struct Server {
    pub(crate) udp: UdpSocket,
    pub(crate) tcp: TcpListener,
    pub(crate) address: SocketAddr,
}

impl Server {
    pub(crate) async fn new() -> Self {
        Self::bind(loopback())
            .await
            .expect("owned DNS socket pair allocation")
    }

    pub(crate) async fn bind(local: SocketAddr) -> io::Result<Self> {
        socket_pair(local, UdpSocket::bind).await
    }

    /// cancel-safe: yes — receives one complete datagram without partial-read state.
    pub(crate) async fn question(&self) -> (Message, SocketAddr) {
        let mut buffer = [0; 4096];
        let (size, source) = self.udp.recv_from(&mut buffer).await.unwrap();
        (Message::from_vec(&buffer[..size]).unwrap(), source)
    }

    pub(crate) async fn answer(&self, data: RData) -> SocketAddr {
        let (query, source) = self.question().await;
        let response = response(&query, Some(data), ResponseCode::NoError);
        self.udp
            .send_to(&response.to_vec().unwrap(), source)
            .await
            .unwrap();
        source
    }

    pub(crate) fn quiet(&self) {
        let mut buffer = [0; 4096];
        assert_eq!(
            self.udp.try_recv_from(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "UNEXPECTED_DNS_IO"
        );
    }
}

const PAIR_ATTEMPTS: usize = 16;

/// cancel-safe: yes — each attempt owns both sockets until the complete pair is returned.
async fn socket_pair<F: Future<Output = io::Result<UdpSocket>>>(
    local: SocketAddr,
    bind_udp: impl FnMut(SocketAddr) -> F,
) -> io::Result<Server> {
    socket_pair_with_diagnostic(
        local,
        TcpListener::bind,
        bind_udp,
        |stage, address, error| {
            eprintln!(
                "owned DNS {stage} bind failed at {address}: {error} (kind: {:?}, raw_os_error: {:?})",
                error.kind(),
                error.raw_os_error()
            );
        },
    )
    .await
}

async fn socket_pair_with_diagnostic<FT, FU>(
    local: SocketAddr,
    mut bind_tcp: impl FnMut(SocketAddr) -> FT,
    mut bind_udp: impl FnMut(SocketAddr) -> FU,
    mut diagnostic: impl FnMut(&str, SocketAddr, &io::Error),
) -> io::Result<Server>
where
    FT: Future<Output = io::Result<TcpListener>>,
    FU: Future<Output = io::Result<UdpSocket>>,
{
    for _ in 0..PAIR_ATTEMPTS {
        let udp = match bind_udp(local).await {
            Ok(udp) => udp,
            Err(error) => {
                diagnostic("UDP", local, &error);
                if error.kind() == io::ErrorKind::AddrInUse {
                    continue;
                }
                return Err(error);
            }
        };
        let address = udp.local_addr()?;
        // Retain the UDP reservation while binding the same TCP port.
        match bind_tcp(address).await {
            Ok(tcp) => return Ok(Server { udp, tcp, address }),
            Err(error) => {
                diagnostic("TCP", address, &error);
                if error.kind() == io::ErrorKind::AddrInUse {
                    continue;
                }
                return Err(error);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "owned DNS socket pair allocation exhausted",
    ))
}

#[tokio::test]
async fn owned_dns_pair_diagnostics_identify_failed_stage_and_address_without_retrying_other_errors()
 {
    use std::cell::Cell;

    let raw_code = if cfg!(windows) { 10013 } else { 13 };
    let expected_kind = io::Error::from_raw_os_error(raw_code).kind();

    let tcp_attempts = Cell::new(0);
    let attempted_tcp = Cell::new(None);
    let tcp_diagnostics = std::cell::RefCell::new(Vec::new());
    let tcp_result = socket_pair_with_diagnostic(
        loopback(),
        |address| {
            tcp_attempts.set(tcp_attempts.get() + 1);
            attempted_tcp.set(Some(address));
            std::future::ready(Err(io::Error::from_raw_os_error(raw_code)))
        },
        UdpSocket::bind,
        |stage, address, error| {
            tcp_diagnostics.borrow_mut().push((
                stage.to_owned(),
                address,
                error.kind(),
                error.raw_os_error(),
            ));
        },
    )
    .await;
    let tcp_error = tcp_result.err().unwrap();
    // Take ownership so no RefCell borrow is held across the next await.
    let tcp_diagnostic = tcp_diagnostics.into_inner();
    assert_eq!(tcp_diagnostic.len(), 1);
    assert_eq!(tcp_diagnostic[0].0, "TCP");
    assert_eq!(tcp_diagnostic[0].1, attempted_tcp.get().unwrap());
    assert_ne!(tcp_diagnostic[0].1.port(), 0);
    assert_eq!(tcp_diagnostic[0].2, expected_kind);
    assert_eq!(tcp_diagnostic[0].3, Some(raw_code));
    assert_eq!(tcp_error.kind(), expected_kind);
    assert_eq!(tcp_error.raw_os_error(), Some(raw_code));
    assert_eq!(
        tcp_attempts.get(),
        1,
        "PAIR_RETRIED_NON_COLLISION_TCP_ERROR"
    );

    let udp_attempts = Cell::new(0);
    let tcp_reached = Cell::new(0);
    let attempted_address = Cell::new(None);
    let udp_diagnostics = std::cell::RefCell::new(Vec::new());
    let result = socket_pair_with_diagnostic(
        loopback(),
        |_| {
            tcp_reached.set(tcp_reached.get() + 1);
            std::future::ready(Err(io::Error::other("TCP must not be reached")))
        },
        |address| {
            udp_attempts.set(udp_attempts.get() + 1);
            attempted_address.set(Some(address));
            std::future::ready(Err(io::Error::from_raw_os_error(raw_code)))
        },
        |stage, address, error| {
            udp_diagnostics.borrow_mut().push((
                stage.to_owned(),
                address,
                error.kind(),
                error.raw_os_error(),
            ));
        },
    )
    .await;
    let error = result.err().unwrap();
    let diagnostics = udp_diagnostics.borrow();
    let actual_address = attempted_address.get().unwrap();
    assert_eq!(
        udp_attempts.get(),
        1,
        "PAIR_RETRIED_NON_COLLISION_UDP_ERROR"
    );
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].0, "UDP");
    assert_eq!(diagnostics[0].1, actual_address);
    assert_eq!(actual_address, loopback());
    assert_eq!(
        tcp_reached.get(),
        0,
        "TCP_BIND_AFTER_FAILED_UDP_RESERVATION"
    );
    assert_eq!(diagnostics[0].2, expected_kind);
    assert_eq!(diagnostics[0].3, Some(raw_code));
    assert_eq!(error.kind(), expected_kind);
    assert_eq!(error.raw_os_error(), Some(raw_code));
}

#[tokio::test]
async fn owned_dns_pair_allocator_retries_tcp_collision_while_retaining_udp() {
    use std::cell::Cell;
    let attempts = Cell::new(0);
    let collision = Cell::new(false);
    let server = socket_pair_with_diagnostic(
        loopback(),
        |address| {
            attempts.set(attempts.get() + 1);
            let collision = &collision;
            async move {
                assert_eq!(
                    UdpSocket::bind(address).await.err().unwrap().kind(),
                    io::ErrorKind::AddrInUse,
                    "PAIR_UDP_RESERVATION_RELEASED_EARLY"
                );
                if !collision.get() {
                    let occupied = TcpListener::bind(address).await?;
                    collision.set(true);
                    let result = TcpListener::bind(address).await;
                    assert_eq!(
                        result.as_ref().err().unwrap().kind(),
                        io::ErrorKind::AddrInUse
                    );
                    drop(occupied);
                    result
                } else {
                    TcpListener::bind(address).await
                }
            }
        },
        UdpSocket::bind,
        |_, _, _| {},
    )
    .await
    .unwrap();
    assert!(collision.get(), "CONTROLLED_TCP_COLLISION_NOT_EXERCISED");
    assert!((2..=PAIR_ATTEMPTS).contains(&attempts.get()));
    assert_eq!(
        server.tcp.local_addr().unwrap(),
        server.udp.local_addr().unwrap()
    );
}

#[tokio::test]
async fn owned_dns_pair_selects_ephemeral_udp_port_before_tcp() {
    use std::cell::Cell;
    let calls = Cell::new(0);
    let server = socket_pair(loopback(), |address| {
        calls.set(calls.get() + 1);
        async move {
            if address.port() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "chosen UDP port denied",
                ));
            }
            UdpSocket::bind(address).await
        }
    })
    .await
    .unwrap();
    assert!((1..=PAIR_ATTEMPTS).contains(&calls.get()));
    assert_ne!(server.address.port(), 0);
    assert_eq!(server.address, server.udp.local_addr().unwrap());
    assert_eq!(server.address, server.tcp.local_addr().unwrap());
}

#[tokio::test]
async fn owned_dns_pair_allocator_bounds_collisions_and_propagates_other_errors() {
    use std::cell::Cell;
    for kind in [io::ErrorKind::AddrInUse, io::ErrorKind::PermissionDenied] {
        let attempts = Cell::new(0);
        let result = socket_pair(loopback(), |_| {
            attempts.set(attempts.get() + 1);
            std::future::ready(Err(io::Error::new(kind, "allocator control failure")))
        })
        .await;
        let error = result.err().unwrap();
        assert_eq!(error.kind(), kind);
        if kind == io::ErrorKind::AddrInUse {
            assert_eq!(attempts.get(), PAIR_ATTEMPTS, "PAIR_RETRY_BOUND_CHANGED");
            assert_eq!(
                error.to_string(),
                "owned DNS socket pair allocation exhausted"
            );
        } else {
            assert_eq!(attempts.get(), 1, "PAIR_RETRIED_NON_COLLISION_ERROR");
            assert_eq!(error.to_string(), "allocator control failure");
        }
    }
    let occupied = UdpSocket::bind(loopback()).await.unwrap();
    let tcp_attempts = Cell::new(0);
    let result = socket_pair_with_diagnostic(
        occupied.local_addr().unwrap(),
        |_| {
            tcp_attempts.set(tcp_attempts.get() + 1);
            std::future::ready(Err(io::Error::other("unexpected TCP bind")))
        },
        UdpSocket::bind,
        |_, _, _| {},
    )
    .await;
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::AddrInUse);
    assert_eq!(
        tcp_attempts.get(),
        0,
        "TCP_BIND_AFTER_FAILED_UDP_RESERVATION"
    );
}

pub(crate) fn a() -> RData {
    RData::A(A(Ipv4Addr::LOCALHOST))
}

pub(crate) fn response(query: &Message, data: Option<RData>, code: ResponseCode) -> Message {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = code;
    response.queries = query.queries.clone();
    if let Some(data) = data {
        response
            .answers
            .push(Record::from_rdata(query.queries[0].name.clone(), 60, data));
    }
    response
}

/// cancel-safe: NO — cancellation can consume a partial frame; the fixture drops the stream.
pub(crate) async fn tcp_question(stream: &mut AsyncIoTokioAsStd<TcpStream>) -> Message {
    let mut size = [0; 2];
    stream.read_exact(&mut size).await.unwrap();
    let mut body = vec![0; usize::from(u16::from_be_bytes(size))];
    stream.read_exact(&mut body).await.unwrap();
    Message::from_vec(&body).unwrap()
}

pub(crate) async fn tcp_answer(stream: &mut AsyncIoTokioAsStd<TcpStream>, response: Message) {
    let body = response.to_vec().unwrap();
    stream
        .write_all(&u16::try_from(body.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&body).await.unwrap();
    stream.flush().await.unwrap();
}
