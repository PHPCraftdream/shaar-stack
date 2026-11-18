//! Tests of the mapping client against a fake gateway on the loopback.

use super::*;
use std::sync::{Arc, Mutex};
use std::time::Instant as StdInstant;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const INTERNAL: u16 = 48_896;
const EXTERNAL_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const LIFETIME: Duration = Duration::from_secs(7200);
const BUDGET: Duration = Duration::from_secs(2);

/// A gateway on the loopback: every datagram it receives is recorded and the datagrams that
/// `script` returns for it (given its index and bytes) are sent back.
struct Fake {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fake {
    fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().unwrap().clone()
    }
}

async fn fake(mut script: impl FnMut(usize, &[u8]) -> Vec<Vec<u8>> + Send + 'static) -> Fake {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 128];
        loop {
            let Ok((length, from)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let request = buffer[..length].to_vec();
            let index = {
                let mut seen = seen.lock().unwrap();
                seen.push(request.clone());
                seen.len() - 1
            };
            for reply in script(index, &request) {
                let _ = socket.send_to(&reply, from).await;
            }
        }
    });
    Fake {
        address,
        requests,
        task,
    }
}

fn is_pcp(request: &[u8]) -> bool {
    request.first() == Some(&2)
}

/// The PCP answer to a MAP request: the request's own nonce and ports, the given code and port.
fn pcp_answer(request: &[u8], code: u8, external_port: u16) -> Vec<u8> {
    let mut reply = request.to_vec();
    reply[1] = 0x81;
    reply[3] = code;
    reply[4..8].copy_from_slice(&7200_u32.to_be_bytes());
    reply[42..44].copy_from_slice(&external_port.to_be_bytes());
    reply[44..60].copy_from_slice(&EXTERNAL_IP.to_ipv6_mapped().octets());
    reply
}

fn natpmp_map_answer(request: &[u8], code: u16, external_port: u16) -> Vec<u8> {
    let mut reply = vec![0_u8; 16];
    reply[1] = 129;
    reply[2..4].copy_from_slice(&code.to_be_bytes());
    reply[8..10].copy_from_slice(&request[4..6]);
    reply[10..12].copy_from_slice(&external_port.to_be_bytes());
    reply[12..16].copy_from_slice(&3600_u32.to_be_bytes());
    reply
}

fn natpmp_external_answer() -> Vec<u8> {
    let mut reply = vec![0_u8; 12];
    reply[1] = 128;
    reply[8..12].copy_from_slice(&EXTERNAL_IP.octets());
    reply
}

/// A gateway that speaks NAT-PMP only: a PCP request gets "unsupported version".
fn natpmp_only(_index: usize, request: &[u8]) -> Vec<Vec<u8>> {
    if is_pcp(request) {
        vec![vec![0, 129, 0, 1, 0, 0, 0, 0]]
    } else if request[1] == 0 {
        vec![natpmp_external_answer()]
    } else {
        vec![natpmp_map_answer(request, 0, 50_002)]
    }
}

async fn map(gateway: &Fake, budget: Duration) -> Result<Mapping, MapError> {
    map_udp(gateway.address, LOCAL, INTERNAL, INTERNAL, LIFETIME, budget).await
}

#[tokio::test]
async fn a_pcp_gateway_grants_the_mapping_with_its_external_endpoint() {
    let gateway = fake(|_, request| vec![pcp_answer(request, 0, INTERNAL)]).await;
    let mapping = map(&gateway, BUDGET).await.unwrap();
    assert_eq!(mapping.protocol, Protocol::Pcp);
    assert_eq!(mapping.internal_port, INTERNAL);
    assert_eq!(mapping.external_port, INTERNAL);
    assert_eq!(mapping.external_ip, Some(IpAddr::V4(EXTERNAL_IP)));
    assert_eq!(mapping.lifetime, LIFETIME);
    let requests = gateway.requests();
    assert_eq!(requests.len(), 1, "one request, no resend");
    assert_eq!(requests[0].len(), 60);
    assert_eq!(&requests[0][40..44], [0xbf, 0x00, 0xbf, 0x00]);
}

#[tokio::test]
async fn the_port_the_gateway_assigns_is_the_one_reported() {
    let gateway = fake(|_, request| vec![pcp_answer(request, 0, 51_234)]).await;
    let mapping = map(&gateway, BUDGET).await.unwrap();
    assert_eq!(mapping.external_port, 51_234);
    assert_eq!(mapping.internal_port, INTERNAL);
}

#[tokio::test]
async fn a_nat_pmp_only_gateway_is_asked_again_in_its_own_protocol() {
    let gateway = fake(natpmp_only).await;
    let mapping = map(&gateway, BUDGET).await.unwrap();
    assert_eq!(mapping.protocol, Protocol::NatPmp);
    assert_eq!(mapping.external_port, 50_002);
    assert_eq!(mapping.external_ip, Some(IpAddr::V4(EXTERNAL_IP)));
    assert_eq!(mapping.lifetime, Duration::from_secs(3600));
    let requests = gateway.requests();
    assert!(is_pcp(&requests[0]));
    assert_eq!(&requests[1][..2], [0, 1], "the NAT-PMP map request");
    assert_eq!(&requests[1][4..8], [0xbf, 0x00, 0xbf, 0x00]);
}

#[tokio::test]
async fn a_refusal_is_reported_with_its_code_in_either_protocol() {
    let pcp = fake(|_, request| vec![pcp_answer(request, 2, 0)]).await;
    assert_eq!(map(&pcp, BUDGET).await, Err(MapError::Refused(2)));
    let natpmp = fake(|_, request| {
        if is_pcp(request) {
            vec![vec![0, 129, 0, 1, 0, 0, 0, 0]]
        } else {
            vec![natpmp_map_answer(request, 4, 0)]
        }
    })
    .await;
    assert_eq!(map(&natpmp, BUDGET).await, Err(MapError::Refused(4)));
}

#[tokio::test]
async fn datagrams_that_are_not_the_answer_are_ignored() {
    let gateway = fake(|_, request| {
        // Garbage, an answer with another nonce, and then the real answer.
        let mut other_nonce = pcp_answer(request, 0, 60_000);
        other_nonce[24] ^= 0xff;
        vec![vec![1, 2, 3], other_nonce, pcp_answer(request, 0, 50_003)]
    })
    .await;
    let mapping = map(&gateway, BUDGET).await.unwrap();
    assert_eq!(mapping.external_port, 50_003);
}

#[tokio::test]
async fn a_request_that_got_no_answer_is_sent_again() {
    let gateway = fake(|index, request| {
        if index == 0 {
            Vec::new()
        } else {
            vec![pcp_answer(request, 0, INTERNAL)]
        }
    })
    .await;
    let mapping = map(&gateway, BUDGET).await.unwrap();
    assert_eq!(mapping.protocol, Protocol::Pcp);
    let requests = gateway.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1], "the same request, the same nonce");
}

#[tokio::test]
async fn a_silent_gateway_ends_within_the_budget() {
    let gateway = fake(|_, _| Vec::new()).await;
    let started = StdInstant::now();
    let result = map(&gateway, Duration::from_millis(600)).await;
    assert_eq!(result, Err(MapError::Silent));
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(500) && elapsed < Duration::from_millis(1500),
        "{elapsed:?}"
    );
    let requests = gateway.requests();
    assert!(requests.iter().any(|request| is_pcp(request)));
    assert!(requests.iter().any(|request| !is_pcp(request)));
}

#[tokio::test]
async fn nothing_listening_on_the_gateway_port_is_silent_not_an_io_error() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let result = map_udp(address, LOCAL, INTERNAL, INTERNAL, LIFETIME, BUDGET).await;
    assert_eq!(result, Err(MapError::Silent));
}

#[tokio::test]
async fn releasing_a_pcp_mapping_sends_a_zero_lifetime_with_the_same_nonce() {
    let gateway = fake(|_, request| vec![pcp_answer(request, 0, INTERNAL)]).await;
    let mapping = map(&gateway, BUDGET).await.unwrap();
    release(gateway.address, LOCAL, &mapping).await.unwrap();
    let requests = gateway.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(&requests[1][4..8], [0, 0, 0, 0], "lifetime zero");
    assert_eq!(&requests[1][24..36], &requests[0][24..36], "same nonce");
    assert_eq!(
        &requests[1][40..42],
        &requests[0][40..42],
        "same internal port"
    );
}

#[tokio::test]
async fn releasing_a_nat_pmp_mapping_deletes_it_by_port_and_lifetime_zero() {
    let gateway = fake(natpmp_only).await;
    let mapping = map(&gateway, BUDGET).await.unwrap();
    release(gateway.address, LOCAL, &mapping).await.unwrap();
    let requests = gateway.requests();
    let delete = requests.last().unwrap();
    assert_eq!(
        delete[..],
        [0, 1, 0, 0, 0xbf, 0x00, 0, 0, 0, 0, 0, 0],
        "internal port, no external port, lifetime zero"
    );
}

#[tokio::test]
async fn a_gateway_that_refuses_the_release_is_reported() {
    let gateway = fake(|index, request| {
        let code = if index == 0 { 0 } else { 2 };
        vec![pcp_answer(request, code, INTERNAL)]
    })
    .await;
    let mapping = map(&gateway, BUDGET).await.unwrap();
    assert_eq!(
        release(gateway.address, LOCAL, &mapping).await,
        Err(MapError::Refused(2))
    );
}

#[test]
fn a_nonce_differs_from_one_mapping_to_the_next() {
    assert_ne!(fresh_nonce(), fresh_nonce());
}

#[test]
fn the_error_and_protocol_tokens_are_fixed_words() {
    assert_eq!(MapError::Refused(2).to_string(), "refused:2");
    assert_eq!(MapError::Silent.to_string(), "silent");
    assert_eq!(MapError::Io.to_string(), "io");
    assert_eq!(Protocol::Pcp.token(), "pcp");
    assert_eq!(Protocol::NatPmp.token(), "nat-pmp");
}
