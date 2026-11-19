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

fn gateway_of(fake: &Fake) -> Gateway {
    Gateway {
        address: fake.address,
        local: LOCAL,
    }
}

#[tokio::test]
async fn the_measurement_reports_a_grant_and_the_release_without_an_address() {
    let gateway = fake(|_, request| vec![pcp_answer(request, 0, 51_000)]).await;
    let lines = measure(Some(gateway_of(&gateway)), INTERNAL, false).await;
    assert_eq!(
        lines,
        [
            "port-map gateway=found",
            "port-map request internal=48896 external=48896 lifetime_s=120",
            "port-map result=granted protocol=pcp external-port=51000 same-port=no lifetime_s=7200",
            "port-map release=yes",
        ]
    );
    let text = lines.join("\n");
    assert!(!text.contains("203.0.113.7") && !text.contains("127.0.0.1"));
}

#[tokio::test]
async fn the_measurement_shows_the_addresses_only_when_asked() {
    let gateway = fake(natpmp_only).await;
    let lines = measure(Some(gateway_of(&gateway)), 50_002, true).await;
    assert_eq!(lines[0], "port-map gateway=found address=127.0.0.1");
    assert_eq!(
        lines[2],
        "port-map result=granted protocol=nat-pmp external-port=50002 same-port=yes lifetime_s=3600 external-address=203.0.113.7"
    );
}

#[tokio::test]
async fn the_measurement_names_a_missing_gateway_a_refusal_and_silence() {
    assert_eq!(
        measure(None, INTERNAL, false).await,
        ["port-map gateway=none"]
    );
    let refusing = fake(|_, request| vec![pcp_answer(request, 2, 0)]).await;
    let lines = measure(Some(gateway_of(&refusing)), INTERNAL, false).await;
    assert_eq!(lines.last().unwrap(), "port-map result=refused:2");
    let silent = fake(|_, _| Vec::new()).await;
    let lines = measure_within(
        Some(gateway_of(&silent)),
        INTERNAL,
        false,
        Duration::from_millis(400),
    )
    .await;
    assert_eq!(lines.last().unwrap(), "port-map result=silent");
    assert_eq!(lines.len(), 3, "no release line after a failure");
}

#[tokio::test]
async fn a_failed_release_is_reported_after_the_grant() {
    let gateway = fake(|index, request| {
        if index == 0 {
            vec![pcp_answer(request, 0, INTERNAL)]
        } else {
            Vec::new()
        }
    })
    .await;
    let lines = measure(Some(gateway_of(&gateway)), INTERNAL, false).await;
    assert_eq!(lines.last().unwrap(), "port-map release=no:silent");
}

/// The pace of the keeper tests: seconds are the unit of the lifetimes on the wire, so the
/// granted lifetime is two seconds and a renewal comes after one.
const FAST: Timing = Timing {
    lifetime: Duration::from_secs(2),
    request_budget: Duration::from_millis(300),
    min_renew: Duration::from_millis(50),
    retry: Duration::from_millis(100),
    silent_retry: Duration::from_millis(100),
};

async fn mapped(keeper: &Keeper) -> Mapping {
    let mut watch = keeper.watch();
    let state = tokio::time::timeout(
        Duration::from_secs(5),
        watch.wait_for(|state| matches!(state, State::Mapped(_))),
    )
    .await
    .expect("mapped in time")
    .expect("keeper alive");
    match *state {
        State::Mapped(mapping) => mapping,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_kept_mapping_is_renewed_with_the_same_nonce_and_deleted_on_stop() {
    let gateway = fake(|_, request| {
        let mut answer = pcp_answer(request, 0, INTERNAL);
        answer[4..8].copy_from_slice(&2_u32.to_be_bytes());
        vec![answer]
    })
    .await;
    let keeper = Keeper::start(gateway_of(&gateway), INTERNAL, FAST);
    assert_eq!(keeper.state(), State::Pending);
    let mapping = mapped(&keeper).await;
    assert_eq!(mapping.external_port, INTERNAL);
    assert_eq!(mapping.lifetime, Duration::from_secs(2));
    tokio::time::sleep(Duration::from_millis(1300)).await;
    keeper.stop().await;
    let requests = gateway.requests();
    assert!(
        requests.len() >= 3,
        "map, renewal, release: {}",
        requests.len()
    );
    for request in &requests {
        assert_eq!(
            &request[24..36],
            &requests[0][24..36],
            "one nonce throughout"
        );
    }
    assert_eq!(
        &requests[1][4..8],
        [0, 0, 0, 2],
        "the renewal asks for the lifetime again"
    );
    let last = requests.last().unwrap();
    assert_eq!(
        &last[4..8],
        [0, 0, 0, 0],
        "the last request deletes the mapping"
    );
}

#[tokio::test]
async fn a_silent_gateway_leaves_the_keeper_unavailable_until_it_answers() {
    let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let open_for_script = Arc::clone(&open);
    let gateway = fake(move |_, request| {
        if open_for_script.load(std::sync::atomic::Ordering::SeqCst) {
            vec![pcp_answer(request, 0, INTERNAL)]
        } else {
            Vec::new()
        }
    })
    .await;
    let keeper = Keeper::start(gateway_of(&gateway), INTERNAL, FAST);
    let mut watch = keeper.watch();
    tokio::time::timeout(
        Duration::from_secs(5),
        watch.wait_for(|state| *state == State::Unavailable(MapError::Silent)),
    )
    .await
    .expect("unavailable in time")
    .expect("keeper alive");
    open.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(mapped(&keeper).await.external_port, INTERNAL);
    keeper.stop().await;
}

#[tokio::test]
async fn a_refusal_is_the_state_of_the_keeper_with_its_code() {
    let gateway = fake(|_, request| vec![pcp_answer(request, 2, 0)]).await;
    let keeper = Keeper::start(gateway_of(&gateway), INTERNAL, FAST);
    let mut watch = keeper.watch();
    tokio::time::timeout(
        Duration::from_secs(5),
        watch.wait_for(|state| *state == State::Unavailable(MapError::Refused(2))),
    )
    .await
    .expect("refusal in time")
    .expect("keeper alive");
    keeper.stop().await;
}

#[tokio::test]
async fn stopping_is_prompt_while_a_request_is_pending_and_deletes_nothing() {
    let gateway = fake(|_, _| Vec::new()).await;
    let slow = Timing {
        request_budget: Duration::from_secs(10),
        ..FAST
    };
    let keeper = Keeper::start(gateway_of(&gateway), INTERNAL, slow);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = StdInstant::now();
    keeper.stop().await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(
        gateway
            .requests()
            .iter()
            .all(|request| request.get(4..8) != Some(&[0_u8; 4][..])),
        "no deletion without a mapping"
    );
}

#[tokio::test]
async fn a_dropped_keeper_ends_its_task() {
    let gateway = fake(|_, request| vec![pcp_answer(request, 0, INTERNAL)]).await;
    let keeper = Keeper::start(gateway_of(&gateway), INTERNAL, FAST);
    let _ = mapped(&keeper).await;
    drop(keeper);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let count = gateway.requests().len();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(gateway.requests().len(), count, "no renewal after the drop");
}

#[tokio::test]
async fn a_renewal_uses_the_nonce_of_the_mapping_it_renews() {
    let gateway = fake(|_, request| vec![pcp_answer(request, 0, 51_000)]).await;
    let first = map(&gateway, BUDGET).await.unwrap();
    let renewed = renew(gateway.address, LOCAL, &first, LIFETIME, BUDGET)
        .await
        .unwrap();
    let requests = gateway.requests();
    assert_eq!(&requests[1][24..36], &requests[0][24..36]);
    assert_eq!(
        &requests[1][42..44],
        [0xc7, 0x38],
        "asks for the assigned port, 51000"
    );
    assert_eq!(renewed.external_port, 51_000);
}
