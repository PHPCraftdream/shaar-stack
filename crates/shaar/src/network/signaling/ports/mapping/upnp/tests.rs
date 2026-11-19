//! Tests of the UPnP client against a fake gateway on the loopback.

use super::{
    fake::{self, Fake, Script},
    *,
};
use std::time::Instant as StdInstant;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const INTERNAL: u16 = 48_896;
const LIFETIME: Duration = Duration::from_secs(7200);
const BUDGET: Duration = Duration::from_secs(2);
const IP1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
const IP2: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";
const PPP: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

async fn map_ports(gateway: &Fake) -> Result<(Igd, Option<IpAddr>), MapError> {
    map(gateway.ssdp, LOCAL, (INTERNAL, INTERNAL), LIFETIME, BUDGET).await
}

fn with_description(services: &[(&str, &str)]) -> Script {
    Script {
        description: fake::description(services),
        ..Script::standard()
    }
}

/// The standard gateway with another answer to one action.
fn answering(action: &'static str, reply: fn() -> (u16, String)) -> Script {
    let standard = Script::standard();
    Script {
        soap: Box::new(move |name, body| {
            if name == action {
                reply()
            } else {
                (Script::standard().soap)(name, body)
            }
        }),
        ..standard
    }
}

#[tokio::test]
async fn a_gateway_is_found_described_and_asked_for_the_mapping() {
    let gateway = fake::start(Script::standard()).await;
    let ports = (INTERNAL, 51_000);
    let (igd, external) = map(gateway.ssdp, LOCAL, ports, LIFETIME, BUDGET)
        .await
        .unwrap();
    assert_eq!((igd.path.as_str(), igd.service), ("/ctl/IPConn", IP1));
    assert_eq!(external, Some(IpAddr::V4(fake::EXTERNAL)));
    assert_eq!(gateway.searches(), 1);
    assert_eq!(gateway.gets(), ["/rootDesc.xml"]);
    assert_eq!(
        gateway.actions(),
        ["AddPortMapping", "GetExternalIPAddress"]
    );
    let posts = gateway.posts();
    assert!(posts.iter().all(|post| post.path == "/ctl/IPConn"));
    assert_eq!(posts[0].action, format!("{IP1}#AddPortMapping"));
    for part in [
        "<NewExternalPort>51000</NewExternalPort>",
        "<NewProtocol>UDP</NewProtocol>",
        "<NewInternalPort>48896</NewInternalPort>",
        "<NewInternalClient>127.0.0.1</NewInternalClient>",
        "<NewEnabled>1</NewEnabled>",
        "<NewLeaseDuration>7200</NewLeaseDuration>",
    ] {
        assert!(posts[0].body.contains(part), "{part} in {}", posts[0].body);
    }
}

#[tokio::test]
async fn the_ip_service_is_preferred_to_the_ppp_service_and_version_two_to_one() {
    let all = with_description(&[(PPP, "/ctl/PPP"), (IP1, "/ctl/IP1"), (IP2, "/ctl/IP2")]);
    let gateway = fake::start(all).await;
    let (igd, _) = map_ports(&gateway).await.unwrap();
    assert_eq!((igd.path.as_str(), igd.service), ("/ctl/IP2", IP2));
    let ppp_only = fake::start(with_description(&[(PPP, "/ctl/PPP")])).await;
    let (igd, _) = map_ports(&ppp_only).await.unwrap();
    assert_eq!((igd.path.as_str(), igd.service), ("/ctl/PPP", PPP));
    assert_eq!(ppp_only.posts()[0].action, format!("{PPP}#AddPortMapping"));
}

#[tokio::test]
async fn a_relative_control_url_is_resolved_against_the_description() {
    let script = Script {
        path: "/upnp/rootDesc.xml".to_owned(),
        ..with_description(&[(IP1, "ctl/IPConn")])
    };
    let gateway = fake::start(script).await;
    let (igd, _) = map_ports(&gateway).await.unwrap();
    assert_eq!(igd.path, "/upnp/ctl/IPConn");
    assert_eq!(gateway.gets(), ["/upnp/rootDesc.xml"]);
}

#[tokio::test]
async fn an_absolute_control_url_on_the_gateway_may_name_another_port() {
    let gateway = fake::start(with_description(&[(IP1, "http://127.0.0.1:9/ctl")])).await;
    let discovered = discover(gateway.ssdp, Instant::now() + BUDGET)
        .await
        .unwrap();
    assert_eq!(discovered.control, "127.0.0.1:9".parse().unwrap());
    assert_eq!(discovered.path, "/ctl");
}

#[tokio::test]
async fn a_control_url_that_names_another_host_is_refused_and_never_contacted() {
    for control in [
        "http://192.0.2.99:5000/ctl",
        "https://127.0.0.1/ctl",
        "ftp://127.0.0.1/ctl",
        "/ctl with space",
    ] {
        let gateway = fake::start(with_description(&[(IP1, control)])).await;
        assert_eq!(
            map_ports(&gateway).await,
            Err(MapError::Unsupported),
            "{control}"
        );
        assert!(gateway.posts().is_empty(), "{control}");
    }
}

#[tokio::test]
async fn a_location_on_another_host_is_refused_and_not_fetched() {
    let script = Script {
        location_host: Some("192.0.2.99".to_owned()),
        ..Script::standard()
    };
    let gateway = fake::start(script).await;
    assert_eq!(map_ports(&gateway).await, Err(MapError::Unsupported));
    assert!(gateway.gets().is_empty());
}

#[tokio::test]
async fn a_description_without_a_mapping_service_is_unsupported() {
    let other = "urn:schemas-upnp-org:service:Layer3Forwarding:1";
    let gateway = fake::start(with_description(&[(other, "/ctl/L3F")])).await;
    assert_eq!(map_ports(&gateway).await, Err(MapError::Unsupported));
    assert!(gateway.posts().is_empty());
}

#[tokio::test]
async fn a_gateway_that_grants_only_permanent_leases_is_asked_again_without_a_lease() {
    let standard = Script::standard();
    let script = Script {
        soap: Box::new(|name, body| match name {
            "AddPortMapping" if !body.contains("<NewLeaseDuration>0<") => fake::fault(725),
            _ => (Script::standard().soap)(name, body),
        }),
        ..standard
    };
    let gateway = fake::start(script).await;
    map_ports(&gateway).await.unwrap();
    assert_eq!(
        gateway.actions(),
        ["AddPortMapping", "AddPortMapping", "GetExternalIPAddress"]
    );
    let posts = gateway.posts();
    assert!(posts[0].body.contains("<NewLeaseDuration>7200<"));
    assert!(
        posts[1]
            .body
            .contains("<NewLeaseDuration>0</NewLeaseDuration>")
    );
}

#[tokio::test]
async fn a_refusal_carries_the_error_code_of_the_gateway_or_the_http_status() {
    for (reply, code) in [
        (fake::fault as fn(u16) -> (u16, String), 718),
        (fake::fault, 501),
    ] {
        let script = Script {
            soap: Box::new(move |_, _| reply(code)),
            ..Script::standard()
        };
        let gateway = fake::start(script).await;
        assert_eq!(map_ports(&gateway).await, Err(MapError::Refused(code)));
    }
    let plain = Script {
        soap: Box::new(|_, _| (404, "<html>nothing</html>".to_owned())),
        ..Script::standard()
    };
    let gateway = fake::start(plain).await;
    assert_eq!(map_ports(&gateway).await, Err(MapError::Refused(404)));
}

#[tokio::test]
async fn an_unreported_external_address_does_not_fail_the_mapping() {
    for reply in ["", "<NewExternalIPAddress>0.0.0.0</NewExternalIPAddress>"] {
        let standard = Script::standard();
        let script = Script {
            soap: Box::new(move |name, body| {
                if name == "GetExternalIPAddress" {
                    (200, fake::answer(name, reply))
                } else {
                    (Script::standard().soap)(name, body)
                }
            }),
            ..standard
        };
        let gateway = fake::start(script).await;
        let (_, external) = map_ports(&gateway).await.unwrap();
        assert_eq!(external, None, "{reply:?}");
    }
    let failing = answering("GetExternalIPAddress", || fake::fault(501));
    let gateway = fake::start(failing).await;
    assert_eq!(map_ports(&gateway).await.unwrap().1, None);
}

#[tokio::test]
async fn a_silent_gateway_ends_within_the_budget_after_resending_the_search() {
    let script = Script {
        ssdp_answers: false,
        ..Script::standard()
    };
    let gateway = fake::start(script).await;
    let started = StdInstant::now();
    let result = map(
        gateway.ssdp,
        LOCAL,
        (INTERNAL, INTERNAL),
        LIFETIME,
        Duration::from_millis(600),
    )
    .await;
    assert_eq!(result, Err(MapError::Silent));
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(500) && elapsed < Duration::from_millis(1500),
        "{elapsed:?}"
    );
    assert!(gateway.searches() >= 2, "{}", gateway.searches());
}

#[tokio::test]
async fn a_gateway_that_never_answers_http_ends_within_the_budget() {
    let script = Script {
        http_answers: false,
        ..Script::standard()
    };
    let gateway = fake::start(script).await;
    let started = StdInstant::now();
    let result = map(
        gateway.ssdp,
        LOCAL,
        (INTERNAL, INTERNAL),
        LIFETIME,
        Duration::from_millis(600),
    )
    .await;
    assert_eq!(result, Err(MapError::Silent));
    assert!(started.elapsed() < Duration::from_millis(1500));
}

#[tokio::test]
async fn a_chunked_description_is_read() {
    let script = Script {
        chunked: true,
        ..Script::standard()
    };
    let gateway = fake::start(script).await;
    let (igd, _) = map_ports(&gateway).await.unwrap();
    assert_eq!(igd.path, "/ctl/IPConn");
}

#[tokio::test]
async fn a_description_above_the_size_cap_is_refused() {
    let script = Script {
        description: "a".repeat(http::MAX_RESPONSE + 1000),
        ..Script::standard()
    };
    let gateway = fake::start(script).await;
    assert_eq!(map_ports(&gateway).await, Err(MapError::Unsupported));
}

#[tokio::test]
async fn a_renewal_asks_again_at_the_same_endpoint_without_a_new_search() {
    let gateway = fake::start(Script::standard()).await;
    let (igd, _) = map_ports(&gateway).await.unwrap();
    renew(&igd, LOCAL, (INTERNAL, INTERNAL), LIFETIME, BUDGET)
        .await
        .unwrap();
    assert_eq!(
        gateway.actions(),
        ["AddPortMapping", "GetExternalIPAddress", "AddPortMapping"]
    );
    assert_eq!((gateway.searches(), gateway.gets().len()), (1, 1));
}

#[tokio::test]
async fn a_deletion_names_the_external_port_and_a_missing_entry_counts_as_deleted() {
    let gateway = fake::start(Script::standard()).await;
    let (igd, _) = map_ports(&gateway).await.unwrap();
    delete(&igd, 51_000, BUDGET).await.unwrap();
    let last = gateway.posts().pop().unwrap();
    assert_eq!(last.action, format!("{IP1}#DeletePortMapping"));
    assert!(
        last.body
            .contains("<NewExternalPort>51000</NewExternalPort><NewProtocol>UDP</NewProtocol>")
    );
    let gone = fake::start(answering("DeletePortMapping", || fake::fault(714))).await;
    let (igd, _) = map_ports(&gone).await.unwrap();
    assert_eq!(delete(&igd, 51_000, BUDGET).await, Ok(()));
    let refusing = fake::start(answering("DeletePortMapping", || fake::fault(501))).await;
    let (igd, _) = map_ports(&refusing).await.unwrap();
    assert_eq!(
        delete(&igd, 51_000, BUDGET).await,
        Err(MapError::Refused(501))
    );
}

#[test]
fn an_ssdp_answer_gives_its_location_only_when_it_is_a_200_answer() {
    let answer = |status: &str, header: &str| format!("{status}\r\nST: x\r\n{header}\r\n\r\n");
    let located = answer("HTTP/1.1 200 OK", "LoCaTiOn:  http://192.0.2.1:80/d.xml ");
    assert_eq!(
        location(located.as_bytes()).as_deref(),
        Some("http://192.0.2.1:80/d.xml")
    );
    for text in [
        answer("HTTP/1.1 404 Not Found", "Location: http://192.0.2.1/d.xml"),
        answer("NOTIFY * HTTP/1.1", "Location: http://192.0.2.1/d.xml"),
        answer("HTTP/1.1 200 OK", "Server: none"),
    ] {
        assert_eq!(location(text.as_bytes()), None, "{text:?}");
    }
    assert_eq!(location(&[0xff, 0xfe]), None);
}

#[test]
fn a_url_is_an_http_address_with_an_ip_host_and_a_plain_path() {
    let (address, path) = parse_url("http://192.0.2.1:5000/ctl/a?b=c").unwrap();
    assert_eq!(
        (address, path),
        ("192.0.2.1:5000".parse().unwrap(), "/ctl/a?b=c")
    );
    assert_eq!(parse_url("http://192.0.2.1").unwrap().1, "/");
    assert_eq!(parse_url("http://192.0.2.1").unwrap().0.port(), 80);
    assert_eq!(parse_url("http://[2001:db8::1]:80/x").unwrap().0.port(), 80);
    for url in [
        "https://192.0.2.1/x",
        "http://router.local/x",
        "http://192.0.2.1/a b",
        "http://192.0.2.1/a\r\nHost: x",
        "192.0.2.1/x",
        "",
    ] {
        assert_eq!(parse_url(url), None, "{url:?}");
    }
}
