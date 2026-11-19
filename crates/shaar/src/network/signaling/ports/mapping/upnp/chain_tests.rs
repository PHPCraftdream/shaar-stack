//! The UPnP leg of the chain, of the keeper and of the measurement: a fake UPnP gateway next to
//! a fake PCP port that is silent or answers.

use std::time::Duration;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Instant as StdInstant,
};

use super::super::{
    Gateway, Keeper, MapError, Protocol, State, Timing, map_any, map_upnp, measure_upnp, release,
    renew,
    tests::{fake as pcp_fake, pcp_answer},
};
use super::fake::{self, Script};

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const INTERNAL: u16 = 48_896;
const LIFETIME: Duration = Duration::from_secs(7200);
const BUDGET: Duration = Duration::from_secs(2);
const SHORT: Duration = Duration::from_millis(600);

fn gateway(pcp: &super::super::tests::Fake, upnp: &fake::Fake) -> Gateway {
    Gateway {
        address: pcp.address,
        upnp: upnp.ssdp,
        local: LOCAL,
    }
}

async fn silent_pcp() -> super::super::tests::Fake {
    pcp_fake(|_, _| Vec::new()).await
}

#[tokio::test]
async fn the_chain_falls_back_to_upnp_when_pcp_and_nat_pmp_are_silent() {
    let pcp = silent_pcp().await;
    let upnp = fake::start(Script::standard()).await;
    let mapping = map_any(gateway(&pcp, &upnp), INTERNAL, LIFETIME, SHORT)
        .await
        .unwrap();
    assert_eq!(mapping.protocol, Protocol::Upnp);
    assert_eq!(
        (mapping.internal_port, mapping.external_port),
        (INTERNAL, INTERNAL)
    );
    assert_eq!(mapping.external_ip, Some(IpAddr::V4(fake::EXTERNAL)));
    assert_eq!(mapping.lifetime, LIFETIME);
    assert!(
        !pcp.requests().is_empty(),
        "PCP and NAT-PMP were asked first"
    );
}

#[tokio::test]
async fn a_pcp_grant_ends_the_chain_before_upnp_is_asked() {
    let pcp = pcp_fake(|_, request| vec![pcp_answer(request, 0, INTERNAL)]).await;
    let upnp = fake::start(Script::standard()).await;
    let mapping = map_any(gateway(&pcp, &upnp), INTERNAL, LIFETIME, BUDGET)
        .await
        .unwrap();
    assert_eq!(mapping.protocol, Protocol::Pcp);
    assert_eq!(upnp.searches(), 0);
    assert!(upnp.gets().is_empty() && upnp.posts().is_empty());
}

#[tokio::test]
async fn the_chain_reports_the_most_telling_of_its_errors() {
    let silent_upnp = Script {
        ssdp_answers: false,
        ..Script::standard()
    };
    let refusing_upnp = Script {
        soap: Box::new(|_, _| fake::fault(718)),
        ..Script::standard()
    };
    let no_service = Script {
        description: fake::description(&[]),
        ..Script::standard()
    };
    let cases = [
        (true, silent_upnp, MapError::Refused(2)),
        (false, refusing_upnp, MapError::Refused(718)),
        (false, no_service, MapError::Unsupported),
        (
            false,
            Script {
                ssdp_answers: false,
                ..Script::standard()
            },
            MapError::Silent,
        ),
    ];
    for (pcp_refuses, script, expected) in cases {
        let pcp = if pcp_refuses {
            pcp_fake(|_, request| vec![pcp_answer(request, 2, 0)]).await
        } else {
            silent_pcp().await
        };
        let upnp = fake::start(script).await;
        let result = map_any(gateway(&pcp, &upnp), INTERNAL, LIFETIME, SHORT).await;
        assert_eq!(result, Err(expected));
    }
}

#[tokio::test]
async fn a_upnp_mapping_is_renewed_and_released_at_its_own_endpoint() {
    let pcp = silent_pcp().await;
    let upnp = fake::start(Script::standard()).await;
    let gateway = gateway(&pcp, &upnp);
    let mapping = map_upnp(gateway, INTERNAL, LIFETIME, BUDGET).await.unwrap();
    let renewed = renew(
        gateway.address,
        LOCAL,
        &mapping,
        Duration::from_secs(3600),
        BUDGET,
    )
    .await
    .unwrap();
    assert_eq!(renewed.protocol, Protocol::Upnp);
    assert_eq!(renewed.lifetime, Duration::from_secs(3600));
    assert_eq!(renewed.external_ip, mapping.external_ip);
    release(gateway.address, LOCAL, &renewed).await.unwrap();
    assert_eq!(
        upnp.actions(),
        [
            "AddPortMapping",
            "GetExternalIPAddress",
            "AddPortMapping",
            "DeletePortMapping"
        ]
    );
    assert_eq!(upnp.searches(), 1, "one search for the three requests");
    assert!(pcp.requests().is_empty(), "the PCP port is not asked");
}

/// The pace of the keeper test: the lifetime is two seconds, so a renewal comes after one.
const FAST: Timing = Timing {
    lifetime: Duration::from_secs(2),
    request_budget: Duration::from_millis(300),
    min_renew: Duration::from_millis(50),
    retry: Duration::from_millis(100),
    silent_retry: Duration::from_millis(100),
};

#[tokio::test]
async fn the_keeper_holds_a_upnp_mapping_renews_it_and_deletes_it_on_stop() {
    let pcp = silent_pcp().await;
    let upnp = fake::start(Script::standard()).await;
    let keeper = Keeper::start(gateway(&pcp, &upnp), INTERNAL, FAST);
    let mut watch = keeper.watch();
    let mapped = tokio::time::timeout(
        Duration::from_secs(5),
        watch.wait_for(|state| matches!(state, State::Mapped(_))),
    )
    .await
    .expect("mapped in time")
    .expect("keeper alive")
    .clone();
    let mapping = match mapped {
        State::Mapped(mapping) => mapping,
        other => panic!("{other:?}"),
    };
    assert_eq!(mapping.protocol, Protocol::Upnp);
    tokio::time::sleep(Duration::from_millis(1300)).await;
    keeper.stop().await;
    let actions = upnp.actions();
    assert_eq!(actions.first().map(String::as_str), Some("AddPortMapping"));
    assert_eq!(
        actions.last().map(String::as_str),
        Some("DeletePortMapping")
    );
    let adds = actions.iter().filter(|a| *a == "AddPortMapping").count();
    assert!(adds >= 2, "mapped and renewed: {actions:?}");
    assert_eq!(upnp.searches(), 1, "a renewal does not search again");
}

#[tokio::test]
async fn the_measurement_names_the_scope_of_the_external_address_and_deletes_the_mapping() {
    let pcp = silent_pcp().await;
    let upnp = fake::start(Script::standard()).await;
    let lines = measure_upnp(Some(gateway(&pcp, &upnp)), INTERNAL, false, BUDGET).await;
    assert_eq!(
        lines,
        [
            "port-map upnp result=granted external-port=48896 same-port=yes external-scope=public",
            "port-map upnp release=yes",
        ]
    );
    assert!(!lines.join("\n").contains("203.0.113.7"));
    let shown = measure_upnp(Some(gateway(&pcp, &upnp)), INTERNAL, true, BUDGET).await;
    assert!(
        shown[0].ends_with(" external-address=203.0.113.7"),
        "{shown:?}"
    );

    let behind_another_nat = Script {
        soap: Box::new(|name, body| {
            if name == "GetExternalIPAddress" {
                (
                    200,
                    fake::answer(
                        name,
                        "<NewExternalIPAddress>10.64.0.9</NewExternalIPAddress>",
                    ),
                )
            } else {
                (Script::standard().soap)(name, body)
            }
        }),
        ..Script::standard()
    };
    let upnp = fake::start(behind_another_nat).await;
    let lines = measure_upnp(Some(gateway(&pcp, &upnp)), INTERNAL, false, BUDGET).await;
    assert!(lines[0].ends_with("external-scope=private"), "{lines:?}");
}

#[tokio::test]
async fn the_measurement_names_a_refusal_silence_and_a_missing_gateway() {
    let pcp = silent_pcp().await;
    let refusing = fake::start(Script {
        soap: Box::new(|_, _| fake::fault(718)),
        ..Script::standard()
    })
    .await;
    let lines = measure_upnp(Some(gateway(&pcp, &refusing)), INTERNAL, false, BUDGET).await;
    assert_eq!(lines, ["port-map upnp result=refused:718"]);
    let silent = fake::start(Script {
        ssdp_answers: false,
        ..Script::standard()
    })
    .await;
    let started = StdInstant::now();
    let lines = measure_upnp(
        Some(gateway(&pcp, &silent)),
        INTERNAL,
        false,
        Duration::from_millis(400),
    )
    .await;
    assert_eq!(lines, ["port-map upnp result=silent"]);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(measure_upnp(None, INTERNAL, false, BUDGET).await.is_empty());
}
