//! The measurement behind `diag port-map`: one mapping at the home router, reported as tokens.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use super::{GATEWAY_PORT, map_udp, release};

/// Lifetime asked for by the measurement: short, so that a mapping that is not released expires
/// soon by itself.
pub const MEASURE_LIFETIME: Duration = Duration::from_secs(120);
/// Bound of the whole mapping request of the measurement.
pub const MEASURE_BUDGET: Duration = Duration::from_secs(3);

/// The gateway to ask, with its mapping port, and the address of this host on its network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gateway {
    pub address: SocketAddr,
    pub local: IpAddr,
}

/// The home router of this machine, when the system names one (a private address).
pub async fn home_gateway() -> Option<Gateway> {
    let router = tokio::task::spawn_blocking(netwatch::interfaces::HomeRouter::new)
        .await
        .ok()??;
    Some(Gateway {
        address: SocketAddr::new(router.gateway, GATEWAY_PORT),
        local: router.my_ip?,
    })
}

/// Asks `gateway` for a mapping of `port` to the same external port, reports what happened and
/// deletes the mapping again. Prints tokens and counts; an address only with `show_address`.
/// cancel-safe: yes — a cancelled measurement leaves a mapping that expires in two minutes.
pub async fn measure(gateway: Option<Gateway>, port: u16, show_address: bool) -> Vec<String> {
    measure_within(gateway, port, show_address, MEASURE_BUDGET).await
}

/// [`measure`] with another bound for the mapping request.
pub async fn measure_within(
    gateway: Option<Gateway>,
    port: u16,
    show_address: bool,
    budget: Duration,
) -> Vec<String> {
    let Some(gateway) = gateway else {
        return vec!["port-map gateway=none".to_owned()];
    };
    let mut lines = Vec::with_capacity(4);
    lines.push(if show_address {
        format!("port-map gateway=found address={}", gateway.address.ip())
    } else {
        "port-map gateway=found".to_owned()
    });
    lines.push(format!(
        "port-map request internal={port} external={port} lifetime_s={}",
        MEASURE_LIFETIME.as_secs()
    ));
    let granted = map_udp(
        gateway.address,
        gateway.local,
        port,
        port,
        MEASURE_LIFETIME,
        budget,
    )
    .await;
    let mapping = match granted {
        Ok(mapping) => mapping,
        Err(error) => {
            lines.push(format!("port-map result={error}"));
            return lines;
        }
    };
    let mut line = format!(
        "port-map result=granted protocol={} external-port={} same-port={} lifetime_s={}",
        mapping.protocol.token(),
        mapping.external_port,
        if mapping.external_port == port {
            "yes"
        } else {
            "no"
        },
        mapping.lifetime.as_secs()
    );
    if let (true, Some(ip)) = (show_address, mapping.external_ip) {
        line.push_str(&format!(" external-address={ip}"));
    }
    lines.push(line);
    lines.push(
        match release(gateway.address, gateway.local, &mapping).await {
            Ok(()) => "port-map release=yes".to_owned(),
            Err(error) => format!("port-map release=no:{error}"),
        },
    );
    lines
}
