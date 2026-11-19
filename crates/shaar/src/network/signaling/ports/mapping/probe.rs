//! The measurement behind `diag port-map`: one mapping at the home router, reported as tokens.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use super::{GATEWAY_PORT, map_udp, map_upnp, release, upnp};

/// Lifetime asked for by the measurement: short, so that a mapping that is not released expires
/// soon by itself.
pub const MEASURE_LIFETIME: Duration = Duration::from_secs(120);
/// Bound of the whole mapping request of the measurement.
pub const MEASURE_BUDGET: Duration = Duration::from_secs(3);

/// The gateway to ask, with its mapping port and its SSDP address, and the address of this host
/// on its network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gateway {
    /// Where PCP and NAT-PMP are asked.
    pub address: SocketAddr,
    /// Where the UPnP search is sent.
    pub upnp: SocketAddr,
    pub local: IpAddr,
}

/// The home router of this machine, when the system names one (a private address).
pub async fn home_gateway() -> Option<Gateway> {
    let router = tokio::task::spawn_blocking(netwatch::interfaces::HomeRouter::new)
        .await
        .ok()??;
    Some(Gateway {
        address: SocketAddr::new(router.gateway, GATEWAY_PORT),
        upnp: SocketAddr::new(router.gateway, upnp::SSDP_PORT),
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

/// The UPnP half of the measurement: one mapping by UPnP at `gateway`, reported as tokens that
/// start with `port-map upnp`, and deleted again. It says whether the external address the
/// gateway reports is public or private (a second NAT in front of the router), and shows the
/// address itself only with `show_address`. Nothing is printed for a missing gateway, which
/// [`measure`] already reports.
/// cancel-safe: yes — a cancelled measurement leaves a mapping that expires in two minutes.
pub async fn measure_upnp(
    gateway: Option<Gateway>,
    port: u16,
    show_address: bool,
    budget: Duration,
) -> Vec<String> {
    let Some(gateway) = gateway else {
        return Vec::new();
    };
    let mapping = match map_upnp(gateway, port, MEASURE_LIFETIME, budget).await {
        Ok(mapping) => mapping,
        Err(error) => return vec![format!("port-map upnp result={error}")],
    };
    let mut line = format!(
        "port-map upnp result=granted external-port={} same-port={} external-scope={}",
        mapping.external_port,
        if mapping.external_port == port {
            "yes"
        } else {
            "no"
        },
        mapping.external_ip.map_or("none", scope),
    );
    if let (true, Some(ip)) = (show_address, mapping.external_ip) {
        line.push_str(&format!(" external-address={ip}"));
    }
    let released = match release(gateway.address, gateway.local, &mapping).await {
        Ok(()) => "port-map upnp release=yes".to_owned(),
        Err(error) => format!("port-map upnp release=no:{error}"),
    };
    vec![line, released]
}

/// Whether an address can be reached from the internet: `private` for the ranges of a local or
/// carrier-grade network, which a gateway behind another NAT reports as its own.
fn scope(address: IpAddr) -> &'static str {
    let private = match address {
        IpAddr::V4(v4) => {
            let [first, second, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (first == 100 && (64..128).contains(&second))
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    };
    if private { "private" } else { "public" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_of_a_local_or_carrier_grade_network_is_private() {
        for text in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.1.1",
            "127.0.0.1",
            "fd00::1",
            "::1",
        ] {
            assert_eq!(scope(text.parse().unwrap()), "private", "{text}");
        }
        for text in [
            "203.0.113.7",
            "100.63.255.255",
            "100.128.0.1",
            "8.8.8.8",
            "2001:db8::1",
        ] {
            assert_eq!(scope(text.parse().unwrap()), "public", "{text}");
        }
    }
}
