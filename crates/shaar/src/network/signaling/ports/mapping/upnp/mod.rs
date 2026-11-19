//! Asking a UPnP Internet Gateway Device for a UDP port mapping (leaf PORT-1, step 3b), the third
//! protocol after PCP and NAT-PMP. The gateway is found by one SSDP search sent to its own
//! address, its description is read over HTTP, and the mapping is made with the SOAP actions
//! `AddPortMapping`, `GetExternalIPAddress` and `DeletePortMapping`. Only the gateway's own
//! address is ever contacted: a description that points elsewhere is refused.

#[cfg(test)]
mod chain_tests;
#[cfg(test)]
pub(super) mod fake;
mod http;
#[cfg(test)]
mod tests;
mod xml;

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    time::{Instant, timeout_at},
};

use super::{FIRST_WAIT, MapError};

/// The UDP port of SSDP on the gateway.
pub(super) const SSDP_PORT: u16 = 1900;
const SEARCH_TARGET: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
/// The services that map ports, the preferred first.
const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];
const MAPPING_NAME: &str = "shaar";
/// SOAP error: the gateway grants only mappings without a lease.
const ONLY_PERMANENT_LEASES: u16 = 725;
/// SOAP error: there is no such mapping, which a deletion wants anyway.
const NO_SUCH_ENTRY: u16 = 714;
/// Bound of the request for the external address that follows a grant.
const EXTERNAL_BUDGET: Duration = Duration::from_millis(500);

/// The control endpoint of the mapping service of one gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Igd {
    control: SocketAddr,
    path: String,
    service: &'static str,
}

/// Finds the mapping service of the gateway at `ssdp` (its address with [`SSDP_PORT`]).
/// cancel-safe: yes.
async fn discover(ssdp: SocketAddr, deadline: Instant) -> Result<Igd, MapError> {
    let location = search(ssdp, deadline).await?;
    let base = parse_url(&location)
        .filter(|(address, _)| address.ip() == ssdp.ip())
        .ok_or(MapError::Unsupported)?;
    let response = http::exchange(
        base.0,
        &http::request("GET", base.0, base.1, &[], ""),
        deadline,
    )
    .await?;
    if response.status != 200 {
        return Err(MapError::Unsupported);
    }
    let (control, path, service) =
        find_control(&response.body, base, ssdp.ip()).ok_or(MapError::Unsupported)?;
    Ok(Igd {
        control,
        path,
        service,
    })
}

/// One SSDP search for the gateway, sent again with doubling waits; the `LOCATION` of the first
/// answer that comes from the gateway's address.
async fn search(ssdp: SocketAddr, deadline: Instant) -> Result<String, MapError> {
    let any = match ssdp {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind((any, 0)).await.map_err(|_| MapError::Io)?;
    let request = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:{SSDP_PORT}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {SEARCH_TARGET}\r\n\r\n"
    );
    let mut buffer = [0_u8; 1500];
    let mut wait = FIRST_WAIT;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(MapError::Silent);
        }
        socket
            .send_to(request.as_bytes(), ssdp)
            .await
            .map_err(|_| MapError::Io)?;
        let until = deadline.min(now + wait);
        loop {
            match timeout_at(until, socket.recv_from(&mut buffer)).await {
                Ok(Ok((length, from))) => {
                    if from.ip() == ssdp.ip()
                        && let Some(location) = location(&buffer[..length])
                    {
                        return Ok(location);
                    }
                }
                // An ICMP error from a gateway that has no SSDP service.
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused
                    ) =>
                {
                    return Err(MapError::Silent);
                }
                Ok(Err(_)) => return Err(MapError::Io),
                Err(_) => break,
            }
        }
        wait *= 2;
    }
}

/// The `LOCATION` header of an SSDP answer with status 200.
fn location(datagram: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(datagram).ok()?;
    let mut lines = text.split("\r\n");
    let status = lines.next()?;
    if !status.starts_with("HTTP/1.") || status.split(' ').nth(1) != Some("200") {
        return None;
    }
    lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("location")
            .then(|| value.trim().to_owned())
    })
}

/// The address and path of an `http://` URL whose host is an IP address.
fn parse_url(url: &str) -> Option<(SocketAddr, &str)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, "/"),
    };
    let address = authority.parse::<SocketAddr>().ok().or_else(|| {
        authority
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 80))
    })?;
    path.bytes()
        .all(|byte| byte.is_ascii_graphic())
        .then_some((address, path))
}

/// The control URL of the most preferred mapping service in the description `xml`, resolved
/// against `base` (the description's own address and path, or its `URLBase` when that names the
/// gateway). A URL that names another host is refused.
fn find_control(
    xml: &str,
    base: (SocketAddr, &str),
    gateway: IpAddr,
) -> Option<(SocketAddr, String, &'static str)> {
    let declared = xml::text(xml, "URLBase");
    let base = declared
        .as_deref()
        .and_then(parse_url)
        .filter(|(address, _)| address.ip() == gateway)
        .unwrap_or(base);
    for service in SERVICES {
        let control = xml::elements(xml, "service")
            .filter(|block| xml::text(block, "serviceType").as_deref() == Some(service))
            .find_map(|block| xml::text(block, "controlURL"));
        if let Some((address, path)) = control.and_then(|url| resolve(&url, base, gateway)) {
            return Some((address, path, service));
        }
    }
    None
}

fn resolve(url: &str, base: (SocketAddr, &str), gateway: IpAddr) -> Option<(SocketAddr, String)> {
    if url.starts_with("http://") {
        let (address, path) = parse_url(url)?;
        return (address.ip() == gateway).then(|| (address, path.to_owned()));
    }
    if url.contains("://") || !url.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    if url.starts_with('/') {
        return Some((base.0, url.to_owned()));
    }
    let directory = &base.1[..=base.1.rfind('/')?];
    Some((base.0, format!("{directory}{url}")))
}

/// Finds the gateway and asks it to forward UDP `external` to `internal` of `local` for
/// `lifetime`; gives up after `budget`. Returns the control endpoint and the external address
/// when the gateway tells it.
/// cancel-safe: yes — a cancelled call may leave a mapping that the gateway expires.
pub(super) async fn map(
    ssdp: SocketAddr,
    local: IpAddr,
    ports: (u16, u16),
    lifetime: Duration,
    budget: Duration,
) -> Result<(Igd, Option<IpAddr>), MapError> {
    let deadline = Instant::now() + budget;
    let igd = discover(ssdp, deadline).await?;
    add(&igd, local, ports, lifetime, deadline).await?;
    let external = external_address(&igd, Instant::now() + EXTERNAL_BUDGET).await;
    Ok((igd, external))
}

/// Asks again for a mapping that [`map`] made: the same request, which the gateway reads as a
/// renewal. cancel-safe: yes.
pub(super) async fn renew(
    igd: &Igd,
    local: IpAddr,
    ports: (u16, u16),
    lifetime: Duration,
    budget: Duration,
) -> Result<(), MapError> {
    add(igd, local, ports, lifetime, Instant::now() + budget).await
}

/// Deletes the mapping of `external_port`; a mapping that is already gone counts as deleted.
/// cancel-safe: yes.
pub(super) async fn delete(
    igd: &Igd,
    external_port: u16,
    budget: Duration,
) -> Result<(), MapError> {
    let arguments = format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort><NewProtocol>UDP</NewProtocol>"
    );
    match soap(
        igd,
        "DeletePortMapping",
        &arguments,
        Instant::now() + budget,
    )
    .await
    {
        Ok(_) | Err(MapError::Refused(NO_SUCH_ENTRY)) => Ok(()),
        Err(error) => Err(error),
    }
}

/// `AddPortMapping`, and again without a lease when the gateway grants no other kind.
async fn add(
    igd: &Igd,
    local: IpAddr,
    (internal, external): (u16, u16),
    lifetime: Duration,
    deadline: Instant,
) -> Result<(), MapError> {
    let seconds = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
    let mut lease = seconds;
    loop {
        let arguments = format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external}</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>{internal}</NewInternalPort><NewInternalClient>{local}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{MAPPING_NAME}</NewPortMappingDescription><NewLeaseDuration>{lease}</NewLeaseDuration>"
        );
        match soap(igd, "AddPortMapping", &arguments, deadline).await {
            Ok(_) => return Ok(()),
            Err(MapError::Refused(ONLY_PERMANENT_LEASES)) if lease != 0 => lease = 0,
            Err(error) => return Err(error),
        }
    }
}

async fn external_address(igd: &Igd, deadline: Instant) -> Option<IpAddr> {
    let body = soap(igd, "GetExternalIPAddress", "", deadline).await.ok()?;
    let address: IpAddr = xml::text(&body, "NewExternalIPAddress")?.parse().ok()?;
    (!address.is_unspecified()).then_some(address)
}

/// One SOAP action; a refusal carries the gateway's `errorCode`, or the HTTP status without one.
async fn soap(
    igd: &Igd,
    action: &str,
    arguments: &str,
    deadline: Instant,
) -> Result<String, MapError> {
    let service = igd.service;
    let body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{service}\">{arguments}</u:{action}></s:Body></s:Envelope>"
    );
    let headers = [
        "Content-Type: text/xml; charset=\"utf-8\"".to_owned(),
        format!("SOAPAction: \"{service}#{action}\""),
    ];
    let request = http::request("POST", igd.control, &igd.path, &headers, &body);
    let response = http::exchange(igd.control, &request, deadline).await?;
    if response.status == 200 {
        return Ok(response.body);
    }
    let code = xml::text(&response.body, "errorCode")
        .and_then(|code| code.parse().ok())
        .unwrap_or(response.status);
    Err(MapError::Refused(code))
}
