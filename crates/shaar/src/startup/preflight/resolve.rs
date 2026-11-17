//! One bounded resolution of the Mainline bootstrap host names before the
//! composed startup. Numeric entries pass through unchanged; each host name
//! contributes its first usable IPv4 address. Lookup errors and host names
//! are never echoed.

use std::future::Future;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use crate::config::NetworkSettings;

use super::StartupError;

/// Upper bound for resolving every bootstrap host name; lookups run concurrently.
pub(crate) const RESOLVE_DEADLINE: Duration = Duration::from_secs(5);

/// Resolves the host names of `network` with the system resolver; `None`
/// when there are no settings or they name no host, so nothing changes.
/// cancel-safe: YES — nothing is retained; a later call starts over.
pub(crate) async fn resolve_network(
    network: Option<&NetworkSettings>,
) -> Result<Option<NetworkSettings>, StartupError> {
    let Some(network) = network else {
        return Ok(None);
    };
    resolve_with(network, RESOLVE_DEADLINE, |name, port| async move {
        tokio::net::lookup_host((name.as_str(), port))
            .await
            .map(Iterator::collect)
    })
    .await
}

/// Same as [`resolve_network`] with an injected lookup (tests).
pub(crate) async fn resolve_with<L, F>(
    network: &NetworkSettings,
    deadline: Duration,
    lookup: L,
) -> Result<Option<NetworkSettings>, StartupError>
where
    L: Fn(String, u16) -> F,
    F: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    let Some(mainline) = network.mainline() else {
        return Ok(None);
    };
    if mainline.hosts().is_empty() {
        return Ok(None);
    }
    let lookups = mainline.hosts().iter().map(|host| {
        let pending = lookup(host.name().to_owned(), host.port());
        async move {
            match tokio::time::timeout(deadline, pending).await {
                Ok(Ok(addresses)) => first_usable(&addresses),
                Ok(Err(_)) | Err(_) => None,
            }
        }
    });
    let resolved: Vec<SocketAddrV4> = futures::future::join_all(lookups)
        .await
        .into_iter()
        .flatten()
        .collect();
    let mainline = mainline.with_resolved(&resolved);
    if mainline.bootstrap().is_empty() {
        return Err(StartupError::BootstrapUnresolved);
    }
    Ok(Some(network.with_mainline(mainline)))
}

/// The first IPv4 address a bootstrap node can be reached at.
fn first_usable(addresses: &[SocketAddr]) -> Option<SocketAddrV4> {
    addresses.iter().find_map(|address| match address {
        SocketAddr::V4(v4)
            if !v4.ip().is_unspecified()
                && !v4.ip().is_multicast()
                && !v4.ip().is_broadcast()
                && v4.port() != 0 =>
        {
            Some(*v4)
        }
        _ => None,
    })
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod tests;
