//! Native endpoint construction; family restriction exists only in controlled tests.

#![forbid(unsafe_code)]

use std::{net::SocketAddr, sync::Arc};

use iroh_base::PublicKey;
use tokio::sync::Semaphore;

use crate::{
    identity::Identity,
    network::{Limits, NetworkError, SignaledEndpoint},
};

/// cancel-safe: NO — the retained startup owner must join construction cleanup.
pub(super) async fn bind(
    identity: &Identity,
    signaling: SocketAddr,
    peers: &[PublicKey],
    limits: Limits,
    slots: Option<Arc<Semaphore>>,
    #[cfg(test)] native: Option<SocketAddr>,
) -> Result<SignaledEndpoint, NetworkError> {
    #[cfg(test)]
    if let Some(native) = native {
        return SignaledEndpoint::bind_native_for_tests(
            identity, native, signaling, peers, limits, slots,
        )
        .await;
    }
    SignaledEndpoint::bind_composed(identity, signaling, peers, limits, slots).await
}

#[cfg(test)]
impl super::SharedResourcesStart {
    pub(crate) fn start_ipv6_only_for_tests(
        identity: &Identity,
        plan: &crate::startup::preflight::ComposedStartupPlan<'_>,
        limits: Limits,
    ) -> Self {
        Self::start_seamed(
            identity,
            plan,
            limits,
            false,
            false,
            false,
            Some(super::start::StageGates {
                after_bridge: None,
                after_native_close: None,
                native_bind: Some(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0))),
            }),
        )
    }
}
