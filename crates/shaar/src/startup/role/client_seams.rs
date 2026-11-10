use super::{ClientPhase, ClientRole};
use crate::config::ClientConfig;
use crate::identity::Identity;
use crate::network::Limits;
use crate::startup::StartupError;
use crate::startup::preflight::preflight_client;
use crate::startup::resources::{SharedResourcesStart, StageControls};
use crate::startup::role::{RoleEventLog, RoleOptions};
use iroh_base::PublicKey;

impl ClientRole {
    /// Retained bridge handle; the role's caller must keep its run future driven.
    pub(crate) fn ygg_bridge_for_tests(&self) -> Result<std::sync::Arc<shaar_ygg::YggBridge>, ()> {
        match &self.phase {
            ClientPhase::Live(parts) => parts.resources.ygg_bridge_for_tests(),
            _ => Err(()),
        }
    }

    /// Builds the retained client role through the real preflight and startup
    /// composition, leaving its owned startup handle in `Starting`.
    pub(crate) fn with_events_seamed_for_tests(
        config: ClientConfig,
        identity: &Identity,
        limits: Limits,
        options: RoleOptions,
        events: RoleEventLog,
        pause_after_bridge: bool,
    ) -> Result<(Self, StageControls), StartupError> {
        options.validate()?;
        let service_key = PublicKey::from_bytes(config.server_key_bytes())
            .map_err(|_| StartupError::InvalidPolicy)?;
        let service_keys = [service_key];
        let plan = preflight_client(&config, identity, &service_keys)?;
        let (start, controls) = SharedResourcesStart::start_shared_seamed_for_tests(
            identity,
            &plan,
            limits,
            false,
            false,
            pause_after_bridge,
        );
        drop(plan);
        let mut role = Self::with_events(config, identity, limits, options, events)?;
        role.phase = ClientPhase::Starting(start);
        Ok((role, controls))
    }
}
