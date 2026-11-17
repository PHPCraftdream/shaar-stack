//! Controlled retained-server startup seams.

#![forbid(unsafe_code)]

use super::*;

impl ServerRole {
    /// Builds the real seamed start with shared admission and optional gates.
    /// Attaches the test observer, leaves the role in `Starting`, and returns
    /// controls for the armed gate; `start()` resumes construction.
    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "Test seam exposes independent startup gates"
    )]
    pub(crate) fn with_events_seamed_for_tests(
        config: ServerConfig,
        identity: &Identity,
        allowlist: Allowlist,
        limits: Limits,
        options: RoleOptions,
        events: RoleEventLog,
        cleanup_hold: bool,
        pause_after_bridge: bool,
    ) -> Result<(Self, crate::startup::resources::StageControls), StartupError> {
        options.validate()?;
        let keys: Vec<PublicKey> = allowlist.keys().collect();
        let plan = preflight_server(&config, identity, &keys)?;
        let (start, controls) = SharedResourcesStart::start_shared_seamed_for_tests(
            identity,
            &plan,
            limits,
            true,
            cleanup_hold,
            pause_after_bridge,
        );
        // Same composition as `with_events` + the seamed starting phase:
        // `Self::new` validates the options, the role skips `new`'s `New`
        // phase by entering `Starting` directly; `start()` resumes it.
        let mut role = Self::new(config, identity, allowlist, limits, options)?;
        role.events = Some(events);
        role.phase = ServerPhase::Starting(start);
        Ok((role, controls))
    }

    /// Real retained server composition restricted to the controlled IPv6 socket.
    pub(crate) fn with_events_ipv6_only_for_tests(
        config: ServerConfig,
        identity: &Identity,
        allowlist: Allowlist,
        limits: Limits,
        options: RoleOptions,
        events: RoleEventLog,
    ) -> Result<Self, StartupError> {
        options.validate()?;
        let keys: Vec<PublicKey> = allowlist.keys().collect();
        let plan = preflight_server(&config, identity, &keys)?;
        let start = SharedResourcesStart::start_ipv6_only_for_tests(identity, &plan, limits, true);
        let mut role = Self::new(config, identity, allowlist, limits, options)?;
        role.events = Some(events);
        role.phase = ServerPhase::Starting(start);
        Ok(role)
    }

    /// Test-only constructor attaching the event observer; otherwise identical
    /// to [`ServerRole::new`].
    #[cfg(test)]
    pub(crate) fn with_events(
        config: ServerConfig,
        identity: &Identity,
        allowlist: Allowlist,
        limits: Limits,
        options: RoleOptions,
        events: RoleEventLog,
    ) -> Result<Self, StartupError> {
        let mut role = Self::new(config, identity, allowlist, limits, options)?;
        role.events = Some(events);
        Ok(role)
    }

    /// Test-only handle to THIS role's retained Yggdrasil bridge (a real
    /// `Arc<YggBridge>` clone; its dropped-datagram counter is the carrier
    /// peer filter observation). `Err(())` when no live composition.
    #[cfg(test)]
    pub(crate) fn ygg_bridge_for_tests(&self) -> Result<std::sync::Arc<shaar_ygg::YggBridge>, ()> {
        match &self.phase {
            ServerPhase::Admitted(parts) | ServerPhase::Live(parts) => {
                parts.resources.ygg_bridge_for_tests()
            }
            _ => Err(()),
        }
    }

    /// Test-only observer of the armed Mainline cleanup hold; `None` before
    /// the composition's owner stage stored it.
    #[cfg(test)]
    pub(crate) fn mainline_cleanup_observer_for_tests(&self) -> Option<n0_mainline::Observer> {
        match &self.phase {
            ServerPhase::Admitted(parts) | ServerPhase::Live(parts) => {
                parts.resources.mainline_cleanup_observer_for_tests()
            }
            _ => None,
        }
    }

    /// Test-only Mainline cleanup hold over the retained composition.
    #[cfg(test)]
    pub(crate) fn mainline_cleanup_hold_for_tests(&self) -> Result<n0_mainline::CleanupHold, ()> {
        match &self.phase {
            ServerPhase::Admitted(parts) | ServerPhase::Live(parts) => {
                parts.resources.mainline_cleanup_hold_for_tests()
            }
            _ => Err(()),
        }
    }
}
