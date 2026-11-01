# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact reversible source edits for a numeric-only Mainline actor constructor."""
from __future__ import annotations


def edits() -> dict[str, list[tuple[str, str]]]:
    """Return narrowly anchored patches for the upstream n0-mainline sources."""
    actor_constructor = '''    pub(crate) fn new(config: config::Config) -> io::Result<Self> {
        let id = if let Some(ip) = config.public_ip {'''
    actor_constructor_edit = '''    pub(crate) fn new(config: config::Config) -> io::Result<Self> {
        Self::new_inner(config, None)
    }

    pub(crate) fn new_numeric(
        bind: SocketAddrV4,
        bootstrap: Box<[SocketAddrV4]>,
    ) -> io::Result<Self> {
        if bootstrap.is_empty()
            || bootstrap.len() > 4
            || bootstrap.iter().any(|addr| addr.port() == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid numeric bootstrap",
            ));
        }
        let config = config::Config {
            bootstrap: Vec::new(),
            port: None,
            server_settings: Default::default(),
            server_mode: false,
            public_ip: None,
            #[cfg(test)]
            disable_announce_signed_peers: false,
        };
        Self::new_inner(config, Some((bind, bootstrap)))
    }

    fn new_inner(
        config: config::Config,
        numeric: Option<(SocketAddrV4, Box<[SocketAddrV4]>)>,
    ) -> io::Result<Self> {
        let hard_client_only = numeric.is_some();
        let id = if let Some(ip) = config.public_ip {'''
    socket_new = '''    pub(crate) fn new(config: &Config) -> io::Result<Self> {
        let port = config.port;'''
    socket_new_edit = '''    pub(crate) fn new(config: &Config) -> io::Result<Self> {
        Self::new_at(config, None)
    }

    pub(crate) fn new_at(
        config: &Config,
        bind: Option<SocketAddrV4>,
    ) -> io::Result<Self> {
        let port = config.port;'''
    socket_binding = '''        let io = if let Some(port) = port {
            UdpIo::bind(SocketAddr::from(([0, 0, 0, 0], port)))?
        } else {
            match UdpIo::bind(SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT))) {
                Ok(io) => Ok(io),
                Err(_) => UdpIo::bind(SocketAddr::from(([0, 0, 0, 0], 0))),
            }?
        };'''
    socket_binding_edit = '''        let io = if let Some(bind) = bind {
            UdpIo::bind(SocketAddr::V4(bind))?
        } else if let Some(port) = port {
            UdpIo::bind(SocketAddr::from(([0, 0, 0, 0], port)))?
        } else {
            match UdpIo::bind(SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT))) {
                Ok(io) => Ok(io),
                Err(_) => UdpIo::bind(SocketAddr::from(([0, 0, 0, 0], 0))),
            }?
        };'''
    return {
        "src/actor.rs": [
            (
                "    get_senders: HashMap<Id, Vec<ResponseSender>>,\n}",
                "    get_senders: HashMap<Id, Vec<ResponseSender>>,\n    hard_client_only: bool,\n}",
            ),
            (actor_constructor, actor_constructor_edit),
            (
                '''        let socket = KrpcSocket::new(&config)?;
        let bootstrap = config
            .bootstrap
            .iter()
            .flat_map(|s| {
                s.to_socket_addrs().map(|addrs| {
                    addrs
                        .filter_map(|addr| match addr {
                            SocketAddr::V4(addr_v4) => Some(addr_v4),
                            _ => None,
                        })
                        .collect::<Box<[_]>>()
                })
            })
            .flatten()
            .collect();''',
                '''        let socket = KrpcSocket::new_at(
            &config,
            numeric.as_ref().map(|(bind, _)| *bind),
        )?;
        let bootstrap = if let Some((_, bootstrap)) = numeric {
            bootstrap.into_vec()
        } else {
            config
                .bootstrap
                .iter()
                .flat_map(|s| {
                    s.to_socket_addrs().map(|addrs| {
                        addrs
                            .filter_map(|addr| match addr {
                                SocketAddr::V4(addr_v4) => Some(addr_v4),
                                _ => None,
                            })
                            .collect::<Box<[_]>>()
                    })
                })
                .flatten()
                .collect()
        };''',
            ),
            (
                "            get_senders: HashMap::new(),\n        })",
                "            get_senders: HashMap::new(),\n            hard_client_only,\n        })",
            ),
            (
                '            if !self.core.server_mode && !self.core.firewalled {',
                '            if !self.hard_client_only && !self.core.server_mode && !self.core.firewalled {',
            ),
            (
                '    fn set_server_mode(&mut self, mode: bool) {\n        self.socket.server_mode = mode;',
                '    fn set_server_mode(&mut self, mode: bool) {\n        if self.hard_client_only {\n            return;\n        }\n        self.socket.server_mode = mode;',
            ),
            (
                '            MessageType::Request(request_specific) => {\n                let (response, should_repopulate_routing_tables)',
                '            MessageType::Request(request_specific) => {\n                if self.hard_client_only {\n                    return None;\n                }\n                let (response, should_repopulate_routing_tables)',
            ),
        ],
        "src/actor/socket.rs": [
            (socket_new, socket_new_edit),
            (socket_binding, socket_binding_edit),
        ],
    }
