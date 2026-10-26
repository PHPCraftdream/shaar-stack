//! Private owned resolver foundation. Public discovery dials remain closed.

mod lifetime;
mod runtime;
mod sockets;
#[cfg(test)]
pub(crate) mod tests;
mod transport;
mod wire;

use std::{future::Future, io, net::SocketAddr, sync::Arc, time::Duration};

use hickory_resolver::{
    Resolver,
    config::{
        ConnectionConfig, LookupIpStrategy, NameServerConfig, OpportunisticEncryption,
        ResolveHosts, ResolverConfig,
    },
    lookup::Lookup,
    lookup_ip::LookupIp,
    net::NetError,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{ExecutorHandle, discovery::absolute_name};
use lifetime::Gate;
pub(crate) use lifetime::Lifetime;
use runtime::Provider;
pub(crate) use transport::NumericOnly;

#[derive(Clone)]
pub(crate) struct OwnedResolver {
    resolver: Resolver<Provider>,
    gate: Gate,
    calls: Arc<Semaphore>,
}

impl OwnedResolver {
    pub(crate) fn new(
        nameservers: &[SocketAddr],
        executor: ExecutorHandle,
    ) -> io::Result<(Lifetime, Self)> {
        let lifetime = Lifetime::new();
        let gate = lifetime.gate();
        let provider = Provider::new(gate, executor, nameservers);
        Ok((lifetime, Self::with_provider(nameservers, provider)?))
    }

    fn with_provider(nameservers: &[SocketAddr], provider: Provider) -> io::Result<Self> {
        let gate = provider.gate.clone();
        let config = ResolverConfig::from_name_servers(
            nameservers
                .iter()
                .map(|server| {
                    let mut udp = ConnectionConfig::udp();
                    let mut tcp = ConnectionConfig::tcp();
                    udp.port = server.port();
                    tcp.port = server.port();
                    NameServerConfig::new(server.ip(), true, vec![udp, tcp])
                })
                .collect(),
        );
        let mut builder = Resolver::builder_with_config(config, provider)
            .with_opportunistic_encryption(OpportunisticEncryption::Disabled);
        let options = builder.options_mut();
        options.cache_size = 0; // Prepared 0.26.3 never constructs Moka on this branch.
        options.use_hosts_file = ResolveHosts::Never;
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.max_active_requests = 4;
        options.timeout = Duration::from_secs(2);
        options.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        options.try_tcp_on_error = true;
        let resolver = builder.build().map_err(io::Error::other)?;
        Ok(Self {
            resolver,
            gate,
            calls: Arc::new(Semaphore::new(4)),
        })
    }

    fn admit(&self, name: &str) -> Result<OwnedSemaphorePermit, NetError> {
        self.gate.check()?;
        absolute_name(name)?;
        self.calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| NetError::Busy)
    }

    /// Captures admission synchronously, including unpolled futures. The permit outlives
    /// the actual lookup and is not released merely because cancellation was requested.
    fn lookup<T: Send, F: Future<Output = Result<T, NetError>> + Send>(
        &self,
        name: String,
        lookup: impl FnOnce(Resolver<Provider>, String) -> F + Send,
    ) -> impl Future<Output = Result<T, NetError>> + Send {
        let permit = self.admit(&name);
        let resolver = self.resolver.clone();
        let gate = self.gate.clone();
        async move {
            let _permit = permit?;
            gate.during(async move { lookup(resolver, name).await })
                .await?
        }
    }
}

impl libp2p::dns::Resolver for OwnedResolver {
    fn lookup_ip(&self, name: String) -> impl Future<Output = Result<LookupIp, NetError>> + Send {
        self.lookup(name, async move |resolver, name| {
            resolver.lookup_ip(name).await
        })
    }

    fn ipv4_lookup(&self, name: String) -> impl Future<Output = Result<Lookup, NetError>> + Send {
        self.lookup(name, async move |resolver, name| {
            resolver.ipv4_lookup(name).await
        })
    }

    fn ipv6_lookup(&self, name: String) -> impl Future<Output = Result<Lookup, NetError>> + Send {
        self.lookup(name, async move |resolver, name| {
            resolver.ipv6_lookup(name).await
        })
    }

    fn txt_lookup(&self, name: String) -> impl Future<Output = Result<Lookup, NetError>> + Send {
        self.lookup(name, async move |resolver, name| {
            resolver.txt_lookup(name).await
        })
    }
}
