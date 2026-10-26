mod endpoints;
mod lifetime;
mod limits;
mod lookup;
pub(crate) mod support;

use super::*;
use crate::OwnedExecutor;
use hickory_resolver::net::runtime::RuntimeProvider;

fn setup(server: SocketAddr) -> (OwnedExecutor, Lifetime, OwnedResolver, Provider) {
    let executor = OwnedExecutor::new();
    let (lifetime, resolver) = OwnedResolver::new(&[server], executor.handle()).unwrap();
    let provider = Provider::new(lifetime.gate(), executor.handle(), &[server]);
    (executor, lifetime, resolver, provider)
}
