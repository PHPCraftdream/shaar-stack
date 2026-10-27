#[cfg(test)]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(test)]
use libp2p::{
    Multiaddr, Transport,
    core::transport::{DialOpts, ListenerId, TransportError, TransportEvent},
    multiaddr::Protocol,
};

/// Until wire and destination-role gates land, no production caller may submit DNS.
/// This sits outside the actual DNS transport, not inside the numeric TCP branch.
#[cfg(test)]
pub(crate) struct NumericOnly<T>(pub(crate) T);

#[cfg(test)]
impl<T: Transport + Unpin> Transport for NumericOnly<T> {
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.0.listen_on(id, address)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.0.remove_listener(id)
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        options: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let mut parts = address.iter();
        let numeric = matches!(parts.next(), Some(Protocol::Ip4(_) | Protocol::Ip6(_)))
            && matches!(parts.next(), Some(Protocol::Tcp(_)))
            && matches!(parts.next(), None | Some(Protocol::P2p(_)))
            && parts.next().is_none();
        if !numeric {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        self.0.dial(address, options)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}
