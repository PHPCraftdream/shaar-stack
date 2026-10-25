use std::{
    pin::Pin,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, Transport,
    core::transport::{DialOpts, ListenerId, PortUse, TransportError, TransportEvent},
};

/// Signaling TCP never performs listener-port hole punching, including behaviour-owned dials.
pub(in super::super) struct FreshPorts<T>(pub(in super::super) T);

impl<T: Transport + Unpin> Transport for FreshPorts<T> {
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
        mut options: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        options.port_use = PortUse::New;
        self.0.dial(address, options)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::{Ready, ready};
    use libp2p::core::Endpoint;
    use std::io;

    #[derive(Default)]
    struct Observed(Option<(Multiaddr, DialOpts)>);
    impl Transport for Observed {
        type Output = ();
        type Error = io::Error;
        type ListenerUpgrade = Ready<io::Result<()>>;
        type Dial = Ready<io::Result<()>>;

        fn listen_on(
            &mut self,
            _: ListenerId,
            _: Multiaddr,
        ) -> Result<(), TransportError<io::Error>> {
            Ok(())
        }
        fn remove_listener(&mut self, _: ListenerId) -> bool {
            true
        }
        fn dial(
            &mut self,
            address: Multiaddr,
            options: DialOpts,
        ) -> Result<Self::Dial, TransportError<io::Error>> {
            self.0 = Some((address, options));
            Ok(ready(Ok(())))
        }
        fn poll(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
            Poll::Pending
        }
    }

    #[test]
    fn behaviour_and_explicit_dials_use_fresh_ports_without_changing_role_or_address() {
        let mut transport = FreshPorts(Observed::default());
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
        for role in [Endpoint::Dialer, Endpoint::Listener] {
            for port_use in [PortUse::Reuse, PortUse::New] {
                let _dial = transport
                    .dial(address.clone(), DialOpts { role, port_use })
                    .unwrap();
                let (observed_address, options) = transport.0.0.take().unwrap();
                assert_eq!(observed_address, address);
                assert_eq!(options.role, role);
                assert_eq!(options.port_use, PortUse::New);
            }
        }
    }
}
