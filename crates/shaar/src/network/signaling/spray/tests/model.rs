//! A model of the pair for the contract cases: the hard side's NAT draws a random external port per
//! destination, the easy side's NAT keeps one external port and admits only an address and port
//! its own socket has written to. Delivery is instant, so a hit happens whichever side writes first
//! (the hard side's datagram is admitted by an easy-side entry written earlier, and an easy-side
//! probe reaches a hard socket whose mapping exists).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use super::super::run::{Datagrams, Opener};
use super::super::{FIRST_PORT, PORT_RANGE, Rng};

pub(super) const HARD_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
pub(super) const EASY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 40000);

type Inbox = mpsc::UnboundedSender<(Vec<u8>, SocketAddrV4)>;

struct State {
    rng: Rng,
    /// Endpoints the easy socket has written to: its filter entries.
    probed: HashSet<SocketAddrV4>,
    /// External port of the hard side's socket `id`, drawn at its first write.
    external: Vec<Option<u16>>,
    by_external: HashMap<u16, usize>,
    hard_inbox: Vec<Inbox>,
    easy_inbox: Option<Inbox>,
}

/// The model network; clones share it.
#[derive(Clone)]
pub(super) struct Net(Arc<Mutex<State>>);

impl Net {
    pub(super) fn new(seed: u64) -> Self {
        Self(Arc::new(Mutex::new(State {
            rng: Rng::seeded(seed),
            probed: HashSet::new(),
            external: Vec::new(),
            by_external: HashMap::new(),
            hard_inbox: Vec::new(),
            easy_inbox: None,
        })))
    }

    pub(super) fn easy_port(&self) -> EasyPort {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.0.lock().unwrap().easy_inbox = Some(sender);
        EasyPort {
            net: self.clone(),
            receiver,
        }
    }

    pub(super) fn opener(&self, limit: usize) -> ModelOpener {
        ModelOpener {
            net: self.clone(),
            limit,
            opened: 0,
        }
    }

    /// The external port the hard side's socket `id` was given, if it has written.
    pub(super) fn external_port(&self, id: usize) -> Option<u16> {
        self.0.lock().unwrap().external.get(id).copied().flatten()
    }
}

pub(super) struct ModelOpener {
    net: Net,
    limit: usize,
    opened: usize,
}

impl Opener for ModelOpener {
    type Port = HardPort;

    async fn open(&mut self) -> io::Result<HardPort> {
        if self.opened >= self.limit {
            return Err(io::Error::other("too many open files"));
        }
        self.opened += 1;
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut state = self.net.0.lock().unwrap();
        let id = state.hard_inbox.len();
        state.hard_inbox.push(sender);
        state.external.push(None);
        drop(state);
        Ok(HardPort {
            id,
            net: self.net.clone(),
            receiver,
        })
    }
}

pub(super) struct HardPort {
    id: usize,
    net: Net,
    receiver: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddrV4)>,
}

impl HardPort {
    /// The index of this socket, in the order the model opened them.
    pub(super) fn id(&self) -> usize {
        self.id
    }
}

pub(super) struct EasyPort {
    net: Net,
    receiver: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddrV4)>,
}

async fn receive(
    receiver: &mut mpsc::UnboundedReceiver<(Vec<u8>, SocketAddrV4)>,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddrV4)> {
    let (bytes, from) = receiver
        .recv()
        .await
        .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
    let length = bytes.len().min(buffer.len());
    buffer[..length].copy_from_slice(&bytes[..length]);
    Ok((length, from))
}

impl Datagrams for HardPort {
    async fn send_to(&mut self, bytes: &[u8], to: SocketAddrV4) -> io::Result<()> {
        if to != EASY {
            return Ok(());
        }
        let mut state = self.net.0.lock().unwrap();
        let drawn = state.external[self.id];
        let external = match drawn {
            Some(port) => port,
            None => {
                let port = loop {
                    let port = FIRST_PORT + state.rng.below(PORT_RANGE as u64) as u16;
                    if !state.by_external.contains_key(&port) {
                        break port;
                    }
                };
                state.external[self.id] = Some(port);
                state.by_external.insert(port, self.id);
                port
            }
        };
        let source = SocketAddrV4::new(HARD_IP, external);
        if state.probed.contains(&source)
            && let Some(inbox) = &state.easy_inbox
        {
            let _ = inbox.send((bytes.to_vec(), source));
        }
        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        receive(&mut self.receiver, buffer).await
    }
}

impl Datagrams for EasyPort {
    async fn send_to(&mut self, bytes: &[u8], to: SocketAddrV4) -> io::Result<()> {
        let mut state = self.net.0.lock().unwrap();
        state.probed.insert(to);
        if *to.ip() == HARD_IP
            && let Some(&id) = state.by_external.get(&to.port())
        {
            let _ = state.hard_inbox[id].send((bytes.to_vec(), EASY));
        }
        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        receive(&mut self.receiver, buffer).await
    }
}
