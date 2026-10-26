#![forbid(unsafe_code)]

use std::{
    cell::RefCell,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use hickory_resolver::proto::{
    op::Query,
    rr::{Name, Record, rdata::TXT},
};
use libp2p_core::{Endpoint, transport::PortUse};

use crate::*;

#[derive(Default, Clone, Debug)]
pub(crate) struct Observed {
    pub pending: usize,
    pub errors: usize,
    pub allocations: usize,
    pub largest_address: usize,
    pub parses: usize,
}

thread_local! {
    static OBSERVED: RefCell<Observed> = RefCell::new(Observed::default());
}

pub(crate) fn observed() -> Observed {
    OBSERVED.with(|value| value.borrow().clone())
}

pub(crate) fn reset() {
    OBSERVED.with(|value| *value.borrow_mut() = Observed::default());
}

pub(crate) fn observe_pending(size: usize) {
    OBSERVED.with(|value| {
        let mut value = value.borrow_mut();
        value.pending = value.pending.max(size);
    });
}

pub(crate) fn observe_error(size: usize) {
    OBSERVED.with(|value| {
        let mut value = value.borrow_mut();
        value.errors = value.errors.max(size);
    });
}

pub(crate) fn observe_allocation(bytes: usize) {
    OBSERVED.with(|value| {
        let mut value = value.borrow_mut();
        value.allocations += 1;
        value.largest_address = value.largest_address.max(bytes);
    });
}

pub(crate) fn observe_parse() {
    OBSERVED.with(|value| value.borrow_mut().parses += 1);
}

pub(crate) fn lookup(records: impl IntoIterator<Item = RData>) -> Lookup {
    Lookup::new_with_max_ttl(
        Query::default(),
        records
            .into_iter()
            .map(|data| Record::from_rdata(Name::root(), 60, data)),
    )
}

pub(crate) fn txt(text: impl AsRef<[u8]>) -> RData {
    RData::TXT(TXT::from_bytes(vec![text.as_ref()]))
}

pub(crate) fn peer(value: u8) -> libp2p_identity::PeerId {
    libp2p_identity::PeerId::from_multihash(
        libp2p_core::multihash::Multihash::wrap(0x12, &[value; 32]).unwrap(),
    )
    .unwrap()
}

pub(crate) fn options() -> DialOpts {
    DialOpts {
        role: Endpoint::Dialer,
        port_use: PortUse::Reuse,
    }
}

pub(crate) fn run(future: impl Future<Output = ()>) {
    reset();
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        ::tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("bounded fixture completion");
    });
}

struct Active(Arc<AtomicUsize>);

impl Active {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

type Answer = dyn Fn(&str) -> Result<Lookup, ResolveError> + Send + Sync;

#[derive(Clone)]
pub(crate) struct FakeResolver {
    answer: Arc<Answer>,
    pub calls: Arc<Mutex<Vec<String>>>,
    pub active: Arc<AtomicUsize>,
    pub pending: bool,
}

impl FakeResolver {
    pub(crate) fn new(
        answer: impl Fn(&str) -> Result<Lookup, ResolveError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            answer: Arc::new(answer),
            calls: Arc::default(),
            active: Arc::default(),
            pending: false,
        }
    }

    // Cancellation drops the active guard; the query log deliberately remains observable.
    async fn query(&self, name: String) -> Result<Lookup, ResolveError> {
        self.calls.lock().push(name.clone());
        let _active = Active::new(self.active.clone());
        if self.pending {
            return future::pending().await;
        }
        (self.answer)(&name)
    }
}

impl Resolver for FakeResolver {
    async fn lookup_ip(&self, name: String) -> Result<LookupIp, ResolveError> {
        self.query(name).await.map(Into::into)
    }

    async fn ipv4_lookup(&self, name: String) -> Result<Lookup, ResolveError> {
        self.query(name).await
    }

    async fn ipv6_lookup(&self, name: String) -> Result<Lookup, ResolveError> {
        self.query(name).await
    }

    async fn txt_lookup(&self, name: String) -> Result<Lookup, ResolveError> {
        self.query(name).await
    }
}

type Policy = dyn Fn(&[u8]) -> bool + Send + Sync;

#[derive(Clone)]
pub(crate) struct PolicyResolver {
    pub inner: FakeResolver,
    policy: Arc<Policy>,
    pub policy_calls: Arc<AtomicUsize>,
}

impl PolicyResolver {
    pub(crate) fn new(
        inner: FakeResolver,
        policy: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner,
            policy: Arc::new(policy),
            policy_calls: Arc::default(),
        }
    }
}

impl Resolver for PolicyResolver {
    fn permits_address(&self, encoded: &[u8]) -> bool {
        self.policy_calls.fetch_add(1, Ordering::SeqCst);
        (self.policy)(encoded)
    }

    async fn lookup_ip(&self, name: String) -> Result<LookupIp, ResolveError> {
        self.inner.lookup_ip(name).await
    }

    async fn ipv4_lookup(&self, name: String) -> Result<Lookup, ResolveError> {
        self.inner.ipv4_lookup(name).await
    }

    async fn ipv6_lookup(&self, name: String) -> Result<Lookup, ResolveError> {
        self.inner.ipv6_lookup(name).await
    }

    async fn txt_lookup(&self, name: String) -> Result<Lookup, ResolveError> {
        self.inner.txt_lookup(name).await
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Success,
    Fail,
    Unsupported,
    Pending,
}

#[derive(Clone)]
pub(crate) struct FakeTransport {
    pub mode: Mode,
    pub dials: Arc<Mutex<Vec<Multiaddr>>>,
    pub active: Arc<AtomicUsize>,
}

impl FakeTransport {
    pub(crate) fn new(mode: Mode) -> Self {
        Self {
            mode,
            dials: Arc::default(),
            active: Arc::default(),
        }
    }
}

impl libp2p_core::Transport for FakeTransport {
    type Output = Multiaddr;
    type Error = io::Error;
    type ListenerUpgrade = BoxFuture<'static, Result<Multiaddr, io::Error>>;
    type Dial = BoxFuture<'static, Result<Multiaddr, io::Error>>;

    fn listen_on(
        &mut self,
        _: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(address))
    }

    fn remove_listener(&mut self, _: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        _: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.dials.lock().push(address.clone());
        let mode = self.mode;
        if matches!(mode, Mode::Unsupported) {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        let active = Active::new(self.active.clone());
        Ok(async move {
            let _active = active;
            match mode {
                Mode::Success => Ok(address),
                Mode::Fail => Err(io::Error::other("owned dial failure")),
                Mode::Pending => future::pending().await,
                Mode::Unsupported => {
                    unreachable!("unsupported addresses return before future creation")
                }
            }
        }
        .boxed())
    }

    fn poll(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

pub(crate) fn error_count(result: Result<Multiaddr, Error<io::Error>>) -> usize {
    match result {
        Err(Error::Dial(errors)) => errors.len(),
        other => panic!("expected aggregate error, got {other:?}"),
    }
}
