#![forbid(unsafe_code)]

use crate::{
    net::{runtime::TokioRuntimeProvider, xfer::DnsHandle, NetError, NoRecords},
    proto::{
        op::{DnsRequest, DnsResponse, Message, OpCode, Query, ResponseCode},
        rr::{
            rdata::{A, CNAME, NS, SOA},
            Name, RData, Record, RecordType,
        },
    },
};
use futures_util::Stream;
use std::{
    cell::Cell,
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
};

#[derive(Clone, Copy)]
pub(crate) enum Work {
    Build,
    Storage,
    ErrorClone,
    Alias,
}

// Probes are thread-local because every cache fixture is explicitly polled on its test thread.

thread_local! {
    static WORK: Cell<[usize; 4]> = const { Cell::new([0; 4]) };
}

pub(crate) fn record(work: Work) {
    WORK.with(|counts| {
        let mut value = counts.get();
        value[work as usize] += 1;
        counts.set(value);
    });
}

pub(crate) struct Probe([usize; 4]);

impl Probe {
    pub(crate) fn new() -> Self {
        Self(WORK.with(|counts| counts.replace([0; 4])))
    }

    pub(crate) fn count(&self, work: Work) -> usize {
        WORK.with(|counts| counts.get()[work as usize])
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        WORK.with(|counts| counts.set(self.0));
    }
}

pub(crate) fn name(value: &str) -> Name {
    Name::from_ascii(value).expect("fixture name")
}

pub(crate) fn query(value: &str, kind: RecordType) -> Query {
    Query::query(name(value), kind)
}

pub(crate) fn a(owner: &Name, ttl: u32, last: u8) -> Record {
    Record::from_rdata(owner.clone(), ttl, RData::A(A::new(192, 0, 2, last)))
}

pub(crate) fn alias(owner: &Name, target: &Name, ttl: u32) -> Record {
    Record::from_rdata(owner.clone(), ttl, RData::CNAME(CNAME(target.clone())))
}

pub(crate) fn message(query: &Query, last: u8) -> Message {
    let mut message = Message::response(42, OpCode::Query);
    message.add_query(query.clone());
    message.add_answers([a(query.name(), 3600, last), a(query.name(), 3600, last + 1)]);
    message.add_authority(Record::from_rdata(
        name("example."),
        3600,
        RData::NS(NS(name("ns.example."))),
    ));
    message.add_additional(a(&name("ns.example."), 3600, 53));
    message
}

pub(crate) fn response(message: Message) -> Result<DnsResponse, NetError> {
    Ok(DnsResponse::from_message(message).expect("fixture DNS serialization"))
}

pub(crate) fn negative(query: &Query, code: ResponseCode, ttl: u32) -> NetError {
    let mut error = NoRecords::new(query.clone(), code);
    error.negative_ttl = Some(ttl);
    error.soa = Some(Box::new(Record::from_rdata(
        name("example."),
        ttl,
        SOA::new(name("ns.example."), name("admin.example."), 1, 2, 3, 4, ttl),
    )));
    error.into()
}

pub(crate) fn negative_response(
    query: &Query,
    code: ResponseCode,
    ttl: u32,
) -> Result<DnsResponse, NetError> {
    let mut message = Message::response(43, OpCode::Query);
    message.metadata.response_code = code;
    message.add_query(query.clone());
    message.add_authority(Record::from_rdata(
        name("example."),
        ttl,
        RData::SOA(SOA::new(
            name("ns.example."),
            name("admin.example."),
            1,
            2,
            3,
            4,
            ttl,
        )),
    ));
    response(message)
}

struct State {
    replies: VecDeque<Result<DnsResponse, NetError>>,
    queries: Vec<Query>,
}

#[derive(Clone)]
pub(crate) struct Script {
    state: Arc<Mutex<State>>,
    pub(crate) verifying: bool,
    pending: bool,
    pub(crate) drops: Arc<AtomicUsize>,
}

impl Script {
    pub(crate) fn new(replies: Vec<Result<DnsResponse, NetError>>) -> Self {
        assert!(replies.len() <= 32, "fixture response bound");
        Self {
            state: Arc::new(Mutex::new(State {
                replies: replies.into(),
                queries: Vec::new(),
            })),
            verifying: false,
            pending: false,
            drops: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn pending() -> Self {
        Self {
            pending: true,
            ..Self::new(Vec::new())
        }
    }

    pub(crate) fn queries(&self) -> Vec<Query> {
        self.state.lock().unwrap().queries.clone()
    }
}

pub(crate) struct Reply {
    result: Option<Result<DnsResponse, NetError>>,
    pending: bool,
    drops: Arc<AtomicUsize>,
}

impl Stream for Reply {
    type Item = Result<DnsResponse, NetError>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.pending {
            // The cancellation fixture never completes this stream.
            Poll::Pending
        } else {
            Poll::Ready(self.result.take())
        }
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

impl DnsHandle for Script {
    type Response = Reply;
    type Runtime = TokioRuntimeProvider;

    fn is_verifying_dnssec(&self) -> bool {
        self.verifying
    }

    fn send(&self, request: DnsRequest) -> Self::Response {
        // Only bounded fixture bookkeeping is locked; no callback or await occurs here.
        let mut state = self.state.lock().unwrap();
        assert!(state.queries.len() < 32, "fixture query bound");
        state.queries.push(request.queries[0].clone());
        let result = if self.pending {
            None
        } else {
            Some(state.replies.pop_front().expect("unexpected fixture query"))
        };
        Reply {
            result,
            pending: self.pending,
            drops: self.drops.clone(),
        }
    }
}

pub(crate) fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

pub(crate) fn ready<F: Future>(future: F) -> F::Output {
    match poll(Box::pin(future).as_mut()) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("scripted fixture unexpectedly pending"),
    }
}
