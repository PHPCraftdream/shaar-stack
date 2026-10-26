use super::{profile_tests::header, receive};
use futures::task::{ArcWake, waker};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

#[derive(Default)]
pub(super) struct Wakes(pub(super) AtomicUsize);
impl ArcWake for Wakes {
    fn wake_by_ref(this: &Arc<Self>) {
        this.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn server() -> SocketAddr {
    "127.0.0.1:5300".parse().unwrap()
}

#[test]
fn wire_dns_udp_discard_budget_yields_and_wakes_once() {
    let wakes = Arc::new(Wakes::default());
    let wake = waker(wakes.clone());
    let mut cx = Context::from_waker(&wake);
    let mut output = [0x55; 4096];
    let mut polls = 0;
    let result = receive(&mut cx, &mut output, server(), |_, _| {
        polls += 1;
        Poll::Ready(Ok((11, server())))
    });
    assert!(result.is_pending());
    assert_eq!(polls, 16, "UNBOUNDED_DNS_DISCARD_WORK");
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert!(output.iter().all(|byte| *byte == 0x55));
    let result = receive(&mut cx, &mut output, server(), |_, bytes| {
        bytes[..12].fill(0);
        Poll::Ready(Ok((12, server())))
    });
    assert!(matches!(result, Poll::Ready(Ok((12, _)))));
}

#[test]
fn wire_dns_udp_pending_does_not_self_wake_or_spin() {
    let wakes = Arc::new(Wakes::default());
    let wake = waker(wakes.clone());
    let mut cx = Context::from_waker(&wake);
    let mut polls = 0;
    assert!(
        receive(&mut cx, &mut [0; 4096], server(), |_, _| {
            polls += 1;
            Poll::Pending
        })
        .is_pending()
    );
    assert_eq!(polls, 1);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
}

#[test]
fn wire_dns_udp_invalid_and_wrong_endpoint_do_not_poison_next_packet() {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut output = [0x55; 4096];
    let mut polls = 0;
    let result = receive(&mut cx, &mut output, server(), |_, bytes| {
        polls += 1;
        bytes[..12].copy_from_slice(&header(0, 0, 0, 0));
        match polls {
            1 => Poll::Ready(Ok((11, server()))),
            2 => Poll::Ready(Ok((4097, server()))),
            3 => {
                bytes[..12].copy_from_slice(&header(1, 65535, 1, 0));
                Poll::Ready(Ok((12, server())))
            }
            4 => Poll::Ready(Ok((12, "127.0.0.1:5301".parse().unwrap()))),
            5 => Poll::Ready(Ok((12, "127.0.0.2:5300".parse().unwrap()))),
            6 => {
                bytes[0] = 42;
                Poll::Ready(Ok((12, server())))
            }
            _ => panic!("valid packet not delivered"),
        }
    });
    assert!(matches!(result, Poll::Ready(Ok((12, _)))));
    assert_eq!(polls, 6);
    assert_eq!(output[0], 42);
    assert!(output[12..].iter().all(|byte| *byte == 0x55));
}

#[test]
fn wire_dns_udp_small_output_is_not_a_successful_truncation() {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    for length in [0, 11] {
        let mut output = [0x55; 11];
        let mut polls = 0;
        assert!(
            receive(&mut cx, &mut output[..length], server(), |_, bytes| {
                polls += 1;
                if polls == 1 {
                    bytes[..12].fill(0);
                    Poll::Ready(Ok((12, server())))
                } else {
                    Poll::Pending
                }
            })
            .is_pending()
        );
        assert_eq!(polls, 2);
        assert_eq!(output, [0x55; 11]);
    }
}

#[test]
fn wire_dns_udp_only_windows_message_size_error_is_discarded() {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut polls = 0;
    let result = receive(&mut cx, &mut [0; 4096], server(), |_, bytes| {
        polls += 1;
        if polls == 1 {
            Poll::Ready(Err(io::Error::from_raw_os_error(10040)))
        } else {
            bytes[..12].fill(0);
            Poll::Ready(Ok((12, server())))
        }
    });
    if cfg!(windows) {
        assert!(matches!(result, Poll::Ready(Ok((12, _)))));
        assert_eq!(polls, 2);
    } else {
        let Poll::Ready(Err(error)) = result else {
            panic!("foreign OS code suppressed")
        };
        assert_eq!(error.raw_os_error(), Some(10040));
        assert_eq!(polls, 1);
    }
}

#[test]
fn wire_dns_udp_unrelated_io_errors_remain_fatal() {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    for code in [10054, 10038, 10013] {
        let mut polls = 0;
        let result = receive(&mut cx, &mut [0; 4096], server(), |_, _| {
            polls += 1;
            Poll::Ready(Err(io::Error::from_raw_os_error(code)))
        });
        let Poll::Ready(Err(error)) = result else {
            panic!("fatal receive error suppressed")
        };
        assert_eq!(error.raw_os_error(), Some(code));
        assert_eq!(polls, 1);
    }
}
