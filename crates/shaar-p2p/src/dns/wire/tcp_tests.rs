use super::{Input, profile_tests::header};
use futures::io::AsyncRead;
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};

enum Step {
    Bytes(VecDeque<u8>),
    Pending,
    Error(io::ErrorKind),
}

#[derive(Default)]
struct Script {
    steps: VecDeque<Step>,
    consumed: usize,
    polls: usize,
}

impl Script {
    fn bytes(&mut self, bytes: &[u8]) {
        self.steps
            .push_back(Step::Bytes(bytes.iter().copied().collect()));
    }
    fn pending(&mut self) {
        self.steps.push_back(Step::Pending);
    }
}

impl AsyncRead for Script {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.polls += 1;
        match self.steps.front_mut() {
            None => Poll::Ready(Ok(0)),
            Some(Step::Pending) => {
                self.steps.pop_front();
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Some(Step::Error(_)) => {
                let Some(Step::Error(kind)) = self.steps.pop_front() else {
                    unreachable!()
                };
                Poll::Ready(Err(io::Error::new(kind, "scripted input failure")))
            }
            Some(Step::Bytes(bytes)) => {
                let length = bytes.len().min(output.len());
                for byte in &mut output[..length] {
                    *byte = bytes.pop_front().unwrap();
                }
                if bytes.is_empty() {
                    self.steps.pop_front();
                }
                self.consumed += length;
                Poll::Ready(Ok(length))
            }
        }
    }
}

fn poll(input: &mut Input, script: &mut Script, output: &mut [u8]) -> Poll<io::Result<usize>> {
    input.poll_read(
        script,
        &mut Context::from_waker(std::task::Waker::noop()),
        output,
    )
}

fn frame(length: u16) -> Vec<u8> {
    let mut bytes = vec![0; usize::from(length) + 2];
    bytes[..2].copy_from_slice(&length.to_be_bytes());
    bytes
}

fn ready(result: Poll<io::Result<usize>>) -> usize {
    let Poll::Ready(result) = result else {
        panic!("unexpected Pending")
    };
    result.unwrap()
}

fn error(result: Poll<io::Result<usize>>, kind: io::ErrorKind) {
    let Poll::Ready(Err(error)) = result else {
        panic!("expected {kind:?}, got {result:?}")
    };
    assert_eq!(error.kind(), kind);
}

#[test]
fn wire_dns_tcp_prefix_stays_private_until_header_validates() {
    for prefix_part in [1, 2] {
        let bytes = frame(4096);
        let mut script = Script::default();
        script.bytes(&bytes[..prefix_part]);
        script.pending();
        script.bytes(&bytes[prefix_part..13]);
        script.pending();
        script.bytes(&bytes[13..]);
        let mut input = Input::default();
        let mut prefix = [0x55; 2];
        assert!(poll(&mut input, &mut script, &mut prefix).is_pending());
        assert_eq!(prefix, [0x55; 2], "PREFIX_RELEASED_BEFORE_HEADER");
        assert!(poll(&mut input, &mut script, &mut prefix).is_pending());
        assert_eq!(prefix, [0x55; 2], "PREFIX_RELEASED_BEFORE_HEADER");
        assert_eq!(script.consumed, 13);
        assert_eq!(ready(poll(&mut input, &mut script, &mut prefix)), 2);
        assert_eq!(prefix, 4096u16.to_be_bytes());
        assert_eq!(script.consumed, 14, "BODY_READ_BEFORE_PREFIX_RELEASE");
    }
}

#[test]
fn wire_dns_tcp_rejects_lengths_before_reading_body_or_releasing_prefix() {
    for length in [0u16, 11, 4097, 65535] {
        let mut script = Script::default();
        script.bytes(&length.to_be_bytes());
        script.bytes(&[0; 12]);
        let mut input = Input::default();
        let mut output = [0x55; 2];
        error(
            poll(&mut input, &mut script, &mut output),
            io::ErrorKind::InvalidData,
        );
        assert_eq!(script.consumed, 2);
        assert_eq!(output, [0x55; 2]);
        let polls = script.polls;
        error(
            poll(&mut input, &mut script, &mut output),
            io::ErrorKind::InvalidData,
        );
        assert_eq!(script.polls, polls, "INVALID_FRAME_RESUMED");
    }
}

#[test]
fn wire_dns_tcp_count_rejection_precedes_upstream_body_allocation() {
    for counts in [
        (2, 0, 0, 0),
        (1, 65, 0, 0),
        (1, 65535, 1, 0),
        (1, 65535, 65535, 2),
    ] {
        let mut script = Script::default();
        script.bytes(&4096u16.to_be_bytes());
        script.bytes(&header(counts.0, counts.1, counts.2, counts.3));
        script.bytes(&[42; 32]);
        let mut prefix = [0x55; 2];
        error(
            poll(&mut Input::default(), &mut script, &mut prefix),
            io::ErrorKind::InvalidData,
        );
        assert_eq!(prefix, [0x55; 2], "HICKORY_COULD_ALLOCATE_BODY");
        assert_eq!(script.consumed, 14);
    }
}

#[test]
fn wire_dns_tcp_fragmentation_pending_and_consecutive_boundary_sizes() {
    for length in [12, 4096] {
        for capacity in [1, 2, 11, 12, 13, 14, 4096, 8192] {
            let expected = [frame(length), frame(12)].concat();
            let mut script = Script::default();
            for byte in &expected {
                script.bytes(&[*byte]);
                script.pending();
            }
            let mut input = Input::default();
            let mut actual = Vec::new();
            let mut output = vec![0; capacity];
            for _ in 0..expected.len() * 3 + 10 {
                match poll(&mut input, &mut script, &mut output) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(0)) => break,
                    Poll::Ready(Ok(length)) => actual.extend_from_slice(&output[..length]),
                    Poll::Ready(Err(error)) => panic!("{error}"),
                }
            }
            assert_eq!(actual, expected);
            assert_eq!(ready(poll(&mut input, &mut script, &mut output)), 0);
        }
    }
}

#[test]
fn wire_dns_tcp_empty_reads_preserve_every_partial_stage() {
    let expected = frame(13);
    let mut script = Script::default();
    let mut input = Input::default();
    for byte in &expected[..14] {
        script.bytes(&[*byte]);
        script.pending();
        let before = script.polls;
        assert_eq!(ready(poll(&mut input, &mut script, &mut [])), 0);
        assert_eq!(script.polls, before);
        let mut output = [0x55; 1];
        if script.consumed < 13 {
            assert!(poll(&mut input, &mut script, &mut output).is_pending());
        }
    }
    script.bytes(&expected[14..]);
    let mut actual = Vec::new();
    for _ in 0..40 {
        let before = script.polls;
        assert_eq!(ready(poll(&mut input, &mut script, &mut [])), 0);
        assert_eq!(script.polls, before);
        let mut output = [0; 1];
        match poll(&mut input, &mut script, &mut output) {
            Poll::Pending => {}
            Poll::Ready(Ok(0)) => break,
            Poll::Ready(Ok(1)) => actual.push(output[0]),
            result => panic!("unexpected {result:?}"),
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn wire_dns_tcp_clean_and_every_partial_eof_are_distinct() {
    let bytes = frame(15);
    for end in 0..bytes.len() {
        let mut script = Script::default();
        if end != 0 {
            script.bytes(&bytes[..end]);
        }
        let mut input = Input::default();
        let mut output = [0; 32];
        if end == 0 {
            assert_eq!(ready(poll(&mut input, &mut script, &mut output)), 0);
        } else {
            let mut terminal = None;
            for _ in 0..4 {
                let result = poll(&mut input, &mut script, &mut output);
                if matches!(result, Poll::Ready(Err(_))) {
                    terminal = Some(result);
                    break;
                }
            }
            error(
                terminal.expect("partial EOF accepted"),
                io::ErrorKind::UnexpectedEof,
            );
            error(
                poll(&mut input, &mut script, &mut output),
                io::ErrorKind::UnexpectedEof,
            );
        }
    }
}

#[test]
fn wire_dns_tcp_io_failure_is_terminal_at_header_and_body() {
    for end in [0, 1, 2, 13, 14, 15] {
        let bytes = frame(16);
        let mut script = Script::default();
        if end != 0 {
            script.bytes(&bytes[..end]);
        }
        script
            .steps
            .push_back(Step::Error(io::ErrorKind::ConnectionReset));
        script.bytes(&bytes);
        let mut input = Input::default();
        let mut output = [0; 32];
        let mut terminal = None;
        for _ in 0..4 {
            let result = poll(&mut input, &mut script, &mut output);
            if matches!(result, Poll::Ready(Err(_))) {
                terminal = Some(result);
                break;
            }
        }
        error(terminal.unwrap(), io::ErrorKind::ConnectionReset);
        let polls = script.polls;
        error(
            poll(&mut input, &mut script, &mut output),
            io::ErrorKind::ConnectionReset,
        );
        assert_eq!(script.polls, polls);
    }
}

#[test]
fn wire_dns_tcp_consecutive_frames_never_share_unvalidated_output() {
    let mut script = Script::default();
    let mut second = frame(12);
    second[6..8].copy_from_slice(&2u16.to_be_bytes());
    let first = frame(12);
    script.bytes(&[first.clone(), second].concat());
    let mut input = Input::default();
    let mut output = [0x55; 64];
    assert_eq!(ready(poll(&mut input, &mut script, &mut output)), 14);
    assert_eq!(&output[..14], first);
    output.fill(0x55);
    error(
        poll(&mut input, &mut script, &mut output),
        io::ErrorKind::InvalidData,
    );
    assert_eq!(output, [0x55; 64]);
}
