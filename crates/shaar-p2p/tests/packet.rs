#![forbid(unsafe_code)]

use futures::{
    executor::block_on,
    io::{AsyncRead, AsyncWrite, Cursor},
};
use libp2p::{StreamProtocol, request_response::Codec};
use shaar_p2p::{CONTROL_PROTOCOL, Datagram, DatagramCodec, MAX_DATAGRAM};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

struct Fragmented {
    cursor: Cursor<Vec<u8>>,
    chunk: usize,
    fail_read: bool,
    fail_write: bool,
}

impl Fragmented {
    fn new(bytes: Vec<u8>, chunk: usize) -> Self {
        Self {
            cursor: Cursor::new(bytes),
            chunk,
            fail_read: false,
            fail_write: false,
        }
    }
}

impl AsyncRead for Fragmented {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.fail_read {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let count = out.len().min(this.chunk);
        Pin::new(&mut this.cursor).poll_read(cx, &mut out[..count])
    }
}

impl AsyncWrite for Fragmented {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.fail_write {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let count = bytes.len().min(this.chunk);
        Pin::new(&mut this.cursor).poll_write(cx, &bytes[..count])
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().cursor).poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().cursor).poll_close(cx)
    }
}

fn protocol() -> StreamProtocol {
    StreamProtocol::new(CONTROL_PROTOCOL)
}

#[test]
fn packet_construction_enforces_bounds_and_redacts_debug() {
    assert!(Datagram::new(&[]).is_err());
    assert!(Datagram::new(&vec![0; MAX_DATAGRAM + 1]).is_err());
    assert_eq!(Datagram::new(&[7]).unwrap().as_bytes(), &[7]);
    assert_eq!(
        Datagram::new(&vec![9; MAX_DATAGRAM])
            .unwrap()
            .as_bytes()
            .len(),
        MAX_DATAGRAM
    );
    let debug = format!(
        "{:?}",
        Datagram::new(b"opaque-packet-private-content").unwrap()
    );
    assert!(debug.contains("len"));
    assert!(!debug.contains("opaque"));
}

#[test]
fn exact_wire_and_roundtrip_survive_single_byte_reads_and_writes() {
    block_on(async {
        let mut codec = DatagramCodec;
        for (length, header) in [(1, [0, 1]), (1500, [5, 220])] {
            for chunk in [1, 7, 1500] {
                let input = vec![0xa5; length];
                let mut written = Fragmented::new(Vec::new(), chunk);
                codec
                    .write_request(&protocol(), &mut written, Datagram::new(&input).unwrap())
                    .await
                    .unwrap();
                let bytes = written.cursor.into_inner();
                assert_eq!(&bytes[..2], &header);
                assert_eq!(&bytes[2..], input.as_slice());
                let mut read = Fragmented::new(bytes, chunk);
                let output = codec.read_request(&protocol(), &mut read).await.unwrap();
                assert_eq!(output.as_bytes(), input);
            }
        }
    });
}

#[test]
fn hostile_lengths_are_rejected_at_the_header_without_consuming_body() {
    block_on(async {
        let mut codec = DatagramCodec;
        for bytes in [vec![0, 0, 42], vec![5, 221, 42], vec![255, 255, 42]] {
            let mut read = Fragmented::new(bytes, 1);
            let error = codec
                .read_request(&protocol(), &mut read)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(read.cursor.position(), 2);
        }
    });
}

#[test]
fn truncated_and_trailing_frames_fail_instead_of_returning_partial_packets() {
    block_on(async {
        let mut codec = DatagramCodec;
        for bytes in [vec![], vec![0], vec![0, 2, 9]] {
            let mut read = Fragmented::new(bytes, 1);
            assert_eq!(
                codec
                    .read_request(&protocol(), &mut read)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        for bytes in [vec![0, 1, 9, 10], vec![0, 1, 9, 0, 1, 8]] {
            let mut read = Fragmented::new(bytes, 1);
            assert_eq!(
                codec
                    .read_request(&protocol(), &mut read)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    });
}

#[test]
fn acknowledgement_is_exactly_one_zero_byte_and_eof() {
    block_on(async {
        let mut codec = DatagramCodec;
        let mut written = Fragmented::new(Vec::new(), 1);
        codec
            .write_response(&protocol(), &mut written, ())
            .await
            .unwrap();
        assert_eq!(written.cursor.into_inner(), vec![0]);
        codec
            .read_response(&protocol(), &mut Fragmented::new(vec![0], 1))
            .await
            .unwrap();
        for bytes in [vec![], vec![1], vec![0, 1]] {
            assert!(
                codec
                    .read_response(&protocol(), &mut Fragmented::new(bytes, 1))
                    .await
                    .is_err()
            );
        }
    });
}

#[test]
fn underlying_io_errors_are_propagated_without_replay() {
    block_on(async {
        let mut codec = DatagramCodec;
        let mut stream = Fragmented::new(Vec::new(), 1);
        stream.fail_read = true;
        assert_eq!(
            codec
                .read_request(&protocol(), &mut stream)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            codec
                .read_response(&protocol(), &mut stream)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionReset
        );
        stream.fail_write = true;
        assert_eq!(
            codec
                .write_request(&protocol(), &mut stream, Datagram::new(&[1]).unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            codec
                .write_response(&protocol(), &mut stream, ())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    });
}
