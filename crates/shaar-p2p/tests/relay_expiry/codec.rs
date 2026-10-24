use std::io;

use asynchronous_codec::{FramedRead, FramedWrite};
use futures::{AsyncRead, AsyncWrite, SinkExt, StreamExt};
use libp2p::{StreamProtocol, request_response::Codec};
use prost::Message;

// Circuit-v2 RESERVE/STATUS subset, not a general relay implementation.
// https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md
#[derive(Clone, PartialEq, Message)]
pub struct Hop {
    #[prost(int32, optional, tag = "1")]
    pub kind: Option<i32>,
    #[prost(message, optional, tag = "3")]
    pub reservation: Option<Reservation>,
    #[prost(message, optional, tag = "4")]
    pub limit: Option<Limit>,
    #[prost(int32, optional, tag = "5")]
    pub status: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Reservation {
    #[prost(uint64, optional, tag = "1")]
    pub expire: Option<u64>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub addresses: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Limit {
    #[prost(uint32, optional, tag = "1")]
    pub duration: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub data: Option<u64>,
}

#[derive(Clone, Default)]
pub struct HopCodec;

async fn read<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Hop> {
    FramedRead::new(io, prost_codec::Codec::<Hop>::new(4096))
        .next()
        .await
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?
        .map_err(Into::into)
}

async fn write<T: AsyncWrite + Unpin + Send>(io: &mut T, message: Hop) -> io::Result<()> {
    if message.encoded_len() > 4096 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    FramedWrite::new(io, prost_codec::Codec::<Hop>::new(4096))
        .send(message)
        .await
        .map_err(Into::into)
}

impl Codec for HopCodec {
    type Protocol = StreamProtocol;
    type Request = Hop;
    type Response = Hop;

    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Hop> {
        read(io).await
    }

    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Hop> {
        read(io).await
    }

    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        message: Hop,
    ) -> io::Result<()> {
        write(io, message).await
    }

    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        message: Hop,
    ) -> io::Result<()> {
        write(io, message).await
    }
}

#[test]
fn fixture_status_matches_normative_tags_and_framed_round_trip() {
    let status = Hop {
        kind: Some(2),
        reservation: None,
        limit: None,
        status: Some(100),
    };
    assert_eq!(status.encode_to_vec(), [8, 2, 40, 100]);
    futures::executor::block_on(async {
        let mut output = futures::io::Cursor::new(Vec::new());
        write(&mut output, status.clone()).await.unwrap();
        assert_eq!(output.get_ref(), &[4, 8, 2, 40, 100]);
        output.set_position(0);
        assert_eq!(read(&mut output).await.unwrap(), status);
    });
}
