use std::{fmt, io};

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response::Codec};

/// Carrier budget, not a classification of encrypted QUIC frame contents.
pub const MAX_DATAGRAM: usize = 1500;
pub const CONTROL_PROTOCOL: &str = "/shaar/quic-signal/1";

/// One nonempty bounded datagram. No heap allocation or plaintext Debug output.
pub struct Datagram {
    len: u16,
    bytes: [u8; MAX_DATAGRAM],
}

impl Datagram {
    pub fn new(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram size is outside carrier budget",
            ));
        }
        let mut packet = Self {
            len: u16::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidInput)?,
            bytes: [0; MAX_DATAGRAM],
        };
        packet.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(packet)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Datagram")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Big-endian u16 length, one datagram, EOF; response is byte zero followed by EOF.
/// No peer identity or authority is taken from the message body.
#[derive(Clone, Default, Debug)]
pub struct DatagramCodec;

async fn require_eof<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<()> {
    let mut trailing = [0];
    if io.read(&mut trailing).await? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing carrier bytes",
        ));
    }
    Ok(())
}

impl Codec for DatagramCodec {
    type Protocol = StreamProtocol;
    type Request = Datagram;
    type Response = ();

    /// cancel-safe: NO — a partial frame is terminal; the handler must drop the substream.
    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Datagram>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut header = [0; 2];
        io.read_exact(&mut header).await?;
        let len = u16::from_be_bytes(header);
        if len == 0 || usize::from(len) > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer datagram length exceeds budget",
            ));
        }
        let mut packet = Datagram {
            len,
            bytes: [0; MAX_DATAGRAM],
        };
        io.read_exact(&mut packet.bytes[..usize::from(len)]).await?;
        require_eof(io).await?;
        Ok(packet)
    }

    /// cancel-safe: NO — acknowledgement parsing is terminal on partial input.
    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<()>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut ack = [0];
        io.read_exact(&mut ack).await?;
        if ack != [0] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid carrier acknowledgement",
            ));
        }
        require_eof(io).await
    }

    /// cancel-safe: NO — the partially written packet must not be replayed on this stream.
    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        packet: Datagram,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&packet.len.to_be_bytes()).await?;
        io.write_all(packet.as_bytes()).await
    }

    /// cancel-safe: NO — partial acknowledgements are terminal.
    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, (): ()) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[0]).await
    }
}
