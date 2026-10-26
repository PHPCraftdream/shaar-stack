use super::{HEADER, MAX, valid};
use futures::io::AsyncRead;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

/// Partial input belongs to the socket, not a cancelable read future.
#[derive(Default)]
pub(in crate::dns) struct Input {
    staged: [u8; HEADER + 2],
    filled: usize,
    released: usize,
    remaining: usize,
    validated: bool,
    terminal: Option<io::ErrorKind>,
    eof: bool,
}

impl Input {
    #[cfg(test)]
    pub(in crate::dns) fn staged_len(&self) -> usize {
        self.filled
    }

    pub(in crate::dns) fn poll_read<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(kind) = self.terminal {
            return Poll::Ready(Err(io::Error::new(kind, "DNS TCP input terminated")));
        }
        if self.eof {
            return Poll::Ready(Ok(0));
        }
        if !self.validated {
            // At most fourteen successful one-byte reads before releasing any prefix.
            while self.filled < self.staged.len() {
                let end = if self.filled < 2 {
                    2
                } else {
                    self.staged.len()
                };
                let read = match std::task::ready!(
                    Pin::new(&mut *stream).poll_read(cx, &mut self.staged[self.filled..end])
                ) {
                    Ok(read) => read,
                    Err(error) => {
                        self.terminal = Some(error.kind());
                        return Poll::Ready(Err(error));
                    }
                };
                if read == 0 {
                    if self.filled == 0 {
                        self.eof = true;
                        return Poll::Ready(Ok(0));
                    }
                    return self.fail(io::ErrorKind::UnexpectedEof);
                }
                self.filled += read;
                if self.filled == 2 {
                    let length = usize::from(u16::from_be_bytes([self.staged[0], self.staged[1]]));
                    if !(HEADER..=MAX).contains(&length) {
                        return self.fail(io::ErrorKind::InvalidData);
                    }
                    self.remaining = length - HEADER;
                }
            }
            if !valid(self.remaining + HEADER, &self.staged[2..]) {
                return self.fail(io::ErrorKind::InvalidData);
            }
            self.validated = true;
        }
        if self.released < self.staged.len() {
            let length = output.len().min(self.staged.len() - self.released);
            output[..length].copy_from_slice(&self.staged[self.released..self.released + length]);
            self.released += length;
            if self.released == self.staged.len() && self.remaining == 0 {
                *self = Self::default();
            }
            return Poll::Ready(Ok(length));
        }
        let limit = output.len().min(self.remaining);
        let read = match std::task::ready!(Pin::new(stream).poll_read(cx, &mut output[..limit])) {
            Ok(0) => return self.fail(io::ErrorKind::UnexpectedEof),
            Ok(read) => read,
            Err(error) => {
                self.terminal = Some(error.kind());
                return Poll::Ready(Err(error));
            }
        };
        self.remaining -= read;
        if self.remaining == 0 {
            *self = Self::default();
        }
        Poll::Ready(Ok(read))
    }

    fn fail(&mut self, kind: io::ErrorKind) -> Poll<io::Result<usize>> {
        self.terminal = Some(kind);
        Poll::Ready(Err(io::Error::new(kind, "invalid DNS TCP input envelope")))
    }
}
