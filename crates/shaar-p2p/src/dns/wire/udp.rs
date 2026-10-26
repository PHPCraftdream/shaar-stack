use std::{
    io,
    net::SocketAddr,
    task::{Context, Poll},
};

use super::{MAX, valid};

const DISCARDS: usize = 16;

fn oversized(error: &io::Error) -> bool {
    // WSAEMSGSIZE consumes an oversized datagram. Other receive failures stay fatal.
    cfg!(windows) && error.raw_os_error() == Some(10040)
}

pub(in crate::dns) fn receive(
    cx: &mut Context<'_>,
    output: &mut [u8],
    server: SocketAddr,
    mut poll: impl FnMut(&mut Context<'_>, &mut [u8]) -> Poll<io::Result<(usize, SocketAddr)>>,
) -> Poll<io::Result<(usize, SocketAddr)>> {
    // One extra byte distinguishes Linux's successful truncation from an exact maximum.
    // Stack ownership also preserves the UDP trait's shared receiver without a lock.
    let mut bytes = [0; MAX + 1];
    for _ in 0..DISCARDS {
        match std::task::ready!(poll(cx, &mut bytes)) {
            Ok((length, peer)) => {
                if peer != server || length > MAX || !valid(length, &bytes[..length]) {
                    continue;
                }
                if length > output.len() {
                    continue; // Never expose a truncated DNS message to the decoder.
                }
                output[..length].copy_from_slice(&bytes[..length]);
                return Poll::Ready(Ok((length, peer)));
            }
            Err(error) if oversized(&error) => continue,
            Err(error) => return Poll::Ready(Err(error)),
        }
    }
    // Yield only after consuming bounded work; Pending from the socket registers itself.
    cx.waker().wake_by_ref();
    Poll::Pending
}
