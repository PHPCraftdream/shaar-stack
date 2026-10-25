use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, Sleep};

/// Counts the actual relayed stream bytes, including Noise/Yamux, in both directions.
/// Separate timers preserve wakeups when the read and write halves have different tasks.
pub(super) struct Budgeted<T> {
    inner: T,
    remaining: u64,
    deadline: Instant,
    read_timer: Pin<Box<Sleep>>,
    write_timer: Pin<Box<Sleep>>,
}

impl<T> Budgeted<T> {
    pub(super) fn new(inner: T, remaining: u64, deadline: Instant) -> Self {
        Self {
            inner,
            remaining,
            deadline,
            read_timer: Box::pin(tokio::time::sleep_until(deadline)),
            write_timer: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }

    fn read_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if Instant::now() >= self.deadline || self.read_timer.as_mut().poll(cx).is_ready() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "relay circuit lifetime exceeded",
            ))
        } else {
            Ok(())
        }
    }

    fn write_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if Instant::now() >= self.deadline || self.write_timer.as_mut().poll(cx).is_ready() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "relay circuit lifetime exceeded",
            ))
        } else {
            Ok(())
        }
    }

    fn limit(&self, length: usize) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "relay circuit byte budget exceeded",
            ));
        }
        Ok(usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(length))
    }

    fn account(&mut self, count: usize, limit: usize) -> io::Result<()> {
        if count > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid relay I/O count",
            ));
        }
        let count =
            u64::try_from(count).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        self.remaining = self
            .remaining
            .checked_sub(count)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(())
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Budgeted<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.read_deadline(cx)?;
        let limit = this.limit(output.len())?;
        match Pin::new(&mut this.inner).poll_read(cx, &mut output[..limit]) {
            Poll::Ready(Ok(count)) => {
                this.account(count, limit)?;
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Budgeted<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.write_deadline(cx)?;
        let limit = this.limit(input.len())?;
        match Pin::new(&mut this.inner).poll_write(cx, &input[..limit]) {
            Poll::Ready(Ok(count)) => {
                this.account(count, limit)?;
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_deadline(cx)?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_deadline(cx)?;
        Pin::new(&mut this.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{AsyncReadExt, AsyncWriteExt, io::Cursor};
    use std::time::Duration;
    use tokio::{sync::oneshot, task::JoinSet};

    #[tokio::test(flavor = "current_thread")]
    async fn read_and_write_share_the_exact_byte_budget_without_silent_eof() {
        let mut io = Budgeted::new(
            Cursor::new(vec![1, 2, 3]),
            5,
            Instant::now() + Duration::from_secs(10),
        );
        let mut bytes = [0; 2];
        io.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, [1, 2]);
        io.write_all(b"abc").await.unwrap();
        assert_eq!(io.inner.get_ref(), &[1, 2, b'a', b'b', b'c']);
        assert_eq!(
            io.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            io.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(io.read(&mut []).await.unwrap(), 0);
        assert_eq!(io.write(&[]).await.unwrap(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn partial_write_stops_at_the_budget_and_cannot_replay_past_it() {
        let mut io = Budgeted::new(
            Cursor::new(Vec::new()),
            3,
            Instant::now() + Duration::from_secs(10),
        );
        assert_eq!(
            io.write_all(b"abcdef").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(io.inner.get_ref(), b"abc");
        assert!(io.write_all(b"def").await.is_err());
        assert_eq!(io.inner.get_ref(), b"abc");
    }

    struct Stalled;
    impl AsyncRead for Stalled {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for Stalled {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_deadline_wakes_both_independent_half_tasks_without_underlying_io() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let io = Budgeted::new(Stalled, 10, Instant::now() + Duration::from_secs(10));
            let (mut reader, mut writer) = io.split();
            let (read_ready, read_observed) = oneshot::channel();
            let (write_ready, write_observed) = oneshot::channel();
            let mut tasks = JoinSet::new();
            tasks.spawn(async move {
                let mut byte = [0];
                let read = reader.read(&mut byte);
                tokio::pin!(read);
                std::future::poll_fn(|cx| {
                    assert!(read.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                read_ready.send(()).unwrap();
                read.await.unwrap_err().kind()
            });
            tasks.spawn(async move {
                let write = writer.write(b"x");
                tokio::pin!(write);
                std::future::poll_fn(|cx| {
                    assert!(write.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                write_ready.send(()).unwrap();
                write.await.unwrap_err().kind()
            });
            read_observed.await.unwrap();
            write_observed.await.unwrap();
            tokio::time::advance(Duration::from_secs(10)).await;
            for _ in 0..2 {
                assert_eq!(
                    tasks.join_next().await.unwrap().unwrap(),
                    io::ErrorKind::TimedOut
                );
            }
        })
        .await
        .expect("independent circuit deadline wakeups");
    }
}
