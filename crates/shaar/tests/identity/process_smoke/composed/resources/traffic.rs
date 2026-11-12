//! Loopback traffic drivers of the P14 resource harness: an echo/stall target and bounded clients.

#![forbid(unsafe_code)]

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinSet,
    time::timeout,
};

const IO: Duration = Duration::from_secs(20);
const CHUNK: usize = 64 * 1024;
const PATTERN: u8 = 0x5a;

/// Fixed target: first byte `E` echoes the stream, `S` holds it open without reading.
pub(super) async fn target_service(
    listener: TcpListener,
    release: Arc<Notify>,
) -> Result<(), String> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|e| e.to_string())?;
                connections.spawn(serve(stream, Arc::clone(&release)));
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn serve(mut stream: TcpStream, release: Arc<Notify>) {
    let mut mode = [0_u8; 1];
    if stream.read_exact(&mut mode).await.is_err() {
        return;
    }
    if mode[0] == b'S' {
        release.notified().await;
        return;
    }
    let (mut reader, mut writer) = stream.split();
    let _ = tokio::io::copy(&mut reader, &mut writer).await;
    let _ = writer.shutdown().await;
}

/// One new TCP connection through the client: send, half-close, read the exact echo.
pub(super) async fn round_trip(front: SocketAddr, payload: &[u8]) -> Result<Duration, String> {
    let started = Instant::now();
    timeout(IO, async {
        let mut stream = TcpStream::connect(front).await?;
        stream.write_all(&[b'E']).await?;
        stream.write_all(payload).await?;
        stream.shutdown().await?;
        let mut echoed = Vec::with_capacity(payload.len());
        stream.read_to_end(&mut echoed).await?;
        if echoed != payload {
            return Err(std::io::Error::other("echo differs from the request"));
        }
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| "round trip deadline".to_owned())?
    .map_err(|e| e.to_string())?;
    Ok(started.elapsed())
}

/// Retries fresh transactions until the route is established or attempts run out.
pub(super) async fn round_trip_eventually(
    front: SocketAddr,
    payload: &[u8],
) -> Result<Duration, String> {
    let mut last = String::new();
    for _ in 0..30 {
        match round_trip(front, payload).await {
            Ok(elapsed) => return Ok(elapsed),
            Err(error) => last = error,
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("no round trip after 30 attempts: {last}"))
}

/// Echoes `mebibytes` through one stream; returns payload MiB per second.
pub(super) async fn bulk(front: SocketAddr, mebibytes: usize) -> Result<f64, String> {
    let total = mebibytes * 1024 * 1024;
    let started = Instant::now();
    let received = timeout(Duration::from_secs(120), async {
        let mut stream = TcpStream::connect(front).await?;
        stream.write_all(&[b'E']).await?;
        let (mut read, mut write) = stream.into_split();
        let sender = async move {
            let chunk = vec![PATTERN; CHUNK];
            let mut sent = 0;
            while sent < total {
                write.write_all(&chunk).await?;
                sent += chunk.len();
            }
            write.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };
        let receiver = async move {
            let mut buffer = vec![0_u8; CHUNK];
            let mut received = 0_usize;
            loop {
                let count = read.read(&mut buffer).await?;
                if count == 0 {
                    return Ok::<usize, std::io::Error>(received);
                }
                if buffer[..count].iter().any(|byte| *byte != PATTERN) {
                    return Err(std::io::Error::other("echoed bytes differ"));
                }
                received += count;
            }
        };
        let ((), received) = tokio::try_join!(sender, receiver)?;
        Ok::<usize, std::io::Error>(received)
    })
    .await
    .map_err(|_| "bulk transfer deadline".to_owned())?
    .map_err(|e| e.to_string())?;
    if received != total {
        return Err(format!("bulk echo returned {received} of {total} bytes"));
    }
    Ok(mebibytes as f64 / started.elapsed().as_secs_f64())
}

/// Opens `count` established streams and keeps them open.
pub(super) async fn hold_streams(
    front: SocketAddr,
    count: usize,
) -> Result<Vec<TcpStream>, String> {
    let mut held = Vec::with_capacity(count);
    for _ in 0..count {
        let mut stream = timeout(IO, TcpStream::connect(front))
            .await
            .map_err(|_| "hold connect deadline")?
            .map_err(|e| e.to_string())?;
        stream.write_all(b"Ex").await.map_err(|e| e.to_string())?;
        let mut byte = [0_u8; 1];
        timeout(IO, stream.read_exact(&mut byte))
            .await
            .map_err(|_| "hold echo deadline")?
            .map_err(|e| e.to_string())?;
        held.push(stream);
    }
    Ok(held)
}

/// Writes into a stream whose target never reads until a write blocks. Returns
/// the accepted bytes and the live stream; fails when `cap_mebibytes` is reached
/// without back-pressure.
pub(super) async fn stalled_upload(
    front: SocketAddr,
    cap_mebibytes: usize,
) -> Result<(usize, TcpStream), String> {
    let mut stream = timeout(IO, TcpStream::connect(front))
        .await
        .map_err(|_| "stall connect deadline")?
        .map_err(|e| e.to_string())?;
    stream.write_all(b"S").await.map_err(|e| e.to_string())?;
    let chunk = vec![0_u8; CHUNK];
    let mut accepted = 0_usize;
    loop {
        match timeout(Duration::from_millis(1500), stream.write_all(&chunk)).await {
            Ok(Ok(())) => {
                accepted += chunk.len();
                if accepted >= cap_mebibytes * 1024 * 1024 {
                    return Err(format!("no back-pressure after {cap_mebibytes} MiB"));
                }
            }
            Ok(Err(error)) => return Err(error.to_string()),
            Err(_) => return Ok((accepted, stream)),
        }
    }
}

#[tokio::test]
async fn target_echoes_and_stalls_by_first_byte() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let release = Arc::new(Notify::new());
    let service = tokio::spawn(target_service(listener, Arc::clone(&release)));
    assert!(round_trip(address, b"hello").await.is_ok());
    assert!(bulk(address, 2).await.unwrap() > 0.0);
    let held = hold_streams(address, 3).await.unwrap();
    assert_eq!(held.len(), 3);
    let (accepted, stalled) = stalled_upload(address, 256).await.unwrap();
    assert!(accepted > 0 && accepted < 256 * 1024 * 1024);
    release.notify_waiters();
    drop((held, stalled));
    service.abort();
}
