//! One HTTP/1.1 request to the gateway, bounded in time and size. The gateway is a device on the
//! local network that answers a few small documents; this is not a general HTTP client.

use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout_at},
};

use super::super::MapError;

/// The most bytes of one answer, head and body together; a longer answer is refused.
pub(super) const MAX_RESPONSE: usize = 128 * 1024;
/// The most bytes before the end of the answer's head.
const MAX_HEAD: usize = 16 * 1024;

pub(super) struct Response {
    pub status: u16,
    pub body: String,
}

/// The text of a request: `headers` are complete lines without the line end.
pub(super) fn request(
    method: &str,
    address: SocketAddr,
    path: &str,
    headers: &[String],
    body: &str,
) -> String {
    let mut text = format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    for header in headers {
        text.push_str(header);
        text.push_str("\r\n");
    }
    text.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    text
}

/// Sends `request` to `address` and reads the answer to its end, all before `deadline`.
/// cancel-safe: yes — the connection is closed with the future.
pub(super) async fn exchange(
    address: SocketAddr,
    request: &str,
    deadline: Instant,
) -> Result<Response, MapError> {
    let attempt = async {
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|_| MapError::Io)?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| MapError::Io)?;
        read_response(&mut stream).await
    };
    timeout_at(deadline, attempt)
        .await
        .map_err(|_| MapError::Silent)?
}

async fn read_response(stream: &mut TcpStream) -> Result<Response, MapError> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(response) = parse(&buffer, false)? {
            return Ok(response);
        }
        if buffer.len() >= MAX_RESPONSE {
            return Err(MapError::Unsupported);
        }
        let read = stream.read(&mut chunk).await.map_err(|_| MapError::Io)?;
        if read == 0 {
            return parse(&buffer, true)?.ok_or(MapError::Io);
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// The answer in `buffer` when it is complete. At the end of the stream (`eof`) a body without a
/// length is complete too. `Ok(None)` means more bytes are needed.
fn parse(buffer: &[u8], eof: bool) -> Result<Option<Response>, MapError> {
    let Some(head_end) = find(buffer, b"\r\n\r\n") else {
        return if buffer.len() > MAX_HEAD {
            Err(MapError::Unsupported)
        } else {
            Ok(None)
        };
    };
    let head = std::str::from_utf8(&buffer[..head_end]).map_err(|_| MapError::Unsupported)?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(MapError::Unsupported)?;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.trim().eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
    }
    let body = &buffer[head_end + 4..];
    let complete = if chunked {
        dechunk(body)
    } else if let Some(length) = length {
        if length > MAX_RESPONSE {
            return Err(MapError::Unsupported);
        }
        (body.len() >= length).then(|| body[..length].to_vec())
    } else {
        eof.then(|| body.to_vec())
    };
    match complete {
        Some(bytes) => Ok(Some(Response {
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })),
        None if eof => Err(MapError::Io),
        None => Ok(None),
    }
}

/// The body of a chunked answer once its last chunk has arrived; trailers are ignored.
fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = find(rest, b"\r\n")?;
        let size_text = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        if size > MAX_RESPONSE || body.len() + size > MAX_RESPONSE {
            return None;
        }
        let chunk = rest.get(..size)?;
        rest.get(size..size + 2)?;
        body.extend_from_slice(chunk);
        rest = &rest[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(bytes: &[u8]) -> Response {
        parse(bytes, false).unwrap().expect("complete")
    }

    #[test]
    fn a_body_with_a_length_is_complete_when_that_many_bytes_arrived() {
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let response = complete(answer);
        assert_eq!((response.status, response.body.as_str()), (200, "hello"));
        assert!(parse(&answer[..answer.len() - 1], false).unwrap().is_none());
        assert!(parse(&answer[..answer.len() - 1], true).is_err());
    }

    #[test]
    fn a_body_without_a_length_ends_with_the_stream() {
        let answer = b"HTTP/1.0 500 Oops\r\n\r\n<fault/>";
        assert!(parse(answer, false).unwrap().is_none());
        let response = parse(answer, true).unwrap().unwrap();
        assert_eq!((response.status, response.body.as_str()), (500, "<fault/>"));
    }

    #[test]
    fn a_chunked_body_is_joined_and_waits_for_its_last_chunk() {
        let answer = b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n4;x=y\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(complete(answer).body, "Wikipedia");
        let cut = &answer[..answer.len() - 5];
        assert!(parse(cut, false).unwrap().is_none());
    }

    #[test]
    fn a_head_that_is_not_http_or_is_too_long_is_refused() {
        assert!(matches!(
            parse(b"garbage\r\n\r\n", false),
            Err(MapError::Unsupported)
        ));
        assert!(matches!(
            parse(b"HTTP/1.1 abc\r\n\r\n", false),
            Err(MapError::Unsupported)
        ));
        assert!(matches!(
            parse(&vec![b'a'; MAX_HEAD + 1], false),
            Err(MapError::Unsupported)
        ));
        assert!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Le", false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_declared_length_above_the_cap_is_refused_before_it_is_read() {
        let answer = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_RESPONSE + 1
        );
        assert!(matches!(
            parse(answer.as_bytes(), false),
            Err(MapError::Unsupported)
        ));
    }

    #[test]
    fn a_broken_chunk_size_never_completes() {
        for body in ["zz\r\nab\r\n0\r\n\r\n", "5\r\nab", "5\r\nabcde\r\n", ""] {
            let answer = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
            assert!(
                parse(answer.as_bytes(), false).unwrap().is_none(),
                "{body:?}"
            );
        }
    }

    #[test]
    fn a_request_names_its_length_and_closes_the_connection() {
        let address: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let text = request(
            "POST",
            address,
            "/ctl",
            &["SOAPAction: \"a#b\"".to_owned()],
            "<x/>",
        );
        assert_eq!(
            text,
            "POST /ctl HTTP/1.1\r\nHost: 192.0.2.1:5000\r\nConnection: close\r\nSOAPAction: \"a#b\"\r\nContent-Length: 4\r\n\r\n<x/>"
        );
    }
}
