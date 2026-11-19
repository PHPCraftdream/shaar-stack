//! A gateway on the loopback that speaks UPnP for the tests: an SSDP responder, a description
//! server and a SOAP endpoint, with a log of what it was asked.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};

pub(super) const EXTERNAL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const IP_SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

type Soap = Box<dyn Fn(&str, &str) -> (u16, String) + Send + Sync>;

/// What the fake does.
pub(super) struct Script {
    /// The document served at `path`.
    pub description: String,
    pub path: String,
    /// The host in the `LOCATION` of the SSDP answer; the fake's own address when `None`.
    pub location_host: Option<String>,
    pub ssdp_answers: bool,
    /// Whether the description and the actions are answered; otherwise the connection is held.
    pub http_answers: bool,
    pub chunked: bool,
    /// The answer to a SOAP action, from its name and its body: the HTTP status and the text.
    pub soap: Soap,
}

impl Script {
    /// A gateway with one `WANIPConnection:1` service at `/ctl/IPConn` that grants everything.
    pub(super) fn standard() -> Self {
        Self {
            description: description(&[(IP_SERVICE, "/ctl/IPConn")]),
            path: "/rootDesc.xml".to_owned(),
            location_host: None,
            ssdp_answers: true,
            http_answers: true,
            chunked: false,
            soap: Box::new(|action, _| match action {
                "GetExternalIPAddress" => (200, external_answer()),
                "AddPortMapping" | "DeletePortMapping" => (200, answer(action, "")),
                _ => fault(401),
            }),
        }
    }
}

/// A device description with the given services, `(type, controlURL)`, in one connection device.
pub(super) fn description(services: &[(&str, &str)]) -> String {
    let list: String = services
        .iter()
        .map(|(kind, control)| {
            format!(
                "<service><serviceType>{kind}</serviceType><controlURL>{control}</controlURL></service>"
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList>{list}</serviceList></device></deviceList></device></deviceList></device></root>"
    )
}

pub(super) fn answer(action: &str, inner: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"{IP_SERVICE}\">{inner}</u:{action}Response></s:Body></s:Envelope>"
    )
}

pub(super) fn external_answer() -> String {
    answer(
        "GetExternalIPAddress",
        &format!("<NewExternalIPAddress>{EXTERNAL}</NewExternalIPAddress>"),
    )
}

/// A SOAP fault with a UPnP error code, as an HTTP 500.
pub(super) fn fault(code: u16) -> (u16, String) {
    (
        500,
        format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><faultcode>s:Client</faultcode><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
        ),
    )
}

#[derive(Clone, Debug)]
pub(super) struct Post {
    pub path: String,
    /// The `SOAPAction` header without its quotes.
    pub action: String,
    pub body: String,
}

#[derive(Default)]
struct Log {
    searches: usize,
    gets: Vec<String>,
    posts: Vec<Post>,
}

pub(super) struct Fake {
    /// Where the SSDP search goes.
    pub ssdp: SocketAddr,
    log: Arc<Mutex<Log>>,
    tasks: [JoinHandle<()>; 2],
}

impl Drop for Fake {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fake {
    pub(super) fn searches(&self) -> usize {
        self.log.lock().unwrap().searches
    }

    pub(super) fn gets(&self) -> Vec<String> {
        self.log.lock().unwrap().gets.clone()
    }

    pub(super) fn posts(&self) -> Vec<Post> {
        self.log.lock().unwrap().posts.clone()
    }

    /// The names of the SOAP actions asked, in order.
    pub(super) fn actions(&self) -> Vec<String> {
        let posts = self.posts();
        posts
            .iter()
            .map(|post| {
                post.action
                    .rsplit('#')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    }
}

pub(super) async fn start(script: Script) -> Fake {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let http = listener.local_addr().unwrap();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let ssdp = udp.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Log::default()));
    let script = Arc::new(script);

    let ssdp_log = Arc::clone(&log);
    let ssdp_script = Arc::clone(&script);
    let search = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        while let Ok((length, from)) = udp.recv_from(&mut buffer).await {
            if !buffer[..length].starts_with(b"M-SEARCH") {
                continue;
            }
            ssdp_log.lock().unwrap().searches += 1;
            if ssdp_script.ssdp_answers {
                let host = ssdp_script.location_host.as_deref().unwrap_or("127.0.0.1");
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://{host}:{}{}\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n",
                    http.port(),
                    ssdp_script.path
                );
                let _ = udp.send_to(reply.as_bytes(), from).await;
            }
        }
    });

    let serve_log = Arc::clone(&log);
    let serve = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(connection(
                stream,
                Arc::clone(&script),
                Arc::clone(&serve_log),
            ));
        }
    });
    Fake {
        ssdp,
        log,
        tasks: [search, serve],
    }
}

async fn connection(mut stream: TcpStream, script: Arc<Script>, log: Arc<Mutex<Log>>) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 2048];
    let (head_end, length) = loop {
        let read = stream.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&buffer).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while buffer.len() < head_end + length {
        let read = stream.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buffer).into_owned();
    let (head, body) = text.split_at(head_end);
    let mut request_line = head.lines().next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default();
    let path = request_line.next().unwrap_or_default().to_owned();
    if !script.http_answers {
        std::future::pending::<()>().await;
    }
    let (status, reply) = if method == "GET" {
        log.lock().unwrap().gets.push(path);
        (200, script.description.clone())
    } else {
        let action = head
            .lines()
            .find_map(|line| line.strip_prefix("SOAPAction: "))
            .unwrap_or_default()
            .trim_matches('"')
            .to_owned();
        let name = action.rsplit('#').next().unwrap_or_default().to_owned();
        log.lock().unwrap().posts.push(Post {
            path,
            action,
            body: body.to_owned(),
        });
        (script.soap)(&name, body)
    };
    let head = if script.chunked && method == "GET" {
        format!("HTTP/1.1 {status} X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
    } else {
        format!(
            "HTTP/1.1 {status} X\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reply.len()
        )
    };
    let _ = stream.write_all(head.as_bytes()).await;
    if script.chunked && method == "GET" {
        for part in reply.as_bytes().chunks(40) {
            let _ = stream
                .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                .await;
            let _ = stream.write_all(part).await;
            let _ = stream.write_all(b"\r\n").await;
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
    } else {
        let _ = stream.write_all(reply.as_bytes()).await;
    }
    let _ = stream.shutdown().await;
}
