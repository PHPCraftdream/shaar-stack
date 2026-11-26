// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! One `PUT` of a signed record to a public pkarr relay (leaf PKARR-1) and one `GET` of it (leaf
//! PKARR-4): the HTTP client, the validated relay address and the classification of the answer.
//! Nothing here keeps state.

use std::sync::Arc;
use std::time::Duration;

use iroh_base::EndpointId;
use url::{Host, Url};

use super::MAX_BODY_BYTES;

/// Header of a relay's `204` that counts the DHT nodes which stored the packet.
const STORED_NODES: &str = "pkarr-dht-stored-nodes";

/// One public pkarr relay: an `https://` base URL with a domain name, or `http://` to a loopback
/// IPv4 literal (the loopback fake relay of the tests). No credentials, query, fragment or path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayUrl(Url);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayUrlError {
    Syntax,
    Scheme,
    Host,
    Credentials,
    Extra,
}

impl RelayUrl {
    pub(crate) fn parse(text: &str) -> Result<Self, RelayUrlError> {
        let url = Url::parse(text).map_err(|_| RelayUrlError::Syntax)?;
        match (url.scheme(), url.host()) {
            ("https", Some(Host::Domain(_))) => {}
            ("https", _) => return Err(RelayUrlError::Host),
            ("http", Some(Host::Ipv4(ip))) if ip.is_loopback() => {}
            _ => return Err(RelayUrlError::Scheme),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(RelayUrlError::Credentials);
        }
        if url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
            return Err(RelayUrlError::Extra);
        }
        Ok(Self(url))
    }

    /// `<base>/<z-base-32 key>`, the path of both `PUT` and `GET`.
    fn record_url(&self, key: EndpointId) -> Url {
        let mut url = self.0.clone();
        url.set_path(&key.to_z32());
        url
    }
}

/// How one `PUT` ended, without any remote text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    /// `204`; the count of the stored-nodes header when it was present and a number.
    Stored(Option<u32>),
    BadRequest,
    /// `409`: a newer packet is already stored, which is not an error.
    Stale,
    TooLarge,
    RateLimited,
    ServerError,
    Status(u16),
    Timeout,
    Network,
}

impl Class {
    pub(super) fn token(self) -> String {
        match self {
            Self::Stored(_) => "stored".to_owned(),
            Self::BadRequest => "bad-request".to_owned(),
            Self::Stale => "stale".to_owned(),
            Self::TooLarge => "too-large".to_owned(),
            Self::RateLimited => "rate-limited".to_owned(),
            Self::ServerError => "server-error".to_owned(),
            Self::Status(code) => format!("status-{code}"),
            Self::Timeout => "timeout".to_owned(),
            Self::Network => "network".to_owned(),
        }
    }

    pub(super) fn stored_nodes(self) -> Option<u32> {
        match self {
            Self::Stored(count) => count,
            _ => None,
        }
    }
}

/// How one `GET` ended, without any remote text. The body of a `200` is the signed packet without
/// its key, at most `MAX_BODY_BYTES`; whether it verifies is for the caller to decide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::native_discovery::runtime) enum Fetched {
    Found(Vec<u8>),
    NotFound,
    TooLarge,
    RateLimited,
    ServerError,
    Status(u16),
    Timeout,
    Network,
}

impl Fetched {
    pub(in crate::native_discovery::runtime) fn token(&self) -> String {
        match self {
            Self::Found(_) => "found".to_owned(),
            Self::NotFound => "not-found".to_owned(),
            Self::TooLarge => "too-large".to_owned(),
            Self::RateLimited => "rate-limited".to_owned(),
            Self::ServerError => "server-error".to_owned(),
            Self::Status(code) => format!("status-{code}"),
            Self::Timeout => "timeout".to_owned(),
            Self::Network => "network".to_owned(),
        }
    }
}

/// The answer of a `GET` that carries no packet (every status but `200`).
pub(super) fn classify_read(status: u16) -> Fetched {
    match status {
        404 => Fetched::NotFound,
        429 => Fetched::RateLimited,
        500..=599 => Fetched::ServerError,
        other => Fetched::Status(other),
    }
}

fn transport_failure(error: &reqwest::Error) -> Fetched {
    if error.is_timeout() {
        Fetched::Timeout
    } else {
        Fetched::Network
    }
}

pub(super) fn classify(status: u16, stored: Option<u32>) -> Class {
    match status {
        204 => Class::Stored(stored),
        400 => Class::BadRequest,
        409 => Class::Stale,
        413 => Class::TooLarge,
        429 => Class::RateLimited,
        500..=599 => Class::ServerError,
        other => Class::Status(other),
    }
}

/// The rustls client of every relay request: the `ring` provider and the bundled roots, not the
/// platform verifier (that one needs a Java environment, which a native process on the phone has
/// not). HTTP/1.1 only: the body is at most 1072 bytes.
fn tls_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The shared HTTP client of one mirror; `bound` caps a whole request, connect included.
pub(super) fn http_client(bound: Duration) -> Option<reqwest::Client> {
    let config = tls_config().ok()?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(bound)
        .build()
        .ok()
}

/// One relay of one key.
pub(super) struct RelayClient {
    http: reqwest::Client,
    url: Url,
}

impl RelayClient {
    pub(super) fn new(http: reqwest::Client, relay: &RelayUrl, key: EndpointId) -> Self {
        Self {
            http,
            url: relay.record_url(key),
        }
    }

    /// `PUT` of `signature, timestamp, DNS packet` (the signed packet without its key). The
    /// request carries its own time bound; a redirect is an answer, not followed.
    pub(super) async fn put(&self, body: &[u8]) -> Class {
        match self
            .http
            .put(self.url.clone())
            .body(body.to_vec())
            .send()
            .await
        {
            Ok(response) => {
                let stored = response
                    .headers()
                    .get(STORED_NODES)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|text| text.trim().parse::<u32>().ok());
                classify(response.status().as_u16(), stored)
            }
            Err(error) if error.is_timeout() => Class::Timeout,
            Err(_) => Class::Network,
        }
    }

    /// `GET` of the signed packet without its key. The request carries its own time bound, the
    /// body included; a redirect is an answer, not followed; the body is read to
    /// `MAX_BODY_BYTES` at most, so a hostile relay cannot make the read grow.
    pub(super) async fn get(&self) -> Fetched {
        let mut response = match self.http.get(self.url.clone()).send().await {
            Ok(response) => response,
            Err(error) => return transport_failure(&error),
        };
        let status = response.status().as_u16();
        if status != 200 {
            return classify_read(status);
        }
        let oversize = response
            .content_length()
            .is_some_and(|length| !usize::try_from(length).is_ok_and(|n| n <= MAX_BODY_BYTES));
        if oversize {
            return Fetched::TooLarge;
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_BODY_BYTES => {
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(_)) => return Fetched::TooLarge,
                Ok(None) => return Fetched::Found(body),
                Err(error) => return transport_failure(&error),
            }
        }
    }
}
